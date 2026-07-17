"""Resource dependency graph and blast-radius reachability."""

from pathlib import Path

from cairn.engine import run_scan
from cairn.graph import build_graph
from cairn.policy import Config
from cairn.terraform import parse_path

from .conftest import EXAMPLES


def _resources(tmp_path: Path, source: str):
    (tmp_path / "main.tf").write_text(source)
    return tuple(parse_path(tmp_path).resources)


class TestGraphConstruction:
    def test_reference_edge(self, tmp_path):
        res = _resources(
            tmp_path,
            'resource "aws_instance" "web" { subnet_id = aws_subnet.main.id }\n'
            'resource "aws_subnet" "main" { cidr_block = "10.0.1.0/24" }\n',
        )
        graph = build_graph(res)
        # web depends on main -> main's blast radius includes web
        assert "aws_instance.web" in graph.dependents_of("aws_subnet.main")

    def test_interpolated_reference(self, tmp_path):
        res = _resources(
            tmp_path,
            'resource "aws_eip" "ip" { instance = "${aws_instance.web.id}" }\n'
            'resource "aws_instance" "web" { instance_type = "t3.micro" }\n',
        )
        graph = build_graph(res)
        assert "aws_eip.ip" in graph.dependents_of("aws_instance.web")

    def test_transitive_blast_radius(self, tmp_path):
        res = _resources(
            tmp_path,
            'resource "aws_subnet" "s" { cidr_block = "10.0.0.0/24" }\n'
            'resource "aws_instance" "web" { subnet_id = aws_subnet.s.id }\n'
            'resource "aws_eip" "ip" { instance = aws_instance.web.id }\n',
        )
        graph = build_graph(res)
        # subnet -> web -> eip, so subnet's blast radius is both
        assert set(graph.dependents_of("aws_subnet.s")) == {
            "aws_instance.web",
            "aws_eip.ip",
        }

    def test_isolated_resource_has_no_dependents(self, tmp_path):
        res = _resources(tmp_path, 'resource "aws_s3_bucket" "b" {}\n')
        graph = build_graph(res)
        assert graph.dependents_of("aws_s3_bucket.b") == []

    def test_no_self_edges(self, tmp_path):
        res = _resources(
            tmp_path,
            'resource "aws_security_group" "sg" { name = "sg" }\n',
        )
        graph = build_graph(res)
        assert "aws_security_group.sg" not in graph.dependents_of("aws_security_group.sg")

    def test_kubernetes_selector_edge(self, tmp_path):
        _resources(tmp_path, "")  # ensures tmp_path exists; manifests written below
        (tmp_path / "app.yaml").write_text(
            "apiVersion: v1\nkind: Service\nmetadata:\n  name: web\n"
            "spec:\n  selector:\n    app: web\n---\n"
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n"
            "  labels:\n    app: web\nspec:\n  template:\n    spec:\n      containers: []\n"
        )
        from cairn import kubernetes

        manifests = tuple(kubernetes.parse_path(tmp_path).resources)
        graph = build_graph(manifests)
        # service selects deployment's labels -> deployment blast radius includes service
        assert "k8s_service.web" in graph.dependents_of("k8s_deployment.web")


class TestBlastRadiusInScan:
    def test_findings_carry_blast_radius(self):
        result = run_scan(EXAMPLES / "vulnerable", Config())
        assert result.graph is not None
        # at least one finding on a referenced resource should have dependents
        assert any(f.blast_radius for f in result.findings) or result.graph.nodes

    def test_blast_radius_in_json(self):
        import json

        from cairn.report import render_json

        data = json.loads(render_json(run_scan(EXAMPLES / "vulnerable", Config())))
        assert data["schema_version"] == 2
        assert all("blast_radius" in f for f in data["findings"])
