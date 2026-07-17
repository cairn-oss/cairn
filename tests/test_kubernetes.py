"""Kubernetes parsing + rules: manifests join the unified pipeline."""

from pathlib import Path

from cairn import kubernetes
from cairn.engine import run_scan
from cairn.policy import Config

from .conftest import EXAMPLES, REPO_ROOT

K8S = REPO_ROOT / "examples" / "kubernetes"


class TestParser:
    def test_manifest_detection_requires_apiversion_and_kind(self, tmp_path: Path):
        (tmp_path / "ci.yaml").write_text("jobs:\n  build:\n    steps: []\n")
        (tmp_path / "app.yaml").write_text(
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec: {}\n"
        )
        result = kubernetes.parse_path(tmp_path)
        assert [r.address for r in result.resources] == ["k8s_pod.p"]
        assert result.errors == []

    def test_multi_document_files(self, tmp_path: Path):
        (tmp_path / "all.yaml").write_text(
            "apiVersion: v1\nkind: Service\nmetadata: {name: a}\n---\n"
            "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: b}\n"
        )
        result = kubernetes.parse_path(tmp_path)
        assert {r.type for r in result.resources} == {"k8s_service", "k8s_configmap"}

    def test_broken_yaml_is_contained(self, tmp_path: Path):
        (tmp_path / "bad.yaml").write_text("kind: [unclosed\napiVersion: v1\n")
        (tmp_path / "good.yaml").write_text("apiVersion: v1\nkind: Pod\nmetadata: {name: x}\n")
        result = kubernetes.parse_path(tmp_path)
        assert len(result.resources) == 1
        assert len(result.errors) == 1

    def test_anchor_bomb_guard(self, tmp_path: Path):
        bomb = "a: &a [x]\n" + "\n".join(f"k{i}: &b{i} [*a]" for i in range(300))
        (tmp_path / "bomb.yaml").write_text("apiVersion: v1\nkind: Pod\n" + bomb)
        result = kubernetes.parse_path(tmp_path)
        assert result.resources == []
        assert any("anchors" in e.message for e in result.errors)

    def test_oversized_file_skipped(self, tmp_path: Path):
        (tmp_path / "big.yaml").write_text("#" + "x" * (kubernetes.MAX_FILE_BYTES + 5))
        result = kubernetes.parse_path(tmp_path)
        assert any("skipped" in e.message for e in result.errors)

    def test_dir_symlinks_not_followed(self, tmp_path: Path):
        import os

        import pytest

        if not hasattr(os, "symlink"):
            pytest.skip("no symlink support")
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "x.yaml").write_text("apiVersion: v1\nkind: Pod\nmetadata: {name: x}\n")
        repo = tmp_path / "repo"
        repo.mkdir()
        try:
            (repo / "link").symlink_to(outside, target_is_directory=True)
        except OSError:
            pytest.skip("symlinks not permitted")
        assert kubernetes.discover_files(repo) == []


class TestRules:
    def test_vulnerable_fixture_fires_every_rule_family(self):
        result = run_scan(K8S / "vulnerable.yaml", Config())
        ids = {f.rule_id for f in result.findings}
        assert {"K8S001", "K8S002", "K8S003", "K8S004", "K8S005", "K8S006"} <= ids

    def test_clean_fixture_is_clean(self):
        result = run_scan(K8S / "clean.yaml", Config())
        assert result.findings == []
        assert result.resources_scanned == 1

    def test_cronjob_pod_spec_is_reached(self, tmp_path: Path):
        (tmp_path / "cron.yaml").write_text(
            """
apiVersion: batch/v1
kind: CronJob
metadata: {name: nightly}
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: task
              image: acme/task:latest
"""
        )
        result = run_scan(tmp_path, Config())
        assert "K8S004" in {f.rule_id for f in result.findings}

    def test_digest_pinned_image_is_clean_for_k8s004(self, tmp_path: Path):
        (tmp_path / "p.yaml").write_text(
            """
apiVersion: v1
kind: Pod
metadata: {name: pinned}
spec:
  containers:
    - name: app
      image: acme/app@sha256:deadbeef
"""
        )
        result = run_scan(tmp_path, Config())
        assert "K8S004" not in {f.rule_id for f in result.findings}


class TestEngineMerge:
    def test_terraform_and_k8s_scan_together(self, tmp_path: Path):
        (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
        (tmp_path / "app.yaml").write_text(
            "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\n"
            "spec:\n  containers:\n    - name: c\n      image: a/b:latest\n"
        )
        result = run_scan(tmp_path, Config())
        types = {f.resource_type for f in result.findings}
        assert "aws_s3_bucket" in types and "k8s_pod" in types
        assert result.files_scanned == 2

    def test_terraform_only_examples_unaffected(self):
        result = run_scan(EXAMPLES / "clean", Config())
        assert result.findings == []


class TestSuppressionSafeFailure:
    def test_k8s_findings_cannot_be_silently_suppressed(self, tmp_path: Path):
        # Manifests lack line anchors, so an ignore marker cannot attach to a
        # K8s resource. The safe outcome is that the finding still fires (or
        # the marker warns) — never a silent suppression.
        (tmp_path / "app.yaml").write_text(
            "# cairn:ignore K8S001 reason=attempt\n"
            "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\n"
            "spec:\n  containers:\n"
            "    - {name: c, image: a/b:1.0, securityContext: {privileged: true}}\n"
        )
        result = run_scan(tmp_path, Config())
        assert "K8S001" in {f.rule_id for f in result.findings}
        assert result.suppressed == []
