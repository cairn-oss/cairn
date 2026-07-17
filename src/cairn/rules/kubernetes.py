"""Built-in Kubernetes rules (K8S···).

All pod-carrying kinds (Deployment, StatefulSet, DaemonSet, Job, CronJob,
ReplicaSet, bare Pod) are inspected through one spec-extraction helper so
each rule states its check once.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from cairn.findings import Category, Severity
from cairn.rules.base import Detection, ScanContext, rule
from cairn.terraform import Resource

_POD_KINDS = (
    "k8s_pod", "k8s_deployment", "k8s_statefulset", "k8s_daemonset",
    "k8s_job", "k8s_cronjob", "k8s_replicaset",
)


def _pod_spec(res: Resource) -> dict[str, Any]:
    body = res.body
    if res.type == "k8s_pod":
        spec = body.get("spec")
    elif res.type == "k8s_cronjob":
        spec = (
            ((body.get("spec") or {}).get("jobTemplate") or {})
            .get("spec", {}).get("template", {}).get("spec")
        )
    else:
        spec = ((body.get("spec") or {}).get("template") or {}).get("spec")
    return spec if isinstance(spec, dict) else {}


def _containers(res: Resource) -> list[dict[str, Any]]:
    spec = _pod_spec(res)
    out: list[dict[str, Any]] = []
    for key in ("containers", "initContainers"):
        items = spec.get(key)
        if isinstance(items, list):
            out.extend(c for c in items if isinstance(c, dict))
    return out


@rule(
    id="K8S001",
    title="Privileged container",
    category=Category.SECURITY,
    severity=Severity.CRITICAL,
    description=(
        "privileged: true removes container isolation entirely — the "
        "container is effectively root on the node."
    ),
    resource_types=_POD_KINDS,
    references=("https://kubernetes.io/docs/concepts/security/pod-security-standards/",),
)
def privileged_container(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    for container in _containers(res):
        security = container.get("securityContext") or {}
        if security.get("privileged") is True:
            yield Detection(
                message=f"Container '{container.get('name', '?')}' runs privileged.",
                fix=(
                    "Drop privileged: true; grant the specific capability "
                    "needed via securityContext.capabilities.add instead."
                ),
                fix_code="securityContext:\n  privileged: false",
            )


@rule(
    id="K8S002",
    title="Container may run as root",
    category=Category.SECURITY,
    severity=Severity.HIGH,
    description=(
        "Neither the pod nor the container enforces runAsNonRoot, so a "
        "compromised process starts with uid 0 in the container."
    ),
    resource_types=_POD_KINDS,
    references=("https://kubernetes.io/docs/tasks/configure-pod-container/security-context/",),
)
def run_as_root(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    pod_security = _pod_spec(res).get("securityContext") or {}
    if pod_security.get("runAsNonRoot") is True:
        return
    for container in _containers(res):
        security = container.get("securityContext") or {}
        if security.get("runAsNonRoot") is not True:
            yield Detection(
                message=(
                    f"Container '{container.get('name', '?')}' does not "
                    "enforce runAsNonRoot."
                ),
                fix="Set securityContext.runAsNonRoot: true (pod- or container-level).",
                fix_code="securityContext:\n  runAsNonRoot: true",
            )
            return  # one finding per workload is signal; per-container is noise


@rule(
    id="K8S003",
    title="hostPath volume mounts the node filesystem",
    category=Category.SECURITY,
    severity=Severity.HIGH,
    description=(
        "hostPath pierces the container boundary; with a writable mount it "
        "is a node-takeover primitive."
    ),
    resource_types=_POD_KINDS,
    references=("https://kubernetes.io/docs/concepts/storage/volumes/#hostpath",),
)
def hostpath_volume(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    volumes = _pod_spec(res).get("volumes")
    if not isinstance(volumes, list):
        return
    for volume in volumes:
        if isinstance(volume, dict) and "hostPath" in volume:
            path = (volume.get("hostPath") or {}).get("path", "?")
            yield Detection(
                message=f"Volume '{volume.get('name', '?')}' mounts hostPath '{path}'.",
                fix=(
                    "Replace hostPath with a PersistentVolumeClaim, emptyDir, "
                    "or projected volume; if unavoidable, mount read-only and "
                    "scope the path tightly."
                ),
            )


@rule(
    id="K8S004",
    title="Unpinned image tag",
    category=Category.RELIABILITY,
    severity=Severity.MEDIUM,
    description=(
        "':latest' (or no tag) means every restart may pull different code "
        "— rollbacks and reproducibility break silently."
    ),
    resource_types=_POD_KINDS,
    references=("https://kubernetes.io/docs/concepts/containers/images/",),
)
def unpinned_image(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    for container in _containers(res):
        image = container.get("image")
        if not isinstance(image, str):
            continue
        reference = image.rsplit("/", 1)[-1]
        if "@sha256:" in image:
            continue
        if ":" not in reference or reference.endswith(":latest"):
            yield Detection(
                message=f"Container '{container.get('name', '?')}' uses unpinned image '{image}'.",
                fix="Pin a version tag (better: a digest) so deploys are reproducible.",
                fix_code=f"image: {image.split(':')[0]}:<version>",
            )


@rule(
    id="K8S005",
    title="Container without resource limits",
    category=Category.COST,
    severity=Severity.MEDIUM,
    description=(
        "No limits means one runaway pod can starve the node (reliability) "
        "and the scheduler can't bin-pack (cost). Requests+limits are how "
        "Kubernetes capacity stays attributable."
    ),
    resource_types=_POD_KINDS,
    references=("https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",),
)
def missing_limits(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    for container in _containers(res):
        resources = container.get("resources") or {}
        if not resources.get("limits"):
            yield Detection(
                message=f"Container '{container.get('name', '?')}' has no resources.limits.",
                fix="Set resources.requests and resources.limits from observed usage.",
                fix_code=(
                    "resources:\n  requests:\n    cpu: 100m\n    memory: 128Mi\n"
                    "  limits:\n    cpu: 500m\n    memory: 256Mi"
                ),
            )


@rule(
    id="K8S006",
    title="Container without health probes",
    category=Category.RELIABILITY,
    severity=Severity.LOW,
    description=(
        "Without liveness/readiness probes, Kubernetes routes traffic to "
        "dead processes and never restarts wedged ones."
    ),
    resource_types=("k8s_deployment", "k8s_statefulset", "k8s_daemonset"),
    references=(
        "https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/",
    ),
)
def missing_probes(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    for container in _containers(res):
        if not container.get("livenessProbe") or not container.get("readinessProbe"):
            yield Detection(
                message=(
                    f"Container '{container.get('name', '?')}' lacks liveness "
                    "and/or readiness probes."
                ),
                fix=(
                    "Add a readinessProbe (gates traffic) and a livenessProbe "
                    "(restarts wedged processes)."
                ),
            )
