"""Resource dependency graph — the v0.4 "digital twin" (local, in-memory).

Turns the flat list of parsed resources into a directed graph so a finding
can report its *blast radius*: the resources downstream of it. An open
security group that fronts a database that holds payments data is a very
different finding from one fronting a throwaway box, and the graph is what
lets Cairn say so.

Edges are derived, offline, from three signals already present in the
parsed bodies:

* **References** — a resource whose attribute mentions another resource's
  address (``aws_instance.web`` or ``${aws_instance.web.id}``) depends on
  it. This is the bulk of real Terraform coupling.
* **explicit depends_on** — the same, stated directly.
* **Kubernetes selectors** — a Service/Deployment ``selector``/``matchLabels``
  that matches another manifest's labels.

Direction: an edge ``A -> B`` means "A depends on B". Blast radius of a
resource R is everything that (transitively) depends on R — i.e. what
breaks or is exposed if R is wrong. That is the *reverse* reachable set.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from cairn.terraform import Resource

# Matches a resource address, optionally wrapped in interpolation and/or
# followed by an attribute path: ${aws_instance.web.id} or aws_s3_bucket.logs
_ADDRESS = re.compile(r"(?<![\w.])([a-z][a-z0-9_]*\.[A-Za-z_][\w-]*)")


@dataclass
class ResourceGraph:
    """A directed dependency graph over resource addresses."""

    #: address -> set of addresses it depends on (A -> B means A needs B)
    edges: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    #: every known address (so isolated resources still appear)
    nodes: set[str] = field(default_factory=set)
    #: reverse adjacency, memoized on build
    _reverse: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    def add_edge(self, src: str, dst: str) -> None:
        if src == dst:
            return
        self.edges[src].add(dst)
        self._reverse[dst].add(src)
        self.nodes.update((src, dst))

    def dependents_of(self, address: str) -> list[str]:
        """Everything that transitively depends on *address* (its blast radius).

        Breadth-first over the reverse edges. The resource itself is not
        included. Result is sorted for stable output.
        """
        seen: set[str] = set()
        queue: deque[str] = deque(self._reverse.get(address, set()))
        while queue:
            node = queue.popleft()
            if node in seen:
                continue
            seen.add(node)
            queue.extend(self._reverse.get(node, set()) - seen)
        return sorted(seen)


def _iter_strings(value: Any) -> list[str]:
    out: list[str] = []
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            out.extend(_iter_strings(v))
    elif isinstance(value, list):
        for v in value:
            out.extend(_iter_strings(v))
    return out


def _k8s_labels(resource: Resource) -> dict[str, str]:
    meta = resource.body.get("metadata") or {}
    labels = meta.get("labels") if isinstance(meta, dict) else None
    return {str(k): str(v) for k, v in labels.items()} if isinstance(labels, dict) else {}


def _k8s_selector(resource: Resource) -> dict[str, str]:
    spec = resource.body.get("spec")
    if not isinstance(spec, dict):
        return {}
    selector = spec.get("selector")
    if isinstance(selector, dict):
        match = selector.get("matchLabels", selector)
        if isinstance(match, dict):
            return {str(k): str(v) for k, v in match.items()}
    return {}


def build_graph(resources: tuple[Resource, ...]) -> ResourceGraph:
    """Construct the dependency graph from parsed resources."""
    graph = ResourceGraph()
    known = {r.address for r in resources}
    for resource in resources:
        graph.nodes.add(resource.address)

    # 1 + 2: reference and depends_on edges (Terraform-style)
    for resource in resources:
        for text in _iter_strings(resource.body):
            for match in _ADDRESS.findall(text):
                if match in known and match != resource.address:
                    graph.add_edge(resource.address, match)

    # 3: Kubernetes selector -> labels edges
    k8s = [r for r in resources if r.type.startswith("k8s_")]
    for consumer in k8s:
        selector = _k8s_selector(consumer)
        if not selector:
            continue
        for provider in k8s:
            if provider.address == consumer.address:
                continue
            labels = _k8s_labels(provider)
            if labels and all(labels.get(k) == v for k, v in selector.items()):
                graph.add_edge(consumer.address, provider.address)

    return graph
