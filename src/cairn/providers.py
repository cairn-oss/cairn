"""Provider inference and the coverage registry.

Cairn is cloud-agnostic: the provider a resource belongs to is derived
from its type prefix, so rules, filtering, reporting and coverage all work
across clouds and on-prem without provider-specific plumbing above the rule
layer.

Two tiers of provider are recognized:

* **Covered** providers have built-in rule packs (AWS, Azure, GCP,
  Kubernetes, vSphere).
* **Known** providers are ones Cairn can *name* but does not yet have
  rules for (Oracle, DigitalOcean, Alibaba, IBM, ...). Naming them makes
  the coverage gap precise in reports rather than a vague "other".
"""

from __future__ import annotations

#: Resource-type prefix -> provider label, for providers with rule packs.
_COVERED_PREFIXES: dict[str, str] = {
    "aws_": "aws",
    "azurerm_": "azure",
    "google_": "gcp",
    "vsphere_": "vsphere",
    "k8s_": "kubernetes",
}

#: Prefixes for providers Cairn can name but has no rules for yet.
_KNOWN_PREFIXES: dict[str, str] = {
    "oci_": "oracle-cloud",
    "digitalocean_": "digitalocean",
    "alicloud_": "alibaba",
    "ibm_": "ibm-cloud",
    "linode_": "linode",
    "hcloud_": "hetzner",
    "openstack_": "openstack",
    "helm_": "helm",
    "kubernetes_": "kubernetes-tf",
    "docker_": "docker",
    "cloudflare_": "cloudflare",
    "datadog_": "datadog",
}

#: Providers that ship with rule coverage today.
COVERED_PROVIDERS = ("aws", "azure", "gcp", "kubernetes", "vsphere")


def provider_for(resource_type: str) -> str:
    """Return the provider label for a resource type.

    Covered providers first, then known-but-uncovered, then ``other``.
    """
    for prefix, provider in _COVERED_PREFIXES.items():
        if resource_type.startswith(prefix):
            return provider
    for prefix, provider in _KNOWN_PREFIXES.items():
        if resource_type.startswith(prefix):
            return provider
    return "other"


def is_covered(resource_type: str) -> bool:
    """True when Cairn has a rule pack for this resource's provider."""
    return any(resource_type.startswith(p) for p in _COVERED_PREFIXES)
