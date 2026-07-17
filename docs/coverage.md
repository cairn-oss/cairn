# Provider coverage

Cairn is **cloud-agnostic and on-prem friendly by architecture**: the
parser and findings model are provider-neutral, and coverage grows by
adding rule packs, not by re-architecting. This page is the honest,
current picture of what is covered.

## Covered today

| Provider | Since | Notes |
|---|---|---|
| **AWS** (`aws_*`) | v0.1 | The deepest pack. |
| **Kubernetes** (manifests) | v0.3 | Platform-agnostic — scans the same on-prem, bare metal, or any managed cluster. |
| **Azure** (`azurerm_*`) | v0.4.5 | |
| **GCP** (`google_*`) | v0.4.5 | |
| **VMware vSphere** (`vsphere_*`) | v0.4.5 | On-prem / private cloud. |

Run `cairn providers` to see the live rule count per provider.

## What "not scanned" means

Terraform for **any** provider is parsed successfully. If a resource's
provider has no rule pack yet (e.g. Oracle Cloud, DigitalOcean), Cairn
reports it as **"not scanned"** — parsed but not checked — rather than
silently calling the run "clean". A scan is only reported "Clean" when
every resource belongs to a covered provider and passed its checks. This
honesty (added in v0.5.1) is deliberate: a false "clean" on an unsupported
provider is worse than saying nothing.

## Historical note (v0.1–v0.3)

Versions **v0.1, v0.2, and v0.3 are not fully cloud-agnostic**: they carry
rules for AWS (and, from v0.3, Kubernetes) only. On those versions a scan
of Azure/GCP/on-prem Terraform parses the files but finds nothing and — on
those releases — reports "clean", which can mislead. This is fixed from
v0.5.1 onward (explicit "not scanned" reporting) and the provider breadth
itself lands in v0.4.5. If you need multi-cloud or on-prem coverage, use
**v0.4.5 or later**.

## Extending coverage

A rule is one small function (see [CONTRIBUTING.md](../CONTRIBUTING.md)); a
whole new provider is a rule module registered in `cairn/rules/`. The
`provider` of a resource is inferred from its type prefix in
`cairn/providers.py` — add a prefix there to name a new provider.
