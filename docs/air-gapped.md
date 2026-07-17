# Running Cairn in an air-gapped / on-prem environment

Cairn is local-first by design, which makes it a natural fit for
air-gapped, regulated, and on-prem estates where a SaaS scanner is a
non-starter. This page covers running it with no internet access.

## What Cairn does and does not send

- **Scanning, proposing, diffing, drift, rollup:** 100% local. No network
  calls, no telemetry, no update checks, no license-server calls.
- **The only optional network path** is `--explain`, which you simply do
  not use in an air-gapped environment (or point at a local Ollama). It is
  off by default.
- Cost estimates come from a **bundled offline price book**, so `diff` and
  cost findings work with no connectivity.

## Install without internet

Build a wheel on a connected machine and carry it in:

```bash
# connected machine
pip download cairn-iac -d ./cairn-offline
# transfer ./cairn-offline to the air-gapped host, then:
pip install --no-index --find-links ./cairn-offline cairn-iac
```

Or use the container image, loaded from a saved tarball:

```bash
docker save cairn:0.4.5 -o cairn.tar        # connected
docker load -i cairn.tar                        # air-gapped
docker run --rm -v "$PWD:/scan:ro" cairn scan /scan
```

## On-prem targets

Beyond the cloud providers, Cairn scans **VMware vSphere** Terraform
(the `VS*` rules) for private-cloud estates. Kubernetes manifest scanning
works identically whether the cluster runs on a cloud or on bare metal in
your datacenter. Filter to just your platform with `--provider`:

```bash
cairn scan ./infra --provider vsphere,kubernetes
```

## What differs on-prem

On-prem resources have no per-hour cloud pricing, so **cost findings are
cloud-only** — the security, reliability, and governance disciplines apply
everywhere and are where on-prem value concentrates. Cairn states this
honestly rather than inventing dollar figures for owned hardware.

## Verifying no egress

Because there are no network calls in the scan path, you can confirm
isolation simply by running under a network namespace with no routes, or
by watching with `strace -f -e trace=network` — a scan makes no outbound
connections.
