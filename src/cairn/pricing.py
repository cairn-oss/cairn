"""Static price book used for cost *estimates*.

These are indicative on-demand prices (us-east-1, Linux, 730 hours/month)
bundled with the release so that scans work offline and never call a cloud
API. They exist to put an order-of-magnitude dollar figure next to a
finding at the moment of the decision — not to replace your bill.

Update cadence: refreshed each release; see ``docs/pricing.md``.
"""

from __future__ import annotations

HOURS_PER_MONTH = 730

#: Approximate on-demand USD/hour for common EC2 instance types.
EC2_HOURLY: dict[str, float] = {
    # previous generation -> modern equivalents cost less for more perf
    "t2.micro": 0.0116,
    "t2.small": 0.023,
    "t2.medium": 0.0464,
    "t2.large": 0.0928,
    "t2.xlarge": 0.1856,
    "m4.large": 0.10,
    "m4.xlarge": 0.20,
    "m4.2xlarge": 0.40,
    "c4.large": 0.10,
    "c4.xlarge": 0.199,
    # current generation
    "t3.micro": 0.0104,
    "t3.small": 0.0208,
    "t3.medium": 0.0416,
    "t3.large": 0.0832,
    "t3.xlarge": 0.1664,
    "m5.large": 0.096,
    "m5.xlarge": 0.192,
    "m5.2xlarge": 0.384,
    "m5.4xlarge": 0.768,
    "m5.8xlarge": 1.536,
    "m5.12xlarge": 2.304,
    "c5.large": 0.085,
    "c5.xlarge": 0.17,
    "c5.2xlarge": 0.34,
    "c5.4xlarge": 0.68,
    "c5.9xlarge": 1.53,
    "r5.large": 0.126,
    "r5.xlarge": 0.252,
    "r5.2xlarge": 0.504,
    "r5.4xlarge": 1.008,
    "r5.8xlarge": 2.016,
}

#: Approximate on-demand USD/hour for common RDS instance classes (single-AZ).
RDS_HOURLY: dict[str, float] = {
    "db.t3.micro": 0.017,
    "db.t3.small": 0.034,
    "db.t3.medium": 0.068,
    "db.t3.large": 0.136,
    "db.m5.large": 0.171,
    "db.m5.xlarge": 0.342,
    "db.m5.2xlarge": 0.684,
    "db.m5.4xlarge": 1.368,
    "db.r5.large": 0.24,
    "db.r5.xlarge": 0.48,
    "db.r5.2xlarge": 0.96,
    "db.r5.4xlarge": 1.92,
}

#: EBS USD per GB-month.
EBS_GB_MONTH: dict[str, float] = {
    "gp2": 0.10,
    "gp3": 0.08,
    "io1": 0.125,
    "io2": 0.125,
    "standard": 0.05,
}

#: An idle (unassociated) Elastic IP, USD/hour.
IDLE_EIP_HOURLY = 0.005

#: Approximate Azure VM USD/month (pay-as-you-go, indicative).
AZURE_VM_MONTHLY: dict[str, float] = {
    "Standard_D2s_v5": 70.0, "Standard_D4s_v5": 140.0, "Standard_D8s_v5": 280.0,
    "Standard_D16s_v5": 560.0, "Standard_D32s_v5": 1120.0,
    "Standard_E8s_v5": 380.0, "Standard_F8s_v2": 250.0,
}

#: Approximate GCP machine-type USD/month (on-demand, indicative).
GCP_MACHINE_MONTHLY: dict[str, float] = {
    "e2-standard-8": 195.0, "e2-standard-16": 390.0, "e2-standard-32": 780.0,
    "n2-standard-8": 280.0, "n2-standard-16": 560.0, "n2-standard-32": 1120.0,
}

#: Instance families considered "large" enough to question by default.
OVERSIZED_PREFIXES = ("4xlarge", "8xlarge", "9xlarge", "12xlarge", "16xlarge", "24xlarge")

#: Previous-generation -> suggested current-generation replacement.
OLD_GENERATION_UPGRADES: dict[str, str] = {
    "t2": "t3",
    "m4": "m5",
    "c4": "c5",
    "r4": "r5",
}


def ec2_monthly(instance_type: str) -> float | None:
    hourly = EC2_HOURLY.get(instance_type)
    return round(hourly * HOURS_PER_MONTH, 2) if hourly is not None else None


def rds_monthly(instance_class: str) -> float | None:
    hourly = RDS_HOURLY.get(instance_class)
    return round(hourly * HOURS_PER_MONTH, 2) if hourly is not None else None
