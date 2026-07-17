"""Open-core edition boundary — the free/paid line, in code and in writing.

The contract, enforced in code:

* Everything in this repository is and stays free: scanning, proposing,
  policy packs, suppressions, cost diffing, every reporter, the LLM
  adapter. The MIT core must remain genuinely useful standalone —
  open-core, never open-bait.
* Paid capabilities are *team/organization* concerns (shared audit,
  org rollups, SSO/SCIM, compliance evidence reports, private registries).
  They live in a separate commercial package that attaches through the
  ``cairn.commercial`` entry point; this module only defines the seam.
* The OSS core never phones home, validates license keys, or degrades:
  without the commercial package everything here runs as COMMUNITY,
  full-featured, forever.
"""

from __future__ import annotations

import enum
from importlib import metadata

from cairn import __version__


class Edition(enum.Enum):
    COMMUNITY = "community"
    TEAM = "team"
    ENTERPRISE = "enterprise"

    @property
    def rank(self) -> int:
        return [Edition.COMMUNITY, Edition.TEAM, Edition.ENTERPRISE].index(self)


#: Capabilities shipped in this repository. Free in every edition, forever.
#: Moving anything out of this set is a breaking-trust event, not a patch.
FREE_FOREVER = frozenset({
    "scan", "propose", "rules", "diff", "packs", "suppressions",
    "explanations", "reports", "audit-log",
})

#: Team/organization capabilities provided by the commercial package.
GATED: dict[str, Edition] = {
    "org-rollups": Edition.TEAM,
    "shared-audit": Edition.TEAM,
    "team-dashboards": Edition.TEAM,
    "sso-scim": Edition.ENTERPRISE,
    "compliance-reports": Edition.ENTERPRISE,
    "private-registry": Edition.ENTERPRISE,
}


class EditionError(Exception):
    """A gated capability was requested without the edition that carries it."""


def current_edition() -> Edition:
    """COMMUNITY unless an installed commercial package says otherwise.

    Detection is local (Python entry points) — no network, no key check,
    nothing that could make the free tier worse.
    """
    try:
        entry_points = metadata.entry_points(group="cairn.commercial")
    except Exception:  # metadata backends vary; absence must never break a scan
        return Edition.COMMUNITY
    for entry_point in entry_points:
        try:
            provider = entry_point.load()
            edition = provider()
            if isinstance(edition, Edition):
                return edition
        except Exception:  # noqa: S112 - a broken commercial plugin must not break the core
            continue
    return Edition.COMMUNITY


def require(feature: str) -> None:
    """Assert *feature* is available; raise a fix-carrying error if not."""
    if feature in FREE_FOREVER:
        return
    needed = GATED.get(feature)
    if needed is None:
        raise ValueError(f"unknown feature {feature!r}")
    if current_edition().rank >= needed.rank:
        return
    raise EditionError(
        f"'{feature}' is a {needed.value}-tier capability. The core you are "
        f"running (cairn {__version__}, community edition) stays fully "
        "functional and free; gated features live in the separate commercial "
        "package."
    )
