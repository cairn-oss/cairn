"""The open-core boundary: community is full-featured, gates are honest."""

import pytest

from cairn.cli import EXIT_OK, main
from cairn.editions import (
    FREE_FOREVER,
    GATED,
    Edition,
    EditionError,
    current_edition,
    require,
)


def test_default_edition_is_community_and_offline():
    assert current_edition() is Edition.COMMUNITY


def test_every_shipped_capability_is_free_forever():
    for feature in ("scan", "propose", "diff", "packs", "suppressions", "reports"):
        require(feature)  # must not raise, in any edition


def test_gated_feature_raises_with_guidance():
    with pytest.raises(EditionError, match=r"community edition"):
        require("compliance-reports")


def test_free_and_gated_sets_do_not_overlap():
    assert not (FREE_FOREVER & set(GATED))


def test_unknown_feature_is_a_programming_error():
    with pytest.raises(ValueError, match="unknown feature"):
        require("teleportation")


def test_license_command_states_the_boundary(capsys):
    assert main(["license"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "community" in out
    assert "Free forever" in out
    assert "separate commercial" in out


class TestEntryPointResolution:
    def test_broken_commercial_plugin_never_breaks_core(self, monkeypatch):
        import cairn.editions as ed

        class _BadEP:
            name = "bad"

            def load(self):
                raise ImportError("commercial package is broken")

        monkeypatch.setattr(ed.metadata, "entry_points", lambda group: [_BadEP()])
        assert ed.current_edition() is Edition.COMMUNITY  # contained, not raised

    def test_valid_commercial_plugin_upgrades_edition(self, monkeypatch):
        import cairn.editions as ed

        class _GoodEP:
            name = "team"

            def load(self):
                return lambda: Edition.TEAM

        monkeypatch.setattr(ed.metadata, "entry_points", lambda group: [_GoodEP()])
        assert ed.current_edition() is Edition.TEAM
        ed.require("org-rollups")  # now available, must not raise

    def test_metadata_backend_failure_degrades_to_community(self, monkeypatch):
        import cairn.editions as ed

        def _boom(group):
            raise RuntimeError("metadata backend unavailable")

        monkeypatch.setattr(ed.metadata, "entry_points", _boom)
        assert ed.current_edition() is Edition.COMMUNITY
