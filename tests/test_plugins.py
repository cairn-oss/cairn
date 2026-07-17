"""Plugin SDK: entry-point rule loading, provenance, and safety."""

import cairn.rules.base as base
from cairn.findings import Category, Severity
from cairn.rules.base import _REGISTRY, load_plugins, rule


class _FakeEP:
    def __init__(self, name, value, loader):
        self.name = name
        self.value = value
        self._loader = loader

    def load(self):
        return self._loader()


def _reset_plugins():
    base._PLUGINS_LOADED = False


def test_plugin_rule_is_registered_with_provenance(monkeypatch):
    _reset_plugins()

    def _register():
        @rule(
            id="PLUG001",
            title="A plugin rule",
            category=Category.SECURITY,
            severity=Severity.LOW,
            description="from a plugin",
        )
        def _check(res, ctx):
            return []

    ep = _FakeEP("acme", "acme_rules.rules:setup", _register)
    monkeypatch.setattr("importlib.metadata.entry_points", lambda group: [ep])

    try:
        warnings = load_plugins()
        assert warnings == []
        assert "PLUG001" in _REGISTRY
        assert _REGISTRY["PLUG001"].source == "acme_rules"
    finally:
        _REGISTRY.pop("PLUG001", None)
        _reset_plugins()


def test_broken_plugin_is_contained(monkeypatch):
    _reset_plugins()

    def _boom():
        raise ImportError("plugin is broken")

    ep = _FakeEP("broken", "broken.rules:setup", _boom)
    monkeypatch.setattr("importlib.metadata.entry_points", lambda group: [ep])

    try:
        warnings = load_plugins()
        assert any("broken" in w for w in warnings)  # reported, not raised
    finally:
        _reset_plugins()


def test_load_is_idempotent(monkeypatch):
    _reset_plugins()
    calls = {"n": 0}

    def _counting(group):
        calls["n"] += 1
        return []

    monkeypatch.setattr("importlib.metadata.entry_points", _counting)
    load_plugins()
    load_plugins()
    assert calls["n"] == 1  # second call short-circuits
    _reset_plugins()
