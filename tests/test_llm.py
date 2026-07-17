import io
import json
import urllib.error
import urllib.request

import pytest

from cairn import llm
from cairn.findings import Category, Finding, Severity
from cairn.llm import ExplainError, build_explainer
from cairn.policy import LLMConfig

FINDING = Finding(
    rule_id="SEC001",
    severity=Severity.CRITICAL,
    category=Category.SECURITY,
    resource_type="aws_security_group",
    resource_name="web",
    file="main.tf",
    line=3,
    message="open to the world",
    fix="close it",
    monthly_cost=12.0,
)


class TestBuildExplainer:
    def test_none_provider_never_calls_network(self):
        explainer = build_explainer(LLMConfig(provider="none"))
        assert explainer.explain(FINDING) is None

    def test_openai_requires_key(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        with pytest.raises(ExplainError, match="OPENAI_API_KEY"):
            build_explainer(LLMConfig(provider="openai"))

    def test_anthropic_requires_key(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(ExplainError, match="ANTHROPIC_API_KEY"):
            build_explainer(LLMConfig(provider="anthropic"))

    def test_ollama_needs_no_key_and_defaults_local(self):
        explainer = build_explainer(LLMConfig(provider="ollama"))
        assert explainer.base_url.startswith("http://localhost")
        assert explainer.api_key is None

    def test_unknown_provider(self):
        with pytest.raises(ExplainError, match=r"unknown llm\.provider"):
            build_explainer(LLMConfig(provider="skynet"))


def _fake_urlopen(payload: dict):
    class _Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def opener(request, timeout=0):
        opener.captured = request  # type: ignore[attr-defined]
        return _Response(json.dumps(payload).encode())

    return opener


class TestProviders:
    def test_openai_compatible_parses_response(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        explainer = build_explainer(LLMConfig(provider="openai"))
        fake = _fake_urlopen(
            {"choices": [{"message": {"content": "  explained  "}}]}
        )
        monkeypatch.setattr(urllib.request, "urlopen", fake)
        assert explainer.explain(FINDING) == "explained"
        sent = json.loads(fake.captured.data)
        # privacy contract: only finding metadata goes out, never file bodies
        assert "aws_security_group.web" in sent["messages"][1]["content"]

    def test_anthropic_parses_response(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
        explainer = build_explainer(LLMConfig(provider="anthropic"))
        fake = _fake_urlopen({"content": [{"type": "text", "text": "why it matters"}]})
        monkeypatch.setattr(urllib.request, "urlopen", fake)
        assert explainer.explain(FINDING) == "why it matters"
        assert fake.captured.headers["X-api-key"] == "sk-ant"

    def test_network_failure_degrades_gracefully(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        explainer = build_explainer(LLMConfig(provider="openai"))

        def boom(*args, **kwargs):
            raise urllib.error.URLError("connection refused")

        monkeypatch.setattr(urllib.request, "urlopen", boom)
        assert explainer.explain(FINDING) is None  # scan must not fail

    def test_malformed_response_degrades_gracefully(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        explainer = build_explainer(LLMConfig(provider="openai"))
        monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen({"nope": True}))
        assert explainer.explain(FINDING) is None

    def test_prompt_includes_cost_estimate(self):
        prompt = llm._finding_prompt(FINDING)
        assert "$12.00" in prompt
        assert "SEC001" in prompt


class TestBaseUrlValidation:
    """A scanned repo's config must not be able to redirect the user's key."""

    def test_https_base_url_accepted(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        explainer = build_explainer(
            LLMConfig(provider="openai", base_url="https://models.internal.corp/v1")
        )
        assert explainer.base_url.startswith("https://")

    def test_http_localhost_accepted(self):
        explainer = build_explainer(
            LLMConfig(provider="ollama", base_url="http://127.0.0.1:8080/v1")
        )
        assert explainer.base_url == "http://127.0.0.1:8080/v1"

    def test_http_remote_rejected(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        with pytest.raises(ExplainError, match=r"refusing llm\.base_url"):
            build_explainer(
                LLMConfig(provider="openai", base_url="http://evil.example.com/v1")
            )

    def test_other_schemes_rejected(self):
        with pytest.raises(ExplainError, match=r"refusing llm\.base_url"):
            build_explainer(
                LLMConfig(provider="ollama", base_url="file:///etc/passwd")
            )
