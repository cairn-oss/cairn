"""LLM adapter — strictly opt-in, bring-your-own-key, replaceable.

Privacy contract (enforced here, documented in SECURITY.md):
    * Nothing is sent anywhere unless the user passes ``--explain`` (or
      configures a provider) — the default provider is ``none``.
    * Only the finding itself (rule metadata + message + resource address)
      is sent. Cairn never uploads file contents, variables or state.
    * Any transport or provider failure degrades gracefully to the built-in
      rule-based fix text; a scan never fails because an LLM did.

Providers:
    * ``openai``    — OpenAI-compatible Chat Completions (``OPENAI_API_KEY``)
    * ``ollama``    — local Ollama server via its OpenAI-compatible endpoint
                      (no key, data stays on the machine)
    * ``anthropic`` — Anthropic Messages API (``ANTHROPIC_API_KEY``)
    * ``none``      — the default: no network, no calls
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from cairn.findings import Finding
from cairn.policy import LLMConfig

_TIMEOUT_SECONDS = 30
_MAX_TOKENS = 400

_SYSTEM_PROMPT = (
    "You are Cairn, an infrastructure auditor. Given one finding from a "
    "Terraform scan, explain in 3-5 plain-English sentences why it matters "
    "for this specific resource, then give a concrete remediation. Mention "
    "the trade-off between cost, security and reliability when relevant. "
    "Be specific and calm; no marketing language."
)


class ExplainError(Exception):
    """Provider misconfiguration the user should hear about (e.g. no key)."""


_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _validated_base_url(url: str) -> str:
    """Allow https anywhere, or plain http strictly to loopback.

    A scanned repository can ship its own ``.cairn.yaml``. Without this
    check, a malicious config could point ``llm.base_url`` at an attacker
    host and receive the user's bearer token on the next ``--explain``.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "https":
        return url
    if parsed.scheme == "http" and (parsed.hostname or "") in _LOOPBACK_HOSTS:
        return url
    raise ExplainError(
        f"refusing llm.base_url {url!r}: must be https://, or http:// to "
        "localhost for local model servers (protects your API key from a "
        "malicious repository config)"
    )


@dataclass(frozen=True)
class Explainer:
    """Resolved provider; ``explain`` returns None on any soft failure."""

    provider: str
    model: str
    base_url: str
    api_key: str | None = None

    def explain(self, finding: Finding) -> str | None:
        if self.provider == "none":
            return None
        prompt = _finding_prompt(finding)
        try:
            if self.provider == "anthropic":
                return _call_anthropic(self, prompt)
            return _call_openai_compatible(self, prompt)
        except (urllib.error.URLError, TimeoutError, ValueError, KeyError, OSError):
            return None  # graceful degradation: rule text still shipped


def build_explainer(config: LLMConfig) -> Explainer:
    """Validate configuration and environment into a ready Explainer."""
    provider = config.provider or "none"
    if provider == "none":
        return Explainer(provider="none", model="", base_url="")
    if provider == "openai":
        key = os.environ.get("OPENAI_API_KEY", "")
        if not key:
            raise ExplainError("llm.provider is 'openai' but OPENAI_API_KEY is not set")
        return Explainer(
            provider=provider,
            model=config.model or "gpt-4o-mini",
            base_url=_validated_base_url(config.base_url or "https://api.openai.com/v1"),
            api_key=key,
        )
    if provider == "ollama":
        return Explainer(
            provider=provider,
            model=config.model or "llama3.1",
            base_url=_validated_base_url(config.base_url or "http://localhost:11434/v1"),
        )
    if provider == "anthropic":
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            raise ExplainError("llm.provider is 'anthropic' but ANTHROPIC_API_KEY is not set")
        return Explainer(
            provider=provider,
            model=config.model or "claude-haiku-4-5-20251001",
            base_url=_validated_base_url(config.base_url or "https://api.anthropic.com"),
            api_key=key,
        )
    raise ExplainError(f"unknown llm.provider {provider!r} (none|openai|ollama|anthropic)")


def _finding_prompt(finding: Finding) -> str:
    return (
        f"Rule {finding.rule_id} ({finding.severity.value}/{finding.category.value}) "
        f"on {finding.address}:\n"
        f"Problem: {finding.message}\n"
        f"Suggested fix: {finding.fix}\n"
        + (
            f"Estimated monthly waste: ${finding.monthly_cost:.2f}\n"
            if finding.monthly_cost
            else ""
        )
    )


def _post_json(url: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - https/localhost only
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", **headers},
    )
    with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))  # type: ignore[no-any-return]


def _call_openai_compatible(explainer: Explainer, prompt: str) -> str | None:
    headers = {}
    if explainer.api_key:
        headers["Authorization"] = f"Bearer {explainer.api_key}"
    data = _post_json(
        f"{explainer.base_url.rstrip('/')}/chat/completions",
        {
            "model": explainer.model,
            "max_tokens": _MAX_TOKENS,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        },
        headers,
    )
    content = data["choices"][0]["message"]["content"]
    return content.strip() if isinstance(content, str) else None


def _call_anthropic(explainer: Explainer, prompt: str) -> str | None:
    data = _post_json(
        f"{explainer.base_url.rstrip('/')}/v1/messages",
        {
            "model": explainer.model,
            "max_tokens": _MAX_TOKENS,
            "system": _SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": prompt}],
        },
        {"x-api-key": explainer.api_key or "", "anthropic-version": "2023-06-01"},
    )
    parts = data.get("content", [])
    text = "".join(p.get("text", "") for p in parts if isinstance(p, dict))
    return text.strip() or None
