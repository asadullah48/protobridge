"""Pluggable reasoner used for human-readable audit narration.

The reasoner is deliberately **non-load-bearing**. It never decides routing and
never decides enforcement — it only describes what the deterministic layers
already concluded. Swapping the backend cannot change a single verdict, only
how the outcome reads.

No hosted API and no API key is involved anywhere in this module.

Backends
--------
``deterministic`` (default)
    Template-driven. No network, no model, byte-identical across runs, so tests
    can assert on its exact output.
``ollama``
    A model you run yourself, reached over plain HTTP on localhost. No key, no
    account, no cloud egress — which suits a component whose job is auditing
    cross-vendor data flows in the first place.
"""

from __future__ import annotations

import json
import os
from typing import Any, Protocol, runtime_checkable
from urllib.request import Request, urlopen

DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
DEFAULT_OLLAMA_MODEL = "llama3.2"

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@runtime_checkable
class Reasoner(Protocol):
    """Turns a compliance outcome into a sentence a human can act on."""

    name: str

    def narrate(
        self,
        *,
        subject: str,
        protocol: str,
        verdict: str,
        violations: list[dict[str, Any]],
        ok: bool,
    ) -> str: ...


def _build_prompt(
    subject: str, protocol: str, verdict: str, violations: list[dict[str, Any]], ok: bool
) -> str:
    return (
        "You are the audit narrator for a protocol interoperability layer.\n"
        f"Protocol: {protocol}\nSubject: {subject}\n"
        f"Transport succeeded: {ok}\nEnforcement verdict: {verdict}\n"
        f"Findings: {violations or 'none'}\n\n"
        "Write two sentences for a compliance officer: what happened, and what "
        "to do about it. No preamble, no bullet points."
    )


class DeterministicReasoner:
    """Offline, dependency-free, byte-identical across runs."""

    name = "deterministic"

    def narrate(
        self,
        *,
        subject: str,
        protocol: str,
        verdict: str,
        violations: list[dict[str, Any]],
        ok: bool,
    ) -> str:
        head = f"{protocol.upper()} call to {subject!r}"
        if not violations:
            outcome = "completed cleanly" if ok else "failed at the transport layer"
            return f"{head} {outcome}; no policy findings."

        codes = ", ".join(sorted({v["code"] for v in violations}))
        worst = max(violations, key=lambda v: _SEVERITY_RANK.get(v["severity"], 0))
        action = {
            "allow": "allowed with findings recorded",
            "redact": "allowed after redacting sensitive fields",
            "block": "blocked",
        }.get(verdict, verdict)
        return (
            f"{head} was {action}. {len(violations)} finding(s) [{codes}]; "
            f"most severe {worst['severity']}: {worst['message']} "
            f"Remediation: {worst['remediation']}."
        )


class OllamaReasoner:
    """Narrates via a locally hosted model over Ollama's HTTP API.

    Requires a running ``ollama serve`` and a pulled model; nothing else. Any
    failure — daemon down, model absent, timeout — degrades to the
    deterministic reasoner rather than breaking the bridge. Narration is
    cosmetic and must never be able to take the system down.
    """

    name = "ollama"

    def __init__(
        self,
        model: str = DEFAULT_OLLAMA_MODEL,
        base_url: str = DEFAULT_OLLAMA_URL,
        *,
        timeout: float = 30.0,
    ) -> None:
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._fallback = DeterministicReasoner()

    def narrate(
        self,
        *,
        subject: str,
        protocol: str,
        verdict: str,
        violations: list[dict[str, Any]],
        ok: bool,
    ) -> str:
        body = json.dumps(
            {
                "model": self._model,
                "prompt": _build_prompt(subject, protocol, verdict, violations, ok),
                "stream": False,
            }
        ).encode("utf-8")
        req = Request(  # noqa: S310 - operator-configured localhost endpoint
            f"{self._base_url}/api/generate",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
                text = json.loads(resp.read().decode("utf-8")).get("response", "").strip()
            if text:
                return text
        except Exception:  # noqa: BLE001 - narration must never break the bridge
            pass
        return self._fallback.narrate(
            subject=subject,
            protocol=protocol,
            verdict=verdict,
            violations=violations,
            ok=ok,
        )


def get_reasoner(backend: str | None = None) -> Reasoner:
    """Resolve the reasoner from an explicit name or ``PROTOBRIDGE_LLM``.

    Anything unrecognised resolves to the deterministic reasoner, so a typo or
    an absent local daemon degrades narration instead of the run.
    """
    choice = (backend or os.getenv("PROTOBRIDGE_LLM") or "deterministic").strip().lower()
    if choice != "ollama":
        return DeterministicReasoner()
    return OllamaReasoner(
        os.getenv("PROTOBRIDGE_MODEL", DEFAULT_OLLAMA_MODEL),
        os.getenv("PROTOBRIDGE_OLLAMA_URL", DEFAULT_OLLAMA_URL),
    )
