"""The three ProtoBridge agents.

``MCPConnector``
    Integrates external APIs and tools by speaking MCP to them.
``A2AGateway``
    Enables cross-vendor agent communication by speaking A2A to peers.
``AuditAgent``
    Monitors compliance and protocol adherence on both sides of every hop.

Each agent is a plain object with plain methods. ``graph.py`` wraps them as
LangGraph nodes, but nothing here depends on LangGraph — the agents stay
unit-testable without building a graph.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from time import perf_counter
from typing import Any

from protobridge.envelope import (
    Classification,
    EnvelopeResult,
    Protocol,
    ProtocolEnvelope,
)
from protobridge.ledger import AuditLedger
from protobridge.llm import Reasoner, get_reasoner
from protobridge.protocols import a2a as a2a_proto
from protobridge.protocols import mcp as mcp_proto
from protobridge.protocols.jsonrpc import JsonRpcError
from protobridge.rules import (
    Phase,
    Verdict,
    Violation,
    decide_verdict,
    evaluate_egress,
    evaluate_ingress,
    find_pii_fields,
    redact,
)

# --------------------------------------------------------------------------
# MCPConnector
# --------------------------------------------------------------------------


class MCPConnector:
    """Binds external capabilities over the Model Context Protocol.

    The session is held **open across calls**: MCP's ``initialize`` handshake
    is per-connection, not per-invocation, so reconnecting per call would pay
    process startup every time and renegotiate the version on every request.
    """

    name = "MCPConnector"
    protocol = Protocol.MCP

    def __init__(self, transport_factory: Callable[[], Any] | None = None) -> None:
        self._transport_factory = transport_factory or mcp_proto.InProcessTransport
        self._client: mcp_proto.MCPClient | None = None

    def _session(self) -> mcp_proto.MCPClient:
        if self._client is None:
            client = mcp_proto.MCPClient(self._transport_factory())
            client.initialize()
            self._client = client
        return self._client

    @property
    def negotiated_version(self) -> str | None:
        return self._session().negotiated_version

    def discover(self) -> list[dict[str, Any]]:
        """MCP capability discovery — ``tools/list``."""
        return self._session().list_tools()

    def invoke(self, env: ProtocolEnvelope) -> EnvelopeResult:
        """Lower an envelope onto ``tools/call`` and lift the reply back."""
        started = perf_counter()
        try:
            raw = self._session().call_tool(env.subject, env.payload)
        except JsonRpcError as exc:
            result = EnvelopeResult.failure(env, f"MCP error {exc.code}: {exc.message}")
            result.latency_ms = (perf_counter() - started) * 1000
            return result
        except Exception as exc:  # noqa: BLE001 - transport failures become results
            result = EnvelopeResult.failure(env, f"MCP transport failure: {exc}")
            result.latency_ms = (perf_counter() - started) * 1000
            return result

        meta = raw.get("_meta") or {}
        label = meta.get(mcp_proto.CLASSIFICATION_META_KEY, Classification.INTERNAL.value)
        try:
            classification = Classification(label)
        except ValueError:
            classification = Classification.INTERNAL

        return EnvelopeResult(
            envelope_id=env.envelope_id,
            trace_id=env.trace_id,
            ok=not raw.get("isError", False),
            protocol=Protocol.MCP,
            subject=env.subject,
            content=raw.get("structuredContent") or {},
            classification=classification,
            latency_ms=(perf_counter() - started) * 1000,
        )

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None


# --------------------------------------------------------------------------
# A2AGateway
# --------------------------------------------------------------------------


class A2AGateway:
    """Delegates work to agents operated by other vendors, over A2A."""

    name = "A2AGateway"
    protocol = Protocol.A2A

    def __init__(self, base_url: str, *, timeout: float = 10.0) -> None:
        self._client = a2a_proto.A2AClient(base_url, timeout=timeout)
        self._card: dict[str, Any] | None = None

    def discover(self) -> dict[str, Any]:
        """A2A capability discovery — fetch the Agent Card."""
        if self._card is None:
            self._card = self._client.fetch_agent_card()
        return self._card

    def delegate(self, env: ProtocolEnvelope) -> EnvelopeResult:
        """Lower an envelope onto ``message/send`` and lift the Task back."""
        started = perf_counter()
        text = env.payload.get("text") or env.payload.get("query") or str(env.payload)
        metadata = {
            a2a_proto.CLASSIFICATION_METADATA_KEY: str(env.classification),
            a2a_proto.TRACE_METADATA_KEY: env.trace_id,
        }
        try:
            task = self._client.send_message(text, skill_id=env.subject, metadata=metadata)
        except JsonRpcError as exc:
            result = EnvelopeResult.failure(env, f"A2A error {exc.code}: {exc.message}")
            result.latency_ms = (perf_counter() - started) * 1000
            return result
        except Exception as exc:  # noqa: BLE001 - transport failures become results
            result = EnvelopeResult.failure(env, f"A2A transport failure: {exc}")
            result.latency_ms = (perf_counter() - started) * 1000
            return result

        state = task.get("status", {}).get("state")
        completed = state == a2a_proto.TaskState.COMPLETED

        # Read the trace id back out of what the peer echoed rather than
        # assuming it survived. If the peer dropped it, TRC-001 fires at egress.
        echoed_trace = (task.get("metadata") or {}).get(a2a_proto.TRACE_METADATA_KEY, "")

        return EnvelopeResult(
            envelope_id=env.envelope_id,
            trace_id=echoed_trace or "",
            ok=completed,
            protocol=Protocol.A2A,
            subject=env.subject,
            content=a2a_proto.task_payload(task) if completed else {"taskState": state},
            error=None if completed else (a2a_proto.task_note(task) or f"task {state}"),
            classification=Classification.INTERNAL,
            latency_ms=(perf_counter() - started) * 1000,
        )


# --------------------------------------------------------------------------
# AuditAgent
# --------------------------------------------------------------------------


@dataclass(slots=True)
class AuditOutcome:
    """What the AuditAgent concluded at one phase of one hop."""

    verdict: Verdict
    violations: list[Violation] = field(default_factory=list)
    narrative: str = ""
    result: EnvelopeResult | None = None
    redacted_fields: list[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.verdict is Verdict.BLOCK

    def violations_as_dicts(self) -> list[dict[str, Any]]:
        return [v.to_dict() for v in self.violations]


class AuditAgent:
    """Monitors compliance and protocol adherence, and records the evidence.

    It runs twice per hop — once before dispatch (admission control) and once
    after (egress control) — because the two phases can only see different
    things. Ingress cannot know a response will carry a national id; egress
    cannot un-send a request.
    """

    name = "AuditAgent"

    def __init__(self, ledger: AuditLedger | None = None, reasoner: Reasoner | None = None) -> None:
        # `is not None`, not `or`: AuditLedger defines __len__, so an empty
        # ledger is falsy and `ledger or AuditLedger()` would silently discard
        # the caller's ledger and write the audit trail somewhere unreadable.
        self.ledger = ledger if ledger is not None else AuditLedger()
        self.reasoner = reasoner if reasoner is not None else get_reasoner()

    # -- admission control -------------------------------------------------

    def ingress(
        self,
        env: ProtocolEnvelope,
        *,
        negotiated_mcp_version: str | None = None,
        agent_card: dict[str, Any] | None = None,
    ) -> AuditOutcome:
        violations = evaluate_ingress(
            env, negotiated_mcp_version=negotiated_mcp_version, agent_card=agent_card
        )
        verdict = decide_verdict(violations, Phase.INGRESS)
        self.ledger.append(
            f"{env.target}.ingress",
            trace_id=env.trace_id,
            actor=env.principal.subject,
            payload=env.payload,
            detail={
                "subject": env.subject,
                "intent": str(env.intent),
                "verdict": str(verdict),
                "violations": [v.code for v in violations],
            },
        )
        return AuditOutcome(verdict=verdict, violations=violations)

    # -- egress control ----------------------------------------------------

    def egress(self, env: ProtocolEnvelope, result: EnvelopeResult) -> AuditOutcome:
        violations = evaluate_egress(env, result)
        verdict = decide_verdict(violations, Phase.EGRESS)

        redacted_fields: list[str] = []
        final = result
        if verdict is Verdict.REDACT:
            redacted_fields = find_pii_fields(result.content)
            final = result.model_copy(update={"content": redact(result.content)})
        elif verdict is Verdict.BLOCK:
            final = result.model_copy(
                update={
                    "ok": False,
                    "content": {},
                    "error": "blocked by AuditAgent: " + "; ".join(v.code for v in violations),
                }
            )

        narrative = self.reasoner.narrate(
            subject=env.subject,
            protocol=str(result.protocol),
            verdict=str(verdict),
            violations=[v.to_dict() for v in violations],
            ok=result.ok,
        )

        self.ledger.append(
            f"{env.target}.egress",
            trace_id=env.trace_id,
            actor=env.principal.subject,
            payload=final.content,
            detail={
                "subject": env.subject,
                "verdict": str(verdict),
                "violations": [v.code for v in violations],
                "redacted_fields": redacted_fields,
                "classification": str(result.classification),
                "latency_ms": round(result.latency_ms, 3),
            },
        )
        return AuditOutcome(
            verdict=verdict,
            violations=violations,
            narrative=narrative,
            result=final,
            redacted_fields=redacted_fields,
        )
