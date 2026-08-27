"""Normalized protocol envelope — the pivot type of the bridge.

Every inbound message (MCP tool call, A2A task) is *lifted* into a
:class:`ProtocolEnvelope`, and every outbound message is *lowered* from one.
This keeps the adapter count at 2N (one codec pair per protocol) instead of
N-squared point-to-point translators.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def _now() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class Protocol(StrEnum):
    """Wire protocols ProtoBridge speaks."""

    MCP = "mcp"
    A2A = "a2a"
    INTERNAL = "internal"


class Intent(StrEnum):
    """What the caller is trying to do, independent of wire protocol."""

    TOOL_INVOKE = "tool.invoke"
    """Bind and call an external capability. Natural fit for MCP."""

    AGENT_DELEGATE = "agent.delegate"
    """Hand a task to another autonomous agent. Natural fit for A2A."""

    CAPABILITY_DISCOVER = "capability.discover"
    """Ask a peer what it can do (MCP ``tools/list`` or an A2A Agent Card)."""


class Classification(StrEnum):
    """Data sensitivity label, ordered from least to most restricted."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

    @property
    def rank(self) -> int:
        return _CLASSIFICATION_ORDER.index(self)

    def exceeds(self, other: Classification) -> bool:
        """True when *self* is more sensitive than *other*."""
        return self.rank > other.rank


_CLASSIFICATION_ORDER = [
    Classification.PUBLIC,
    Classification.INTERNAL,
    Classification.CONFIDENTIAL,
    Classification.RESTRICTED,
]


class Principal(BaseModel):
    """Who is making the request. Drives allowlists and redaction."""

    subject: str = Field(description="Stable identifier, e.g. 'svc:planner'.")
    role: str = Field(default="agent", description="Role used for tool allowlisting.")
    tenant: str = Field(default="default", description="Tenant / org boundary.")
    clearance: Classification = Field(
        default=Classification.INTERNAL,
        description="Highest classification this principal may receive unredacted.",
    )
    crosses_vendor_boundary: bool = Field(
        default=False,
        description="True when the peer is operated by a different vendor.",
    )


class ProtocolEnvelope(BaseModel):
    """Protocol-neutral request travelling through the bridge."""

    envelope_id: str = Field(default_factory=lambda: new_id("env"))
    trace_id: str = Field(default_factory=lambda: new_id("trc"))
    created_at: datetime = Field(default_factory=_now)

    source: Protocol = Protocol.INTERNAL
    target: Protocol = Protocol.INTERNAL
    intent: Intent = Intent.TOOL_INVOKE

    subject: str = Field(description="Tool name (MCP) or skill id (A2A).")
    payload: dict[str, Any] = Field(default_factory=dict)

    principal: Principal
    classification: Classification = Classification.INTERNAL

    def child(self, *, target: Protocol, intent: Intent, subject: str) -> ProtocolEnvelope:
        """Derive a downstream envelope that keeps the same ``trace_id``.

        Trace propagation lives in the envelope rather than transport headers,
        because headers do not survive an MCP stdio hop.
        """
        return self.model_copy(
            update={
                "envelope_id": new_id("env"),
                "created_at": _now(),
                "source": self.target,
                "target": target,
                "intent": intent,
                "subject": subject,
            }
        )


class EnvelopeResult(BaseModel):
    """Protocol-neutral response."""

    envelope_id: str
    trace_id: str
    ok: bool = True
    protocol: Protocol = Protocol.INTERNAL
    subject: str = ""
    content: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    classification: Classification = Classification.INTERNAL
    latency_ms: float = 0.0

    @classmethod
    def failure(cls, env: ProtocolEnvelope, message: str) -> EnvelopeResult:
        return cls(
            envelope_id=env.envelope_id,
            trace_id=env.trace_id,
            ok=False,
            protocol=env.target,
            subject=env.subject,
            error=message,
        )
