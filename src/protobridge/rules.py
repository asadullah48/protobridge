"""Compliance and protocol-adherence rules.

Rules are grouped by **phase**, not by protocol:

``ingress``
    "Should this request be allowed to leave?" — allowlists, version pinning,
    capability declaration, boundary checks.
``egress``
    "Is this response safe to hand back?" — PII exposure, classification
    escalation, trace continuity.

The split matters because a PII leak is invisible at ingress: you only learn
the response carried a national id after the tool has already returned it.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

from protobridge import crm as crm_proto
from protobridge.envelope import (
    Classification,
    EnvelopeResult,
    Intent,
    Protocol,
    ProtocolEnvelope,
)
from protobridge.protocols import a2a as a2a_proto
from protobridge.protocols import mcp as mcp_proto

REDACTION_PLACEHOLDER = "[REDACTED]"

ALL_PII_FIELDS = mcp_proto.PII_FIELDS | crm_proto.CRM_PII_FIELDS
"""Every field name the audit layer treats as personally identifiable.

Unioning the CRM's field names in here is the whole integration on the egress
side: no rule changes, because the rules already walk field names rather than
value patterns. A Twenty person record becomes governed the moment its field
names are known.
"""


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)


_SEVERITY_ORDER = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


class Phase(StrEnum):
    INGRESS = "ingress"
    EGRESS = "egress"


class Verdict(StrEnum):
    """What the AuditAgent decided to do about a set of violations."""

    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"


@dataclass(frozen=True, slots=True)
class Violation:
    code: str
    severity: Severity
    message: str
    remediation: str
    phase: Phase

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------
# Policy configuration
# --------------------------------------------------------------------------

_BASE_TOOLS = frozenset({"fx.convert", "kb.search"})
_CRM_READ_TOOLS = frozenset(
    {"crm.person_search", "crm.person_get", "crm.company_search", "crm.opportunity_list"}
)
_CRM_ALL_TOOLS = _CRM_READ_TOOLS | crm_proto.WRITE_TOOLS

ROLE_TOOL_ALLOWLIST: dict[str, frozenset[str]] = {
    "agent": _BASE_TOOLS,
    "planner": _BASE_TOOLS,
    "hr-agent": _BASE_TOOLS | {"hr.employee_lookup"},
    "crm-agent": _BASE_TOOLS | _CRM_READ_TOOLS,
    "crm-writer": _BASE_TOOLS | _CRM_ALL_TOOLS,
    "admin": _BASE_TOOLS | {"hr.employee_lookup"} | _CRM_ALL_TOOLS,
}

ROLE_WRITE_PERMISSION: frozenset[str] = frozenset({"crm-writer", "admin"})
"""Roles permitted to mutate an external system of record.

Kept separate from the tool allowlist on purpose. Until the CRM arrived every
tool was read-only, so "allowlisted" and "may read" were the same thing. They
are not the same thing once a tool can write to a live customer record, and
collapsing them would let a read grant become a write grant by accident.
"""

ROLE_SKILL_ALLOWLIST: dict[str, frozenset[str]] = {
    "agent": frozenset({"vendor.risk_assessment", "supply.lead_time_estimate"}),
    "planner": frozenset({"vendor.risk_assessment", "supply.lead_time_estimate"}),
    "hr-agent": frozenset(),
    "admin": frozenset({"vendor.risk_assessment", "supply.lead_time_estimate"}),
}


# --------------------------------------------------------------------------
# Ingress rules
# --------------------------------------------------------------------------


def evaluate_ingress(
    env: ProtocolEnvelope,
    *,
    negotiated_mcp_version: str | None = None,
    agent_card: dict[str, Any] | None = None,
) -> list[Violation]:
    """Check a request before it crosses the bridge."""
    violations: list[Violation] = []

    if env.target is Protocol.MCP:
        allowed = ROLE_TOOL_ALLOWLIST.get(env.principal.role, frozenset())
        if env.subject not in allowed:
            violations.append(
                Violation(
                    code="GOV-001",
                    severity=Severity.HIGH,
                    message=(
                        f"role {env.principal.role!r} is not permitted to invoke "
                        f"tool {env.subject!r}"
                    ),
                    remediation="add the tool to ROLE_TOOL_ALLOWLIST or use a privileged role",
                    phase=Phase.INGRESS,
                )
            )
        if env.subject in crm_proto.WRITE_TOOLS and env.principal.role not in ROLE_WRITE_PERMISSION:
            violations.append(
                Violation(
                    code="GOV-003",
                    severity=Severity.CRITICAL,
                    message=(
                        f"role {env.principal.role!r} may read but not write; "
                        f"{env.subject!r} mutates a live customer record"
                    ),
                    remediation=(
                        "grant a role in ROLE_WRITE_PERMISSION, or route the change "
                        "through a human approval step"
                    ),
                    phase=Phase.INGRESS,
                )
            )
        if (
            negotiated_mcp_version is not None
            and negotiated_mcp_version not in mcp_proto.SUPPORTED_PROTOCOL_VERSIONS
        ):
            violations.append(
                Violation(
                    code="MCP-001",
                    severity=Severity.CRITICAL,
                    message=f"peer negotiated unsupported MCP version {negotiated_mcp_version!r}",
                    remediation="pin the peer to a supported version rather than downgrading",
                    phase=Phase.INGRESS,
                )
            )

    if env.target is Protocol.A2A:
        allowed_skills = ROLE_SKILL_ALLOWLIST.get(env.principal.role, frozenset())
        if env.subject not in allowed_skills:
            violations.append(
                Violation(
                    code="GOV-002",
                    severity=Severity.HIGH,
                    message=(
                        f"role {env.principal.role!r} is not permitted to delegate to "
                        f"skill {env.subject!r}"
                    ),
                    remediation="add the skill to ROLE_SKILL_ALLOWLIST or use a privileged role",
                    phase=Phase.INGRESS,
                )
            )
        if agent_card is not None:
            declared = {s.get("id") for s in agent_card.get("skills", [])}
            if env.subject not in declared:
                violations.append(
                    Violation(
                        code="A2A-001",
                        severity=Severity.HIGH,
                        message=(
                            f"remote agent card does not declare skill {env.subject!r}; "
                            f"declared: {sorted(x for x in declared if x)}"
                        ),
                        remediation="re-fetch the Agent Card or route to a peer that declares it",
                        phase=Phase.INGRESS,
                    )
                )
            card_version = agent_card.get("protocolVersion")
            if card_version and card_version != a2a_proto.PROTOCOL_VERSION:
                violations.append(
                    Violation(
                        code="A2A-002",
                        severity=Severity.MEDIUM,
                        message=(
                            f"agent card advertises A2A {card_version}, bridge speaks "
                            f"{a2a_proto.PROTOCOL_VERSION}"
                        ),
                        remediation="verify field compatibility before trusting the peer",
                        phase=Phase.INGRESS,
                    )
                )

        # POL-004: restricted material must not leave the tenant boundary.
        if (
            env.classification is Classification.RESTRICTED
            and env.principal.crosses_vendor_boundary
        ):
            violations.append(
                Violation(
                    code="SEC-002",
                    severity=Severity.CRITICAL,
                    message=(
                        "restricted-classification payload is being sent to an agent "
                        "operated by another vendor"
                    ),
                    remediation="execute a data processing addendum or downgrade the payload",
                    phase=Phase.INGRESS,
                )
            )

    if env.intent is Intent.AGENT_DELEGATE and env.target is Protocol.MCP:
        violations.append(
            Violation(
                code="PRO-002",
                severity=Severity.LOW,
                message="delegation intent routed onto MCP, which has no task lifecycle",
                remediation="route agent delegation over A2A so the peer can refuse the task",
                phase=Phase.INGRESS,
            )
        )

    return violations


# --------------------------------------------------------------------------
# Egress rules
# --------------------------------------------------------------------------


def find_pii_fields(payload: Any, fields: frozenset[str] = ALL_PII_FIELDS) -> list[str]:
    """Recursively collect the names of PII-bearing fields present in a payload."""
    found: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in fields:
                    found.add(key)
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(payload)
    return sorted(found)


def redact(payload: Any, fields: frozenset[str] = ALL_PII_FIELDS) -> Any:
    """Return a copy with every PII-bearing field replaced by a placeholder.

    Sensitivity is a property of the *field name* declared by the source
    protocol, not of the value's shape — so this walks keys rather than
    pattern-matching values.
    """
    if isinstance(payload, dict):
        return {
            key: (REDACTION_PLACEHOLDER if key in fields else redact(value, fields))
            for key, value in payload.items()
        }
    if isinstance(payload, list):
        return [redact(item, fields) for item in payload]
    return payload


def evaluate_egress(env: ProtocolEnvelope, result: EnvelopeResult) -> list[Violation]:
    """Check a response before it is handed back to the caller."""
    violations: list[Violation] = []

    if result.trace_id != env.trace_id:
        violations.append(
            Violation(
                code="TRC-001",
                severity=Severity.MEDIUM,
                message=(
                    f"trace id broke across the hop: sent {env.trace_id!r}, "
                    f"received {result.trace_id!r}"
                ),
                remediation="propagate trace_id in the envelope, not in transport headers",
                phase=Phase.EGRESS,
            )
        )

    exposed = find_pii_fields(result.content)
    if exposed and result.classification.exceeds(env.principal.clearance):
        violations.append(
            Violation(
                code="SEC-001",
                severity=Severity.HIGH,
                message=(
                    f"response exposes PII fields {exposed} at classification "
                    f"{result.classification!s}, above principal clearance "
                    f"{env.principal.clearance!s}"
                ),
                remediation="redact the fields or raise the principal's clearance",
                phase=Phase.EGRESS,
            )
        )
    elif result.classification.exceeds(env.principal.clearance):
        violations.append(
            Violation(
                code="PRO-001",
                severity=Severity.MEDIUM,
                message=(
                    f"response classified {result.classification!s} exceeds principal "
                    f"clearance {env.principal.clearance!s}"
                ),
                remediation="downgrade the response or raise the principal's clearance",
                phase=Phase.EGRESS,
            )
        )

    if not result.ok and not result.error:
        violations.append(
            Violation(
                code="PRO-003",
                severity=Severity.LOW,
                message="failed result carries no error description",
                remediation="always populate EnvelopeResult.error on failure",
                phase=Phase.EGRESS,
            )
        )

    return violations


# --------------------------------------------------------------------------
# === POLICY SEAM ==========================================================
# Everything above reports *facts*. What to DO about them is a business
# decision that differs per organization, so it is deliberately isolated in
# this one function. Swap it without touching a single rule.
# --------------------------------------------------------------------------


def max_severity(violations: list[Violation]) -> Severity | None:
    if not violations:
        return None
    return max((v.severity for v in violations), key=lambda s: s.rank)


def decide_verdict(violations: list[Violation], phase: Phase) -> Verdict:
    """Turn a set of violations into an enforcement decision.

    The default policy is deliberately **asymmetric**, because the two phases
    have different blast radii:

    * **Ingress is fail-closed.** Nothing has left the building yet, so
      blocking is cheap and a wrong call is merely inconvenient. Anything
      ``HIGH`` or above stops the request.
    * **Egress prefers REDACT over BLOCK.** The expensive work already
      happened and the caller usually needs the non-sensitive remainder, so
      dropping the offending fields beats discarding the whole response.
      Only ``CRITICAL`` findings destroy the result outright.

    Trade-offs an operator may want to invert: a regulated tenant might make
    egress fail-closed too, accepting the wasted work; a latency-sensitive one
    might downgrade ingress ``HIGH`` to a warning and lean on egress redaction
    as the only control.
    """
    worst = max_severity(violations)
    if worst is None:
        return Verdict.ALLOW

    if phase is Phase.INGRESS:
        return Verdict.BLOCK if worst.rank >= Severity.HIGH.rank else Verdict.ALLOW

    if worst is Severity.CRITICAL:
        return Verdict.BLOCK
    if worst.rank >= Severity.HIGH.rank:
        return Verdict.REDACT
    return Verdict.ALLOW
