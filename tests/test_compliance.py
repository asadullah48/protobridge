"""Audit ledger integrity, policy rules, and end-to-end graph behaviour."""

from __future__ import annotations

import json

import pytest

from protobridge.agents import MCPConnector
from protobridge.envelope import (
    Classification,
    EnvelopeResult,
    Intent,
    Principal,
    Protocol,
    ProtocolEnvelope,
)
from protobridge.graph import build_bridge, run_envelope
from protobridge.ledger import GENESIS_HASH, AuditEntry, AuditLedger
from protobridge.llm import DeterministicReasoner, get_reasoner
from protobridge.rules import (
    Phase,
    Severity,
    Verdict,
    decide_verdict,
    evaluate_egress,
    evaluate_ingress,
    find_pii_fields,
    redact,
)

# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


@pytest.fixture
def planner() -> Principal:
    return Principal(subject="svc:planner", role="planner", tenant="acme")


@pytest.fixture
def hr_agent() -> Principal:
    return Principal(subject="svc:hr", role="hr-agent", tenant="acme")


@pytest.fixture
def bridge():
    """A graph with an in-process MCP transport and no A2A peer."""
    ledger = AuditLedger()
    app = build_bridge(
        mcp_connector=MCPConnector(),
        ledger=ledger,
        reasoner=DeterministicReasoner(),
    )
    return app, ledger


# --------------------------------------------------------------------------
# Ledger
# --------------------------------------------------------------------------


def test_empty_ledger_head_is_genesis():
    assert AuditLedger().head() == GENESIS_HASH


def test_chain_links_each_entry_to_its_predecessor():
    ledger = AuditLedger()
    first = ledger.append("a", trace_id="t", actor="svc:test", payload={"n": 1})
    second = ledger.append("b", trace_id="t", actor="svc:test", payload={"n": 2})

    assert first.prev_hash == GENESIS_HASH
    assert second.prev_hash == first.entry_hash
    assert ledger.head() == second.entry_hash
    assert ledger.verify().valid


def test_verify_detects_a_rewritten_entry_and_names_it():
    """Whoever can append can also rewrite — chaining makes that detectable."""
    ledger = AuditLedger()
    for index in range(3):
        ledger.append(f"e{index}", trace_id="t", actor="svc:test", payload={"n": index})

    original = ledger.entries[1]
    ledger._entries[1] = AuditEntry(  # noqa: SLF001 - deliberate tamper
        seq=original.seq,
        ts=original.ts,
        event=original.event,
        trace_id=original.trace_id,
        actor="svc:attacker",
        payload_digest=original.payload_digest,
        prev_hash=original.prev_hash,
        entry_hash=original.entry_hash,
        detail=original.detail,
    )

    status = ledger.verify()
    assert not status.valid
    assert status.broken_at == 1


def test_ledger_records_a_digest_not_the_payload():
    """The integrity proof must survive dropping the sensitive bytes."""
    ledger = AuditLedger()
    entry = ledger.append(
        "hr", trace_id="t", actor="svc:test", payload={"national_id": "XXXXX-1234567-8"}
    )
    assert "XXXXX-1234567-8" not in json.dumps(entry.to_dict())
    assert len(entry.payload_digest) == 64


def test_for_trace_filters_to_one_request():
    ledger = AuditLedger()
    ledger.append("a", trace_id="trc_1", actor="svc:test")
    ledger.append("b", trace_id="trc_2", actor="svc:test")
    ledger.append("c", trace_id="trc_1", actor="svc:test")
    assert [e.event for e in ledger.for_trace("trc_1")] == ["a", "c"]


def test_write_jsonl_round_trips(tmp_path):
    ledger = AuditLedger()
    ledger.append("demo.alpha", trace_id="trc_fixture", actor="svc:test", payload={"n": 1})
    path = ledger.write_jsonl(tmp_path / "audit.jsonl")

    lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert lines[0]["event"] == "demo.alpha"
    assert lines[0]["prev_hash"] == GENESIS_HASH


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------


def test_tool_outside_role_allowlist_is_a_high_finding(planner):
    env = ProtocolEnvelope(
        target=Protocol.MCP, subject="hr.employee_lookup", payload={}, principal=planner
    )
    violations = evaluate_ingress(env)
    assert [v.code for v in violations] == ["GOV-001"]
    assert violations[0].severity is Severity.HIGH


def test_tool_inside_role_allowlist_is_clean(hr_agent):
    env = ProtocolEnvelope(
        target=Protocol.MCP, subject="hr.employee_lookup", payload={}, principal=hr_agent
    )
    assert evaluate_ingress(env) == []


def test_unsupported_mcp_version_is_critical(planner):
    env = ProtocolEnvelope(target=Protocol.MCP, subject="fx.convert", payload={}, principal=planner)
    violations = evaluate_ingress(env, negotiated_mcp_version="1999-01-01")
    assert any(v.code == "MCP-001" and v.severity is Severity.CRITICAL for v in violations)


def test_skill_absent_from_agent_card_is_flagged(planner):
    env = ProtocolEnvelope(
        target=Protocol.A2A,
        intent=Intent.AGENT_DELEGATE,
        subject="vendor.risk_assessment",
        payload={},
        principal=planner,
    )
    violations = evaluate_ingress(env, agent_card={"skills": [{"id": "something.else"}]})
    assert any(v.code == "A2A-001" for v in violations)


def test_restricted_payload_crossing_a_vendor_boundary_is_critical():
    principal = Principal(subject="svc:proc", role="planner", crosses_vendor_boundary=True)
    env = ProtocolEnvelope(
        target=Protocol.A2A,
        intent=Intent.AGENT_DELEGATE,
        subject="vendor.risk_assessment",
        payload={},
        principal=principal,
        classification=Classification.RESTRICTED,
    )
    violations = evaluate_ingress(env)
    assert any(v.code == "SEC-002" and v.severity is Severity.CRITICAL for v in violations)


def test_broken_trace_propagation_is_detected(planner):
    env = ProtocolEnvelope(
        target=Protocol.A2A, subject="vendor.risk_assessment", payload={}, principal=planner
    )
    result = EnvelopeResult(envelope_id=env.envelope_id, trace_id="", protocol=Protocol.A2A)
    assert any(v.code == "TRC-001" for v in evaluate_egress(env, result))


def test_pii_above_clearance_is_a_high_egress_finding(hr_agent):
    env = ProtocolEnvelope(
        target=Protocol.MCP, subject="hr.employee_lookup", payload={}, principal=hr_agent
    )
    result = EnvelopeResult(
        envelope_id=env.envelope_id,
        trace_id=env.trace_id,
        protocol=Protocol.MCP,
        content={"record": {"name": "Ada Lovelace", "national_id": "XXXXX-1234567-8"}},
        classification=Classification.RESTRICTED,
    )
    violations = evaluate_egress(env, result)
    assert any(v.code == "SEC-001" and v.severity is Severity.HIGH for v in violations)


def test_redact_walks_nested_structures_by_field_name():
    payload = {"record": {"name": "Ada", "email": "a@b.c"}, "peers": [{"national_id": "X"}]}
    assert find_pii_fields(payload) == ["email", "national_id"]

    cleaned = redact(payload)
    assert cleaned["record"]["name"] == "Ada"
    assert cleaned["record"]["email"] == "[REDACTED]"
    assert cleaned["peers"][0]["national_id"] == "[REDACTED]"
    # The original is untouched.
    assert payload["record"]["email"] == "a@b.c"


# --------------------------------------------------------------------------
# Policy seam
# --------------------------------------------------------------------------


def test_no_findings_always_allows():
    assert decide_verdict([], Phase.INGRESS) is Verdict.ALLOW
    assert decide_verdict([], Phase.EGRESS) is Verdict.ALLOW


def test_ingress_is_fail_closed_and_egress_prefers_redaction(planner):
    """The default policy is asymmetric because the phases differ in blast radius."""
    env = ProtocolEnvelope(
        target=Protocol.MCP, subject="hr.employee_lookup", payload={}, principal=planner
    )
    high = evaluate_ingress(env)  # GOV-001, severity HIGH
    assert decide_verdict(high, Phase.INGRESS) is Verdict.BLOCK
    assert decide_verdict(high, Phase.EGRESS) is Verdict.REDACT


def test_critical_blocks_in_both_phases():
    principal = Principal(subject="svc:proc", role="planner", crosses_vendor_boundary=True)
    env = ProtocolEnvelope(
        target=Protocol.A2A,
        subject="vendor.risk_assessment",
        payload={},
        principal=principal,
        classification=Classification.RESTRICTED,
    )
    critical = evaluate_ingress(env)
    assert decide_verdict(critical, Phase.INGRESS) is Verdict.BLOCK
    assert decide_verdict(critical, Phase.EGRESS) is Verdict.BLOCK


# --------------------------------------------------------------------------
# Reasoner
# --------------------------------------------------------------------------


def test_default_reasoner_needs_no_network_or_key():
    assert get_reasoner().name == "deterministic"


def test_unknown_backend_degrades_to_deterministic():
    assert get_reasoner("nonsense-backend").name == "deterministic"


def test_deterministic_narration_is_stable():
    reasoner = DeterministicReasoner()
    args = {
        "subject": "fx.convert",
        "protocol": "mcp",
        "verdict": "allow",
        "violations": [],
        "ok": True,
    }
    assert reasoner.narrate(**args) == reasoner.narrate(**args)
    assert "no policy findings" in reasoner.narrate(**args)


# --------------------------------------------------------------------------
# Graph, end to end
# --------------------------------------------------------------------------


def test_permitted_call_flows_through_and_is_audited(bridge, planner):
    app, ledger = bridge
    env = ProtocolEnvelope(
        target=Protocol.MCP,
        subject="fx.convert",
        payload={"amount": 100, "from": "USD", "to": "EUR"},
        principal=planner,
    )
    state = run_envelope(app, env)

    assert state["route"] == "mcp"
    assert state["verdict"] == Verdict.ALLOW
    assert state["result"].content["converted"] == 92.0
    # Ingress and egress each wrote one entry.
    assert [e.event for e in ledger.for_trace(env.trace_id)] == ["mcp.ingress", "mcp.egress"]
    assert ledger.verify().valid


def test_under_cleared_caller_gets_redacted_content(bridge, hr_agent):
    app, _ledger = bridge
    env = ProtocolEnvelope(
        target=Protocol.MCP,
        subject="hr.employee_lookup",
        payload={"employee_id": "E-1001"},
        principal=hr_agent,
    )
    state = run_envelope(app, env)

    record = state["result"].content["record"]
    assert state["verdict"] == Verdict.REDACT
    assert record["national_id"] == "[REDACTED]"
    assert record["email"] == "[REDACTED]"
    # Non-sensitive fields survive — redaction, not destruction.
    assert record["department"] == "Platform Engineering"


def test_disallowed_tool_never_reaches_the_connector(bridge, planner):
    """The blocked route proves admission control ran before dispatch."""
    app, ledger = bridge
    env = ProtocolEnvelope(
        target=Protocol.MCP,
        subject="hr.employee_lookup",
        payload={"employee_id": "E-1001"},
        principal=planner,
    )
    state = run_envelope(app, env)

    assert state["route"] == "blocked"
    assert state["result"].ok is False
    assert "GOV-001" in state["result"].error
    # Only an ingress entry: nothing egressed, because nothing was dispatched.
    assert [e.event for e in ledger.for_trace(env.trace_id)] == ["mcp.ingress"]


def test_a2a_route_without_a_peer_fails_cleanly(bridge, planner):
    app, _ledger = bridge
    env = ProtocolEnvelope(
        target=Protocol.A2A,
        intent=Intent.AGENT_DELEGATE,
        subject="vendor.risk_assessment",
        payload={"text": "Assess risk for acme-logistics"},
        principal=planner,
    )
    state = run_envelope(app, env)

    assert state["route"] == "a2a"
    assert state["result"].ok is False
    assert "no A2A peer" in state["result"].error


def test_trace_id_is_preserved_across_the_hop(bridge, planner):
    app, _ledger = bridge
    env = ProtocolEnvelope(
        target=Protocol.MCP,
        subject="kb.search",
        payload={"query": "protocol version pinning"},
        principal=planner,
    )
    state = run_envelope(app, env)
    assert state["result"].trace_id == env.trace_id
