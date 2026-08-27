"""Twenty CRM adapter, and the governance it inherits.

The point of these tests is that the CRM required **no new egress rule**. Its
PII field names were unioned into ``ALL_PII_FIELDS`` and the existing redaction
rules governed it immediately. What did need a new rule is the write path —
every tool before this one was read-only.

Everything here runs against the offline ``FakeTwentyBackend``; no Twenty
workspace is contacted.
"""

from __future__ import annotations

import pytest

from protobridge import crm
from protobridge.agents import MCPConnector
from protobridge.envelope import Classification, Principal, Protocol, ProtocolEnvelope
from protobridge.graph import build_bridge, run_envelope
from protobridge.ledger import AuditLedger
from protobridge.llm import DeterministicReasoner
from protobridge.protocols.jsonrpc import JsonRpcError
from protobridge.protocols.mcp import MCPClient, connect
from protobridge.rules import (
    ALL_PII_FIELDS,
    ROLE_TOOL_ALLOWLIST,
    ROLE_WRITE_PERMISSION,
    Verdict,
    evaluate_ingress,
    find_pii_fields,
    redact,
)


@pytest.fixture(autouse=True)
def no_live_workspace(monkeypatch):
    """Guarantee the suite never reaches a real Twenty instance."""
    monkeypatch.delenv("TWENTY_BASE_URL", raising=False)
    monkeypatch.delenv("TWENTY_API_KEY", raising=False)


@pytest.fixture
def bridge():
    ledger = AuditLedger()
    app = build_bridge(
        mcp_connector=MCPConnector(crm.InProcessTransport),
        ledger=ledger,
        reasoner=DeterministicReasoner(),
    )
    return app, ledger


def call(app, role, tool, payload, clearance=Classification.INTERNAL):
    principal = Principal(subject=f"svc:{role}", role=role, clearance=clearance)
    env = ProtocolEnvelope(target=Protocol.MCP, subject=tool, payload=payload, principal=principal)
    return run_envelope(app, env)


# --------------------------------------------------------------------------
# Backend selection
# --------------------------------------------------------------------------


def test_default_backend_is_offline():
    """ProtoBridge's zero-key promise has to survive the CRM integration."""
    assert crm.get_backend().name == "fake"


def test_real_backend_needs_both_url_and_key(monkeypatch):
    monkeypatch.setenv("TWENTY_BASE_URL", "https://crm.example.test")
    assert crm.get_backend().name == "fake", "a URL alone must not activate the live backend"

    monkeypatch.setenv("TWENTY_API_KEY", "not-a-real-key")
    assert crm.get_backend().name == "twenty-rest"


def test_rest_backend_unwraps_twenty_response_shapes():
    """Twenty's schema is workspace-specific, so unwrapping stays defensive."""
    unwrap = crm.TwentyRestBackend._unwrap
    assert unwrap({"data": {"people": [{"id": "1"}]}}, "people") == [{"id": "1"}]
    assert unwrap({"data": {"person": {"id": "1"}}}, "person") == [{"id": "1"}]
    assert unwrap({"data": [{"id": "1"}]}, "people") == [{"id": "1"}]
    assert unwrap({"unexpected": True}, "people") == []
    assert unwrap(None, "people") == []


# --------------------------------------------------------------------------
# MCP surface
# --------------------------------------------------------------------------


def test_crm_server_speaks_mcp():
    with connect(crm.InProcessTransport()) as client:
        assert client.negotiated_version == crm.PROTOCOL_VERSION
        assert client.server_info["name"] == crm.SERVER_NAME
        assert client.server_info["backend"] == "fake"

        names = {tool["name"] for tool in client.list_tools()}
        assert names == {spec["name"] for spec in crm.TOOL_SPECS}


def test_crm_rejects_unsupported_protocol_version():
    client = MCPClient(crm.InProcessTransport())
    with pytest.raises(JsonRpcError):
        client.initialize("1999-01-01")


def test_person_search_returns_records_labelled_restricted():
    with connect(crm.InProcessTransport()) as client:
        result = client.call_tool("crm.person_search", {"query": "Nadia"})

    people = result["structuredContent"]["people"]
    assert len(people) == 1
    assert people[0]["name"]["firstName"] == "Nadia"
    assert result["_meta"][crm.CLASSIFICATION_META_KEY] == "restricted"
    assert result["_meta"][crm.BACKEND_META_KEY] == "fake"


def test_company_search_is_only_internal():
    """Firmographics are not personal data and should not be over-classified."""
    with connect(crm.InProcessTransport()) as client:
        result = client.call_tool("crm.company_search", {"query": "Acme"})
    assert result["_meta"][crm.CLASSIFICATION_META_KEY] == "internal"
    assert result["structuredContent"]["companies"][0]["name"] == "Acme Logistics"


def test_opportunity_list_totals_the_pipeline():
    with connect(crm.InProcessTransport()) as client:
        result = client.call_tool("crm.opportunity_list", {"limit": 5})
    payload = result["structuredContent"]
    assert len(payload["opportunities"]) == 2
    # 240000000000 + 875000000000 micros -> 1_115_000.0
    assert payload["pipeline_value"] == 1115000.0
    assert result["_meta"][crm.CLASSIFICATION_META_KEY] == "confidential"


def test_unknown_person_is_invalid_params():
    with connect(crm.InProcessTransport()) as client:
        with pytest.raises(JsonRpcError):
            client.call_tool("crm.person_get", {"person_id": "does-not-exist"})


def test_missing_required_argument_is_invalid_params():
    with connect(crm.InProcessTransport()) as client:
        with pytest.raises(JsonRpcError) as excinfo:
            client.call_tool("crm.person_search", {})
        assert excinfo.value.code == -32602


# --------------------------------------------------------------------------
# The integration itself: CRM PII inherits the existing rules
# --------------------------------------------------------------------------


def test_crm_pii_fields_joined_the_shared_set():
    for field in ("primaryEmail", "primaryPhoneNumber", "city"):
        assert field in ALL_PII_FIELDS
    # The original MCP fields are still governed.
    assert "national_id" in ALL_PII_FIELDS


def test_redaction_reaches_twenty_composite_fields():
    """Twenty nests PII under composite fields; redaction walks into them."""
    record = {
        "name": {"firstName": "Nadia", "lastName": "Rahman"},
        "emails": {"primaryEmail": "nadia.rahman@example.test"},
        "phones": {"primaryPhoneNumber": "+92-300-0000001"},
        "city": "Karachi",
        "jobTitle": "Head of Procurement",
    }
    assert find_pii_fields(record) == ["city", "primaryEmail", "primaryPhoneNumber"]

    cleaned = redact(record)
    assert cleaned["emails"]["primaryEmail"] == "[REDACTED]"
    assert cleaned["phones"]["primaryPhoneNumber"] == "[REDACTED]"
    assert cleaned["city"] == "[REDACTED]"
    # Non-personal fields survive: redaction, not destruction.
    assert cleaned["name"]["firstName"] == "Nadia"
    assert cleaned["jobTitle"] == "Head of Procurement"


def test_under_cleared_caller_gets_redacted_contacts(bridge):
    app, _ledger = bridge
    state = call(app, "crm-agent", "crm.person_search", {"query": "Nadia"})

    assert state["verdict"] == Verdict.REDACT
    assert state["redacted_fields"] == ["city", "primaryEmail", "primaryPhoneNumber"]
    person = state["result"].content["people"][0]
    assert person["emails"]["primaryEmail"] == "[REDACTED]"
    assert person["name"]["firstName"] == "Nadia"


def test_cleared_caller_sees_the_full_contact(bridge):
    app, _ledger = bridge
    state = call(
        app, "crm-agent", "crm.person_search", {"query": "Nadia"}, Classification.RESTRICTED
    )
    assert state["verdict"] == Verdict.ALLOW
    person = state["result"].content["people"][0]
    assert person["emails"]["primaryEmail"] == "nadia.rahman@example.test"


def test_role_without_crm_access_is_blocked_before_dispatch(bridge):
    app, ledger = bridge
    state = call(app, "planner", "crm.person_search", {"query": "Nadia"})

    assert state["route"] == "blocked"
    assert "GOV-001" in state["result"].error
    trace = ledger.for_trace(state["result"].trace_id)
    assert [e.event for e in trace] == ["mcp.ingress"], "nothing should have egressed"


# --------------------------------------------------------------------------
# Writes need their own permission
# --------------------------------------------------------------------------


def test_note_create_is_the_only_write_tool():
    assert crm.WRITE_TOOLS == frozenset({"crm.note_create"})


def test_read_role_cannot_write_even_though_it_reads_crm(bridge):
    """Allowlisted-to-read must not imply allowed-to-write."""
    app, _ledger = bridge
    state = call(app, "crm-agent", "crm.note_create", {"title": "t", "body": "b"})

    codes = {v["code"] for v in state["violations"]}
    assert "GOV-003" in codes
    assert state["verdict"] == Verdict.BLOCK
    assert state["route"] == "blocked"


def test_gov_003_is_critical_and_names_the_record_risk():
    principal = Principal(subject="svc:crm", role="crm-agent")
    env = ProtocolEnvelope(
        target=Protocol.MCP,
        subject="crm.note_create",
        payload={"title": "t", "body": "b"},
        principal=principal,
    )
    violations = {v.code: v for v in evaluate_ingress(env)}
    assert "GOV-003" in violations
    assert violations["GOV-003"].severity == "critical"
    assert "mutates a live customer record" in violations["GOV-003"].message


def test_write_role_may_write(bridge):
    app, ledger = bridge
    state = call(
        app,
        "crm-writer",
        "crm.note_create",
        {"title": "Call summary", "body": "Discussed renewal."},
    )

    assert state["verdict"] == Verdict.ALLOW
    assert state["result"].content["note"]["title"] == "Call summary"
    assert ledger.verify().valid


def test_write_permission_is_separate_from_the_tool_allowlist():
    """Two distinct grants, so a read grant can never become a write grant."""
    assert "crm.note_create" in ROLE_TOOL_ALLOWLIST["crm-writer"]
    assert "crm.note_create" not in ROLE_TOOL_ALLOWLIST["crm-agent"]
    assert "crm-writer" in ROLE_WRITE_PERMISSION
    assert "crm-agent" not in ROLE_WRITE_PERMISSION


def test_every_crm_hop_is_audited(bridge):
    app, ledger = bridge
    call(app, "crm-agent", "crm.company_search", {"query": "Acme"})
    call(app, "crm-writer", "crm.note_create", {"title": "t", "body": "b"})

    events = [e.event for e in ledger]
    assert events.count("mcp.ingress") == 2
    assert events.count("mcp.egress") == 2
    assert ledger.verify().valid
