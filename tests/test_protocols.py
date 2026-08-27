"""Protocol conformance: JSON-RPC framing, MCP over stdio, A2A over HTTP."""

from __future__ import annotations

import pytest

from protobridge.protocols import a2a as a2a_proto
from protobridge.protocols import mcp as mcp_proto
from protobridge.protocols.jsonrpc import (
    METHOD_NOT_FOUND,
    Dispatcher,
    JsonRpcError,
    notification,
    request,
    unwrap,
)

# --------------------------------------------------------------------------
# JSON-RPC 2.0
# --------------------------------------------------------------------------


def test_dispatcher_returns_result_for_request():
    rpc = Dispatcher()
    rpc.register("echo", lambda params: params)
    response = rpc.dispatch(request("echo", {"a": 1}, id=7))
    assert response["id"] == 7
    assert unwrap(response) == {"a": 1}


def test_dispatcher_stays_silent_for_notifications():
    """A notification has no id, and the spec forbids replying to it."""
    rpc = Dispatcher()
    rpc.register("ping", lambda _params: {"pong": True})
    assert rpc.dispatch(notification("ping")) is None


def test_unknown_method_is_method_not_found():
    rpc = Dispatcher()
    response = rpc.dispatch(request("nope", id=1))
    with pytest.raises(JsonRpcError) as excinfo:
        unwrap(response)
    assert excinfo.value.code == METHOD_NOT_FOUND


def test_handler_exception_becomes_rpc_error_not_a_crash():
    rpc = Dispatcher()

    def boom(_params):
        raise ValueError("kaboom")

    rpc.register("boom", boom)
    with pytest.raises(JsonRpcError):
        unwrap(rpc.dispatch(request("boom", id=1)))


def test_malformed_json_is_parse_error():
    rpc = Dispatcher()
    response = rpc.dispatch_raw("{not json")
    assert response["error"]["code"] == -32700


# --------------------------------------------------------------------------
# MCP
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "transport_factory",
    [mcp_proto.InProcessTransport, mcp_proto.StdioTransport],
    ids=["in-process", "stdio-subprocess"],
)
def test_mcp_handshake_discovery_and_invocation(transport_factory):
    """The same client drives both transports identically."""
    with mcp_proto.connect(transport_factory()) as client:
        assert client.negotiated_version == mcp_proto.PROTOCOL_VERSION
        assert client.server_info["name"] == mcp_proto.SERVER_NAME

        names = {tool["name"] for tool in client.list_tools()}
        assert names == {"fx.convert", "kb.search", "hr.employee_lookup"}

        result = client.call_tool("fx.convert", {"amount": 100, "from": "USD", "to": "EUR"})
        assert result["structuredContent"]["converted"] == 92.0
        assert result["isError"] is False


def test_mcp_rejects_unsupported_protocol_version():
    client = mcp_proto.MCPClient(mcp_proto.InProcessTransport())
    with pytest.raises(JsonRpcError):
        client.initialize("1999-01-01")


def test_mcp_propagates_classification_through_meta():
    """Sensitivity labels ride in `_meta`, which the spec reserves for this."""
    with mcp_proto.connect() as client:
        public = client.call_tool("fx.convert", {"amount": 1, "from": "USD", "to": "EUR"})
        restricted = client.call_tool("hr.employee_lookup", {"employee_id": "E-1001"})

    key = mcp_proto.CLASSIFICATION_META_KEY
    assert public["_meta"][key] == "public"
    assert restricted["_meta"][key] == "restricted"


def test_mcp_missing_required_argument_is_invalid_params():
    with mcp_proto.connect() as client:
        with pytest.raises(JsonRpcError) as excinfo:
            client.call_tool("fx.convert", {"amount": 1})
        assert excinfo.value.code == -32602


# --------------------------------------------------------------------------
# A2A
# --------------------------------------------------------------------------


def test_a2a_agent_card_is_discoverable_over_http():
    with a2a_proto.running_server() as base_url:
        card = a2a_proto.A2AClient(base_url).fetch_agent_card()

    assert card["name"] == a2a_proto.AGENT_CARD["name"]
    assert card["protocolVersion"] == a2a_proto.PROTOCOL_VERSION
    assert {skill["id"] for skill in card["skills"]} == a2a_proto.SKILL_IDS


def test_a2a_message_send_completes_a_task():
    with a2a_proto.running_server() as base_url:
        client = a2a_proto.A2AClient(base_url)
        task = client.send_message(
            "Assess risk for globex-freight", skill_id="vendor.risk_assessment"
        )

        assert task["status"]["state"] == a2a_proto.TaskState.COMPLETED
        payload = a2a_proto.task_payload(task)
        assert payload["vendor"] == "globex-freight"
        assert payload["tier"] == "medium"

        # tasks/get must return the same task by id.
        assert client.get_task(task["id"])["id"] == task["id"]


def test_a2a_peer_rejects_restricted_input_at_its_own_boundary():
    """Policy is enforced on both sides of the wire, not only by the caller."""
    with a2a_proto.running_server() as base_url:
        task = a2a_proto.A2AClient(base_url).send_message(
            "anything",
            skill_id="vendor.risk_assessment",
            metadata={a2a_proto.CLASSIFICATION_METADATA_KEY: "restricted"},
        )

    assert task["status"]["state"] == a2a_proto.TaskState.REJECTED
    assert "addendum" in a2a_proto.task_note(task)


def test_a2a_rejects_undeclared_skill():
    with a2a_proto.running_server() as base_url:
        task = a2a_proto.A2AClient(base_url).send_message("x", skill_id="not.a.real.skill")
    assert task["status"]["state"] == a2a_proto.TaskState.REJECTED


def test_a2a_echoes_trace_metadata_back_to_the_caller():
    with a2a_proto.running_server() as base_url:
        task = a2a_proto.A2AClient(base_url).send_message(
            "Assess risk for acme-logistics",
            skill_id="vendor.risk_assessment",
            metadata={a2a_proto.TRACE_METADATA_KEY: "trc_fixture"},
        )
    assert task["metadata"][a2a_proto.TRACE_METADATA_KEY] == "trc_fixture"


def test_a2a_legacy_tasks_send_alias_still_works():
    rpc, _tasks = a2a_proto.build_server()
    response = rpc.dispatch(
        request("tasks/send", {"message": a2a_proto.text_message("hello")}, id=1)
    )
    assert unwrap(response)["kind"] == "task"
