"""LangGraph wiring for the bridge.

The shape of the graph is the point::

    START
      |
      v
    audit_ingress ---- blocked ----> END
      |  |
      |  +--- a2a ---> a2a_gateway ---+
      |                               |
      +----- mcp ---> mcp_connector --+
                                      |
                                      v
                                 audit_egress --> END

There is no edge into a connector that bypasses ``audit_ingress``. The audit is
structural rather than optional: you cannot forget to call the auditor, because
the only path to a protocol adapter runs through it.
"""

from __future__ import annotations

from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from protobridge.agents import A2AGateway, AuditAgent, MCPConnector
from protobridge.envelope import EnvelopeResult, Protocol, ProtocolEnvelope
from protobridge.ledger import AuditLedger
from protobridge.llm import Reasoner
from protobridge.rules import Verdict


class BridgeState(TypedDict, total=False):
    """State carried between graph nodes.

    One path per run, so plain last-write-wins semantics are correct here and
    no reducers are needed.
    """

    envelope: ProtocolEnvelope
    route: str
    result: EnvelopeResult | None
    verdict: str
    violations: list[dict[str, Any]]
    narrative: str
    redacted_fields: list[str]


ROUTE_MCP = "mcp"
ROUTE_A2A = "a2a"
ROUTE_BLOCKED = "blocked"


def build_bridge(
    *,
    mcp_connector: MCPConnector | None = None,
    a2a_gateway: A2AGateway | None = None,
    audit_agent: AuditAgent | None = None,
    ledger: AuditLedger | None = None,
    reasoner: Reasoner | None = None,
) -> Any:
    """Compile the bridge graph.

    Every collaborator is injectable so tests can drive the graph with an
    in-process MCP transport and no A2A peer at all.
    """
    connector = mcp_connector or MCPConnector()
    gateway = a2a_gateway
    auditor = audit_agent or AuditAgent(ledger=ledger, reasoner=reasoner)

    # -- nodes ------------------------------------------------------------

    def audit_ingress(state: BridgeState) -> BridgeState:
        env = state["envelope"]

        negotiated: str | None = None
        card: dict[str, Any] | None = None
        if env.target is Protocol.MCP:
            try:
                negotiated = connector.negotiated_version
            except Exception:  # noqa: BLE001 - an unreachable peer is itself a finding
                negotiated = None
        elif env.target is Protocol.A2A and gateway is not None:
            try:
                card = gateway.discover()
            except Exception:  # noqa: BLE001 - an undiscoverable peer is itself a finding
                card = None

        outcome = auditor.ingress(env, negotiated_mcp_version=negotiated, agent_card=card)
        if outcome.blocked:
            route = ROUTE_BLOCKED
        elif env.target is Protocol.A2A:
            route = ROUTE_A2A
        else:
            route = ROUTE_MCP

        return {
            "route": route,
            "verdict": str(outcome.verdict),
            "violations": outcome.violations_as_dicts(),
        }

    def mcp_connector_node(state: BridgeState) -> BridgeState:
        return {"result": connector.invoke(state["envelope"])}

    def a2a_gateway_node(state: BridgeState) -> BridgeState:
        env = state["envelope"]
        if gateway is None:
            return {"result": EnvelopeResult.failure(env, "no A2A peer is configured")}
        return {"result": gateway.delegate(env)}

    def audit_egress(state: BridgeState) -> BridgeState:
        env = state["envelope"]
        result = state.get("result")
        if result is None:
            result = EnvelopeResult.failure(env, "connector produced no result")
        outcome = auditor.egress(env, result)
        return {
            "result": outcome.result,
            "verdict": str(outcome.verdict),
            "violations": state.get("violations", []) + outcome.violations_as_dicts(),
            "narrative": outcome.narrative,
            "redacted_fields": outcome.redacted_fields,
        }

    def blocked_node(state: BridgeState) -> BridgeState:
        env = state["envelope"]
        codes = "; ".join(v["code"] for v in state.get("violations", []))
        result = EnvelopeResult.failure(env, f"blocked at ingress by AuditAgent: {codes}")
        narrative = auditor.reasoner.narrate(
            subject=env.subject,
            protocol=str(env.target),
            verdict=str(Verdict.BLOCK),
            violations=state.get("violations", []),
            ok=False,
        )
        return {"result": result, "verdict": str(Verdict.BLOCK), "narrative": narrative}

    # -- wiring -----------------------------------------------------------

    graph = StateGraph(BridgeState)
    graph.add_node("audit_ingress", audit_ingress)
    graph.add_node("mcp_connector", mcp_connector_node)
    graph.add_node("a2a_gateway", a2a_gateway_node)
    graph.add_node("audit_egress", audit_egress)
    graph.add_node("blocked", blocked_node)

    graph.add_edge(START, "audit_ingress")
    graph.add_conditional_edges(
        "audit_ingress",
        lambda state: state["route"],
        {
            ROUTE_MCP: "mcp_connector",
            ROUTE_A2A: "a2a_gateway",
            ROUTE_BLOCKED: "blocked",
        },
    )
    graph.add_edge("mcp_connector", "audit_egress")
    graph.add_edge("a2a_gateway", "audit_egress")
    graph.add_edge("audit_egress", END)
    graph.add_edge("blocked", END)

    compiled = graph.compile()
    compiled.protobridge_audit = auditor  # type: ignore[attr-defined]
    return compiled


def run_envelope(app: Any, env: ProtocolEnvelope) -> BridgeState:
    """Run one envelope through a compiled bridge."""
    return app.invoke({"envelope": env, "violations": []})


MERMAID = """flowchart TD
    START([request]) --> AI[audit_ingress<br/>AuditAgent]
    AI -->|route = mcp| MC[mcp_connector<br/>MCPConnector]
    AI -->|route = a2a| AG[a2a_gateway<br/>A2AGateway]
    AI -->|verdict = block| BL[blocked]
    MC --> AE[audit_egress<br/>AuditAgent]
    AG --> AE
    AE --> DONE([response])
    BL --> DONE
"""


def mermaid() -> str:
    """Mermaid source for the bridge graph, for docs and the CLI."""
    return MERMAID
