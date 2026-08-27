"""Command-line entry point.

protobridge demo          run the full interoperability scenario offline
protobridge graph         print the bridge graph as mermaid
protobridge card          print the reference A2A Agent Card
protobridge tools         list the reference MCP tool catalogue
protobridge serve-mcp     run the reference MCP server on stdio
protobridge serve-a2a     run the reference A2A agent over HTTP
protobridge audit         run the scenario and verify the audit chain
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from protobridge import __version__
from protobridge.agents import A2AGateway, MCPConnector
from protobridge.envelope import (
    Classification,
    Intent,
    Principal,
    Protocol,
    ProtocolEnvelope,
)
from protobridge.graph import build_bridge, mermaid, run_envelope
from protobridge.ledger import AuditLedger
from protobridge.llm import get_reasoner
from protobridge.protocols import a2a as a2a_proto
from protobridge.protocols import mcp as mcp_proto

RULE = "-" * 72


def _print_scenario(index: int, title: str, state: dict[str, Any]) -> None:
    result = state.get("result")
    print(f"\n[{index}] {title}")
    print(f"    route     : {state.get('route', 'n/a')}")
    print(f"    verdict   : {state.get('verdict')}")
    findings = state.get("violations") or []
    if findings:
        codes = ", ".join(f"{v['code']}({v['severity']})" for v in findings)
        print(f"    findings  : {codes}")
    else:
        print("    findings  : none")
    if state.get("redacted_fields"):
        print(f"    redacted  : {', '.join(state['redacted_fields'])}")
    if result is not None:
        if result.ok:
            print(f"    content   : {json.dumps(result.content, ensure_ascii=False)[:200]}")
        else:
            print(f"    error     : {result.error}")
        print(f"    latency   : {result.latency_ms:.1f} ms")
    if state.get("narrative"):
        print(f"    narrative : {state['narrative']}")


def cmd_demo(args: argparse.Namespace) -> int:
    """End-to-end scenario: MCP tools, an A2A peer, and the audit chain."""
    reasoner = get_reasoner(args.llm)
    ledger = AuditLedger()

    print(RULE)
    print(f"ProtoBridge {__version__} - MCP + A2A interoperability demo")
    print(f"  MCP protocol : {mcp_proto.PROTOCOL_VERSION} (stdio, subprocess)")
    print(f"  A2A protocol : {a2a_proto.PROTOCOL_VERSION} (http, ephemeral port)")
    print(f"  reasoner     : {reasoner.name}")
    print(RULE)

    connector = MCPConnector(mcp_proto.StdioTransport)
    try:
        with a2a_proto.running_server() as base_url:
            gateway = A2AGateway(base_url)
            card = gateway.discover()
            print(f"\ndiscovered A2A peer: {card['name']} @ {base_url}")
            print(f"  skills: {', '.join(s['id'] for s in card['skills'])}")
            tools = connector.discover()
            print(f"discovered MCP tools: {', '.join(t['name'] for t in tools)}")

            app = build_bridge(
                mcp_connector=connector,
                a2a_gateway=gateway,
                ledger=ledger,
                reasoner=reasoner,
            )

            planner = Principal(subject="svc:planner", role="planner", tenant="acme")
            hr_agent = Principal(subject="svc:hr", role="hr-agent", tenant="acme")
            vendor_facing = Principal(
                subject="svc:procurement",
                role="planner",
                tenant="acme",
                crosses_vendor_boundary=True,
            )

            scenarios = [
                (
                    "MCP tool call, fully permitted",
                    ProtocolEnvelope(
                        target=Protocol.MCP,
                        intent=Intent.TOOL_INVOKE,
                        subject="fx.convert",
                        payload={"amount": 250, "from": "USD", "to": "PKR"},
                        principal=planner,
                    ),
                ),
                (
                    "MCP tool returning PII, caller under-cleared -> redaction",
                    ProtocolEnvelope(
                        target=Protocol.MCP,
                        intent=Intent.TOOL_INVOKE,
                        subject="hr.employee_lookup",
                        payload={"employee_id": "E-1001"},
                        principal=hr_agent,
                    ),
                ),
                (
                    "MCP tool outside the caller's allowlist -> blocked at ingress",
                    ProtocolEnvelope(
                        target=Protocol.MCP,
                        intent=Intent.TOOL_INVOKE,
                        subject="hr.employee_lookup",
                        payload={"employee_id": "E-1002"},
                        principal=planner,
                    ),
                ),
                (
                    "A2A delegation to a cross-vendor agent",
                    ProtocolEnvelope(
                        target=Protocol.A2A,
                        intent=Intent.AGENT_DELEGATE,
                        subject="vendor.risk_assessment",
                        payload={"text": "Assess risk for globex-freight"},
                        principal=planner,
                    ),
                ),
                (
                    "A2A delegation carrying restricted data across a vendor boundary",
                    ProtocolEnvelope(
                        target=Protocol.A2A,
                        intent=Intent.AGENT_DELEGATE,
                        subject="vendor.risk_assessment",
                        payload={"text": "Assess risk for initech-supply"},
                        principal=vendor_facing,
                        classification=Classification.RESTRICTED,
                    ),
                ),
                (
                    "A2A delegation to a second declared skill",
                    ProtocolEnvelope(
                        target=Protocol.A2A,
                        intent=Intent.AGENT_DELEGATE,
                        subject="supply.lead_time_estimate",
                        payload={"text": "Lead time for acme-logistics"},
                        principal=planner,
                    ),
                ),
            ]

            for index, (title, env) in enumerate(scenarios, start=1):
                _print_scenario(index, title, run_envelope(app, env))
    finally:
        connector.close()

    status = ledger.verify()
    chain = "INTACT" if status.valid else f"BROKEN at entry {status.broken_at}"
    print(f"\n{RULE}")
    print("audit ledger")
    print(f"  entries    : {len(ledger)}")
    print(f"  chain      : {chain}")
    print(f"  head       : {ledger.head()}")
    print(RULE)

    if args.ledger_out:
        path = ledger.write_jsonl(args.ledger_out)
        print(f"wrote {len(ledger)} ledger entries to {path}")

    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    """Run the scenario, then demonstrate that tampering is detectable."""
    rc = cmd_demo(args)
    if rc != 0:
        return rc

    print("\ntamper check")
    ledger = AuditLedger()
    ledger.append("demo.alpha", trace_id="trc_demo", actor="svc:demo", payload={"n": 1})
    ledger.append("demo.beta", trace_id="trc_demo", actor="svc:demo", payload={"n": 2})
    ledger.append("demo.gamma", trace_id="trc_demo", actor="svc:demo", payload={"n": 3})
    print(f"  fresh chain      : {ledger.verify()}")

    # Rewrite entry 1 in place, as an attacker with log access would.
    entries = list(ledger.entries)
    forged = type(entries[1])(
        seq=entries[1].seq,
        ts=entries[1].ts,
        event="demo.beta",
        trace_id=entries[1].trace_id,
        actor="svc:attacker",
        payload_digest=entries[1].payload_digest,
        prev_hash=entries[1].prev_hash,
        entry_hash=entries[1].entry_hash,
        detail=entries[1].detail,
    )
    ledger._entries[1] = forged  # noqa: SLF001 - deliberate tamper for the demo
    status = ledger.verify()
    print(f"  after tampering  : {status}")
    print(f"  detected at entry: {status.broken_at}")
    return 0


def cmd_graph(_args: argparse.Namespace) -> int:
    print(mermaid())
    return 0


def cmd_card(_args: argparse.Namespace) -> int:
    print(json.dumps(a2a_proto.AGENT_CARD, indent=2, ensure_ascii=False))
    return 0


def cmd_tools(_args: argparse.Namespace) -> int:
    print(json.dumps(mcp_proto.TOOL_SPECS, indent=2, ensure_ascii=False))
    return 0


def cmd_serve_mcp(_args: argparse.Namespace) -> int:
    # The banner goes to stderr: MCP stdio reserves stdout for JSON frames.
    print("protobridge MCP server ready on stdio", file=sys.stderr)
    mcp_proto.serve_stdio()
    return 0


def cmd_serve_a2a(args: argparse.Namespace) -> int:
    server = a2a_proto.make_server(args.host, args.port)
    host, port = server.server_address[0], server.server_address[1]
    print(f"protobridge A2A agent on http://{host}:{port}")
    print(f"  agent card: http://{host}:{port}{a2a_proto.AGENT_CARD_PATH}")
    print("  ctrl-c to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        server.server_close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="protobridge",
        description="MCP + A2A interoperability layer for agentic AI systems.",
    )
    parser.add_argument("--version", action="version", version=f"protobridge {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="run the full interoperability scenario offline")
    demo.add_argument(
        "--llm",
        default=None,
        choices=["deterministic", "ollama"],
        help="narration backend (default: PROTOBRIDGE_LLM, else deterministic)",
    )
    demo.add_argument(
        "--ledger-out",
        nargs="?",
        const="protobridge-audit.jsonl",
        default=None,
        help="write the audit ledger to a JSON Lines file",
    )
    demo.set_defaults(func=cmd_demo)

    audit = sub.add_parser("audit", help="run the scenario and verify the audit chain")
    audit.add_argument("--llm", default=None, choices=["deterministic", "ollama"])
    audit.add_argument("--ledger-out", nargs="?", const="protobridge-audit.jsonl", default=None)
    audit.set_defaults(func=cmd_audit)

    sub.add_parser("graph", help="print the bridge graph as mermaid").set_defaults(func=cmd_graph)
    sub.add_parser("card", help="print the reference A2A Agent Card").set_defaults(func=cmd_card)
    sub.add_parser("tools", help="print the reference MCP tool catalogue").set_defaults(
        func=cmd_tools
    )
    sub.add_parser("serve-mcp", help="run the reference MCP server on stdio").set_defaults(
        func=cmd_serve_mcp
    )

    serve_a2a = sub.add_parser("serve-a2a", help="run the reference A2A agent over HTTP")
    serve_a2a.add_argument("--host", default="127.0.0.1")
    serve_a2a.add_argument("--port", type=int, default=8931)
    serve_a2a.set_defaults(func=cmd_serve_a2a)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
