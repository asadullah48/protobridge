"""Model Context Protocol adapter: types, reference server, and stdio client.

MCP is JSON-RPC 2.0 over **stdio**, and it is *tool-shaped*: a client spawns a
server as a subprocess, negotiates a protocol version, discovers tools, and
calls them.

Two invariants of the stdio transport drive the code here:

1. **stdout carries only newline-delimited JSON frames.** A stray ``print()``
   corrupts the stream, so every diagnostic in this module goes to stderr.
2. **Sensitivity labels ride in ``_meta``.** The MCP spec reserves ``_meta``
   for implementation-defined annotations, so ProtoBridge propagates data
   classification without forking the protocol.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from typing import Protocol as TypingProtocol

from protobridge.envelope import Classification
from protobridge.protocols.jsonrpc import (
    INVALID_PARAMS,
    Dispatcher,
    JsonRpcError,
    notification,
    request,
    unwrap,
)

# --------------------------------------------------------------------------
# Protocol constants
# --------------------------------------------------------------------------

PROTOCOL_VERSION = "2025-06-18"
"""Version this implementation prefers."""

SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
"""Versions the server accepts during ``initialize``."""

SERVER_NAME = "protobridge-reference-mcp"
SERVER_VERSION = "0.1.0"

CLASSIFICATION_META_KEY = "protobridge/classification"


# --------------------------------------------------------------------------
# Reference tool catalogue (synthetic, offline, deterministic)
# --------------------------------------------------------------------------

_FX_RATES: dict[tuple[str, str], float] = {
    ("USD", "EUR"): 0.92,
    ("EUR", "USD"): 1.09,
    ("USD", "PKR"): 278.50,
    ("PKR", "USD"): 0.0036,
    ("USD", "GBP"): 0.79,
    ("GBP", "USD"): 1.27,
}

_POLICY_KB: list[dict[str, str]] = [
    {
        "id": "POL-004",
        "title": "Third-party agent data sharing",
        "text": (
            "Restricted classification records must not be transmitted to an agent "
            "operated by a different vendor without a signed data processing addendum."
        ),
    },
    {
        "id": "POL-011",
        "title": "Tool invocation logging",
        "text": (
            "Every external tool invocation must be written to an append-only ledger "
            "carrying the caller principal and a correlation identifier."
        ),
    },
    {
        "id": "POL-017",
        "title": "Protocol version pinning",
        "text": (
            "Agents must reject peers advertising an unsupported protocol version "
            "rather than silently downgrading."
        ),
    },
]

_EMPLOYEES: dict[str, dict[str, Any]] = {
    "E-1001": {
        "employee_id": "E-1001",
        "name": "Ada Lovelace",
        "email": "ada@example.internal",
        "national_id": "XXXXX-1234567-8",
        "salary_band": "L5",
        "department": "Platform Engineering",
    },
    "E-1002": {
        "employee_id": "E-1002",
        "name": "Grace Hopper",
        "email": "grace@example.internal",
        "national_id": "XXXXX-7654321-0",
        "salary_band": "L6",
        "department": "Compliance",
    },
}


TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "fx.convert",
        "title": "Currency converter",
        "description": "Convert an amount between two ISO-4217 currency codes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "amount": {"type": "number", "description": "Amount in the source currency."},
                "from": {"type": "string", "description": "Source ISO-4217 code, e.g. USD."},
                "to": {"type": "string", "description": "Target ISO-4217 code, e.g. EUR."},
            },
            "required": ["amount", "from", "to"],
        },
    },
    {
        "name": "kb.search",
        "title": "Policy knowledge base search",
        "description": "Full-text search across internal governance policies.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Free-text query."},
                "top_k": {"type": "integer", "description": "Maximum results.", "default": 3},
            },
            "required": ["query"],
        },
    },
    {
        "name": "hr.employee_lookup",
        "title": "Employee record lookup",
        "description": "Fetch a full HR record. Returns personally identifiable information.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "employee_id": {"type": "string", "description": "Employee id, e.g. E-1001."},
            },
            "required": ["employee_id"],
        },
    },
]

TOOL_CLASSIFICATION: dict[str, Classification] = {
    "fx.convert": Classification.PUBLIC,
    "kb.search": Classification.INTERNAL,
    "hr.employee_lookup": Classification.RESTRICTED,
}

PII_FIELDS = frozenset({"email", "national_id", "salary_band"})
"""Fields the audit layer treats as personally identifiable."""


def _require(args: dict[str, Any], key: str) -> Any:
    if key not in args:
        raise JsonRpcError(INVALID_PARAMS, f"missing required argument: {key!r}")
    return args[key]


def _tool_fx_convert(args: dict[str, Any]) -> dict[str, Any]:
    amount = float(_require(args, "amount"))
    src = str(_require(args, "from")).upper()
    dst = str(_require(args, "to")).upper()
    if src == dst:
        rate = 1.0
    else:
        rate = _FX_RATES.get((src, dst), 0.0)
        if not rate:
            raise JsonRpcError(INVALID_PARAMS, f"no rate available for {src}->{dst}")
    return {
        "amount": amount,
        "from": src,
        "to": dst,
        "rate": rate,
        "converted": round(amount * rate, 4),
    }


def _tool_kb_search(args: dict[str, Any]) -> dict[str, Any]:
    query = str(_require(args, "query")).lower()
    top_k = int(args.get("top_k", 3))
    terms = [t for t in query.split() if t]
    scored = []
    for doc in _POLICY_KB:
        haystack = f"{doc['title']} {doc['text']}".lower()
        score = sum(haystack.count(term) for term in terms)
        if score:
            scored.append((score, doc))
    scored.sort(key=lambda pair: (-pair[0], pair[1]["id"]))
    return {"query": query, "results": [doc for _, doc in scored[:top_k]]}


def _tool_hr_employee_lookup(args: dict[str, Any]) -> dict[str, Any]:
    employee_id = str(_require(args, "employee_id")).upper()
    record = _EMPLOYEES.get(employee_id)
    if record is None:
        raise JsonRpcError(INVALID_PARAMS, f"unknown employee: {employee_id}")
    return {"record": dict(record)}


_TOOL_IMPLS = {
    "fx.convert": _tool_fx_convert,
    "kb.search": _tool_kb_search,
    "hr.employee_lookup": _tool_hr_employee_lookup,
}


# --------------------------------------------------------------------------
# Server
# --------------------------------------------------------------------------


def build_server() -> Dispatcher:
    """Build a dispatcher implementing the MCP server half."""
    rpc = Dispatcher()
    state = {"initialized": False}

    @rpc.method("initialize")
    def _initialize(params: dict[str, Any]) -> dict[str, Any]:
        requested = params.get("protocolVersion", PROTOCOL_VERSION)
        if requested not in SUPPORTED_PROTOCOL_VERSIONS:
            raise JsonRpcError(
                INVALID_PARAMS,
                f"unsupported protocol version: {requested}",
                {"supported": list(SUPPORTED_PROTOCOL_VERSIONS)},
            )
        state["initialized"] = True
        return {
            "protocolVersion": requested,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        }

    @rpc.method("notifications/initialized")
    def _initialized(_params: dict[str, Any]) -> None:
        return None

    @rpc.method("ping")
    def _ping(_params: dict[str, Any]) -> dict[str, Any]:
        return {}

    @rpc.method("tools/list")
    def _tools_list(_params: dict[str, Any]) -> dict[str, Any]:
        return {"tools": [dict(spec) for spec in TOOL_SPECS]}

    @rpc.method("tools/call")
    def _tools_call(params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        impl = _TOOL_IMPLS.get(name) if isinstance(name, str) else None
        if impl is None:
            raise JsonRpcError(INVALID_PARAMS, f"unknown tool: {name!r}")
        arguments = params.get("arguments") or {}
        structured = impl(arguments)
        classification = TOOL_CLASSIFICATION.get(name, Classification.INTERNAL)
        return {
            "content": [{"type": "text", "text": json.dumps(structured, ensure_ascii=False)}],
            "structuredContent": structured,
            "isError": False,
            "_meta": {CLASSIFICATION_META_KEY: str(classification)},
        }

    return rpc


def serve_stdio(stdin: Any = None, stdout: Any = None, rpc: Dispatcher | None = None) -> None:
    """Run the reference MCP server over newline-delimited JSON on stdio."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    rpc = rpc or build_server()

    for raw in stdin:
        line = raw.strip()
        if not line:
            continue
        response = rpc.dispatch_raw(line)
        if response is None:
            continue  # notification: the spec forbids a reply
        stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
        stdout.flush()


# --------------------------------------------------------------------------
# Transports
# --------------------------------------------------------------------------


class Transport(TypingProtocol):
    """Anything that can carry one JSON-RPC frame and hand back the reply."""

    def send(self, message: dict[str, Any]) -> dict[str, Any] | None: ...

    def close(self) -> None: ...


class InProcessTransport:
    """Calls a :class:`Dispatcher` directly — no subprocess, no process startup.

    Frames still round-trip through ``json.dumps``/``loads`` so that type
    coercion matches the real wire path.
    """

    def __init__(self, rpc: Dispatcher | None = None) -> None:
        self._rpc = rpc or build_server()

    def send(self, message: dict[str, Any]) -> dict[str, Any] | None:
        return self._rpc.dispatch_raw(json.dumps(message))

    def close(self) -> None:
        return None


class StdioTransport:
    """Spawns the reference server as a subprocess and speaks real stdio MCP."""

    def __init__(self, command: list[str] | None = None) -> None:
        self._command = command or [sys.executable, "-m", "protobridge.protocols.mcp"]
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
        self._proc = subprocess.Popen(  # noqa: S603 - constructed command, not user input
            self._command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            bufsize=1,
            env=env,
        )

    def send(self, message: dict[str, Any]) -> dict[str, Any] | None:
        if self._proc.stdin is None or self._proc.stdout is None:
            raise RuntimeError("MCP subprocess pipes are not available")
        self._proc.stdin.write(json.dumps(message, ensure_ascii=False) + "\n")
        self._proc.stdin.flush()
        if "id" not in message:
            return None  # notification
        line = self._proc.stdout.readline()
        if not line:
            raise RuntimeError("MCP server closed the stream before replying")
        return json.loads(line)

    def close(self) -> None:
        if self._proc.poll() is None:
            try:
                if self._proc.stdin is not None:
                    self._proc.stdin.close()
                self._proc.wait(timeout=5)
            except Exception:  # noqa: BLE001 - best-effort teardown
                self._proc.kill()


# --------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------


class MCPClient:
    """Client half of MCP: handshake, discovery, invocation."""

    def __init__(self, transport: Transport | None = None) -> None:
        self.transport: Transport = transport or InProcessTransport()
        self._next_id = 0
        self.server_info: dict[str, Any] = {}
        self.negotiated_version: str | None = None

    def _call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        self._next_id += 1
        response = self.transport.send(request(method, params, id=self._next_id))
        if response is None:
            raise RuntimeError(f"no response to {method}")
        return unwrap(response)

    def initialize(self, protocol_version: str = PROTOCOL_VERSION) -> dict[str, Any]:
        result = self._call(
            "initialize",
            {
                "protocolVersion": protocol_version,
                "capabilities": {},
                "clientInfo": {"name": "protobridge", "version": "0.1.0"},
            },
        )
        self.negotiated_version = result.get("protocolVersion")
        self.server_info = result.get("serverInfo", {})
        # Per spec the client confirms with a notification and expects no reply.
        self.transport.send(notification("notifications/initialized"))
        return result

    def list_tools(self) -> list[dict[str, Any]]:
        return self._call("tools/list").get("tools", [])

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self._call("tools/call", {"name": name, "arguments": arguments})

    def close(self) -> None:
        self.transport.close()


@contextmanager
def connect(transport: Transport | None = None) -> Iterator[MCPClient]:
    """Open an initialized MCP session and guarantee teardown."""
    client = MCPClient(transport)
    try:
        client.initialize()
        yield client
    finally:
        client.close()


if __name__ == "__main__":  # pragma: no cover - exercised via StdioTransport
    serve_stdio()
