"""Agent2Agent adapter: Agent Card, HTTP JSON-RPC server, and client.

A2A inverts MCP's shape. Where MCP asks *"what tools do you have?"* over a pipe
the caller owns, A2A asks *"who are you and what can you do?"* over HTTP via a
public discovery document at ``/.well-known/agent.json``.

A2A is also **task-oriented rather than call-oriented**: ``message/send``
returns a ``Task`` carrying a lifecycle state, so a peer can *refuse* work.
The reference agent below uses that to reject restricted data at its own
boundary — policy is enforced on both sides of the wire, not only by the
caller.
"""

from __future__ import annotations

import json
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.request import Request, urlopen

from protobridge.protocols.jsonrpc import (
    INVALID_PARAMS,
    Dispatcher,
    JsonRpcError,
    failure,
    request,
    unwrap,
)

PROTOCOL_VERSION = "0.3.0"
AGENT_CARD_PATH = "/.well-known/agent.json"
AGENT_CARD_PATH_ALT = "/.well-known/agent-card.json"
RPC_PATH = "/"

CLASSIFICATION_METADATA_KEY = "protobridge/classification"
TRACE_METADATA_KEY = "protobridge/traceId"


class TaskState:
    """A2A task lifecycle states used by this implementation."""

    SUBMITTED = "submitted"
    WORKING = "working"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"
    CANCELED = "canceled"

    TERMINAL = frozenset({COMPLETED, FAILED, REJECTED, CANCELED})


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


# --------------------------------------------------------------------------
# Agent Card — the A2A discovery document
# --------------------------------------------------------------------------

AGENT_CARD: dict[str, Any] = {
    "name": "Northwind Vendor Risk Agent",
    "description": (
        "Third-party agent that scores supplier risk and estimates logistics "
        "lead times. Operated by a different vendor than the calling system."
    ),
    "url": "http://127.0.0.1:8931/",
    "version": "1.4.0",
    "protocolVersion": PROTOCOL_VERSION,
    "provider": {"organization": "Northwind Analytics", "url": "https://example.com"},
    "capabilities": {
        "streaming": False,
        "pushNotifications": False,
        "stateTransitionHistory": True,
    },
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain", "application/json"],
    "skills": [
        {
            "id": "vendor.risk_assessment",
            "name": "Vendor risk assessment",
            "description": "Score a supplier's operational and financial risk from 0.0 to 1.0.",
            "tags": ["risk", "procurement", "vendor"],
            "examples": ["Assess risk for acme-logistics"],
            "inputModes": ["text/plain"],
            "outputModes": ["application/json"],
        },
        {
            "id": "supply.lead_time_estimate",
            "name": "Lead time estimate",
            "description": "Estimate delivery lead time in days for a supplier and route.",
            "tags": ["logistics", "supply-chain"],
            "examples": ["Lead time for acme-logistics to Karachi"],
            "inputModes": ["text/plain"],
            "outputModes": ["application/json"],
        },
    ],
}

SKILL_IDS = frozenset(skill["id"] for skill in AGENT_CARD["skills"])


# --------------------------------------------------------------------------
# Reference skill implementations (synthetic, deterministic)
# --------------------------------------------------------------------------

_VENDOR_RISK: dict[str, float] = {
    "acme-logistics": 0.22,
    "globex-freight": 0.58,
    "initech-supply": 0.81,
}

_LEAD_TIME_DAYS: dict[str, int] = {
    "acme-logistics": 12,
    "globex-freight": 21,
    "initech-supply": 34,
}


def _tier(score: float) -> str:
    if score < 0.35:
        return "low"
    if score < 0.70:
        return "medium"
    return "high"


def _extract_vendor(text: str) -> str:
    """Pull a known vendor slug out of free text, defaulting to the first known one."""
    lowered = text.lower()
    for vendor in _VENDOR_RISK:
        if vendor in lowered:
            return vendor
    return "acme-logistics"


def _skill_vendor_risk(text: str) -> dict[str, Any]:
    vendor = _extract_vendor(text)
    score = _VENDOR_RISK[vendor]
    return {
        "skill": "vendor.risk_assessment",
        "vendor": vendor,
        "risk_score": score,
        "tier": _tier(score),
        "assessed_at": _now_iso(),
    }


def _skill_lead_time(text: str) -> dict[str, Any]:
    vendor = _extract_vendor(text)
    return {
        "skill": "supply.lead_time_estimate",
        "vendor": vendor,
        "lead_time_days": _LEAD_TIME_DAYS[vendor],
        "assessed_at": _now_iso(),
    }


_SKILL_IMPLS = {
    "vendor.risk_assessment": _skill_vendor_risk,
    "supply.lead_time_estimate": _skill_lead_time,
}


# --------------------------------------------------------------------------
# Message / Task helpers
# --------------------------------------------------------------------------


def text_message(
    text: str, *, role: str = "user", metadata: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Build an A2A ``Message`` with a single text part."""
    msg: dict[str, Any] = {
        "kind": "message",
        "role": role,
        "messageId": _new_id("msg"),
        "parts": [{"kind": "text", "text": text}],
    }
    if metadata:
        msg["metadata"] = metadata
    return msg


def message_text(message: dict[str, Any]) -> str:
    """Concatenate the text parts of a Message."""
    return " ".join(
        part.get("text", "") for part in message.get("parts", []) if part.get("kind") == "text"
    ).strip()


# --------------------------------------------------------------------------
# Server
# --------------------------------------------------------------------------


def build_server() -> tuple[Dispatcher, dict[str, dict[str, Any]]]:
    """Build the A2A dispatcher and expose its in-memory task store."""
    tasks: dict[str, dict[str, Any]] = {}
    rpc = Dispatcher()

    def _transition(task: dict[str, Any], state: str, note: str | None = None) -> None:
        task["status"] = {"state": state, "timestamp": _now_iso()}
        if note:
            task["status"]["message"] = text_message(note, role="agent")

    def _handle_send(params: dict[str, Any]) -> dict[str, Any]:
        message = params.get("message")
        if not isinstance(message, dict):
            raise JsonRpcError(INVALID_PARAMS, "params.message is required")

        metadata = {**(params.get("metadata") or {}), **(message.get("metadata") or {})}
        skill_id = metadata.get("skillId") or params.get("skillId")
        text = message_text(message)

        task_id = _new_id("task")
        task: dict[str, Any] = {
            "id": task_id,
            "contextId": params.get("contextId") or metadata.get("contextId") or _new_id("ctx"),
            "kind": "task",
            "history": [message],
            "artifacts": [],
            "metadata": metadata,
            "status": {"state": TaskState.SUBMITTED, "timestamp": _now_iso()},
        }
        tasks[task_id] = task

        # Boundary policy: this agent belongs to another vendor and refuses
        # restricted material outright, regardless of what the caller claims.
        if metadata.get(CLASSIFICATION_METADATA_KEY) == "restricted":
            _transition(
                task,
                TaskState.REJECTED,
                "Restricted-classification input refused: no data processing addendum on file.",
            )
            return task

        if skill_id is not None and skill_id not in SKILL_IDS:
            _transition(task, TaskState.REJECTED, f"Unknown skill: {skill_id}")
            return task

        impl = _SKILL_IMPLS.get(skill_id) if skill_id else _skill_vendor_risk
        _transition(task, TaskState.WORKING)
        try:
            payload = impl(text)
        except Exception as exc:  # noqa: BLE001 - reported as a failed task, not an RPC error
            _transition(task, TaskState.FAILED, str(exc))
            return task

        task["artifacts"].append(
            {
                "artifactId": _new_id("art"),
                "name": payload["skill"],
                "parts": [{"kind": "text", "text": json.dumps(payload, ensure_ascii=False)}],
            }
        )
        _transition(task, TaskState.COMPLETED)
        return task

    rpc.register("message/send", _handle_send)
    rpc.register("tasks/send", _handle_send)  # legacy alias

    @rpc.method("tasks/get")
    def _tasks_get(params: dict[str, Any]) -> dict[str, Any]:
        task_id = params.get("id")
        task = tasks.get(task_id) if isinstance(task_id, str) else None
        if task is None:
            raise JsonRpcError(INVALID_PARAMS, f"unknown task: {task_id!r}")
        return task

    @rpc.method("tasks/cancel")
    def _tasks_cancel(params: dict[str, Any]) -> dict[str, Any]:
        task_id = params.get("id")
        task = tasks.get(task_id) if isinstance(task_id, str) else None
        if task is None:
            raise JsonRpcError(INVALID_PARAMS, f"unknown task: {task_id!r}")
        if task["status"]["state"] not in TaskState.TERMINAL:
            _transition(task, TaskState.CANCELED)
        return task

    @rpc.method("agent/getAuthenticatedExtendedCard")
    def _extended_card(_params: dict[str, Any]) -> dict[str, Any]:
        return dict(AGENT_CARD)

    return rpc, tasks


class _Handler(BaseHTTPRequestHandler):
    """HTTP surface: a discovery GET plus a JSON-RPC POST."""

    protocol_version = "HTTP/1.1"
    rpc: Dispatcher  # injected by make_server

    def log_message(self, fmt: str, *args: Any) -> None:
        return  # keep stdout clean; the CLI prints its own banner

    def _respond(self, status: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path in (AGENT_CARD_PATH, AGENT_CARD_PATH_ALT):
            self._respond(200, AGENT_CARD)
            return
        self._respond(404, {"error": "not found", "path": self.path})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        response = self.rpc.dispatch_raw(raw)
        if response is None:
            # Notification: A2A over HTTP still needs a status line.
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._respond(200, response)

    def do_PUT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._respond(405, failure(None, INVALID_PARAMS, "method not allowed"))


def make_server(host: str = "127.0.0.1", port: int = 8931) -> ThreadingHTTPServer:
    """Create (but do not start) an A2A HTTP server."""
    rpc, _tasks = build_server()
    handler = type("BoundA2AHandler", (_Handler,), {"rpc": rpc})
    return ThreadingHTTPServer((host, port), handler)


@contextmanager
def running_server(host: str = "127.0.0.1", port: int = 0) -> Iterator[str]:
    """Run an A2A server on a background thread; yield its base URL.

    Passing ``port=0`` binds an ephemeral port, which keeps tests from
    colliding with an already-running instance.
    """
    server = make_server(host, port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    bound_host, bound_port = server.server_address[0], server.server_address[1]
    try:
        yield f"http://{bound_host}:{bound_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


# --------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------


class A2AClient:
    """Client half of A2A: discover the card, send messages, poll tasks."""

    def __init__(self, base_url: str, *, timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._next_id = 0
        self.agent_card: dict[str, Any] | None = None

    def fetch_agent_card(self) -> dict[str, Any]:
        url = f"{self.base_url}{AGENT_CARD_PATH}"
        with urlopen(url, timeout=self.timeout) as resp:  # noqa: S310
            self.agent_card = json.loads(resp.read().decode("utf-8"))
        return self.agent_card

    def supports_skill(self, skill_id: str) -> bool:
        card = self.agent_card or self.fetch_agent_card()
        return any(skill["id"] == skill_id for skill in card.get("skills", []))

    def _rpc(self, method: str, params: dict[str, Any]) -> Any:
        self._next_id += 1
        body = json.dumps(request(method, params, id=self._next_id)).encode("utf-8")
        req = Request(  # noqa: S310 - base_url is operator-configured
            f"{self.base_url}{RPC_PATH}",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
            return unwrap(json.loads(resp.read().decode("utf-8")))

    def send_message(
        self,
        text: str,
        *,
        skill_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send one message and return the resulting Task."""
        meta = dict(metadata or {})
        if skill_id:
            meta["skillId"] = skill_id
        return self._rpc("message/send", {"message": text_message(text, metadata=meta)})

    def get_task(self, task_id: str) -> dict[str, Any]:
        return self._rpc("tasks/get", {"id": task_id})

    def cancel_task(self, task_id: str) -> dict[str, Any]:
        return self._rpc("tasks/cancel", {"id": task_id})


def task_payload(task: dict[str, Any]) -> dict[str, Any]:
    """Decode the first JSON artifact of a completed task."""
    for artifact in task.get("artifacts", []):
        for part in artifact.get("parts", []):
            if part.get("kind") == "text":
                try:
                    return json.loads(part["text"])
                except json.JSONDecodeError:
                    return {"text": part["text"]}
    return {}


def task_note(task: dict[str, Any]) -> str:
    """Human-readable reason attached to a task's current status, if any."""
    status_message = task.get("status", {}).get("message")
    return message_text(status_message) if status_message else ""
