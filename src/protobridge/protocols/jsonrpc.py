"""JSON-RPC 2.0 primitives shared by the MCP and A2A adapters.

Both protocols ProtoBridge speaks are JSON-RPC 2.0 at the message layer; they
differ only in transport (stdio vs HTTP) and method vocabulary
(``tools/call`` vs ``message/send``). Factoring the RPC core out once makes
that shared ancestry explicit and keeps the two servers thin.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

JSONRPC_VERSION = "2.0"

# Standard JSON-RPC 2.0 error codes.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

Handler = Callable[[dict[str, Any]], Any]


class JsonRpcError(Exception):
    """A JSON-RPC error, raisable from a handler and serializable to the wire."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data

    def to_dict(self) -> dict[str, Any]:
        err: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            err["data"] = self.data
        return err


def request(method: str, params: dict[str, Any] | None = None, *, id: Any = 1) -> dict[str, Any]:
    msg: dict[str, Any] = {"jsonrpc": JSONRPC_VERSION, "id": id, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def notification(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """A request without an ``id`` — the peer must not reply."""
    msg: dict[str, Any] = {"jsonrpc": JSONRPC_VERSION, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def success(id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": id, "result": result}


def failure(id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": id,
        "error": JsonRpcError(code, message, data).to_dict(),
    }


def unwrap(response: dict[str, Any]) -> Any:
    """Return ``result`` or raise :class:`JsonRpcError` built from ``error``."""
    if "error" in response:
        err = response["error"]
        raise JsonRpcError(
            err.get("code", INTERNAL_ERROR),
            err.get("message", "unknown error"),
            err.get("data"),
        )
    if "result" not in response:
        raise JsonRpcError(INVALID_REQUEST, "response carried neither result nor error")
    return response["result"]


class Dispatcher:
    """Transport-agnostic method router.

    The MCP server feeds it newline-delimited stdin frames; the A2A server
    feeds it HTTP POST bodies. Neither knows the difference.
    """

    def __init__(self) -> None:
        self._handlers: dict[str, Handler] = {}

    def method(self, name: str) -> Callable[[Handler], Handler]:
        def decorate(fn: Handler) -> Handler:
            self._handlers[name] = fn
            return fn

        return decorate

    def register(self, name: str, handler: Handler) -> None:
        self._handlers[name] = handler

    @property
    def methods(self) -> list[str]:
        return sorted(self._handlers)

    def dispatch(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Handle one message. Returns ``None`` for notifications."""
        msg_id = message.get("id")
        is_notification = "id" not in message

        if message.get("jsonrpc") != JSONRPC_VERSION:
            return (
                None
                if is_notification
                else failure(msg_id, INVALID_REQUEST, "jsonrpc field must be '2.0'")
            )

        method = message.get("method")
        handler = self._handlers.get(method) if isinstance(method, str) else None
        if handler is None:
            return (
                None
                if is_notification
                else failure(msg_id, METHOD_NOT_FOUND, f"unknown method: {method!r}")
            )

        try:
            result = handler(message.get("params") or {})
        except JsonRpcError as exc:
            return None if is_notification else failure(msg_id, exc.code, exc.message, exc.data)
        except Exception as exc:  # noqa: BLE001 - surfaced to the caller as an RPC error
            return None if is_notification else failure(msg_id, INTERNAL_ERROR, str(exc))

        return None if is_notification else success(msg_id, result)

    def dispatch_raw(self, raw: str | bytes) -> dict[str, Any] | None:
        try:
            message = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return failure(None, PARSE_ERROR, f"invalid JSON: {exc}")
        if not isinstance(message, dict):
            return failure(None, INVALID_REQUEST, "batch requests are not supported")
        return self.dispatch(message)
