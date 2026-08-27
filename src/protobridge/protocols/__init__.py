"""Wire-protocol adapters.

Each adapter module is self-contained — types, server, and client together —
so the two protocols can be read side by side:

``jsonrpc``
    Shared JSON-RPC 2.0 framing and a transport-agnostic dispatcher.
``mcp``
    Model Context Protocol: JSON-RPC over **stdio**, tool-shaped
    (``initialize`` / ``tools/list`` / ``tools/call``).
``a2a``
    Agent2Agent: JSON-RPC over **HTTP** with a discovery document, peer-shaped
    (``/.well-known/agent.json`` / ``message/send`` / ``tasks/get``).
"""

__all__ = ["a2a", "jsonrpc", "mcp"]
