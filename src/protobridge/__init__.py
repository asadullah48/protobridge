"""ProtoBridge — an MCP + A2A interoperability layer for agentic AI systems.

Public surface is intentionally small: build an envelope, run the graph.

    from protobridge import ProtocolEnvelope, Principal

Heavier symbols (servers, clients, the audit ledger, the LangGraph app) live
in their own modules so that ``import protobridge`` stays cheap and free of
side effects.
"""

from protobridge.envelope import (
    Classification,
    EnvelopeResult,
    Intent,
    Principal,
    Protocol,
    ProtocolEnvelope,
)

__version__ = "0.1.0"

__all__ = [
    "Classification",
    "EnvelopeResult",
    "Intent",
    "Principal",
    "Protocol",
    "ProtocolEnvelope",
    "__version__",
]
