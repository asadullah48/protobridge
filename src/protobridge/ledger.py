"""Tamper-evident audit ledger.

A plain append-only log proves nothing: whoever can append can also rewrite.
Chaining each entry's hash over the previous entry's hash makes tampering
*detectable* — altering entry 3 invalidates 4..N, so :meth:`AuditLedger.verify`
can name the exact break point.

The chain covers a **digest** of the payload rather than the payload itself, so
the integrity proof survives even when policy required the sensitive bytes be
dropped.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


def _canonical(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no incidental whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def digest(obj: Any) -> str:
    return hashlib.sha256(_canonical(obj).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """One immutable link in the chain."""

    seq: int
    ts: str
    event: str
    trace_id: str
    actor: str
    payload_digest: str
    prev_hash: str
    entry_hash: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    def compute_hash(self) -> str:
        """Hash over every field except ``entry_hash`` itself."""
        return digest(
            {
                "seq": self.seq,
                "ts": self.ts,
                "event": self.event,
                "trace_id": self.trace_id,
                "actor": self.actor,
                "payload_digest": self.payload_digest,
                "prev_hash": self.prev_hash,
                "detail": self.detail,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ChainStatus:
    """Result of verifying the chain."""

    valid: bool
    length: int
    broken_at: int | None = None
    reason: str = ""

    def __bool__(self) -> bool:
        return self.valid


class AuditLedger:
    """Append-only, hash-chained record of everything crossing the bridge."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    # -- writing ----------------------------------------------------------

    def append(
        self,
        event: str,
        *,
        trace_id: str,
        actor: str,
        payload: Any = None,
        detail: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Append one entry and return it."""
        prev_hash = self._entries[-1].entry_hash if self._entries else GENESIS_HASH
        draft = AuditEntry(
            seq=len(self._entries),
            ts=datetime.now(UTC).isoformat(),
            event=event,
            trace_id=trace_id,
            actor=actor,
            payload_digest=digest(payload),
            prev_hash=prev_hash,
            detail=dict(detail or {}),
        )
        sealed = AuditEntry(
            seq=draft.seq,
            ts=draft.ts,
            event=draft.event,
            trace_id=draft.trace_id,
            actor=draft.actor,
            payload_digest=draft.payload_digest,
            prev_hash=draft.prev_hash,
            entry_hash=draft.compute_hash(),
            detail=draft.detail,
        )
        self._entries.append(sealed)
        return sealed

    # -- reading ----------------------------------------------------------

    @property
    def entries(self) -> tuple[AuditEntry, ...]:
        return tuple(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self) -> Iterator[AuditEntry]:
        return iter(self._entries)

    def for_trace(self, trace_id: str) -> list[AuditEntry]:
        """Every entry belonging to one end-to-end request."""
        return [e for e in self._entries if e.trace_id == trace_id]

    def head(self) -> str:
        """Current chain head — publish this to make the log externally provable."""
        return self._entries[-1].entry_hash if self._entries else GENESIS_HASH

    # -- integrity --------------------------------------------------------

    def verify(self) -> ChainStatus:
        """Walk the chain and report the first break, if any."""
        expected_prev = GENESIS_HASH
        for index, entry in enumerate(self._entries):
            if entry.seq != index:
                return ChainStatus(False, len(self._entries), index, f"seq {entry.seq} != {index}")
            if entry.prev_hash != expected_prev:
                return ChainStatus(False, len(self._entries), index, "prev_hash does not match")
            if entry.entry_hash != entry.compute_hash():
                return ChainStatus(False, len(self._entries), index, "entry contents were altered")
            expected_prev = entry.entry_hash
        return ChainStatus(True, len(self._entries))

    # -- export -----------------------------------------------------------

    def to_jsonl(self) -> str:
        return "\n".join(_canonical(e.to_dict()) for e in self._entries)

    def write_jsonl(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.to_jsonl() + "\n", encoding="utf-8")
        return target
