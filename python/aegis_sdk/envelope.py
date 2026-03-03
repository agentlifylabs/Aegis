"""Event envelope construction and hash-chain management for Aegis Python SDK."""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from aegis_sdk.canon import hash_object


class EventType(str, Enum):
    MODEL_CALL_STARTED   = "MODEL_CALL_STARTED"
    MODEL_CALL_FINISHED  = "MODEL_CALL_FINISHED"
    TOOL_CALL_PROPOSED   = "TOOL_CALL_PROPOSED"
    TOOL_CALL_ALLOWED    = "TOOL_CALL_ALLOWED"
    TOOL_CALL_DENIED     = "TOOL_CALL_DENIED"
    TOOL_CALL_EXECUTED   = "TOOL_CALL_EXECUTED"
    TOOL_RESULT          = "TOOL_RESULT"
    POLICY_DECISION      = "POLICY_DECISION"
    APPROVAL_REQUESTED   = "APPROVAL_REQUESTED"
    APPROVAL_DECIDED     = "APPROVAL_DECIDED"
    MEMORY_READ          = "MEMORY_READ"
    MEMORY_WRITE         = "MEMORY_WRITE"
    HANDOFF_REQUESTED    = "HANDOFF_REQUESTED"
    HANDOFF_COMPLETED    = "HANDOFF_COMPLETED"
    CHECKPOINT_CREATED   = "CHECKPOINT_CREATED"
    TERMINATION          = "TERMINATION"
    ERROR_RAISED         = "ERROR_RAISED"


@dataclass
class Envelope:
    tenant_id:  str
    user_id:    str
    session_id: str
    seq:        int
    ts_unix_ms: int
    event_type: EventType
    payload:    Any
    prev_hash:  Optional[bytes] = None
    hash:       Optional[bytes] = None

    def _hashable_dict(self) -> dict:
        """Return the dict used for hashing (hash field excluded)."""
        d: dict = {
            "tenant_id":  self.tenant_id,
            "user_id":    self.user_id,
            "session_id": self.session_id,
            "seq":        self.seq,
            "ts_unix_ms": self.ts_unix_ms,
            "event_type": self.event_type.value,
            "payload":    self.payload,
        }
        if self.prev_hash:
            d["prev_hash"] = list(self.prev_hash)  # bytes -> list[int] for JSON
        return d

    def seal(self) -> None:
        """Compute and set the hash field."""
        if self.seq == 0 and self.prev_hash:
            raise ValueError("seq=0 must have empty prev_hash")
        self.hash = hash_object(self._hashable_dict())

    def verify(self) -> bool:
        """Return True if the stored hash matches the computed hash."""
        saved = self.hash
        self.hash = None
        self.seal()
        result = self.hash == saved
        if not result:
            self.hash = saved
        return result

    def to_dict(self) -> dict:
        d = self._hashable_dict()
        if self.hash:
            d["hash"] = list(self.hash)
        return d


class Builder:
    """Constructs a chain of sealed envelopes for a session."""

    def __init__(
        self,
        tenant_id: str,
        user_id: str,
        session_id: str,
        next_seq: int = 0,
        prev_hash: Optional[bytes] = None,
    ) -> None:
        self.tenant_id  = tenant_id
        self.user_id    = user_id
        self.session_id = session_id
        self._next_seq  = next_seq
        self._last_hash = prev_hash

    def append(self, event_type: EventType, payload: Any = None) -> Envelope:
        e = Envelope(
            tenant_id  = self.tenant_id,
            user_id    = self.user_id,
            session_id = self.session_id,
            seq        = self._next_seq,
            ts_unix_ms = int(time.time() * 1000),
            event_type = event_type,
            payload    = payload,
            prev_hash  = self._last_hash,
        )
        e.seal()
        self._last_hash = e.hash
        self._next_seq += 1
        return e
