"""RFC 8785 (JCS) canonical JSON implementation for Aegis.

Produces byte-for-byte identical output to the Go canon package so that
hash values are cross-platform deterministic.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical JSON bytes for *value*."""
    return _canonicalize_value(value)


def hash_object(value: Any) -> bytes:
    """Return SHA-256(canonicalize(value)) as raw bytes."""
    return hashlib.sha256(canonicalize(value)).digest()


def hash_object_hex(value: Any) -> str:
    """Return SHA-256(canonicalize(value)) as a lowercase hex string."""
    return hash_object(value).hex()


# ── internal ──────────────────────────────────────────────────────────────────


def _canonicalize_value(v: Any) -> bytes:
    if v is None:
        return b"null"
    if isinstance(v, bool):
        return b"true" if v else b"false"
    if isinstance(v, int):
        return _canonicalize_int(v)
    if isinstance(v, float):
        return _canonicalize_float(v)
    if isinstance(v, str):
        return _canonicalize_string(v)
    if isinstance(v, (list, tuple)):
        return _canonicalize_array(v)
    if isinstance(v, dict):
        return _canonicalize_object(v)
    raise TypeError(f"canon: unsupported type {type(v)!r}")


def _canonicalize_int(n: int) -> bytes:
    # Integers serialize as their decimal representation with no decimal point.
    return str(n).encode()


def _canonicalize_float(f: float) -> bytes:
    # Use json.dumps which matches Go's strconv.AppendFloat shortest representation.
    return json.dumps(f, separators=(",", ":")).encode()


def _canonicalize_string(s: str) -> bytes:
    # json.dumps produces correct Unicode escape sequences consistent with Go.
    return json.dumps(s, ensure_ascii=False, separators=(",", ":")).encode()


def _canonicalize_array(arr: list | tuple) -> bytes:
    parts = [_canonicalize_value(item) for item in arr]
    return b"[" + b",".join(parts) + b"]"


def _canonicalize_object(obj: dict) -> bytes:
    # JCS: keys sorted by Unicode code point order (Python's default str sort).
    parts = []
    for k in sorted(obj.keys()):
        key_bytes = _canonicalize_string(k)
        val_bytes = _canonicalize_value(obj[k])
        parts.append(key_bytes + b":" + val_bytes)
    return b"{" + b",".join(parts) + b"}"
