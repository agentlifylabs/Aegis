# Python SDK

The `aegis_sdk` Python package provides envelope construction, hash-chain
management, and an HTTP client for communicating with `aegisd`.

---

## Installation

```bash
# From the repo
pip install -e python/

# Once published to PyPI
pip install aegis-sdk
```

**Requirements:** Python 3.11+, no third-party dependencies.

---

## Core Concepts

The SDK has three components:

| Module | Purpose |
|---|---|
| `aegis_sdk.envelope` | Build and seal event envelopes; manage hash chains |
| `aegis_sdk.canon` | RFC 8785 canonical JSON + SHA-256 hashing |
| `aegis_sdk.client` | HTTP client for `aegisd` |

---

## Building Events

### `Builder`

The `Builder` manages the hash chain for a single session. Calling `.append()`
produces a sealed `Envelope` and advances the chain automatically.

```python
from aegis_sdk import Builder, EventType

builder = Builder(
    tenant_id  = "acme",
    user_id    = "user-42",
    session_id = "sess-001",
)

# First event (seq=0)
e0 = builder.append(
    EventType.MODEL_CALL_STARTED,
    {"model_id": "gpt-4o", "call_id": "m1"},
)

# Second event (seq=1, prev_hash = e0.hash)
e1 = builder.append(
    EventType.TOOL_CALL_PROPOSED,
    {"tool_name": "read_file", "call_id": "t1", "args": {"path": "/workspace/data.csv"}},
)

print(e0.seq)   # 0
print(e1.seq)   # 1
print(e1.prev_hash == e0.hash)  # True
```

### Resuming a Chain

If aegisd already has events for a session (e.g., after a restart), resume the
chain from the last known sequence number and hash:

```python
builder = Builder(
    tenant_id  = "acme",
    user_id    = "user-42",
    session_id = "sess-001",
    next_seq   = 5,
    prev_hash  = bytes.fromhex("a3f2..."),
)
```

### `Envelope`

You can also construct envelopes manually and seal them:

```python
from aegis_sdk.envelope import Envelope, EventType

e = Envelope(
    tenant_id  = "acme",
    user_id    = "u1",
    session_id = "sess-001",
    seq        = 0,
    ts_unix_ms = 1700000000000,
    event_type = EventType.TOOL_CALL_PROPOSED,
    payload    = {"tool_name": "read_file", "call_id": "c1", "args": {}},
)
e.seal()

# Verify the hash
assert e.verify()

# Serialise for the wire
d = e.to_dict()
```

---

## Event Types

```python
from aegis_sdk import EventType

EventType.MODEL_CALL_STARTED
EventType.MODEL_CALL_FINISHED
EventType.TOOL_CALL_PROPOSED
EventType.TOOL_CALL_ALLOWED
EventType.TOOL_CALL_DENIED
EventType.TOOL_CALL_EXECUTED
EventType.TOOL_RESULT
EventType.POLICY_DECISION
EventType.APPROVAL_REQUESTED
EventType.APPROVAL_DECIDED
EventType.MEMORY_READ
EventType.MEMORY_WRITE
EventType.HANDOFF_REQUESTED
EventType.HANDOFF_COMPLETED
EventType.CHECKPOINT_CREATED
EventType.TERMINATION
EventType.ERROR_RAISED
```

---

## HTTP Client

### `AegisClient`

```python
from aegis_sdk import AegisClient

client = AegisClient("http://localhost:8080")
```

### `append_event`

Send a sealed envelope to aegisd:

```python
response = client.append_event(envelope)
# {"seq": 0, "hash": "a3f2..."}
```

Raises `RuntimeError` on HTTP errors (4xx / 5xx).

### `list_events`

Retrieve events for a tenant and optionally filter by session or event type:

```python
page = client.list_events(
    tenant_id  = "acme",
    session_id = "sess-001",   # optional
    event_type = "TOOL_CALL_PROPOSED",  # optional
    limit      = 100,
)
# page["Events"] is a list of event dicts
# page["NextToken"] for pagination
```

### `get_snapshot`

Retrieve the current session snapshot:

```python
snapshot = client.get_snapshot("acme", "sess-001")
# {
#   "steps_consumed":      5,
#   "tool_calls_consumed": 3,
#   "wall_time_ms":        12000,
#   "is_tainted":          false,
#   "sanitized_keys":      [],
#   "loop_violation":      ""
# }
```

### `verify_chain`

Verify the hash chain integrity for a session:

```python
result = client.verify_chain("acme", "sess-001")
# {"valid": true, "first_bad_seq": 0, "error": ""}

assert result["valid"], f"Chain broken at seq {result['first_bad_seq']}"
```

---

## Complete Example

An agent framework integration that records every step, checks policy before
each tool call, and verifies chain integrity at the end:

```python
from aegis_sdk import Builder, EventType, AegisClient

client  = AegisClient("http://localhost:8080")
builder = Builder(tenant_id="acme", user_id="u1", session_id="sess-example")

# 1. Record model call start
e = builder.append(EventType.MODEL_CALL_STARTED, {"model_id": "gpt-4o", "call_id": "m1"})
client.append_event(e)

# 2. Agent proposes a tool call — record and ingest
e = builder.append(EventType.TOOL_CALL_PROPOSED, {
    "tool_name": "read_file",
    "call_id":   "t1",
    "args":      {"path": "/workspace/report.txt"},
})
client.append_event(e)

# 3. Execute the tool
result = read_file("/workspace/report.txt")   # your actual tool execution

# 4. Record the result (marks session as tainted)
e = builder.append(EventType.TOOL_RESULT, {
    "call_id": "t1",
    "result":  result,
})
client.append_event(e)

# 5. Record clean termination (clears taint)
e = builder.append(EventType.TERMINATION, {"reason": "task_complete"})
client.append_event(e)

# 6. Verify the chain end-to-end
chain = client.verify_chain("acme", "sess-example")
assert chain["valid"], "Hash chain integrity violation detected"
print(f"Session complete. {builder._next_seq} events recorded.")
```

---

## Canonical JSON (`aegis_sdk.canon`)

The `canon` module implements RFC 8785 (JCS) deterministic JSON serialisation
and SHA-256 hashing. This is used internally by `Envelope.seal()` but can also
be used directly:

```python
from aegis_sdk.canon import canonical_json, hash_object

# Deterministic JSON bytes (keys sorted, Unicode-escaped)
data = {"b": 2, "a": 1}
assert canonical_json(data) == b'{"a":1,"b":2}'

# SHA-256 of the canonical form
digest = hash_object(data)  # returns bytes
```

The canonical form is identical across the Go and Python implementations,
guaranteeing that hash chains built in Python can be verified by aegisd (Go)
and vice versa.

---

## Running SDK Tests

```bash
cd python
pip install -e ".[dev]"
python -m pytest -v
```

Tests cover canonical JSON edge cases (Unicode, floats, nested structures) and
envelope seal/verify round-trips.
