# Core Concepts

This document explains how Aegis works from first principles — the event model,
the policy engine, taint tracking, deterministic replay, and telemetry.

---

## The Central Idea

An AI agent is, at its core, a sequence of decisions: call this tool, read that
memory, write this file. Aegis makes that sequence **auditable**, **controlled**,
and **replayable** by sitting in the path of every action and:

1. **Recording** it as a cryptographically-sealed event
2. **Evaluating** it against a declared capability policy before allowing it
3. **Storing** the result in an append-only, hash-chained log

No action reaches the outside world without passing through these three steps.

---

## The Event Model

### Envelopes

Every agent action becomes an **Envelope** — a sealed, immutable record:

```
┌───────────────────────────────────────────────────────────┐
│  tenant_id   session_id   seq   ts_unix_ms   event_type   │
│  payload (any JSON)                                        │
│  prev_hash   →   hash = SHA-256(canonical JSON of above)  │
└───────────────────────────────────────────────────────────┘
```

The `hash` is computed over the RFC 8785 canonical (JCS) form of all fields
**except** `hash` itself, ensuring the hash is deterministic across languages
and platforms.

### The Hash Chain

Events in a session form a linked chain:

```
event[0]  hash: H0  prev_hash: nil
event[1]  hash: H1  prev_hash: H0
event[2]  hash: H2  prev_hash: H1
...
```

Tampering with any event breaks all subsequent hashes. The chain is verifiable
at any time via `GET /v1/sessions/{id}/verify`.

### Event Types

| Event Type | When it fires |
|---|---|
| `MODEL_CALL_STARTED` | Agent sends a prompt to the model |
| `MODEL_CALL_FINISHED` | Model responds |
| `TOOL_CALL_PROPOSED` | Agent wants to call a tool — **evaluated by policy** |
| `TOOL_CALL_ALLOWED` | Policy permitted the call |
| `TOOL_CALL_DENIED` | Policy blocked the call |
| `TOOL_CALL_EXECUTED` | Tool call was forwarded to upstream |
| `TOOL_RESULT` | Tool returned a result — **marks session as tainted** |
| `POLICY_DECISION` | Records the full policy decision for audit |
| `APPROVAL_REQUESTED` | Human approval required before proceeding |
| `APPROVAL_DECIDED` | Human approved or denied |
| `MEMORY_READ` | Agent read from memory — **marks session as tainted** |
| `MEMORY_WRITE` | Agent wrote to memory |
| `HANDOFF_REQUESTED` | Multi-agent handoff initiated |
| `HANDOFF_COMPLETED` | Handoff completed |
| `CHECKPOINT_CREATED` | Snapshot checkpoint saved |
| `TERMINATION` | Session ended cleanly — **clears taint** |
| `ERROR_RAISED` | Error occurred during execution |

---

## The Snapshot Reducer

As events are ingested, the **snapshot reducer** maintains a running aggregate
of session state. This state is passed to the Rego policy engine on every
`TOOL_CALL_PROPOSED` evaluation.

Key snapshot fields:

| Field | Type | Description |
|---|---|---|
| `steps_consumed` | int | Total steps taken in this session |
| `tool_calls_consumed` | int | Total tool calls made |
| `wall_time_ms` | int | Elapsed wall clock time since session start |
| `loop_violation` | string | Non-empty when a loop/no-progress was detected |
| `is_tainted` | bool | `true` when any taint source has been processed |
| `sanitized_keys` | []string | Keys for which sanitisation has been confirmed |

The reducer is deterministic — replaying the same event sequence always
produces the same snapshot. This is the foundation of exact-mode replay.

---

## The Policy Engine

### Architecture

```
TOOL_CALL_PROPOSED
      │
      ▼
┌─────────────────────────────┐
│  Rego policy engine (OPA)   │
│  input:                     │
│    event    — the proposal  │
│    snapshot — session state │
│    manifest — permissions   │
└──────────────┬──────────────┘
               │
       ┌───────┴────────┐
       │                │
    allow            deny / require_approval
    + constraints    + reason code
```

The policy evaluates `TOOL_CALL_PROPOSED` events only. All other event types
pass through with `allow`.

### Decision Rules (in priority order)

The Rego policy evaluates rules in this order — the **first matching rule wins**:

1. **`PERMISSION_UNDECLARED`** — tool not listed in `manifest.permissions.tools`
2. **`EGRESS_DENY`** — network tool and destination not in `permissions.net.domains`
3. **`BUDGET_EXCEEDED`** — any budget counter has crossed its limit
4. **`LOOP_DETECTED`** — reducer flagged a loop or no-progress violation
5. **`TAINTED_TO_HIGH_RISK`** — session is tainted and tool is a high-risk sink
6. **`EXEC_DENY`** — exec tool and the specific binary is not in `permissions.exec.allowed_bins`
7. **`APPROVAL_REQUIRED`** — tool is in `manifest.permissions.approval_required`
8. **`allow`** — none of the above matched

### Constraints

When a decision is `allow`, the response also includes **constraints** that the
agent framework should enforce on the tool call:

```json
{
  "constraints": {
    "max_output_bytes": 1048576,
    "timeout_ms":       30000
  }
}
```

These values come from the manifest's budget limits and serve as runtime
guardrails even for allowed calls.

---

## Taint Tracking

Taint tracking is Aegis's primary defence against **prompt injection** — where
malicious content in a retrieved document, tool result, or memory read
attempts to exfiltrate data or run arbitrary commands.

### How Taint Propagates

When the reducer processes certain event types, it marks the session as
**tainted**:

- `TOOL_RESULT` — any tool output is considered untrusted
- `MEMORY_READ` — memory may contain adversarially-crafted content
- Taint propagates forward: once tainted, the session remains tainted until
  clean termination

When the session ends with a clean `TERMINATION` event, taint is cleared.

### High-Risk Sinks

When a session is tainted, the policy blocks calls to high-risk sinks:

| Sink prefix | Why it is high-risk |
|---|---|
| `exec` | Arbitrary code execution |
| `write_file`, `fs.write` | Filesystem writes |
| `db.write`, `database.write` | Database mutations |
| `net.post`, `net.put`, `net.patch`, `net.delete` | Destructive network calls |
| `mcp.https.post`, `mcp.https.put` | HTTP mutations via MCP |

### Sanitisation Bypass

When the agent framework explicitly sanitises a piece of content (e.g., escapes
it, validates it, or passes it through a safety filter), it can register a
`SanitizedText` event with a unique key. Subsequent tool calls carrying that
key as `sanitizer_key` in their payload bypass the taint block:

```
TOOL_RESULT received → session tainted
agent sanitises output → SanitizedText{key: "safe-k1"}
exec call with sanitizer_key: "safe-k1" → allowed
```

---

## Budget Enforcement

Every session has a budget, declared in the manifest. The reducer tracks
consumption, and the policy enforces limits:

| Budget | Default | Field |
|---|---|---|
| Max steps | 24 | `snapshot.steps_consumed` |
| Max tool calls | 12 | `snapshot.tool_calls_consumed` |
| Max wall time | 120,000 ms | `snapshot.wall_time_ms` |
| Max output bytes | 1,048,576 | Enforced as constraint |
| Timeout per tool | 30,000 ms | Enforced as constraint |

Budgets are declared per-manifest and can be tightened per deployment.

---

## Loop Detection

The loop detector (`pkg/loop`) watches for runaway agents before they exhaust
resources or enter infinite tool-call cycles.

Detection strategies:

| Strategy | Trigger | Action |
|---|---|---|
| Identical call | Same tool + identical args repeated ≥ 2× | Sets `loop_violation` |
| No progress | Snapshot hash unchanged for ≥ 3 consecutive steps | Sets `loop_violation` |
| Repeating sequence | Tool-name sequence of length 3–7 repeated twice | Sets `loop_violation` |

When `loop_violation` is set on the snapshot, the Rego policy returns
`LOOP_DETECTED` on the next `TOOL_CALL_PROPOSED`, stopping the agent.

The violation record includes a **cycle trace** (event sequence numbers) for
root-cause debugging.

---

## Deterministic Replay

Every session is replayable from its event log. Replay has two modes:

### Exact Replay

Tool results are read from the encrypted event log (AES-256-GCM). No external
calls are made. The snapshot hash at every step must be byte-identical to the
original run.

Use case: **CI regression testing** — prove that a policy change or code change
does not alter agent behaviour.

### Live Replay

Tool calls are re-executed against a live upstream. Results are diffed against
the recorded outputs.

Use case: **Model swap testing** — replace GPT-4o with a new model and see
exactly where behaviour diverges.

### DiffReport

Both modes produce a machine-readable `DiffReport`:

```json
{
  "session_id":     "sess-001",
  "mode":           "exact",
  "steps_replayed": 12,
  "identical":      true,
  "diffs":          []
}
```

---

## Telemetry

Aegis emits an OTel-compatible span for every ingested event, written to a
local NDJSON file by default. **No outbound network connections are made.**

Each span includes:
- `trace_id`, `span_id` — for correlation with your existing OTel stack
- `session_id`, `tenant_id`, `event_type`, `seq` — for filtering
- `attrs` — a redacted copy of the event payload

### PII Redaction

The redaction pipeline runs before every export and scrubs:

- Secret-bearing keys: `password`, `token`, `api_key`, `authorization`, `secret`, `credential`, `private_key`
- Email addresses → `[EMAIL]`
- Phone numbers → `[PHONE]`
- 32+ character hex strings (bearer tokens) → `[TOKEN]`
- All fields in nested maps are recursively redacted

The original event in the store is **never mutated** — redaction applies only
to the exported span copy.

### Zero-Egress Guarantee

Disabling Aegis telemetry (`--telemetry-disabled`) replaces the exporter with
a no-op. This **never** sets `OTEL_SDK_DISABLED` — your application's own OTel
spans continue to export normally.

---

## The Capability Manifest

Every agent skill is associated with an `aegis-manifest.json` that declares:

- Which **tools** it may call
- Which **network domains** it may reach
- Which **binaries** it may execute
- **Budget limits** (steps, tool calls, wall time, output size)
- Which tools require **human approval** before execution
- Whether a **sandbox** is required
- **Integrity** information (file hashes, Cosign signature)

This manifest is the contract between the skill publisher and the operator. It
is loaded at daemon startup and enforced at runtime for every tool call.

→ See [Capability Manifest](manifest.md) for the full field reference.

---

## The MCP Proxy

The MCP proxy (`pkg/proxy`) intercepts Model Context Protocol tool calls and
enforces the full Aegis pipeline before forwarding them upstream:

```
tools/call
    │
    ▼
TOOL_CALL_PROPOSED event
    │
    ▼
Policy evaluation
    ├─ allow     → TOOL_CALL_ALLOWED → upstream → TOOL_RESULT
    ├─ deny      → TOOL_CALL_DENIED  → JSON-RPC error -32000
    └─ approval  → APPROVAL_REQUESTED → JSON-RPC error -32001 + token
```

Two transport modes are supported:

- **stdio** — for local agent frameworks (pipe-based communication)
- **Streamable HTTP** — `POST /mcp` for requests, `GET /mcp` for SSE keepalive

---

## The Conformance Suite

The conformance suite provides portable, machine-verifiable assurance that an
aegisd deployment is behaving correctly. Conformance packs are YAML test
definitions executed against a live server.

→ See [Conformance Suite](conformance.md) for how to run packs and write your own.
