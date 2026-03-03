# Getting Started with Aegis

This guide takes you from zero to a running Aegis daemon with your first event
ingested, a policy decision evaluated, and a hash chain verified — in under
ten minutes.

---

## Prerequisites

| Dependency | Version | Notes |
|---|---|---|
| Go | 1.22+ | `go version` |
| gcc / clang | any | Required for SQLite CGo bindings |
| Python | 3.11+ | Optional — only needed for the Python SDK |
| Docker + Compose | any | Optional — only needed for container deployment |

---

## 1. Build

```bash
git clone https://github.com/aegis-framework/aegis.git
cd aegis

make build
# Produces: bin/aegisd   bin/aegisctl
```

---

## 2. Start the daemon

For local development, no manifest or config file is required:

```bash
./bin/aegisd --addr :8080
# aegisd listening on :8080
```

You can confirm it is running:

```bash
curl http://localhost:8080/healthz
# {"status":"ok"}

curl http://localhost:8080/readyz
# {"status":"ok"}
```

---

## 3. Ingest your first event

Every agent action is recorded as a sealed, hash-chained **envelope**. The
simplest event is a `TOOL_CALL_PROPOSED` at sequence 0 (the start of a session):

```bash
curl -s -X POST http://localhost:8080/v1/events \
  -H 'Content-Type: application/json' \
  -d '{
    "tenant_id":  "acme",
    "session_id": "sess-001",
    "seq":        0,
    "ts_unix_ms": 1700000000000,
    "event_type": "TOOL_CALL_PROPOSED",
    "payload": {
      "tool_name": "read_file",
      "call_id":   "c1",
      "args":      {"path": "/workspace/data.csv"}
    }
  }'
```

Response:

```json
{"seq": 0, "hash": "a3f2..."}
```

The `hash` is the SHA-256 of the RFC 8785 canonical JSON of this event.
Subsequent events in the same session must supply `prev_hash` equal to this
value to maintain chain integrity.

---

## 4. Evaluate a policy decision

Before executing a tool call, ask aegisd whether it is permitted:

```bash
curl -s -X POST http://localhost:8080/v1/policy/decide \
  -H 'Content-Type: application/json' \
  -d '{
    "event": {
      "event_type": "TOOL_CALL_PROPOSED",
      "payload": {"tool_name": "read_file", "call_id": "c1", "args": {}}
    },
    "snapshot": {
      "steps_consumed":      3,
      "tool_calls_consumed": 2,
      "wall_time_ms":        5000
    },
    "manifest": {
      "schema":    "aegis.dev/manifest/v0.1",
      "name":      "my-skill",
      "version":   "0.1.0",
      "publisher": "acme",
      "permissions": {
        "tools":   ["read_file"],
        "budgets": {"max_steps": 24, "max_tool_calls": 12, "max_wall_time_ms": 120000}
      },
      "sandbox":   {"required": false},
      "integrity": {}
    }
  }'
```

Response when allowed:

```json
{
  "outcome": "allow",
  "reason":  "OK",
  "constraints": {
    "max_output_bytes": 1048576,
    "timeout_ms":       30000
  }
}
```

Response when denied (tool not declared):

```json
{"outcome": "deny", "reason": "PERMISSION_UNDECLARED", "constraints": {}}
```

→ See [Policy Reference](policy.md) for all possible outcomes and reason codes.

---

## 5. List events

Retrieve all events for a session:

```bash
curl "http://localhost:8080/v1/events?tenant_id=acme&session_id=sess-001"
```

```json
{
  "Events": [
    {
      "tenant_id":  "acme",
      "session_id": "sess-001",
      "seq":        0,
      "event_type": "TOOL_CALL_PROPOSED",
      ...
    }
  ],
  "NextToken": ""
}
```

---

## 6. Verify the hash chain

After ingesting events, verify chain integrity end-to-end:

```bash
curl "http://localhost:8080/v1/sessions/sess-001/verify?tenant_id=acme"
```

```json
{"valid": true, "first_bad_seq": 0, "error": ""}
```

If any event has been tampered with, `valid` is `false` and `first_bad_seq`
points to the first broken link.

Or use `aegisctl`:

```bash
./bin/aegisctl verify --tenant-id acme --session-id sess-001 \
  --server http://localhost:8080
```

---

## 7. Using a manifest file

Create `aegis-manifest.json`:

```json
{
  "schema":    "aegis.dev/manifest/v0.1",
  "name":      "my-research-skill",
  "version":   "1.0.0",
  "publisher": "acme-corp",
  "permissions": {
    "tools":   ["read_file", "mcp.https"],
    "net":     {"domains": ["api.openai.com", "*.wikipedia.org"]},
    "budgets": {
      "max_steps":        24,
      "max_tool_calls":   12,
      "max_wall_time_ms": 120000
    }
  },
  "sandbox":   {"required": true},
  "integrity": {}
}
```

Validate it:

```bash
./bin/aegisctl manifest validate aegis-manifest.json
# OK
```

Start aegisd with the manifest loaded:

```bash
./bin/aegisd --manifest aegis-manifest.json --addr :8080
```

→ See [Capability Manifest](manifest.md) for the full field reference.

---

## 8. Using aegis.yaml (optional)

Instead of passing every flag on the command line, use a config file:

```yaml
# aegis.yaml
dsn:        "file:aegis.db?mode=rwc&cache=shared&_journal_mode=WAL"
addr:       ":8080"
manifest:   "aegis-manifest.json"
trust_mode: "dev"

telemetry:
  path: "/tmp/aegis-traces.ndjson"

log:
  level:  "info"
  format: "text"
```

```bash
./bin/aegisd --config aegis.yaml
```

CLI flags always override file values.

---

## 9. Python SDK quick-start

Install the SDK:

```bash
pip install -e python/
```

Send events and verify the chain:

```python
from aegis_sdk import Builder, EventType, AegisClient

client  = AegisClient("http://localhost:8080")
builder = Builder(tenant_id="acme", user_id="u1", session_id="sess-py-001")

# Append a sealed event
e = builder.append(EventType.TOOL_CALL_PROPOSED, {
    "tool_name": "read_file",
    "call_id":   "c1",
    "args":      {"path": "/workspace/data.csv"},
})
client.append_event(e)

# Verify chain integrity
result = client.verify_chain("acme", "sess-py-001")
assert result["valid"]
```

→ See [Python SDK](python-sdk.md) for the full reference.

---

## Next Steps

- **[Core Concepts](concepts.md)** — understand the event model, policy engine, taint tracking, and replay
- **[Capability Manifest](manifest.md)** — learn how to declare exactly what your agent is allowed to do
- **[Policy Reference](policy.md)** — understand every decision rule and reason code
- **[Hardening Guide](hardening.md)** — TLS, production deployment, secrets management
