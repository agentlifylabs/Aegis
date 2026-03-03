# Aegis — Agent Control Plane

> **Deny-by-default. Tamper-evident. Deterministically replayable.**

Aegis is an open-source control plane that sits between your AI agent framework and the outside world. It enforces least-privilege capability policies, builds a cryptographically-linked audit log of every agent action, and makes every run deterministically replayable for debugging and compliance.

```
Your Agent Framework
        │
        │  tool calls, model calls, memory reads
        ▼
  ┌───────────┐    policy decision    ┌──────────────────────┐
  │  aegisd   │──────────────────────▶│  Rego policy engine  │
  │  daemon   │◀──────────────────────│  (embedded OPA)      │
  └─────┬─────┘   allow / deny        └──────────────────────┘
        │
        │  sealed, hash-chained events
        ▼
  ┌─────────────┐
  │  Event log  │  SQLite (dev) · PostgreSQL (prod)
  │  (append-   │
  │   only)     │
  └─────────────┘
        ▲
  aegisctl CLI  ·  Python SDK
```

## What Aegis Does

| Problem                                      | How Aegis Solves It                             |
| -------------------------------------------- | ----------------------------------------------- |
| Agent calls an undeclared tool               | Denied — `PERMISSION_UNDECLARED`                |
| Agent exhausts compute budget                | Denied — `BUDGET_EXCEEDED`                      |
| Agent enters a tool-call loop                | Denied — `LOOP_DETECTED`                        |
| Prompt injection flows to `exec`             | Denied — `TAINTED_TO_HIGH_RISK`                 |
| Agent calls an unapproved destructive action | Paused — `APPROVAL_REQUIRED`                    |
| "What did the agent actually do?"            | Deterministic replay from event log             |
| Compliance audit                             | Tamper-evident hash chain + conformance reports |

## Documentation

| Document                                       | Description                                                   |
| ---------------------------------------------- | ------------------------------------------------------------- |
| **[Getting Started](docs/getting-started.md)** | Install, run your first server, send your first event         |
| **[Core Concepts](docs/concepts.md)**          | Event model, policy engine, taint tracking, replay, telemetry |
| **[Capability Manifest](docs/manifest.md)**    | How to declare what your agent is allowed to do               |
| **[Policy Reference](docs/policy.md)**         | All decision rules, reason codes, and how to customise policy |
| **[Conformance Suite](docs/conformance.md)**   | Run compliance tests, write custom packs, read reports        |
| **[Python SDK](docs/python-sdk.md)**           | Send events and query aegisd from Python                      |
| **[Hardening Guide](docs/hardening.md)**       | TLS, mTLS, reverse proxy, OS hardening, secrets               |
| **[Backup & Restore](docs/backup-restore.md)** | SQLite and PostgreSQL backup procedures                       |

## Quick Start

**Prerequisites:** Go 1.22+, `gcc` (SQLite CGo), Python 3.11+ (optional SDK).

```bash
# 1. Build
make build

# 2. Start aegisd (SQLite, dev mode — no manifest required)
./bin/aegisd --addr :8080

# 3. Send a test event
curl -s -X POST http://localhost:8080/v1/events \
  -H 'Content-Type: application/json' \
  -d '{
    "tenant_id": "acme",
    "session_id": "sess-001",
    "seq": 0,
    "ts_unix_ms": 1700000000000,
    "event_type": "TOOL_CALL_PROPOSED",
    "payload": {"tool_name": "read_file", "call_id": "c1", "args": {}}
  }'

# 4. Check the daemon health
curl http://localhost:8080/healthz
curl http://localhost:8080/readyz
```

→ See [Getting Started](docs/getting-started.md) for the full walkthrough including policy decisions and chain verification.

## Capability Manifest

Every agent skill declares its permissions in an `aegis-manifest.json` file. Aegis enforces this at runtime — any tool not listed is denied.

```json
{
  "schema": "aegis.dev/manifest/v0.1",
  "name": "my-research-skill",
  "version": "1.0.0",
  "publisher": "acme-corp",
  "permissions": {
    "tools": ["read_file", "mcp.https"],
    "net": {
      "domains": ["api.openai.com", "*.wikipedia.org"]
    },
    "budgets": {
      "max_steps": 24,
      "max_tool_calls": 12,
      "max_wall_time_ms": 120000
    }
  },
  "sandbox": { "required": true },
  "integrity": {}
}
```

→ See [Capability Manifest](docs/manifest.md) for the full field reference.

## Policy Decisions

Ask aegisd whether a tool call is allowed against a live session snapshot:

```bash
curl -s -X POST http://localhost:8080/v1/policy/decide \
  -H 'Content-Type: application/json' \
  -d '{
    "event": {
      "event_type": "TOOL_CALL_PROPOSED",
      "payload": {"tool_name": "read_file", "call_id": "c2", "args": {}}
    },
    "snapshot": {"steps_consumed": 3, "tool_calls_consumed": 2, "wall_time_ms": 5000},
    "manifest": { ... }
  }'
```

```json
{
  "outcome": "allow",
  "reason": "OK",
  "constraints": { "max_output_bytes": 1048576, "timeout_ms": 30000 }
}
```

→ See [Policy Reference](docs/policy.md) for all decision rules and reason codes.

## Deployment

### Docker Compose (recommended)

```bash
# Local development (SQLite)
make docker-dev

# Production (PostgreSQL, aegisd bound to 127.0.0.1 behind a TLS proxy)
make docker-prod
```

### aegis.yaml config file

```yaml
dsn: 'file:/var/lib/aegis/aegis.db?mode=rwc&cache=shared&_journal_mode=WAL'
addr: ':8080'
trust_mode: 'prod'
manifest: '/etc/aegis/aegis-manifest.json'
rate_limit: 120

telemetry:
  path: '/var/lib/aegis/traces.ndjson'

log:
  level: 'info'
  format: 'json'
```

```bash
./bin/aegisd --config /etc/aegis/aegis.yaml
```

CLI flags always override file values.

### systemd

```bash
sudo cp deploy/aegisd.service /etc/systemd/system/aegisd.service
sudo systemctl daemon-reload && sudo systemctl enable --now aegisd
```

→ See [Hardening Guide](docs/hardening.md) for TLS, mTLS, and production checklists.

## Repo Layout

```
cmd/aegisd/          daemon binary
cmd/aegisctl/        CLI (verify, export, manifest commands)
internal/config/     aegis.yaml loader
internal/server/     HTTP API handlers
pkg/canon/           RFC 8785 canonical JSON + SHA-256 hashing
pkg/eventlog/        Envelope, hash chain, event type constants
pkg/policy/          OPA/Rego policy engine
pkg/policy/bundle/   Embedded Rego bundle (decide.rego)
pkg/manifest/        Capability manifest loader, validator, integrity verifier
pkg/proxy/           MCP proxy (stdio + Streamable HTTP)
pkg/loop/            Loop detector + budget guard
pkg/approval/        Approval router (HMAC tokens, staged decisions)
pkg/taint/           Taint tracker (prompt-injection controls)
pkg/replay/          Deterministic replay (Recorder, Replayer, DiffReport)
pkg/telemetry/       NDJSON span exporter, PII redactor
pkg/openclaw/        OpenClaw adapter + bad-pattern scanner
pkg/store/           EventStore interface
pkg/store/sqlite/    SQLite adapter
pkg/store/postgres/  PostgreSQL adapter
pkg/store/reducer/   Snapshot reducer
conformance/         Conformance suite runner + YAML packs
conformance/packs/   baseline-safety, prompt-injection, path-traversal, …
integration/         End-to-end integration tests
deploy/              docker-compose files, systemd unit, config templates
docs/                User documentation
policies/aegis/      Canonical Rego bundle (reference copy)
python/aegis_sdk/    Python SDK (canon, envelope, HTTP client)
```

## Running Tests

```bash
make test                 # all Go tests (unit + integration + config)
make integration          # integration suite only
make python-test          # Python SDK tests
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

*Built with the principle that agent safety is an infrastructure problem, not an afterthought.*
