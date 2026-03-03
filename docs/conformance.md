# Conformance Suite

The Aegis conformance suite provides portable, machine-verifiable assurance
that an `aegisd` deployment enforces the correct security properties. Tests are
defined in YAML, run against a live server, and produce a JSON compliance
report with per-requirement evidence.

---

## Quick Start

```bash
# Run all conformance tests against a local aegisd
go test -race ./conformance/... -v -timeout 60s

# Or via make
make conformance
```

---

## Conformance Packs

A **pack** is a named YAML file containing a set of test cases, each tied to a
requirement ID. Six packs ship with Aegis v0.1:

| Pack | File | Requirements | Coverage |
|---|---|---|---|
| `baseline-safety` | `conformance/packs/baseline-safety.yaml` | SEC-001…005 | Deny-by-default, budget, egress |
| `prompt-injection` | `conformance/packs/prompt-injection.yaml` | TI-001…003 | Taint-to-high-risk-sink blocking |
| `path-traversal` | `conformance/packs/path-traversal.yaml` | FS-001…003 | fs.write, write_file, db.write denial |
| `telemetry-no-egress` | `conformance/packs/telemetry-no-egress.yaml` | OBS-001…002 | Policy stability with telemetry fields |
| `replay-determinism` | `conformance/packs/replay-determinism.yaml` | REP-001…003 | Identical outcomes on replay |
| `handoff-correctness` | `conformance/packs/handoff-correctness.yaml` | HND-001…003 | Budget accumulation, tainted handoff |

---

## Test Case Format

Each test case is a YAML document specifying a policy request and an expected
outcome:

```yaml
name: baseline-safety
description: Core deny-by-default safety requirements for all Aegis deployments.
version: "0.1"
tests:
  - id: BS-001
    pack: baseline-safety
    req_id: SEC-001
    description: Undeclared tool is denied
    request:
      event:
        event_type: TOOL_CALL_PROPOSED
        payload:
          tool_name: write_file
          call_id:   t1
          args:      {}
      snapshot: {}
      manifest:
        schema:    "aegis.dev/manifest/v0.1"
        name:      test-skill
        version:   "0.1.0"
        publisher: acme
        permissions:
          tools:   ["read_file"]   # write_file is NOT declared
          budgets: {}
        sandbox:   { required: false }
        integrity: {}
    expect:
      outcome: deny
      reason:  PERMISSION_UNDECLARED
```

### Test Case Fields

| Field | Required | Description |
|---|---|---|
| `id` | ✅ | Unique identifier within the pack (e.g. `BS-001`) |
| `pack` | ✅ | Pack name — must match the pack's `name` field |
| `req_id` | ✅ | Requirement ID this test verifies (e.g. `SEC-001`) |
| `description` | ✅ | Human-readable description |
| `request.event` | ✅ | The event to evaluate (mirrors `POST /v1/policy/decide` body) |
| `request.snapshot` | ✅ | Session snapshot state |
| `request.manifest` | ✅ | Capability manifest to evaluate against |
| `expect.outcome` | ✅ | Expected outcome: `allow`, `deny`, or `require_approval` |
| `expect.reason` | | Optional reason code substring to match |

---

## Running Packs Programmatically

Use the `conformance` package directly from Go:

```go
import (
    "context"
    "encoding/json"
    "os"

    "github.com/aegis-framework/aegis/conformance"
)

// Load a pack from a YAML file
f, _ := os.Open("conformance/packs/baseline-safety.yaml")
pack, _ := conformance.LoadPack(f)

// Run against a live aegisd
runner := &conformance.Runner{AegisdAddr: "http://localhost:8080"}
report, _ := runner.Run(context.Background(), pack)

// Print the machine-readable report
enc := json.NewEncoder(os.Stdout)
enc.SetIndent("", "  ")
enc.Encode(report)
```

---

## The Compliance Report

Each run produces a `Report` struct (serialised as JSON):

```json
{
  "pack":         "baseline-safety",
  "aegisd_addr":  "http://localhost:8080",
  "run_at":       "2026-03-01T12:00:00Z",
  "total_tests":  5,
  "passed":       5,
  "failed":       0,
  "skipped":      0,
  "compliant":    true,
  "violated_reqs": [],
  "badge_markdown": "![Aegis baseline-safety: compliant](https://img.shields.io/badge/aegis%20baseline--safety-compliant-brightgreen)",
  "results": [
    {
      "id":          "BS-001",
      "pack":        "baseline-safety",
      "req_id":      "SEC-001",
      "description": "Undeclared tool is denied",
      "status":      "PASS",
      "outcome":     "deny",
      "reason":      "PERMISSION_UNDECLARED",
      "expected":    { "outcome": "deny", "reason": "PERMISSION_UNDECLARED" },
      "evidence":    { "outcome": "deny", "reason": "PERMISSION_UNDECLARED" }
    }
  ]
}
```

### Report Fields

| Field | Description |
|---|---|
| `compliant` | `true` if all tests passed |
| `violated_reqs` | List of requirement IDs for failed tests |
| `badge_markdown` | Paste into your README — automatically updates on each run |
| `results[].status` | `PASS`, `FAIL`, or `SKIP` |
| `results[].evidence` | The actual response from aegisd for comparison |

---

## Writing a Custom Pack

Create a YAML file with the same structure. You can test any combination of
event types, snapshots, and manifest configurations.

### Example: custom data-egress pack

```yaml
name: data-egress-controls
description: Verify that sensitive data domains are blocked.
version: "0.1"
tests:
  - id: DE-001
    pack: data-egress-controls
    req_id: DATA-001
    description: Calls to competitor domain are blocked
    request:
      event:
        event_type: TOOL_CALL_PROPOSED
        payload:
          tool_name: mcp.https
          call_id:   t1
          args:
            domain: competitor.example.com
      snapshot:
        steps_consumed: 1
        tool_calls_consumed: 1
        wall_time_ms: 500
      manifest:
        schema:    "aegis.dev/manifest/v0.1"
        name:      my-skill
        version:   "0.1.0"
        publisher: acme
        permissions:
          tools: ["mcp.https"]
          net:
            domains: ["api.openai.com"]   # competitor.example.com NOT listed
          budgets:
            max_steps: 24
            max_tool_calls: 12
            max_wall_time_ms: 120000
        sandbox:   { required: true }
        integrity: {}
    expect:
      outcome: deny
      reason:  EGRESS_DENY

  - id: DE-002
    pack: data-egress-controls
    req_id: DATA-002
    description: Calls to approved domain are allowed
    request:
      event:
        event_type: TOOL_CALL_PROPOSED
        payload:
          tool_name: mcp.https
          call_id:   t2
          args:
            domain: api.openai.com
      snapshot:
        steps_consumed: 1
        tool_calls_consumed: 1
        wall_time_ms: 500
      manifest:
        schema:    "aegis.dev/manifest/v0.1"
        name:      my-skill
        version:   "0.1.0"
        publisher: acme
        permissions:
          tools: ["mcp.https"]
          net:
            domains: ["api.openai.com"]
          budgets:
            max_steps: 24
            max_tool_calls: 12
            max_wall_time_ms: 120000
        sandbox:   { required: true }
        integrity: {}
    expect:
      outcome: allow
```

Then run it:

```go
f, _ := os.Open("my-org/packs/data-egress-controls.yaml")
pack, _ := conformance.LoadPack(f)
runner := &conformance.Runner{AegisdAddr: "http://localhost:8080"}
report, _ := runner.Run(ctx, pack)
```

---

## CI Integration

Add a conformance step to your GitHub Actions workflow:

```yaml
- name: Start aegisd
  run: ./bin/aegisd --addr :8080 &
  env:
    AEGIS_ENV: test

- name: Wait for aegisd to be ready
  run: |
    for i in $(seq 1 10); do
      curl -sf http://localhost:8080/healthz && break || sleep 1
    done

- name: Run conformance suite
  run: go test -race ./conformance/... -v -timeout 60s
```

---

## Badge

Paste the `badge_markdown` from the report output into your README to show
compliance status at a glance:

```markdown
![Aegis baseline-safety: compliant](https://img.shields.io/badge/aegis%20baseline--safety-compliant-brightgreen)
```
