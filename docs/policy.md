# Policy Reference

Aegis uses an embedded OPA/Rego policy to evaluate every `TOOL_CALL_PROPOSED` event before it is forwarded to the agent's tool executor.

---

## API

```bash
POST /v1/policy/decide
Content-Type: application/json

{
  "event":    { "event_type": "TOOL_CALL_PROPOSED", "payload": { "tool_name": "read_file", "call_id": "c1", "args": {} } },
  "snapshot": { "steps_consumed": 3, "tool_calls_consumed": 2, "wall_time_ms": 5000 },
  "manifest": { ... }
}
```

Response:

```json
{
  "outcome":     "allow",
  "reason":      "OK",
  "constraints": { "max_output_bytes": 1048576, "timeout_ms": 30000 }
}
```

---

## Outcomes

| Outcome | Meaning |
|---|---|
| `allow` | Tool call is permitted. Respect the `constraints` object. |
| `deny` | Tool call is blocked. The `reason` field explains why. |
| `require_approval` | Execution paused — a human must approve before proceeding. |

---

## Reason Codes

Rules are evaluated **in this order**. The first matching rule wins.

### 1. `PERMISSION_UNDECLARED`

The requested tool is not listed in `manifest.permissions.tools`.

**Fix:** add the tool name to `permissions.tools` in your manifest.

### 2. `EGRESS_DENY`

A network tool (`mcp.https`, `mcp.http`, `net`) was called with a domain not
listed in `manifest.permissions.net.domains`.

**Fix:** add the domain (or a `*.example.com` wildcard) to `permissions.net.domains`.

### 3. `BUDGET_EXCEEDED`

One of the session budget counters has crossed its limit:
- `snapshot.steps_consumed >= manifest.permissions.budgets.max_steps`
- `snapshot.tool_calls_consumed >= manifest.permissions.budgets.max_tool_calls`
- `snapshot.wall_time_ms >= manifest.permissions.budgets.max_wall_time_ms`

**Fix:** raise the budget in the manifest, or redesign the agent to be more efficient.

Default limits: `max_steps=24`, `max_tool_calls=12`, `max_wall_time_ms=120000`.

### 4. `LOOP_DETECTED`

`snapshot.loop_violation` is non-empty, meaning the loop detector flagged
repeated identical calls, a no-progress condition, or a repeating call sequence.

**Fix:** review the agent's logic for runaway loops; the violation includes a cycle trace.

### 5. `TAINTED_TO_HIGH_RISK`

The session is tainted (`snapshot.is_tainted == true`) and the requested tool
is a high-risk sink:

| Sink prefixes |
|---|
| `exec` · `write_file` · `fs.write` |
| `db.write` · `database.write` |
| `net.post` · `net.put` · `net.patch` · `net.delete` |
| `mcp.https.post` · `mcp.https.put` |

The session becomes tainted when any `TOOL_RESULT` or `MEMORY_READ` event is
processed. This prevents prompt injection attacks from escalating to destructive
actions.

**Fix:** explicitly sanitise the tainted content and register a `SanitizedText`
event, then pass `sanitizer_key` in the tool call payload.

### 6. `EXEC_DENY`

The `exec` tool was called but the specific binary (`payload.args.bin`) is not
listed in `manifest.permissions.exec.allowed_bins`.

**Fix:** add the binary path to `permissions.exec.allowed_bins`. Declaring `exec`
in `permissions.tools` is necessary but not sufficient — each binary must be
individually allowlisted.

### 7. `APPROVAL_REQUIRED`

The tool is listed in `manifest.permissions.approval_required`. Execution is
paused. A human must call `aegisctl approve <token> --allow` or `--deny`.

### 8. `OK` (allow)

No rule matched — the call is permitted.

---

## The `constraints` Object

When outcome is `allow`, the response includes constraints the framework must
enforce:

| Constraint | Source | Default |
|---|---|---|
| `max_output_bytes` | `manifest.permissions.budgets.max_output_bytes` | 1,048,576 |
| `timeout_ms` | `manifest.permissions.budgets.timeout_ms` | 30,000 |

---

## Non-`TOOL_CALL_PROPOSED` Events

All event types other than `TOOL_CALL_PROPOSED` pass through with
`{"outcome": "allow", "reason": "OK", "constraints": {}}`. The policy only
gates tool proposals.

---

## Customising the Policy

The embedded Rego bundle lives at `pkg/policy/bundle/aegis/decide.rego`. It is
compiled into the binary at build time via `go:embed`.

The canonical reference copy is also at `policies/aegis/decide.rego`.

### Adding a Custom Rule

To add custom logic (e.g., tenant-specific tool blocklists), edit
`decide.rego` and add an `else` clause before the final `allow` case:

```rego
} else := {"outcome": "deny", "reason": "CUSTOM_DENY", "constraints": {}} if {
    input.event.event_type == "TOOL_CALL_PROPOSED"
    _my_custom_condition
}
```

Then define `_my_custom_condition` as a helper rule.

After editing, rebuild: `make build` and re-run tests: `make test`.

### Testing Policy Changes

Use the conformance suite to validate changes do not break existing guarantees:

```bash
make test
# includes pkg/policy/... unit tests and integration/... end-to-end tests
```

---

## Rego Input Shape

The complete input document passed to the policy:

```json
{
  "event": {
    "event_type": "TOOL_CALL_PROPOSED",
    "payload": {
      "tool_name":    "exec",
      "call_id":      "c5",
      "args":         { "bin": "/usr/bin/git" },
      "sanitizer_key": ""
    }
  },
  "snapshot": {
    "steps_consumed":      5,
    "tool_calls_consumed": 3,
    "wall_time_ms":        12000,
    "loop_violation":      "",
    "is_tainted":          false,
    "sanitized_keys":      []
  },
  "manifest": {
    "schema":    "aegis.dev/manifest/v0.1",
    "name":      "my-skill",
    "version":   "1.0.0",
    "publisher": "acme",
    "permissions": {
      "tools":            ["exec"],
      "net":              { "domains": [] },
      "exec":             { "allowed_bins": ["/usr/bin/git"] },
      "approval_required": [],
      "budgets": {
        "max_steps": 24, "max_tool_calls": 12, "max_wall_time_ms": 120000,
        "max_output_bytes": 1048576, "timeout_ms": 30000
      }
    },
    "sandbox":   { "required": true },
    "integrity": {}
  }
}
```
