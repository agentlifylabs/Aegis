package aegis.decide

import rego.v1

# ── entrypoint ────────────────────────────────────────────────────────────────

decision := result if {
	result := _evaluate
}

_evaluate := {"outcome": "deny", "reason": "PERMISSION_UNDECLARED", "constraints": {}} if {
	input.event.event_type == "TOOL_CALL_PROPOSED"
	not _tool_declared
} else := {"outcome": "deny", "reason": "EGRESS_DENY", "constraints": {}} if {
	input.event.event_type == "TOOL_CALL_PROPOSED"
	_is_net_tool
	not _net_allowed
} else := {"outcome": "deny", "reason": "BUDGET_EXCEEDED", "constraints": {}} if {
	input.event.event_type == "TOOL_CALL_PROPOSED"
	not _budget_ok
} else := {"outcome": "deny", "reason": "LOOP_DETECTED", "constraints": {}} if {
	input.event.event_type == "TOOL_CALL_PROPOSED"
	_loop_detected
} else := {"outcome": "deny", "reason": "TAINTED_TO_HIGH_RISK", "constraints": {}} if {
	input.event.event_type == "TOOL_CALL_PROPOSED"
	_tainted_high_risk_sink
} else := {"outcome": "deny", "reason": "EXEC_DENY", "constraints": {}} if {
	input.event.event_type == "TOOL_CALL_PROPOSED"
	_is_exec_tool
	not _exec_allowed
} else := {"outcome": "require_approval", "reason": "APPROVAL_REQUIRED", "constraints": {}} if {
	input.event.event_type == "TOOL_CALL_PROPOSED"
	_requires_approval
} else := {"outcome": "allow", "reason": "OK", "constraints": _constraints} if {
	input.event.event_type == "TOOL_CALL_PROPOSED"
}

_evaluate := {"outcome": "allow", "reason": "OK", "constraints": {}} if {
	input.event.event_type != "TOOL_CALL_PROPOSED"
}

# ── helpers ───────────────────────────────────────────────────────────────────

_tool_name := input.event.payload.tool_name

_declared_tools contains t if {
	t := input.manifest.permissions.tools[_]
}

_tool_declared if {
	_tool_name in _declared_tools
}

_net_tools := {"mcp.http", "mcp.https", "net"}

_is_net_tool if {
	some t in _net_tools
	startswith(_tool_name, t)
}

_is_exec_tool if {
	startswith(_tool_name, "exec")
}

_net_allowed if {
	some domain in input.manifest.permissions.net.domains
	_domain_matches(domain, input.event.payload.args.domain)
}

_domain_matches(pattern, candidate) if {
	not startswith(pattern, "*")
	pattern == candidate
}

_domain_matches(pattern, candidate) if {
	startswith(pattern, "*.")
	suffix := substring(pattern, 1, -1)
	endswith(candidate, suffix)
}

_exec_allowed if {
	some bin in input.manifest.permissions.exec.allowed_bins
	bin == input.event.payload.args.bin
}

# Budget: read from snapshot reducer fields (steps_consumed, tool_calls_consumed, wall_time_ms).
_max_steps      := object.get(input.manifest, ["permissions", "budgets", "max_steps"], 24)
_max_tool_calls := object.get(input.manifest, ["permissions", "budgets", "max_tool_calls"], 12)
_max_wall_ms    := object.get(input.manifest, ["permissions", "budgets", "max_wall_time_ms"], 120000)

_budget_ok if {
	object.get(input.snapshot, "steps_consumed", 0) < _max_steps
	object.get(input.snapshot, "tool_calls_consumed", 0) < _max_tool_calls
	object.get(input.snapshot, "wall_time_ms", 0) < _max_wall_ms
}

# ── Loop / no-progress guard (Epic 06) ───────────────────────────────────────
# The reducer sets snapshot.loop_violation when a loop is detected.
_loop_detected if {
	input.snapshot.loop_violation != null
	input.snapshot.loop_violation != ""
}

# ── Taint / prompt-injection guard (Epic 08) ─────────────────────────────────

_high_risk_sink_prefixes := [
	"exec", "fs.write", "write_file",
	"db.write", "database.write",
	"net.post", "net.put", "net.patch", "net.delete",
	"mcp.https.post", "mcp.https.put",
]

_is_high_risk_sink if {
	some prefix in _high_risk_sink_prefixes
	startswith(_tool_name, prefix)
}

_context_is_tainted if {
	object.get(input.snapshot, "is_tainted", false) == true
}

_sanitizer_key := object.get(input.event.payload, "sanitizer_key", "")

_sanitized if {
	_sanitizer_key != ""
	some k in object.get(input.snapshot, "sanitized_keys", [])
	k == _sanitizer_key
}

_tainted_high_risk_sink if {
	_is_high_risk_sink
	_context_is_tainted
	not _sanitized
}

# ── Approval ──────────────────────────────────────────────────────────────────

_requires_approval if {
	_tool_name in input.manifest.permissions.approval_required
}

_constraints := {
	"max_output_bytes": object.get(input.manifest, ["permissions", "budgets", "max_output_bytes"], 1048576),
	"timeout_ms":       object.get(input.manifest, ["permissions", "budgets", "timeout_ms"], 30000),
}
