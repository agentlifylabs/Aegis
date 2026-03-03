package aegis.decide

import rego.v1

# ── entrypoint ────────────────────────────────────────────────────────────────

# decision is the primary output consumed by the policy engine.
# Result: {"outcome": "allow"|"deny"|"require_approval", "reason": <code>, "constraints": {...}}
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
} else := {"outcome": "deny", "reason": "EXEC_DENY", "constraints": {}} if {
	input.event.event_type == "TOOL_CALL_PROPOSED"
	_is_exec_tool
	not _exec_allowed
} else := {"outcome": "deny", "reason": "BUDGET_EXCEEDED", "constraints": {}} if {
	input.event.event_type == "TOOL_CALL_PROPOSED"
	not _budget_ok
} else := {"outcome": "require_approval", "reason": "APPROVAL_REQUIRED", "constraints": {}} if {
	input.event.event_type == "TOOL_CALL_PROPOSED"
	_requires_approval
} else := {"outcome": "allow", "reason": "OK", "constraints": _constraints} if {
	input.event.event_type == "TOOL_CALL_PROPOSED"
}

# Non-tool events are always allowed through (policy only gates ToolCallProposed).
_evaluate := {"outcome": "allow", "reason": "OK", "constraints": {}} if {
	input.event.event_type != "TOOL_CALL_PROPOSED"
}

# ── helper rules ──────────────────────────────────────────────────────────────

_tool_name := input.event.payload.tool_name

_declared_tools := {t | t := input.manifest.permissions.tools[_]}

_tool_declared if {
	_tool_name in _declared_tools
}

# effectful tool categories
_effectful_tools := {"exec", "fs.write", "mcp.http", "mcp.https", "net"}

is_effectful_tool if {
	some t in _effectful_tools
	startswith(_tool_name, t)
}

_net_tools := {"mcp.http", "mcp.https", "net"}

_is_net_tool if {
	some t in _net_tools
	startswith(_tool_name, t)
}

_is_exec_tool if {
	startswith(_tool_name, "exec")
}

# net allowlist from manifest
_allowed_domains := {d | d := input.manifest.permissions.net.domains[_]}

_net_allowed if {
	some domain in _allowed_domains
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

# exec allowlist
_allowed_bins := {b | b := input.manifest.permissions.exec.allowed_bins[_]}

_exec_allowed if {
	some bin in _allowed_bins
	bin == input.event.payload.args.bin
}

# budgets
_max_steps := object.get(input.manifest, ["permissions", "budgets", "max_steps"], 24)
_max_tool_calls := object.get(input.manifest, ["permissions", "budgets", "max_tool_calls"], 12)

_budget_ok if {
	input.snapshot.total_events < _max_steps
	input.snapshot.tool_call_count < _max_tool_calls
}

# approval-required tools
_approval_tools := {t | t := input.manifest.permissions.approval_required[_]}

_requires_approval if {
	_tool_name in _approval_tools
}

is_tainted_arg if {
	some label in input.snapshot.taint_labels
	some v in input.event.payload.args
	contains(v, label)
}

within_fs_roots(path) if {
	some root in input.manifest.permissions.fs.write_roots
	startswith(path, root)
}

# output constraints bundled with allow decisions
_constraints := {
	"max_output_bytes": object.get(input.manifest, ["permissions", "budgets", "max_output_bytes"], 1048576),
	"timeout_ms":       object.get(input.manifest, ["permissions", "budgets", "timeout_ms"], 30000),
}
