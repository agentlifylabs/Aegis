package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// baseManifest returns a minimal manifest with a read-only tool declared.
func baseManifest(tools ...string) map[string]any {
	return map[string]any{
		"schema":  "aegis.dev/manifest/v0.1",
		"name":    "test-skill",
		"version": "0.1.0",
		"permissions": map[string]any{
			"tools": tools,
			"budgets": map[string]any{
				"max_steps":      float64(24),
				"max_tool_calls": float64(12),
			},
			"net":              map[string]any{"domains": []any{}},
			"exec":             map[string]any{"allowed_bins": []any{}},
			"approval_required": []any{},
		},
	}
}

func emptySnapshot() map[string]any {
	return map[string]any{
		"total_events":    float64(0),
		"tool_call_count": float64(0),
		"taint_labels":    []any{},
	}
}

func toolEvent(toolName string) map[string]any {
	return map[string]any{
		"event_type": "TOOL_CALL_PROPOSED",
		"payload": map[string]any{
			"tool_name": toolName,
			"args":      map[string]any{},
		},
	}
}

func newEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := New()
	require.NoError(t, err)
	return e
}

// ── Epic 03 acceptance tests ──────────────────────────────────────────────────

func TestPolicy_ToolNotInManifest_Denied(t *testing.T) {
	e := newEngine(t)
	d, err := e.Evaluate(context.Background(), Input{
		Event:    toolEvent("write_file"),
		Snapshot: emptySnapshot(),
		Manifest: baseManifest("read_file"), // write_file NOT declared
	})
	require.NoError(t, err)
	assert.Equal(t, OutcomeDeny, d.Outcome)
	assert.Equal(t, ReasonPermissionUndeclared, d.Reason)
}

func TestPolicy_ToolInManifest_Allowed(t *testing.T) {
	e := newEngine(t)
	d, err := e.Evaluate(context.Background(), Input{
		Event:    toolEvent("read_file"),
		Snapshot: emptySnapshot(),
		Manifest: baseManifest("read_file"),
	})
	require.NoError(t, err)
	assert.Equal(t, OutcomeAllow, d.Outcome)
	assert.Equal(t, ReasonOK, d.Reason)
}

func TestPolicy_NetToolNotAllowlisted_Denied(t *testing.T) {
	e := newEngine(t)
	manifest := baseManifest("mcp.http")
	manifest["permissions"].(map[string]any)["net"] = map[string]any{
		"domains": []any{"api.notion.com"},
	}
	event := map[string]any{
		"event_type": "TOOL_CALL_PROPOSED",
		"payload": map[string]any{
			"tool_name": "mcp.http",
			"args":      map[string]any{"domain": "evil.example.com"},
		},
	}
	d, err := e.Evaluate(context.Background(), Input{
		Event:    event,
		Snapshot: emptySnapshot(),
		Manifest: manifest,
	})
	require.NoError(t, err)
	assert.Equal(t, OutcomeDeny, d.Outcome)
	assert.Equal(t, ReasonEgressDeny, d.Reason)
}

func TestPolicy_NetToolAllowlisted_Allowed(t *testing.T) {
	e := newEngine(t)
	manifest := baseManifest("mcp.http")
	manifest["permissions"].(map[string]any)["net"] = map[string]any{
		"domains": []any{"api.notion.com"},
	}
	event := map[string]any{
		"event_type": "TOOL_CALL_PROPOSED",
		"payload": map[string]any{
			"tool_name": "mcp.http",
			"args":      map[string]any{"domain": "api.notion.com"},
		},
	}
	d, err := e.Evaluate(context.Background(), Input{
		Event:    event,
		Snapshot: emptySnapshot(),
		Manifest: manifest,
	})
	require.NoError(t, err)
	assert.Equal(t, OutcomeAllow, d.Outcome)
}

func TestPolicy_WildcardDomain_Allowed(t *testing.T) {
	e := newEngine(t)
	manifest := baseManifest("mcp.https")
	manifest["permissions"].(map[string]any)["net"] = map[string]any{
		"domains": []any{"*.googleapis.com"},
	}
	event := map[string]any{
		"event_type": "TOOL_CALL_PROPOSED",
		"payload": map[string]any{
			"tool_name": "mcp.https",
			"args":      map[string]any{"domain": "storage.googleapis.com"},
		},
	}
	d, err := e.Evaluate(context.Background(), Input{
		Event:    event,
		Snapshot: emptySnapshot(),
		Manifest: manifest,
	})
	require.NoError(t, err)
	assert.Equal(t, OutcomeAllow, d.Outcome)
}

func TestPolicy_BudgetExceeded_Denied(t *testing.T) {
	e := newEngine(t)
	snap := map[string]any{
		"steps_consumed":      float64(25), // exceeds default max_steps=24
		"tool_calls_consumed": float64(0),
	}
	d, err := e.Evaluate(context.Background(), Input{
		Event:    toolEvent("read_file"),
		Snapshot: snap,
		Manifest: baseManifest("read_file"),
	})
	require.NoError(t, err)
	assert.Equal(t, OutcomeDeny, d.Outcome)
	assert.Equal(t, ReasonBudgetExceeded, d.Reason)
}

func TestPolicy_ApprovalRequired(t *testing.T) {
	e := newEngine(t)
	manifest := baseManifest("deploy")
	manifest["permissions"].(map[string]any)["approval_required"] = []any{"deploy"}
	d, err := e.Evaluate(context.Background(), Input{
		Event:    toolEvent("deploy"),
		Snapshot: emptySnapshot(),
		Manifest: manifest,
	})
	require.NoError(t, err)
	assert.Equal(t, OutcomeRequireApproval, d.Outcome)
	assert.Equal(t, ReasonApprovalRequired, d.Reason)
}

func TestPolicy_NonToolEvent_AlwaysAllowed(t *testing.T) {
	e := newEngine(t)
	event := map[string]any{
		"event_type": "MODEL_CALL_STARTED",
		"payload":    map[string]any{"model_id": "gpt-4o"},
	}
	d, err := e.Evaluate(context.Background(), Input{
		Event:    event,
		Snapshot: emptySnapshot(),
		Manifest: baseManifest(),
	})
	require.NoError(t, err)
	assert.Equal(t, OutcomeAllow, d.Outcome)
}

func TestPolicy_AllowDecisionHasConstraints(t *testing.T) {
	e := newEngine(t)
	d, err := e.Evaluate(context.Background(), Input{
		Event:    toolEvent("read_file"),
		Snapshot: emptySnapshot(),
		Manifest: baseManifest("read_file"),
	})
	require.NoError(t, err)
	assert.Equal(t, OutcomeAllow, d.Outcome)
	assert.NotNil(t, d.Constraints)
	assert.Contains(t, d.Constraints, "timeout_ms")
	assert.Contains(t, d.Constraints, "max_output_bytes")
}

func TestPolicy_ExecToolDeniedByDefault(t *testing.T) {
	e := newEngine(t)
	manifest := baseManifest("exec")
	manifest["permissions"].(map[string]any)["exec"] = map[string]any{
		"allowed_bins": []any{"/usr/bin/git"},
	}
	event := map[string]any{
		"event_type": "TOOL_CALL_PROPOSED",
		"payload": map[string]any{
			"tool_name": "exec",
			"args":      map[string]any{"bin": "/bin/bash"},
		},
	}
	d, err := e.Evaluate(context.Background(), Input{
		Event:    event,
		Snapshot: emptySnapshot(),
		Manifest: manifest,
	})
	require.NoError(t, err)
	assert.Equal(t, OutcomeDeny, d.Outcome)
	assert.Equal(t, ReasonExecDeny, d.Reason)
}
