package taint

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Label management ──────────────────────────────────────────────────────────

func TestAddLabel_Idempotent(t *testing.T) {
	tr := New()
	tr.AddLabel(LabelToolOutput)
	tr.AddLabel(LabelToolOutput)
	assert.Len(t, tr.ActiveLabels, 1)
}

func TestIsTainted_EmptyIsFalse(t *testing.T) {
	assert.False(t, New().IsTainted())
}

func TestIsTainted_TrueAfterLabel(t *testing.T) {
	tr := New()
	tr.AddLabel(LabelUserInput)
	assert.True(t, tr.IsTainted())
}

// ── Sanitization ──────────────────────────────────────────────────────────────

func TestSanitization_KeyRecorded(t *testing.T) {
	tr := New()
	tr.AddLabel(LabelToolOutput)
	tr.RecordSanitization("call-42")
	assert.True(t, tr.IsSanitized("call-42"))
}

func TestSanitization_IdempotentKey(t *testing.T) {
	tr := New()
	tr.RecordSanitization("k1")
	tr.RecordSanitization("k1")
	assert.Len(t, tr.SanitizedKeys, 1)
}

// ── CheckSink ─────────────────────────────────────────────────────────────────

func TestCheckSink_NotTainted_Allowed(t *testing.T) {
	tr := New() // no taint labels
	assert.Nil(t, tr.CheckSink("exec.bash", ""))
}

func TestCheckSink_TaintedLowRisk_Allowed(t *testing.T) {
	tr := New()
	tr.AddLabel(LabelToolOutput)
	assert.Nil(t, tr.CheckSink("read_file", ""))
}

func TestCheckSink_TaintedHighRisk_Blocked(t *testing.T) {
	tr := New()
	tr.AddLabel(LabelToolOutput)
	v := tr.CheckSink("exec.bash", "")
	require.NotNil(t, v)
	assert.Equal(t, ReasonTaintedToHighRisk, v.Reason)
	assert.Contains(t, v.TaintLabels, LabelToolOutput)
}

func TestCheckSink_TaintedHighRisk_SanitizedAllowed(t *testing.T) {
	tr := New()
	tr.AddLabel(LabelToolOutput)
	tr.RecordSanitization("call-safe")
	// With sanitizer key matching, should be allowed.
	assert.Nil(t, tr.CheckSink("exec.bash", "call-safe"))
}

func TestCheckSink_TaintedHighRisk_WrongKeyBlocked(t *testing.T) {
	tr := New()
	tr.AddLabel(LabelToolOutput)
	tr.RecordSanitization("call-safe")
	// Different key — still blocked.
	require.NotNil(t, tr.CheckSink("exec.bash", "call-other"))
}

// ── High-risk sink detection ──────────────────────────────────────────────────

func TestIsHighRiskSink(t *testing.T) {
	highRisk := []string{
		"exec.bash", "exec", "fs.write", "write_file",
		"db.write", "database.write",
		"net.post", "net.put", "net.patch", "net.delete",
		"mcp.https.post",
	}
	for _, tool := range highRisk {
		assert.True(t, IsHighRiskSink(tool), "expected %q to be high-risk", tool)
	}
	lowRisk := []string{"read_file", "search", "mcp.https.get", "list_dir"}
	for _, tool := range lowRisk {
		assert.False(t, IsHighRiskSink(tool), "expected %q to be low-risk", tool)
	}
}

// ── Propagation ───────────────────────────────────────────────────────────────

func TestPropagateModelOutput_WhenTainted(t *testing.T) {
	tr := New()
	tr.AddLabel(LabelUserInput)
	tr.PropagateModelOutput()
	assert.True(t, tr.HasLabel(LabelModelOutput))
}

func TestPropagateModelOutput_WhenClean(t *testing.T) {
	tr := New()
	tr.PropagateModelOutput()
	assert.False(t, tr.HasLabel(LabelModelOutput))
}

// ── ToMap ─────────────────────────────────────────────────────────────────────

func TestToMap_Fields(t *testing.T) {
	tr := New()
	tr.AddLabel(LabelToolOutput)
	tr.RecordSanitization("k1")
	m := tr.ToMap()
	assert.True(t, m["is_tainted"].(bool))
	labels := m["active_labels"].([]any)
	assert.Contains(t, labels, LabelToolOutput)
}

// ── Acceptance: prompt injection corpus blocked ────────────────────────────────

func TestAcceptance_PromptInjectionBlocked(t *testing.T) {
	// Simulates: tool result contains injected content → model output tagged →
	// tool call to exec is blocked.
	tr := New()

	// Step 1: tool result arrives (potentially injected).
	tr.AddLabel(LabelToolOutput)
	// Step 2: model processes tainted output.
	tr.PropagateModelOutput()

	// Step 3: model proposes exec call.
	v := tr.CheckSink("exec.bash", "")
	require.NotNil(t, v)
	assert.Equal(t, ReasonTaintedToHighRisk, v.Reason)
}

func TestAcceptance_SanitizerAllowsFlow(t *testing.T) {
	tr := New()
	tr.AddLabel(LabelToolOutput)
	tr.PropagateModelOutput()

	// Sanitizer runs and records its output key.
	tr.RecordSanitization("sanitized-content-abc")

	// Now exec is allowed.
	v := tr.CheckSink("exec.bash", "sanitized-content-abc")
	assert.Nil(t, v)
}

// ── Reset ─────────────────────────────────────────────────────────────────────

func TestReset_ClearsAll(t *testing.T) {
	tr := New()
	tr.AddLabel(LabelUserInput)
	tr.RecordSanitization("k1")
	tr.Reset()
	assert.False(t, tr.IsTainted())
	assert.Empty(t, tr.SanitizedKeys)
}
