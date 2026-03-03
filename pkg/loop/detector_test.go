package loop

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func budget(steps, tools uint32) BudgetConfig {
	return BudgetConfig{MaxSteps: steps, MaxToolCalls: tools}
}

// ── Budget tests ──────────────────────────────────────────────────────────────

func TestBudget_StepsExceeded(t *testing.T) {
	d := New(budget(3, 100))
	for i := uint64(0); i < 3; i++ {
		assert.Nil(t, d.RecordStep(i))
	}
	v := d.RecordStep(3)
	require.NotNil(t, v)
	assert.Equal(t, ReasonBudgetSteps, v.Reason)
	assert.Equal(t, ActionStop, v.Action)
}

func TestBudget_ToolCallsExceeded(t *testing.T) {
	d := New(budget(100, 2))
	assert.Nil(t, d.RecordToolCall(0, "read_file", nil, "", 0))
	assert.Nil(t, d.RecordToolCall(1, "read_file", map[string]any{"a": 1}, "", 0))
	v := d.RecordToolCall(2, "write_file", nil, "", 0)
	require.NotNil(t, v)
	assert.Equal(t, ReasonBudgetToolCalls, v.Reason)
	assert.Equal(t, ActionStop, v.Action)
}

func TestBudget_WallTimeExceeded(t *testing.T) {
	d := New(BudgetConfig{MaxSteps: 100, MaxToolCalls: 100, MaxWallTimeMs: 1000})
	d.SetSessionStart(0)
	v := d.RecordToolCall(1, "read_file", nil, "", 2000) // 2s > 1s limit
	require.NotNil(t, v)
	assert.Equal(t, ReasonBudgetWallTime, v.Reason)
}

func TestBudget_ModelCallsExceeded(t *testing.T) {
	d := New(BudgetConfig{MaxSteps: 100, MaxToolCalls: 100, MaxModelCalls: 2})
	assert.Nil(t, d.RecordModelCall(0))
	assert.Nil(t, d.RecordModelCall(1))
	v := d.RecordModelCall(2)
	require.NotNil(t, v)
	assert.Equal(t, ReasonBudgetModelCalls, v.Reason)
}

// ── Loop condition 1: identical call ─────────────────────────────────────────

func TestLoop_IdenticalCall_Detected(t *testing.T) {
	d := New(budget(100, 100))
	args := map[string]any{"path": "/etc/passwd"}
	assert.Nil(t, d.RecordToolCall(0, "read_file", args, "snap1", 0))
	v := d.RecordToolCall(1, "read_file", args, "snap2", 0)
	require.NotNil(t, v)
	assert.Equal(t, ReasonLoopIdentical, v.Reason)
	assert.Equal(t, ActionRequireApproval, v.Action)
	assert.Contains(t, v.CycleTrace, uint64(0))
	assert.Contains(t, v.CycleTrace, uint64(1))
}

func TestLoop_IdenticalCall_DifferentArgs_NotDetected(t *testing.T) {
	d := New(budget(100, 100))
	assert.Nil(t, d.RecordToolCall(0, "read_file", map[string]any{"path": "/a"}, "s1", 0))
	assert.Nil(t, d.RecordToolCall(1, "read_file", map[string]any{"path": "/b"}, "s2", 0))
}

// ── Loop condition 2: no progress ────────────────────────────────────────────

func TestLoop_NoProgress_Detected(t *testing.T) {
	d := New(budget(100, 100))
	snapHash := "abc123"
	_ = d.RecordToolCall(0, "tool_a", nil, snapHash, 0)
	_ = d.RecordToolCall(1, "tool_b", nil, snapHash, 0)
	v := d.RecordToolCall(2, "tool_c", nil, snapHash, 0)
	require.NotNil(t, v)
	assert.Equal(t, ReasonLoopNoProgress, v.Reason)
	assert.Equal(t, ActionRequireApproval, v.Action)
	assert.Len(t, v.CycleTrace, 3)
}

func TestLoop_NoProgress_ResetOnChange(t *testing.T) {
	d := New(budget(100, 100))
	_ = d.RecordToolCall(0, "a", nil, "hash1", 0)
	_ = d.RecordToolCall(1, "b", nil, "hash1", 0)
	// Progress: hash changes.
	_ = d.RecordToolCall(2, "c", nil, "hash2", 0)
	// Two more with same new hash — not yet 3.
	assert.Nil(t, d.RecordToolCall(3, "d", nil, "hash2", 0))
}

// ── Loop condition 3: repeating sequence ─────────────────────────────────────

func TestLoop_RepeatingSequence_Detected(t *testing.T) {
	d := New(budget(100, 100))
	// Sequence A→B→C repeated twice = 6 calls.
	tools := []string{"a", "b", "c", "a", "b", "c"}
	var lastV *LoopViolation
	for i, tool := range tools {
		v := d.RecordToolCall(uint64(i), tool, nil, fmt.Sprintf("hash%d", i), 0)
		if v != nil {
			lastV = v
		}
	}
	require.NotNil(t, lastV)
	assert.Equal(t, ReasonLoopSequence, lastV.Reason)
	assert.Len(t, lastV.CycleTrace, 6)
}

func TestLoop_RepeatingSequence_NotDetectedUntilTwice(t *testing.T) {
	d := New(budget(100, 100))
	// Only one pass of the sequence — no violation yet.
	for i, tool := range []string{"a", "b", "c"} {
		assert.Nil(t, d.RecordToolCall(uint64(i), tool, nil, "", 0))
	}
}

// ── Acceptance test: looping repro terminates before recursion limit ──────────

func TestAcceptance_LoopingReproTerminatesEarly(t *testing.T) {
	const systemRecursionLimit = 1000
	d := New(budget(100, 100))
	args := map[string]any{"query": "same question"}

	var stopSeq int
	for i := 0; i < systemRecursionLimit; i++ {
		v := d.RecordToolCall(uint64(i), "search", args, "same-hash", 0)
		if v != nil {
			stopSeq = i
			assert.Less(t, stopSeq, systemRecursionLimit,
				"must stop well before recursion limit")
			t.Logf("stopped at seq=%d reason=%s trace=%v", stopSeq, v.Reason, v.CycleTrace)
			return
		}
	}
	t.Fatal("loop not detected within system recursion limit")
}

func TestAcceptance_StopReasonsIncludeCycleTrace(t *testing.T) {
	d := New(budget(100, 100))
	args := map[string]any{"x": 1}
	d.RecordToolCall(10, "deploy", args, "h1", 0)
	v := d.RecordToolCall(20, "deploy", args, "h2", 0)
	require.NotNil(t, v)
	assert.NotEmpty(t, v.CycleTrace, "cycle trace must be populated")
	assert.Equal(t, uint64(10), v.CycleTrace[0])
	assert.Equal(t, uint64(20), v.CycleTrace[1])
}
