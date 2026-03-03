package reducer

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aegis-framework/aegis/pkg/eventlog"
	"github.com/aegis-framework/aegis/pkg/store"
)

func makeEnvelope(t *testing.T, b *eventlog.Builder, et eventlog.EventType, payload any) *eventlog.Envelope {
	t.Helper()
	e, err := b.Append(et, payload)
	require.NoError(t, err)
	return e
}

func TestReducer_BudgetCounting(t *testing.T) {
	b := eventlog.NewBuilder("t1", "u1", "s1")
	r := New("t1", "s1")

	events := []*eventlog.Envelope{
		makeEnvelope(t, b, eventlog.EventTypeModelCallStarted, map[string]any{"call_id": "c1"}),
		makeEnvelope(t, b, eventlog.EventTypeModelCallFinished, nil),
		makeEnvelope(t, b, eventlog.EventTypeToolCallProposed, map[string]any{"call_id": "t1", "tool_name": "read_file"}),
		makeEnvelope(t, b, eventlog.EventTypePolicyDecision, map[string]any{"outcome": "ALLOW"}),
		makeEnvelope(t, b, eventlog.EventTypeToolCallAllowed, map[string]any{"policy_ref": "baseline"}),
		makeEnvelope(t, b, eventlog.EventTypeToolCallExecuted, nil),
		makeEnvelope(t, b, eventlog.EventTypeToolResult, map[string]any{"is_error": false}),
	}

	for _, e := range events {
		_, err := r.Apply(e)
		require.NoError(t, err)
	}

	assert.Equal(t, uint32(len(events)), r.State.Budgets.StepsConsumed)
	assert.Equal(t, uint32(1), r.State.Budgets.ModelCallsConsumed)
	assert.Equal(t, uint32(1), r.State.Budgets.ToolCallsConsumed)
	assert.Equal(t, "read_file", r.State.LastOutcomes.LastToolName)
	assert.Equal(t, "ALLOW", r.State.LastOutcomes.LastPolicyOutcome)
}

func TestReducer_TaintLabels(t *testing.T) {
	b := eventlog.NewBuilder("t1", "u1", "s1")
	r := New("t1", "s1")

	// ToolResult and MemoryRead should add taint labels.
	_, err := r.Apply(makeEnvelope(t, b, eventlog.EventTypeModelCallStarted, nil))
	require.NoError(t, err)
	_, err = r.Apply(makeEnvelope(t, b, eventlog.EventTypeModelCallFinished, nil))
	require.NoError(t, err)
	_, err = r.Apply(makeEnvelope(t, b, eventlog.EventTypeToolCallProposed, map[string]any{"tool_name": "search"}))
	require.NoError(t, err)
	_, err = r.Apply(makeEnvelope(t, b, eventlog.EventTypePolicyDecision, nil))
	require.NoError(t, err)
	_, err = r.Apply(makeEnvelope(t, b, eventlog.EventTypeToolCallAllowed, nil))
	require.NoError(t, err)
	_, err = r.Apply(makeEnvelope(t, b, eventlog.EventTypeToolCallExecuted, nil))
	require.NoError(t, err)
	_, err = r.Apply(makeEnvelope(t, b, eventlog.EventTypeToolResult, nil))
	require.NoError(t, err)

	assert.Contains(t, r.State.TaintLabels, "tool_output")

	_, err = r.Apply(makeEnvelope(t, b, eventlog.EventTypeMemoryRead, nil))
	require.NoError(t, err)

	assert.Contains(t, r.State.TaintLabels, "memory_read")

	// Duplicate taint labels should not be added.
	_, err = r.Apply(makeEnvelope(t, b, eventlog.EventTypeMemoryRead, nil))
	require.NoError(t, err)
	count := 0
	for _, l := range r.State.TaintLabels {
		if l == "memory_read" {
			count++
		}
	}
	assert.Equal(t, 1, count, "duplicate taint labels must not accumulate")
}

func TestReducer_SnapshotOnTermination(t *testing.T) {
	b := eventlog.NewBuilder("t1", "u1", "s1")
	r := New("t1", "s1")

	_, _ = r.Apply(makeEnvelope(t, b, eventlog.EventTypeModelCallStarted, nil))
	snap, err := r.Apply(makeEnvelope(t, b, eventlog.EventTypeTermination, nil))
	require.NoError(t, err)
	require.NotNil(t, snap, "snapshot must be emitted on Termination")
	assert.Len(t, snap.SnapshotHash, 32)
}

func TestReducer_SnapshotOnApprovalRequested(t *testing.T) {
	b := eventlog.NewBuilder("t1", "u1", "s1")
	r := New("t1", "s1")

	_, _ = r.Apply(makeEnvelope(t, b, eventlog.EventTypeModelCallStarted, nil))
	_, _ = r.Apply(makeEnvelope(t, b, eventlog.EventTypeModelCallFinished, nil))
	_, _ = r.Apply(makeEnvelope(t, b, eventlog.EventTypeToolCallProposed, nil))
	_, _ = r.Apply(makeEnvelope(t, b, eventlog.EventTypePolicyDecision, nil))
	snap, err := r.Apply(makeEnvelope(t, b, eventlog.EventTypeApprovalRequested, nil))
	require.NoError(t, err)
	require.NotNil(t, snap, "snapshot must be emitted on ApprovalRequested")
}

func TestReducer_SnapshotCadence(t *testing.T) {
	b := eventlog.NewBuilder("t1", "u1", "s1")
	r := New("t1", "s1")

	var lastSnap *store.Snapshot
	// Emit 50 ModelCallStarted events to trigger the cadence snapshot.
	for i := 0; i < SnapshotCadence; i++ {
		snap, err := r.Apply(makeEnvelope(t, b, eventlog.EventTypeModelCallStarted, nil))
		require.NoError(t, err)
		if snap != nil {
			lastSnap = snap
		}
	}
	require.NotNil(t, lastSnap, "snapshot must be emitted every 50 events")
}

func TestReducer_HandoffState(t *testing.T) {
	b := eventlog.NewBuilder("t1", "u1", "s1")
	r := New("t1", "s1")

	_, _ = r.Apply(makeEnvelope(t, b, eventlog.EventTypeModelCallStarted, nil))
	_, _ = r.Apply(makeEnvelope(t, b, eventlog.EventTypeModelCallFinished, nil))
	_, _ = r.Apply(makeEnvelope(t, b, eventlog.EventTypeHandoffRequested, map[string]any{
		"from_agent": "agent-a",
		"to_agent":   "agent-b",
		"context_id": "ctx-1",
	}))

	assert.True(t, r.State.Handoff.InHandoff)
	assert.Equal(t, "agent-a", r.State.Handoff.FromAgent)
	assert.Equal(t, "agent-b", r.State.Handoff.ToAgent)

	_, _ = r.Apply(makeEnvelope(t, b, eventlog.EventTypeHandoffCompleted, nil))
	assert.False(t, r.State.Handoff.InHandoff)
}

func TestReducer_RestoreFromSnapshot(t *testing.T) {
	b := eventlog.NewBuilder("t1", "u1", "s1")
	r1 := New("t1", "s1")

	for i := 0; i < 10; i++ {
		_, _ = r1.Apply(makeEnvelope(t, b, eventlog.EventTypeModelCallStarted, nil))
	}
	snap, err := r1.Snapshot(9, 0)
	require.NoError(t, err)

	r2, err := NewFromSnapshot("t1", "s1", snap)
	require.NoError(t, err)

	assert.Equal(t, r1.State.Budgets.StepsConsumed, r2.State.Budgets.StepsConsumed)
	assert.Equal(t, r1.State.Budgets.ModelCallsConsumed, r2.State.Budgets.ModelCallsConsumed)
}

func TestReducer_SnapshotHashIsStable(t *testing.T) {
	b := eventlog.NewBuilder("t1", "u1", "s1")
	r := New("t1", "s1")

	for i := 0; i < 3; i++ {
		_, _ = r.Apply(makeEnvelope(t, b, eventlog.EventTypeModelCallStarted, nil))
	}
	s1, err := r.Snapshot(2, 1700000000000)
	require.NoError(t, err)

	// Second snapshot from identical state must yield identical hash.
	s2, err := r.Snapshot(2, 1700000000000)
	require.NoError(t, err)

	assert.Equal(t, s1.SnapshotHash, s2.SnapshotHash, "snapshot hash must be deterministic")
}

func TestReducer_SnapshotJSONRoundTrip(t *testing.T) {
	b := eventlog.NewBuilder("t1", "u1", "s1")
	r := New("t1", "s1")
	_, _ = r.Apply(makeEnvelope(t, b, eventlog.EventTypeModelCallStarted, map[string]any{"call_id": "c1"}))
	snap, err := r.Snapshot(0, 0)
	require.NoError(t, err)

	var decoded SnapshotState
	require.NoError(t, json.Unmarshal(snap.StateJSON, &decoded))
	assert.Equal(t, r.State.Budgets.ModelCallsConsumed, decoded.Budgets.ModelCallsConsumed)
}
