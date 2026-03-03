package eventlog

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidator_HappyPath(t *testing.T) {
	b := NewBuilder("t1", "u1", "s1")
	v := NewValidator("s1")

	steps := []EventType{
		EventTypeModelCallStarted,
		EventTypeModelCallFinished,
		EventTypeToolCallProposed,
		EventTypePolicyDecision,
		EventTypeToolCallAllowed,
		EventTypeToolCallExecuted,
		EventTypeToolResult,
		EventTypeTermination,
	}

	for _, et := range steps {
		e, err := b.Append(et, nil)
		require.NoError(t, err)
		assert.NoError(t, v.Validate(e), "expected valid transition to %s", et)
	}
}

func TestValidator_RejectsToolResultWithoutExecuted(t *testing.T) {
	b := NewBuilder("t1", "u1", "s1")
	v := NewValidator("s1")

	// Valid start.
	e0, err := b.Append(EventTypeModelCallStarted, nil)
	require.NoError(t, err)
	require.NoError(t, v.Validate(e0))

	e1, err := b.Append(EventTypeModelCallFinished, nil)
	require.NoError(t, err)
	require.NoError(t, v.Validate(e1))

	e2, err := b.Append(EventTypeToolCallProposed, nil)
	require.NoError(t, err)
	require.NoError(t, v.Validate(e2))

	e3, err := b.Append(EventTypePolicyDecision, nil)
	require.NoError(t, err)
	require.NoError(t, v.Validate(e3))

	e4, err := b.Append(EventTypeToolCallAllowed, nil)
	require.NoError(t, err)
	require.NoError(t, v.Validate(e4))

	// Skip ToolCallExecuted and go directly to ToolResult.
	e5, err := b.Append(EventTypeToolResult, nil)
	require.NoError(t, err)
	// This should fail: ToolCallAllowed -> ToolResult is invalid.
	// (ToolResult is only valid after ToolCallExecuted)
	// But the transition table says ToolCallAllowed -> ToolCallExecuted only.
	assert.Error(t, v.Validate(e5), "ToolResult without ToolCallExecuted must be rejected")
}

func TestValidator_RejectsInvalidStartEvent(t *testing.T) {
	b := NewBuilder("t1", "u1", "s1")
	v := NewValidator("s1")

	// ToolResult is not a valid start event.
	e, err := b.Append(EventTypeToolResult, nil)
	require.NoError(t, err)
	assert.Error(t, v.Validate(e), "ToolResult as first event must be rejected")
}

func TestValidator_ApprovalFlow(t *testing.T) {
	b := NewBuilder("t1", "u1", "s1")
	v := NewValidator("s1")

	steps := []EventType{
		EventTypeModelCallStarted,
		EventTypeModelCallFinished,
		EventTypeToolCallProposed,
		EventTypePolicyDecision,
		EventTypeApprovalRequested,
		EventTypeApprovalDecided,
		EventTypeToolCallAllowed,
		EventTypeToolCallExecuted,
		EventTypeToolResult,
		EventTypeTermination,
	}
	for _, et := range steps {
		e, err := b.Append(et, nil)
		require.NoError(t, err)
		assert.NoError(t, v.Validate(e), "expected valid step %s", et)
	}
}

func TestValidator_RejectsEventAfterTermination(t *testing.T) {
	b := NewBuilder("t1", "u1", "s1")
	v := NewValidator("s1")

	e0, err := b.Append(EventTypeModelCallStarted, nil)
	require.NoError(t, err)
	require.NoError(t, v.Validate(e0))

	e1, err := b.Append(EventTypeTermination, nil)
	require.NoError(t, err)
	require.NoError(t, v.Validate(e1))

	// Any event after Termination should fail.
	e2, err := b.Append(EventTypeModelCallStarted, nil)
	require.NoError(t, err)
	assert.Error(t, v.Validate(e2), "event after Termination must be rejected")
}

func TestValidator_NonMonotonicSeq(t *testing.T) {
	v := NewValidator("s1")
	b := NewBuilder("t1", "u1", "s1")

	e0, _ := b.Append(EventTypeModelCallStarted, nil)
	require.NoError(t, v.Validate(e0))

	// Re-use the same seq number.
	e1 := &Envelope{
		TenantID:  "t1",
		UserID:    "u1",
		SessionID: "s1",
		Seq:       0, // duplicate seq
		EventType: EventTypeModelCallFinished,
	}
	require.NoError(t, e1.Seal())
	assert.Error(t, v.Validate(e1), "non-monotonic seq must be rejected")
}

func TestValidateSequence(t *testing.T) {
	b := NewBuilder("t1", "u1", "s1")
	events := make([]*Envelope, 0)
	for _, et := range []EventType{
		EventTypeModelCallStarted,
		EventTypeModelCallFinished,
		EventTypeTermination,
	} {
		e, err := b.Append(et, nil)
		require.NoError(t, err)
		events = append(events, e)
	}
	assert.NoError(t, ValidateSequence(events))
}
