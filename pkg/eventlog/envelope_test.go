package eventlog

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuilder_Chain(t *testing.T) {
	b := NewBuilder("tenant-1", "user-1", "session-1")

	e0, err := b.Append(EventTypeModelCallStarted, map[string]any{
		"model_id": "gpt-4o",
		"call_id":  "call-0",
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(0), e0.Seq)
	assert.Nil(t, e0.PrevHash, "first event must have nil prev_hash")
	assert.NotNil(t, e0.Hash)

	e1, err := b.Append(EventTypeModelCallFinished, map[string]any{
		"call_id":      "call-0",
		"finish_reason": "stop",
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(1), e1.Seq)
	assert.Equal(t, e0.Hash, e1.PrevHash, "e1.prev_hash must equal e0.hash")
}

func TestEnvelope_Verify(t *testing.T) {
	b := NewBuilder("tenant-1", "user-1", "session-1")
	e, err := b.Append(EventTypeModelCallStarted, map[string]any{"model_id": "gpt-4o"})
	require.NoError(t, err)

	assert.NoError(t, e.Verify())

	// Tamper with payload and verify that hash check fails.
	original := e.Payload
	e.Payload = map[string]any{"model_id": "tampered"}
	assert.Error(t, e.Verify(), "tampered payload must fail verification")
	e.Payload = original
}

func TestVerifyChain_Tamper(t *testing.T) {
	b := NewBuilder("t1", "u1", "s1")
	events := make([]*Envelope, 5)
	types := []EventType{
		EventTypeModelCallStarted,
		EventTypeModelCallFinished,
		EventTypeToolCallProposed,
		EventTypePolicyDecision,
		EventTypeToolCallAllowed,
	}
	for i, et := range types {
		e, err := b.Append(et, map[string]any{"seq_debug": i})
		require.NoError(t, err)
		events[i] = e
	}

	// Chain should be valid.
	badSeq, err := VerifyChain(events)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), badSeq)

	// Tamper with event[2]'s payload.
	events[2].Payload = map[string]any{"tampered": true}

	badSeq, err = VerifyChain(events)
	assert.Error(t, err)
	assert.Equal(t, uint64(2), badSeq, "first bad seq should be the tampered event")
}

func TestVerifyChain_BrokenLink(t *testing.T) {
	b := NewBuilder("t1", "u1", "s1")
	e0, err := b.Append(EventTypeModelCallStarted, nil)
	require.NoError(t, err)
	e1, err := b.Append(EventTypeModelCallFinished, nil)
	require.NoError(t, err)

	// Break the link by zeroing e1's prev_hash.
	e1.PrevHash = make([]byte, 32)

	_, err = VerifyChain([]*Envelope{e0, e1})
	assert.Error(t, err)
}

func TestMarshalRoundTrip(t *testing.T) {
	b := NewBuilder("t1", "u1", "s1")
	orig, err := b.Append(EventTypeToolCallProposed, map[string]any{
		"tool_name": "read_file",
		"args":      map[string]any{"path": "/tmp/foo"},
	})
	require.NoError(t, err)

	data, err := MarshalEnvelope(orig)
	require.NoError(t, err)

	restored, err := UnmarshalEnvelope(data)
	require.NoError(t, err)

	assert.Equal(t, orig.Seq, restored.Seq)
	assert.Equal(t, orig.SessionID, restored.SessionID)
	assert.Equal(t, orig.EventType, restored.EventType)
	assert.Equal(t, orig.Hash, restored.Hash)
}

func TestNewBuilderFromSeq(t *testing.T) {
	b1 := NewBuilder("t1", "u1", "s1")
	e0, err := b1.Append(EventTypeModelCallStarted, nil)
	require.NoError(t, err)

	// Continue chain from a new builder.
	b2 := NewBuilderFromSeq("t1", "u1", "s1", 1, e0.Hash)
	e1, err := b2.Append(EventTypeModelCallFinished, nil)
	require.NoError(t, err)

	assert.Equal(t, uint64(1), e1.Seq)
	assert.Equal(t, e0.Hash, e1.PrevHash)
}
