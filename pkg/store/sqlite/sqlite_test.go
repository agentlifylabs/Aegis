package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aegis-framework/aegis/pkg/eventlog"
	"github.com/aegis-framework/aegis/pkg/store"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestAppendAndGetEvent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	b := eventlog.NewBuilder("t1", "u1", "session-1")
	e, err := b.Append(eventlog.EventTypeModelCallStarted, map[string]any{"model_id": "gpt-4o"})
	require.NoError(t, err)

	require.NoError(t, s.AppendEvent(ctx, "t1", e))

	got, err := s.GetEvent(ctx, "t1", "session-1", 0)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), got.Seq)
	assert.Equal(t, "MODEL_CALL_STARTED", got.EventType)
	assert.Equal(t, e.Hash, got.Hash)
}

func TestAppendChain(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	b := eventlog.NewBuilder("t1", "u1", "session-chain")
	types := []eventlog.EventType{
		eventlog.EventTypeModelCallStarted,
		eventlog.EventTypeModelCallFinished,
		eventlog.EventTypeTermination,
	}
	for _, et := range types {
		e, err := b.Append(et, nil)
		require.NoError(t, err)
		require.NoError(t, s.AppendEvent(ctx, "t1", e))
	}

	// Verify chain.
	badSeq, err := s.VerifyChain(ctx, "t1", "session-chain")
	require.NoError(t, err)
	assert.Equal(t, uint64(0), badSeq)
}

func TestVerifyChain_DetectsTampering(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	b := eventlog.NewBuilder("t1", "u1", "session-tamper")
	e0, err := b.Append(eventlog.EventTypeModelCallStarted, nil)
	require.NoError(t, err)
	require.NoError(t, s.AppendEvent(ctx, "t1", e0))

	e1, err := b.Append(eventlog.EventTypeModelCallFinished, nil)
	require.NoError(t, err)
	require.NoError(t, s.AppendEvent(ctx, "t1", e1))

	// Directly tamper with e0's hash in the DB.
	_, err = s.db.ExecContext(ctx,
		`UPDATE events SET hash=? WHERE session_id='session-tamper' AND seq=0`,
		[]byte("00000000000000000000000000000000"),
	)
	require.NoError(t, err)

	// VerifyChain should detect the broken link at seq=1 (because e1.prev_hash != tampered e0.hash).
	badSeq, err := s.VerifyChain(ctx, "t1", "session-tamper")
	assert.Error(t, err)
	assert.Equal(t, uint64(1), badSeq)
}

func TestListEvents_Filters(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	b := eventlog.NewBuilder("t1", "u1", "session-list")
	types := []eventlog.EventType{
		eventlog.EventTypeModelCallStarted,
		eventlog.EventTypeModelCallFinished,
		eventlog.EventTypeToolCallProposed,
		eventlog.EventTypePolicyDecision,
		eventlog.EventTypeToolCallAllowed,
		eventlog.EventTypeToolCallExecuted,
		eventlog.EventTypeToolResult,
		eventlog.EventTypeTermination,
	}
	for _, et := range types {
		e, err := b.Append(et, nil)
		require.NoError(t, err)
		require.NoError(t, s.AppendEvent(ctx, "t1", e))
	}

	page, err := s.ListEvents(ctx, "t1", store.EventFilter{
		SessionID: "session-list",
		EventType: "TOOL_CALL_PROPOSED",
	})
	require.NoError(t, err)
	assert.Len(t, page.Events, 1)
	assert.Equal(t, "TOOL_CALL_PROPOSED", page.Events[0].EventType)
}

func TestSnapshotRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	stateJSON := []byte(`{"budgets":{"steps_consumed":5}}`)
	hash, err := ComputeSnapshotHash(stateJSON)
	require.NoError(t, err)

	snap := &store.Snapshot{
		TenantID:     "t1",
		SessionID:    "session-snap",
		LastSeq:      5,
		TsUnixMs:     time.Now().UnixMilli(),
		StateJSON:    stateJSON,
		SnapshotHash: hash,
	}
	require.NoError(t, s.SaveSnapshot(ctx, snap))

	got, err := s.GetSnapshot(ctx, "t1", "session-snap")
	require.NoError(t, err)
	assert.Equal(t, snap.LastSeq, got.LastSeq)
	assert.Equal(t, snap.SnapshotHash, got.SnapshotHash)
	assert.Equal(t, snap.StateJSON, got.StateJSON)
}

func TestSnapshotUpdate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	snap1 := &store.Snapshot{
		TenantID: "t1", SessionID: "s1", LastSeq: 1,
		TsUnixMs: NowMs(), StateJSON: []byte(`{"budgets":{}}`),
	}
	snap1.SnapshotHash, _ = ComputeSnapshotHash(snap1.StateJSON)
	require.NoError(t, s.SaveSnapshot(ctx, snap1))

	snap2 := &store.Snapshot{
		TenantID: "t1", SessionID: "s1", LastSeq: 50,
		TsUnixMs: NowMs(), StateJSON: []byte(`{"budgets":{"steps_consumed":50}}`),
	}
	snap2.SnapshotHash, _ = ComputeSnapshotHash(snap2.StateJSON)
	require.NoError(t, s.SaveSnapshot(ctx, snap2))

	got, err := s.GetSnapshot(ctx, "t1", "s1")
	require.NoError(t, err)
	assert.Equal(t, uint64(50), got.LastSeq)
}

func TestGetEvent_NotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_, err := s.GetEvent(ctx, "t1", "no-session", 0)
	assert.ErrorIs(t, err, store.ErrNotFound)
}

func TestGetSnapshot_NotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_, err := s.GetSnapshot(ctx, "t1", "no-session")
	assert.ErrorIs(t, err, store.ErrNotFound)
}
