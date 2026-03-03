package replay

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aegis-framework/aegis/pkg/eventlog"
	sqlitestore "github.com/aegis-framework/aegis/pkg/store/sqlite"
)

// ── helpers ───────────────────────────────────────────────────────────────────

var testKey = []byte("01234567890123456789012345678901") // 32 bytes

func newStore(t *testing.T) *sqlitestore.Store {
	t.Helper()
	st, err := sqlitestore.New(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func keys() KeyStore { return KeyStore{"tenant1": testKey} }

// buildSessionViaRecorder does the same but uses the Recorder so outputs are captured.
func buildSessionViaRecorder(t *testing.T, rec *Recorder, tenantID, sessionID string) {
	t.Helper()
	ctx := context.Background()
	b := eventlog.NewBuilder(tenantID, "user1", sessionID)

	for _, ev := range []struct {
		et      eventlog.EventType
		payload map[string]any
	}{
		{eventlog.EventTypeModelCallStarted, map[string]any{"call_id": "c1", "model_id": "gpt-4o"}},
		{eventlog.EventTypeToolCallProposed, map[string]any{"tool_name": "read_file", "call_id": "t1", "args": map[string]any{"path": "/tmp/x"}}},
		{eventlog.EventTypeToolResult, map[string]any{"call_id": "t1", "result": "file contents", "is_error": false}},
		{eventlog.EventTypeModelCallFinished, map[string]any{"call_id": "c1", "output": "summary"}},
		{eventlog.EventTypeTermination, map[string]any{"reason": "COMPLETED"}},
	} {
		e, err := b.Append(ev.et, ev.payload)
		require.NoError(t, err)
		require.NoError(t, rec.Record(ctx, tenantID, e))
	}
}

// ── Encryption round-trip ─────────────────────────────────────────────────────

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	plain := []byte(`{"result":"secret data"}`)
	enc, err := Encrypt(testKey, plain)
	require.NoError(t, err)
	assert.NotEmpty(t, enc)

	got, err := Decrypt(testKey, enc)
	require.NoError(t, err)
	assert.Equal(t, plain, got)
}

func TestEncryptDecrypt_UniqueEachTime(t *testing.T) {
	plain := []byte("hello")
	enc1, _ := Encrypt(testKey, plain)
	enc2, _ := Encrypt(testKey, plain)
	assert.NotEqual(t, enc1, enc2, "nonce must differ each encryption")
}

func TestDecrypt_WrongKey_Fails(t *testing.T) {
	plain := []byte("secret")
	enc, _ := Encrypt(testKey, plain)
	wrongKey := []byte("99999999999999999999999999999999")
	_, err := Decrypt(wrongKey, enc)
	assert.ErrorIs(t, err, ErrDecryptFailed)
}

func TestDecrypt_Tampered_Fails(t *testing.T) {
	plain := []byte("secret")
	enc, _ := Encrypt(testKey, plain)
	// Flip a byte in the middle.
	b := []byte(enc)
	b[len(b)/2] ^= 0xFF
	_, err := Decrypt(testKey, string(b))
	assert.ErrorIs(t, err, ErrDecryptFailed)
}

// ── Recorder ─────────────────────────────────────────────────────────────────

func TestRecorder_CapturesToolResultAndModelOutput(t *testing.T) {
	st := newStore(t)
	rec := NewRecorder(st, keys())
	buildSessionViaRecorder(t, rec, "tenant1", "sess1")

	outputs := rec.GetOutputs("tenant1", "sess1")
	require.Len(t, outputs, 2, "expect ToolResult + ModelCallFinished")

	types := []string{outputs[0].EventType, outputs[1].EventType}
	assert.Contains(t, types, string(eventlog.EventTypeToolResult))
	assert.Contains(t, types, string(eventlog.EventTypeModelCallFinished))
}

func TestRecorder_PayloadDecryptable(t *testing.T) {
	st := newStore(t)
	rec := NewRecorder(st, keys())
	buildSessionViaRecorder(t, rec, "tenant1", "sess2")

	outputs := rec.GetOutputs("tenant1", "sess2")
	for _, o := range outputs {
		plain, err := Decrypt(testKey, o.EncryptedHex)
		require.NoError(t, err)
		var payload map[string]any
		require.NoError(t, json.Unmarshal(plain, &payload))
		assert.NotEmpty(t, payload)
	}
}

func TestRecorder_SkipsOtherEventTypes(t *testing.T) {
	st := newStore(t)
	rec := NewRecorder(st, keys())
	ctx := context.Background()
	b := eventlog.NewBuilder("tenant1", "u1", "sess-skip")
	e, _ := b.Append(eventlog.EventTypeModelCallStarted, map[string]any{"call_id": "c1"})
	require.NoError(t, rec.Record(ctx, "tenant1", e))
	assert.Empty(t, rec.GetOutputs("tenant1", "sess-skip"))
}

func TestRecorder_NoKey_DoesNotError(t *testing.T) {
	st := newStore(t)
	rec := NewRecorder(st, KeyStore{}) // no keys
	ctx := context.Background()
	b := eventlog.NewBuilder("tenant1", "u1", "sess-nokey")
	e, _ := b.Append(eventlog.EventTypeToolResult, map[string]any{"result": "x"})
	assert.NoError(t, rec.Record(ctx, "tenant1", e))
}

// ── Exact replay ─────────────────────────────────────────────────────────────

// Acceptance test: exact replay yields identical snapshot_hash at every step.
func TestExactReplay_SnapshotHashIdentical(t *testing.T) {
	st := newStore(t)
	rec := NewRecorder(st, keys())
	buildSessionViaRecorder(t, rec, "tenant1", "sess-exact")

	replayer := NewReplayer(st, keys(), rec)
	report, err := replayer.ReplayExact(context.Background(), "tenant1", "sess-exact")
	require.NoError(t, err)

	assert.Equal(t, "exact", report.Mode)
	assert.Greater(t, report.StepsReplayed, 0)
	assert.Empty(t, report.Diffs, "exact replay must produce no diffs")
	assert.True(t, report.Identical)
}

func TestExactReplay_MultipleEvents_AllStepsReplayed(t *testing.T) {
	st := newStore(t)
	rec := NewRecorder(st, keys())
	buildSessionViaRecorder(t, rec, "tenant1", "sess-multi")

	replayer := NewReplayer(st, keys(), rec)
	report, err := replayer.ReplayExact(context.Background(), "tenant1", "sess-multi")
	require.NoError(t, err)
	assert.Equal(t, 5, report.StepsReplayed) // 5 events in buildSessionViaRecorder
}

// ── Live replay ───────────────────────────────────────────────────────────────

// mockUpstream returns a fixed result for any tool call.
type mockUpstream struct {
	result json.RawMessage
	diffResult json.RawMessage // if non-nil, returned on 2nd call
	callCount  int
}

func (m *mockUpstream) Execute(_ context.Context, _ string, _ map[string]any) (json.RawMessage, error) {
	m.callCount++
	if m.diffResult != nil && m.callCount > 1 {
		return m.diffResult, nil
	}
	return m.result, nil
}

// Acceptance test: live replay diffs are stable and machine-readable.
func TestLiveReplay_Identical_WhenResultsMatch(t *testing.T) {
	st := newStore(t)
	rec := NewRecorder(st, keys())
	buildSessionViaRecorder(t, rec, "tenant1", "sess-live1")

	// Upstream returns the same fields as recorded (order doesn't matter; jsonEqual is semantic).
	up := &mockUpstream{result: json.RawMessage(`{"call_id":"t1","result":"file contents","is_error":false}`)}
	replayer := NewReplayer(st, keys(), rec)
	report, err := replayer.ReplayLive(context.Background(), "tenant1", "sess-live1", up)
	require.NoError(t, err)
	assert.Equal(t, "live", report.Mode)
	assert.True(t, report.Identical)
	assert.Empty(t, report.Diffs)
}

func TestLiveReplay_Diff_WhenResultsDiffer(t *testing.T) {
	st := newStore(t)
	rec := NewRecorder(st, keys())
	buildSessionViaRecorder(t, rec, "tenant1", "sess-live2")

	// Upstream returns a different result.
	up := &mockUpstream{result: json.RawMessage(`{"result":"DIFFERENT","is_error":false}`)}
	replayer := NewReplayer(st, keys(), rec)
	report, err := replayer.ReplayLive(context.Background(), "tenant1", "sess-live2", up)
	require.NoError(t, err)

	assert.False(t, report.Identical)
	require.NotEmpty(t, report.Diffs)
	diff := report.Diffs[0]
	assert.Equal(t, "tool_result", diff.Field)
	assert.NotNil(t, diff.Recorded)
	assert.NotNil(t, diff.Replayed)
}

func TestLiveReplay_DiffReport_IsMachineReadable(t *testing.T) {
	st := newStore(t)
	rec := NewRecorder(st, keys())
	buildSessionViaRecorder(t, rec, "tenant1", "sess-live3")

	up := &mockUpstream{result: json.RawMessage(`{"result":"changed"}`)}
	replayer := NewReplayer(st, keys(), rec)
	report, err := replayer.ReplayLive(context.Background(), "tenant1", "sess-live3", up)
	require.NoError(t, err)

	// Must be JSON-serialisable (machine-readable).
	b, err := json.Marshal(report)
	require.NoError(t, err)
	var roundTrip DiffReport
	require.NoError(t, json.Unmarshal(b, &roundTrip))
	assert.Equal(t, report.SessionID, roundTrip.SessionID)
	assert.Equal(t, report.Mode, roundTrip.Mode)
}

func TestLiveReplay_EmptySession_NoError(t *testing.T) {
	st := newStore(t)
	rec := NewRecorder(st, keys())
	replayer := NewReplayer(st, keys(), rec)
	report, err := replayer.ReplayLive(context.Background(), "tenant1", "nonexistent", nil)
	require.NoError(t, err)
	assert.Equal(t, 0, report.StepsReplayed)
	assert.True(t, report.Identical)
}
