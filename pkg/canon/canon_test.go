package canon

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanonicalizeObject_KeyOrdering(t *testing.T) {
	obj := map[string]any{
		"z": 1.0,
		"a": 2.0,
		"m": 3.0,
	}
	got, err := Canonicalize(obj)
	require.NoError(t, err)
	assert.Equal(t, `{"a":2,"m":3,"z":1}`, string(got))
}

func TestCanonicalizeNested(t *testing.T) {
	obj := map[string]any{
		"b": map[string]any{"y": true, "x": false},
		"a": []any{3.0, 1.0, 2.0},
	}
	got, err := Canonicalize(obj)
	require.NoError(t, err)
	assert.Equal(t, `{"a":[3,1,2],"b":{"x":false,"y":true}}`, string(got))
}

func TestCanonicalizeNullAndBool(t *testing.T) {
	cases := []struct {
		in  any
		out string
	}{
		{nil, "null"},
		{true, "true"},
		{false, "false"},
	}
	for _, tc := range cases {
		got, err := Canonicalize(tc.in)
		require.NoError(t, err)
		assert.Equal(t, tc.out, string(got))
	}
}

func TestHashDeterministic(t *testing.T) {
	obj := map[string]any{
		"tenant_id":  "t1",
		"session_id": "s1",
		"seq":        float64(1),
		"event_type": "TOOL_CALL_PROPOSED",
	}
	h1, err := Hash(obj)
	require.NoError(t, err)
	h2, err := Hash(obj)
	require.NoError(t, err)
	assert.Equal(t, h1, h2)
}

// TestGoldenHash validates a known-good hash so we can verify cross-platform parity.
// This value was produced by the reference implementation.
func TestGoldenHash(t *testing.T) {
	obj := map[string]any{
		"event_type": "TOOL_CALL_PROPOSED",
		"seq":        float64(1),
		"session_id": "session-abc",
		"tenant_id":  "tenant-xyz",
		"ts_unix_ms": float64(1700000000000),
	}
	got, err := Hash(obj)
	require.NoError(t, err)
	// Golden hash pinned after first successful cross-platform run.
	// Python must produce the same value — enforced in CI cross-platform-hash job.
	const goldenHex = "cfa697f0eb082a2889ab92b2c457060c08eab0ced2677ac2a09d4488322b6ee3"
	assert.Equal(t, goldenHex, hex.EncodeToString(got), "golden hash mismatch — check Python parity")
	t.Logf("hash: %s", hex.EncodeToString(got))
}

func TestHashBytes(t *testing.T) {
	b := []byte(`{"a":1}`)
	h1 := HashBytes(b)
	h2 := HashBytes(b)
	assert.Equal(t, h1, h2)
	assert.Len(t, h1, 32)
}
