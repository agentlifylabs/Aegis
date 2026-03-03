package approval

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testSecret = []byte("test-hmac-secret-32-bytes-padding!!")

func newRouter() *Router {
	return New(testSecret, 5*time.Minute)
}

// ── Issue ─────────────────────────────────────────────────────────────────────

func TestIssue_CreatesToken(t *testing.T) {
	r := newRouter()
	ap, err := r.Issue("t1", "sess1", "deploy", map[string]any{"env": "prod"})
	require.NoError(t, err)
	assert.NotEmpty(t, ap.Token)
	assert.Equal(t, StatusPending, ap.Status)
	assert.Equal(t, "deploy", ap.ToolName)
	assert.Greater(t, ap.ExpiresMs, ap.CreatedMs)
}

func TestIssue_TokensAreUnique(t *testing.T) {
	r := newRouter()
	a1, _ := r.Issue("t1", "s1", "tool", nil)
	a2, _ := r.Issue("t1", "s1", "tool", nil)
	assert.NotEqual(t, a1.Token, a2.Token)
}

// ── Decide: allow ─────────────────────────────────────────────────────────────

func TestDecide_Allow_NoEdit(t *testing.T) {
	r := newRouter()
	args := map[string]any{"path": "/tmp/x"}
	ap, _ := r.Issue("t1", "s1", "write_file", args)

	updated, patch, err := r.Decide(ap.Token, Decision{Allow: true})
	require.NoError(t, err)
	assert.Equal(t, StatusAllowed, updated.Status)
	assert.Nil(t, patch, "no patch when args unchanged")
	assert.Equal(t, args, updated.FinalArgs)
}

func TestDecide_Allow_WithEdit_ProducesPatch(t *testing.T) {
	r := newRouter()
	orig := map[string]any{"path": "/tmp/x", "content": "hello"}
	ap, _ := r.Issue("t1", "s1", "write_file", orig)

	edited := map[string]any{"path": "/tmp/x", "content": "hello-sanitized"}
	updated, patch, err := r.Decide(ap.Token, Decision{Allow: true, EditedArgs: edited})
	require.NoError(t, err)
	assert.Equal(t, StatusAllowed, updated.Status)
	require.NotNil(t, patch)
	assert.Equal(t, edited, updated.FinalArgs)

	// Diff should capture the "content" change.
	var foundChange bool
	for _, d := range patch.Diff {
		if d.Key == "content" && d.Op == "change" {
			foundChange = true
			assert.Equal(t, "hello", d.Before)
			assert.Equal(t, "hello-sanitized", d.After)
		}
	}
	assert.True(t, foundChange, "diff must include content change")
}

func TestDecide_Allow_EditedArgsSupercede(t *testing.T) {
	// Acceptance test: edited approval args supersede original; original cannot be replayed.
	r := newRouter()
	orig := map[string]any{"cmd": "rm -rf /"}
	ap, _ := r.Issue("t1", "s1", "exec", orig)

	safeArgs := map[string]any{"cmd": "ls /tmp"}
	updated, _, err := r.Decide(ap.Token, Decision{Allow: true, EditedArgs: safeArgs})
	require.NoError(t, err)
	assert.Equal(t, safeArgs, updated.FinalArgs)
	assert.NotEqual(t, orig, updated.FinalArgs, "original args must not be used")
}

// ── Decide: deny ─────────────────────────────────────────────────────────────

func TestDecide_Deny_NoSideEffects(t *testing.T) {
	r := newRouter()
	ap, _ := r.Issue("t1", "s1", "send_email", map[string]any{"to": "ceo@corp.com"})

	updated, patch, err := r.Decide(ap.Token, Decision{Allow: false, Message: "not approved"})
	require.NoError(t, err)
	assert.Equal(t, StatusDenied, updated.Status)
	assert.Nil(t, patch)
	assert.Equal(t, "not approved", updated.DeniedByMsg)
	assert.Nil(t, updated.FinalArgs)
}

// ── Double-decide guard ───────────────────────────────────────────────────────

func TestDecide_AlreadyDecided_Error(t *testing.T) {
	r := newRouter()
	ap, _ := r.Issue("t1", "s1", "tool", nil)
	_, _, err := r.Decide(ap.Token, Decision{Allow: true})
	require.NoError(t, err)
	_, _, err = r.Decide(ap.Token, Decision{Allow: false})
	assert.ErrorIs(t, err, ErrDecided)
}

// ── Expiry ────────────────────────────────────────────────────────────────────

func TestDecide_Expired_Error(t *testing.T) {
	r := New(testSecret, 1*time.Millisecond) // tiny TTL
	ap, _ := r.Issue("t1", "s1", "tool", nil)
	time.Sleep(5 * time.Millisecond)
	_, _, err := r.Decide(ap.Token, Decision{Allow: true})
	assert.ErrorIs(t, err, ErrExpired)
}

// ── Not found ─────────────────────────────────────────────────────────────────

func TestDecide_NotFound_Error(t *testing.T) {
	r := newRouter()
	_, _, err := r.Decide("no-such-token", Decision{Allow: true})
	assert.ErrorIs(t, err, ErrNotFound)
}

// ── ListPending ───────────────────────────────────────────────────────────────

func TestListPending_ReturnsOnlyPending(t *testing.T) {
	r := newRouter()
	ap1, _ := r.Issue("t1", "s1", "tool_a", nil)
	ap2, _ := r.Issue("t1", "s1", "tool_b", nil)
	_, _ = r.Issue("t2", "s2", "tool_c", nil) // different tenant

	// Decide on ap1.
	_, _, _ = r.Decide(ap1.Token, Decision{Allow: true})

	pending := r.ListPending("t1")
	require.Len(t, pending, 1)
	assert.Equal(t, ap2.Token, pending[0].Token)
}

// ── RenderPrompt ──────────────────────────────────────────────────────────────

func TestRenderPrompt_ContainsKeyFields(t *testing.T) {
	r := newRouter()
	ap, _ := r.Issue("tenant-1", "sess-99", "deploy", map[string]any{"env": "prod"})
	prompt := RenderPrompt(ap)
	assert.Contains(t, prompt, ap.Token)
	assert.Contains(t, prompt, "deploy")
	assert.Contains(t, prompt, "tenant-1")
}

// ── StagedPatch diff ──────────────────────────────────────────────────────────

func TestBuildArgsDiff_AddRemoveChange(t *testing.T) {
	orig := map[string]any{"a": 1, "b": "hello", "c": true}
	edited := map[string]any{"a": 2, "b": "hello", "d": "new"}

	diff := buildArgsDiff(orig, edited)

	ops := make(map[string]string)
	for _, e := range diff {
		ops[e.Key] = e.Op
	}
	assert.Equal(t, "change", ops["a"])
	assert.Equal(t, "remove", ops["c"])
	assert.Equal(t, "add", ops["d"])
	_, hasB := ops["b"]
	assert.False(t, hasB, "unchanged key must not appear in diff")
}
