package proxy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aegis-framework/aegis/pkg/loop"
	"github.com/aegis-framework/aegis/pkg/manifest"
	"github.com/aegis-framework/aegis/pkg/policy"
	sqlitestore "github.com/aegis-framework/aegis/pkg/store/sqlite"
)

// mockUpstream is a test double for the upstream MCP server.
type mockUpstream struct {
	result json.RawMessage
	err    error
	calls  []string
}

func (m *mockUpstream) Call(_ context.Context, toolName string, _ map[string]any) (json.RawMessage, error) {
	m.calls = append(m.calls, toolName)
	if m.err != nil {
		return nil, m.err
	}
	if m.result != nil {
		return m.result, nil
	}
	return json.RawMessage(`{"ok":true}`), nil
}

func baseManifest(tools ...string) *manifest.Manifest {
	return &manifest.Manifest{
		Schema:    manifest.SchemaVersion,
		Name:      "test-skill",
		Version:   "0.1.0",
		Publisher: "acme",
		Permissions: manifest.Permissions{
			Tools: tools,
			Budgets: manifest.BudgetLimits{
				MaxSteps:     24,
				MaxToolCalls: 12,
			},
			Net:  manifest.NetPermissions{},
			Exec: manifest.ExecPermissions{},
		},
	}
}

func newTestProxy(t *testing.T, m *manifest.Manifest, upstream Upstream) *Proxy {
	t.Helper()
	eng, err := policy.New()
	require.NoError(t, err)

	st, err := sqlitestore.New(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	return New(Config{
		TenantID:  "t1",
		UserID:    "u1",
		SessionID: "session-proxy-test",
		Manifest:  m,
		Store:     st,
		Engine:    eng,
		Upstream:  upstream,
	}, 0, nil)
}

func toolCallReq(id any, toolName string, args map[string]any) *Request {
	params, _ := json.Marshal(ToolCallParams{Name: toolName, Arguments: args})
	return &Request{
		JSONRPC: "2.0",
		ID:      id,
		Method:  "tools/call",
		Params:  params,
	}
}

// ── Epic 05 acceptance tests ──────────────────────────────────────────────────

func TestProxy_AllowedTool_PassThrough(t *testing.T) {
	up := &mockUpstream{}
	p := newTestProxy(t, baseManifest("read_file"), up)

	resp := p.Handle(context.Background(), toolCallReq(1, "read_file", map[string]any{"path": "/tmp/x"}))
	require.Nil(t, resp.Error, "unexpected error: %+v", resp.Error)
	assert.Equal(t, 1, len(up.calls))
	assert.Equal(t, "read_file", up.calls[0])
}

func TestProxy_DeniedTool_ReturnsMCPError(t *testing.T) {
	up := &mockUpstream{}
	p := newTestProxy(t, baseManifest("read_file"), up) // write_file NOT declared

	resp := p.Handle(context.Background(), toolCallReq(2, "write_file", nil))
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodePolicyDeny, resp.Error.Code)
	assert.Equal(t, 0, len(up.calls)) // must NOT be forwarded
}

func TestProxy_ApprovalRequired_ReturnsPending(t *testing.T) {
	m := baseManifest("deploy")
	m.Permissions.ApprovalRequired = []string{"deploy"}

	up := &mockUpstream{}
	p := newTestProxy(t, m, up)

	resp := p.Handle(context.Background(), toolCallReq(3, "deploy", nil))
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeApprovalPending, resp.Error.Code)
	assert.Equal(t, 0, len(up.calls))

	data, ok := resp.Error.Data.(map[string]any)
	require.True(t, ok)
	assert.NotEmpty(t, data["approval_token"])
}

func TestProxy_UpstreamError_WritesAuditEvent(t *testing.T) {
	up := &mockUpstream{err: assert.AnError}
	p := newTestProxy(t, baseManifest("read_file"), up)

	resp := p.Handle(context.Background(), toolCallReq(4, "read_file", nil))
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeInternalError, resp.Error.Code)
}

func TestProxy_RateLimit_BlocksAfterMax(t *testing.T) {
	up := &mockUpstream{}
	eng, err := policy.New()
	require.NoError(t, err)
	st, err := sqlitestore.New(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	p := New(Config{
		TenantID:  "t1",
		UserID:    "u1",
		SessionID: "session-rate",
		Manifest:  baseManifest("read_file"),
		Store:     st,
		Engine:    eng,
		Upstream:  up,
		RateLimit: 2, // only 2 calls per minute
		Budget: loop.BudgetConfig{
			MaxSteps:     1000,
			MaxToolCalls: 1000, // high limit so loop detector doesn't interfere
		},
	}, 0, nil)

	// First two calls must succeed — use distinct args to avoid identical-call loop detector.
	for i := 0; i < 2; i++ {
		args := map[string]any{"idx": i}
		resp := p.Handle(context.Background(), toolCallReq(i, "read_file", args))
		assert.Nil(t, resp.Error, "call %d should succeed", i)
	}
	// Third call must be rate-limited — rate limiter fires before policy.
	resp := p.Handle(context.Background(), toolCallReq(99, "read_file", map[string]any{"idx": 99}))
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodePolicyDeny, resp.Error.Code)
	data := resp.Error.Data.(map[string]any)
	assert.Equal(t, "RATE_LIMITED", data["reason"])
}

func TestProxy_AuditChainIntact(t *testing.T) {
	up := &mockUpstream{}
	eng, err := policy.New()
	require.NoError(t, err)
	st, err := sqlitestore.New(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	p := New(Config{
		TenantID:  "t1",
		UserID:    "u1",
		SessionID: "session-audit",
		Manifest:  baseManifest("read_file"),
		Store:     st,
		Engine:    eng,
		Upstream:  up,
	}, 0, nil)

	// Run a successful tool call (emits ToolCallProposed + ToolCallExecuted + ToolResult = 3 events)
	resp := p.Handle(context.Background(), toolCallReq(1, "read_file", nil))
	require.Nil(t, resp.Error)

	// Verify the chain.
	badSeq, err := st.VerifyChain(context.Background(), "t1", "session-audit")
	assert.NoError(t, err, "chain broken at seq %d", badSeq)
}

func TestProxy_NonToolMethod_PassThrough(t *testing.T) {
	up := &mockUpstream{result: json.RawMessage(`{"tools":[]}`)}
	p := newTestProxy(t, baseManifest(), up)

	req := &Request{JSONRPC: "2.0", ID: 5, Method: "tools/list"}
	resp := p.Handle(context.Background(), req)
	assert.Nil(t, resp.Error)
}
