// Package proxy implements the Aegis MCP proxy (Epic 05).
// It intercepts MCP tools/call requests, evaluates them through the policy engine,
// emits audit events, and forwards allowed calls to the upstream MCP server.
//
// Supported transports: stdio (local) and Streamable HTTP.
package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/aegis-framework/aegis/pkg/eventlog"
	"github.com/aegis-framework/aegis/pkg/loop"
	"github.com/aegis-framework/aegis/pkg/manifest"
	"github.com/aegis-framework/aegis/pkg/policy"
	"github.com/aegis-framework/aegis/pkg/store"
	"github.com/aegis-framework/aegis/pkg/store/reducer"
)

// ── MCP message types (JSON-RPC 2.0 subset) ───────────────────────────────────

// Request is a JSON-RPC 2.0 request.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is a JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError is a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// MCP JSON-RPC error codes.
const (
	ErrCodeMethodNotFound  = -32601
	ErrCodeInvalidParams   = -32602
	ErrCodeInternalError   = -32603
	ErrCodePolicyDeny      = -32000 // Aegis extension: policy denied
	ErrCodeApprovalPending = -32001 // Aegis extension: approval required
)

// ToolCallParams is the params structure for tools/call.
type ToolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

// ── Upstream interface ────────────────────────────────────────────────────────

// Upstream is the interface for forwarding calls to a real MCP server.
type Upstream interface {
	// Call forwards a tools/call request and returns the raw result bytes or an error.
	Call(ctx context.Context, toolName string, args map[string]any) (json.RawMessage, error)
}

// ── Proxy ─────────────────────────────────────────────────────────────────────

// Config holds Proxy configuration.
type Config struct {
	TenantID  string
	UserID    string
	SessionID string
	Manifest  *manifest.Manifest
	Store     store.EventStore
	Engine    *policy.Engine
	Upstream  Upstream
	// RateLimit is the maximum tool calls per minute per (tenant, tool) pair.
	// 0 means unlimited.
	RateLimit int
	// Budget configures loop-detector limits for this session.
	// Zero values use the detector defaults (max_steps=24, max_tool_calls=12).
	Budget loop.BudgetConfig
}

// Proxy intercepts MCP requests, enforces policy, emits events, and forwards allowed calls.
type Proxy struct {
	cfg     Config
	builder *eventlog.Builder
	reducer *reducer.Reducer

	mu          sync.Mutex
	rateBuckets map[string]*tokenBucket // key: tenantID/toolName
}

// New creates a new Proxy. The builder seq starts at 0; pass nextSeq and prevHash
// to resume an existing session.
func New(cfg Config, nextSeq uint64, prevHash []byte) *Proxy {
	return &Proxy{
		cfg:         cfg,
		builder:     eventlog.NewBuilderFromSeq(cfg.TenantID, cfg.UserID, cfg.SessionID, nextSeq, prevHash),
		reducer:     reducer.NewWithBudget(cfg.TenantID, cfg.SessionID, cfg.Budget),
		rateBuckets: make(map[string]*tokenBucket),
	}
}

// Handle processes a single JSON-RPC request and returns the response.
// It is safe to call from multiple goroutines.
func (p *Proxy) Handle(ctx context.Context, req *Request) *Response {
	switch req.Method {
	case "tools/call":
		return p.handleToolCall(ctx, req)
	default:
		// Pass through non-tool methods without policy gating.
		return p.passThrough(ctx, req)
	}
}

func (p *Proxy) handleToolCall(ctx context.Context, req *Request) *Response {
	var params ToolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return errResponse(req.ID, ErrCodeInvalidParams, "invalid tools/call params", nil)
	}

	// ── 1. Emit ToolCallProposed ──────────────────────────────────────────────
	payload := map[string]any{
		"tool_name": params.Name,
		"args":      params.Arguments,
	}
	proposed, err := p.emit(ctx, eventlog.EventTypeToolCallProposed, payload)
	if err != nil {
		return errResponse(req.ID, ErrCodeInternalError, "emit proposed: "+err.Error(), nil)
	}

	// ── 2. Rate limit check ───────────────────────────────────────────────────
	if p.cfg.RateLimit > 0 {
		key := p.cfg.TenantID + "/" + params.Name
		p.mu.Lock()
		b, ok := p.rateBuckets[key]
		if !ok {
			b = newTokenBucket(p.cfg.RateLimit, time.Minute)
			p.rateBuckets[key] = b
		}
		allowed := b.Take()
		p.mu.Unlock()
		if !allowed {
			_ = p.emitDenied(ctx, params.Name, "RATE_LIMITED")
			return errResponse(req.ID, ErrCodePolicyDeny, "rate limit exceeded", map[string]any{
				"reason": "RATE_LIMITED",
				"tool":   params.Name,
			})
		}
	}

	// ── 3. Policy evaluation ──────────────────────────────────────────────────
	snap := &p.reducer.State
	decision, err := p.cfg.Engine.EvaluateEnvelope(ctx, proposed, snap, p.cfg.Manifest.ToMap())
	if err != nil {
		return errResponse(req.ID, ErrCodeInternalError, "policy eval: "+err.Error(), nil)
	}

	switch decision.Outcome {
	case policy.OutcomeDeny:
		_, _ = p.emit(ctx, eventlog.EventTypeToolCallDenied, map[string]any{
			"tool_name": params.Name,
			"reason":    decision.Reason,
		})
		return errResponse(req.ID, ErrCodePolicyDeny, "tool call denied", map[string]any{
			"reason": decision.Reason,
			"tool":   params.Name,
		})

	case policy.OutcomeRequireApproval:
		approvalToken := fmt.Sprintf("approval-%s-%d", p.cfg.SessionID, proposed.Seq)
		_, _ = p.emit(ctx, eventlog.EventTypeApprovalRequested, map[string]any{
			"tool_name":      params.Name,
			"approval_token": approvalToken,
		})
		return errResponse(req.ID, ErrCodeApprovalPending, "approval required", map[string]any{
			"approval_token": approvalToken,
			"tool":           params.Name,
		})
	}

	// ── 4. Forward to upstream ────────────────────────────────────────────────
	_, _ = p.emit(ctx, eventlog.EventTypeToolCallExecuted, map[string]any{
		"tool_name": params.Name,
	})

	result, upErr := p.cfg.Upstream.Call(ctx, params.Name, params.Arguments)
	if upErr != nil {
		_, _ = p.emit(ctx, eventlog.EventTypeErrorRaised, map[string]any{
			"tool_name": params.Name,
			"error":     upErr.Error(),
		})
		return errResponse(req.ID, ErrCodeInternalError, "upstream error: "+upErr.Error(), nil)
	}

	// ── 5. Emit ToolResult ────────────────────────────────────────────────────
	var resultAny any
	_ = json.Unmarshal(result, &resultAny)
	_, _ = p.emit(ctx, eventlog.EventTypeToolResult, map[string]any{
		"tool_name": params.Name,
		"result":    resultAny,
	})

	return &Response{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	}
}

func (p *Proxy) passThrough(ctx context.Context, req *Request) *Response {
	if p.cfg.Upstream == nil {
		return errResponse(req.ID, ErrCodeMethodNotFound, fmt.Sprintf("method %q not supported", req.Method), nil)
	}
	// Non-tool methods forwarded as-is; no audit event emitted.
	raw, err := p.cfg.Upstream.Call(ctx, req.Method, nil)
	if err != nil {
		return errResponse(req.ID, ErrCodeInternalError, err.Error(), nil)
	}
	return &Response{JSONRPC: "2.0", ID: req.ID, Result: raw}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func (p *Proxy) emit(ctx context.Context, et eventlog.EventType, payload any) (*eventlog.Envelope, error) {
	p.mu.Lock()
	env, err := p.builder.Append(et, payload)
	p.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if p.cfg.Store != nil {
		if storeErr := p.cfg.Store.AppendEvent(ctx, p.cfg.TenantID, env); storeErr != nil {
			return env, fmt.Errorf("store: %w", storeErr)
		}
	}
	// Drive reducer; persist snapshot if due.
	if snap, _ := p.reducer.Apply(env); snap != nil && p.cfg.Store != nil {
		_ = p.cfg.Store.SaveSnapshot(ctx, snap)
	}
	return env, nil
}

func (p *Proxy) emitDenied(ctx context.Context, toolName, reason string) error {
	_, err := p.emit(ctx, eventlog.EventTypeToolCallDenied, map[string]any{
		"tool_name": toolName,
		"reason":    reason,
	})
	return err
}

func errResponse(id any, code int, msg string, data any) *Response {
	return &Response{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &RPCError{Code: code, Message: msg, Data: data},
	}
}

// ── Token bucket rate limiter ─────────────────────────────────────────────────

type tokenBucket struct {
	mu       sync.Mutex
	tokens   int
	max      int
	interval time.Duration
	lastFill time.Time
}

func newTokenBucket(max int, interval time.Duration) *tokenBucket {
	return &tokenBucket{
		tokens:   max,
		max:      max,
		interval: interval,
		lastFill: time.Now(),
	}
}

// Take consumes one token. Returns false if the bucket is empty.
func (b *tokenBucket) Take() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if elapsed := now.Sub(b.lastFill); elapsed >= b.interval {
		b.tokens = b.max
		b.lastFill = now
	}
	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}
