// Package approval implements the Epic 07 approval router.
//
// Approval tokens are HMAC-SHA256 signed, time-limited references to a
// pending tool call. The router stores pending approvals in memory (with an
// optional persistence hook) and exposes methods for:
//   - Issuing a token for a pending tool call.
//   - Deciding (allow / deny / edit-args) on a token.
//   - Querying pending tokens (for CLI and webhook polling).
package approval

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ── Errors ────────────────────────────────────────────────────────────────────

var (
	ErrNotFound  = errors.New("approval: token not found")
	ErrExpired   = errors.New("approval: token expired")
	ErrDecided   = errors.New("approval: already decided")
)

// ── Token model ───────────────────────────────────────────────────────────────

// Status is the lifecycle state of a pending approval.
type Status string

const (
	StatusPending  Status = "PENDING"
	StatusAllowed  Status = "ALLOWED"
	StatusDenied   Status = "DENIED"
)

// PendingApproval is a single item awaiting a human decision.
type PendingApproval struct {
	Token     string         `json:"token"`
	SessionID string         `json:"session_id"`
	TenantID  string         `json:"tenant_id"`
	ToolName  string         `json:"tool_name"`
	OrigArgs  map[string]any `json:"orig_args"`
	CreatedMs int64          `json:"created_ms"`
	ExpiresMs int64          `json:"expires_ms"`
	Status    Status         `json:"status"`

	// Populated after decision.
	DecidedMs   int64          `json:"decided_ms,omitempty"`
	FinalArgs   map[string]any `json:"final_args,omitempty"` // may differ from OrigArgs if edited
	DeniedByMsg string         `json:"denied_by_msg,omitempty"`
}

// IsExpired reports whether the token has passed its expiry time.
func (p *PendingApproval) IsExpired(now time.Time) bool {
	return now.UnixMilli() > p.ExpiresMs
}

// ── Decision ──────────────────────────────────────────────────────────────────

// Decision is the payload for approving or denying a pending token.
type Decision struct {
	// Allow or deny.
	Allow bool `json:"allow"`
	// EditedArgs, if non-nil, replaces OrigArgs when Allow is true.
	// The edited args are the canonical call that will be executed.
	EditedArgs map[string]any `json:"edited_args,omitempty"`
	// Message is an optional human note attached to the decision.
	Message string `json:"message,omitempty"`
}

// ── Router ────────────────────────────────────────────────────────────────────

// Router manages pending approval tokens.
type Router struct {
	secret []byte        // HMAC signing key
	ttl    time.Duration // token TTL (default 10 min)

	mu      sync.RWMutex
	pending map[string]*PendingApproval // keyed by token
}

// New creates a Router with the given HMAC secret and token TTL.
// If ttl is zero, 10 minutes is used.
func New(secret []byte, ttl time.Duration) *Router {
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	return &Router{
		secret:  secret,
		ttl:     ttl,
		pending: make(map[string]*PendingApproval),
	}
}

// Issue creates and stores a new approval token for a pending tool call.
func (r *Router) Issue(tenantID, sessionID, toolName string, args map[string]any) (*PendingApproval, error) {
	now := time.Now()
	nonce, err := randomHex(8)
	if err != nil {
		return nil, fmt.Errorf("approval: nonce: %w", err)
	}
	payload := fmt.Sprintf("%s|%s|%s|%s|%d", tenantID, sessionID, toolName, nonce, now.UnixMilli())
	sig := sign(r.secret, payload)
	token := sig[:16] + "-" + nonce // 16-char sig prefix + nonce for readability

	ap := &PendingApproval{
		Token:     token,
		SessionID: sessionID,
		TenantID:  tenantID,
		ToolName:  toolName,
		OrigArgs:  args,
		CreatedMs: now.UnixMilli(),
		ExpiresMs: now.Add(r.ttl).UnixMilli(),
		Status:    StatusPending,
	}

	r.mu.Lock()
	r.pending[token] = ap
	r.mu.Unlock()
	return ap, nil
}

// Decide records a human decision on a pending token.
// Returns the updated PendingApproval and a *StagedPatch (non-nil when Allow=true
// and edited args differ from original args).
func (r *Router) Decide(token string, d Decision) (*PendingApproval, *StagedPatch, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ap, ok := r.pending[token]
	if !ok {
		return nil, nil, ErrNotFound
	}
	if ap.Status != StatusPending {
		return nil, nil, ErrDecided
	}
	if ap.IsExpired(time.Now()) {
		return nil, nil, ErrExpired
	}

	now := time.Now().UnixMilli()
	if d.Allow {
		ap.Status = StatusAllowed
		if d.EditedArgs != nil {
			ap.FinalArgs = d.EditedArgs
		} else {
			ap.FinalArgs = ap.OrigArgs
		}
	} else {
		ap.Status = StatusDenied
		ap.DeniedByMsg = d.Message
	}
	ap.DecidedMs = now

	// Build a staged patch if args were edited.
	var patch *StagedPatch
	if d.Allow && d.EditedArgs != nil {
		patch = &StagedPatch{
			Token:    token,
			OrigArgs: ap.OrigArgs,
			NewArgs:  d.EditedArgs,
			Diff:     buildArgsDiff(ap.OrigArgs, d.EditedArgs),
		}
	}

	return ap, patch, nil
}

// Get retrieves a pending approval by token (read-only).
func (r *Router) Get(token string) (*PendingApproval, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ap, ok := r.pending[token]
	if !ok {
		return nil, ErrNotFound
	}
	// Return a copy to avoid data races.
	cp := *ap
	return &cp, nil
}

// ListPending returns all currently PENDING (non-expired) approvals for a tenant.
func (r *Router) ListPending(tenantID string) []*PendingApproval {
	now := time.Now()
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*PendingApproval
	for _, ap := range r.pending {
		if ap.TenantID == tenantID && ap.Status == StatusPending && !ap.IsExpired(now) {
			cp := *ap
			out = append(out, &cp)
		}
	}
	return out
}

// Purge removes expired or decided tokens older than the given age.
func (r *Router) Purge(olderThan time.Duration) int {
	threshold := time.Now().Add(-olderThan).UnixMilli()
	r.mu.Lock()
	defer r.mu.Unlock()
	removed := 0
	for token, ap := range r.pending {
		if ap.Status != StatusPending && ap.DecidedMs < threshold {
			delete(r.pending, token)
			removed++
		}
		if ap.Status == StatusPending && ap.ExpiresMs < threshold {
			delete(r.pending, token)
			removed++
		}
	}
	return removed
}

// ── StagedPatch ───────────────────────────────────────────────────────────────

// StagedPatch represents an edited approval where arguments differ from the original.
// It is emitted as a diff record so the audit log captures the exact change.
type StagedPatch struct {
	Token    string           `json:"token"`
	OrigArgs map[string]any   `json:"orig_args"`
	NewArgs  map[string]any   `json:"new_args"`
	Diff     []ArgDiffEntry   `json:"diff"`
}

// ArgDiffEntry is a single key-level diff between original and edited args.
type ArgDiffEntry struct {
	Key    string `json:"key"`
	Op     string `json:"op"`  // "add", "remove", "change"
	Before any    `json:"before,omitempty"`
	After  any    `json:"after,omitempty"`
}

func buildArgsDiff(orig, edited map[string]any) []ArgDiffEntry {
	var diff []ArgDiffEntry
	for k, v := range edited {
		ov, exists := orig[k]
		if !exists {
			diff = append(diff, ArgDiffEntry{Key: k, Op: "add", After: v})
		} else if !jsonEqual(ov, v) {
			diff = append(diff, ArgDiffEntry{Key: k, Op: "change", Before: ov, After: v})
		}
	}
	for k, v := range orig {
		if _, exists := edited[k]; !exists {
			diff = append(diff, ArgDiffEntry{Key: k, Op: "remove", Before: v})
		}
	}
	return diff
}

func jsonEqual(a, b any) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}

// ── Renderer ──────────────────────────────────────────────────────────────────

// RenderPrompt returns a human-readable approval prompt for a pending approval.
func RenderPrompt(ap *PendingApproval) string {
	argsJSON, _ := json.MarshalIndent(ap.OrigArgs, "  ", "  ")
	return fmt.Sprintf(`Approval required
  Token:   %s
  Tenant:  %s
  Session: %s
  Tool:    %s
  Args:
  %s
  Expires: %s
  
  aegisctl approve %s --allow
  aegisctl approve %s --deny`,
		ap.Token,
		ap.TenantID,
		ap.SessionID,
		ap.ToolName,
		string(argsJSON),
		time.UnixMilli(ap.ExpiresMs).UTC().Format(time.RFC3339),
		ap.Token,
		ap.Token,
	)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func sign(secret []byte, payload string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
