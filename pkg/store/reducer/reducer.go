// Package reducer implements the snapshot reducer (Epics 02, 06, 08).
// It applies events to a SnapshotState, producing a new snapshot at the
// configured cadence (every 50 events, on Termination, on ApprovalRequested).
// Epic 06: embeds LoopState for loop/budget detection.
// Epic 08: embeds TaintState for prompt-injection controls.
package reducer

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/aegis-framework/aegis/pkg/canon"
	"github.com/aegis-framework/aegis/pkg/eventlog"
	"github.com/aegis-framework/aegis/pkg/loop"
	"github.com/aegis-framework/aegis/pkg/store"
	"github.com/aegis-framework/aegis/pkg/taint"
)

const SnapshotCadence = 50 // snapshot every N events

// SnapshotState is the in-memory accumulated state for a session.
// It maps directly to the protobuf SnapshotState message.
type SnapshotState struct {
	Budgets               BudgetState            `json:"budgets"`
	ActiveToolPermissions []ActiveToolPermission  `json:"active_tool_permissions,omitempty"`
	LastOutcomes          LastOutcomes            `json:"last_outcomes"`
	TaintLabels           []string                `json:"taint_labels,omitempty"`
	Handoff               HandoffState            `json:"handoff"`

	// Epic 06: loop detection state.
	LoopViolation string `json:"loop_violation,omitempty"` // reason code when loop detected

	// Epic 08: taint tracking state (replaces the flat TaintLabels above for
	// new logic; TaintLabels kept for backwards compatibility).
	Taint taint.Tracker `json:"taint"`
}

// PolicyInputSnapshot returns a flat map with the fields read by the Rego policy.
// Keys match what decide.rego expects on input.snapshot.
func (s *SnapshotState) PolicyInputSnapshot() map[string]any {
	return map[string]any{
		"steps_consumed":      s.Budgets.StepsConsumed,
		"tool_calls_consumed": s.Budgets.ToolCallsConsumed,
		"wall_time_ms":        s.Budgets.WallTimeMs,
		"loop_violation":      s.LoopViolation,
		"is_tainted":          s.Taint.IsTainted(),
		"sanitized_keys":      s.Taint.SanitizedKeys,
	}
}

// BudgetState tracks consumption counters.
type BudgetState struct {
	StepsConsumed       uint32 `json:"steps_consumed"`
	ModelCallsConsumed  uint32 `json:"model_calls_consumed"`
	ToolCallsConsumed   uint32 `json:"tool_calls_consumed"`
	WallTimeMs          int64  `json:"wall_time_ms"`
	SessionStartMs      int64  `json:"session_start_ms"`
}

// ActiveToolPermission records a policy-granted tool permission.
type ActiveToolPermission struct {
	ToolName  string `json:"tool_name"`
	GrantedBy string `json:"granted_by"`
	ExpiresMs int64  `json:"expires_ms"` // 0 = session-scoped
}

// LastOutcomes tracks the most-recent outcomes for policy decisions.
type LastOutcomes struct {
	LastModelCallID  string `json:"last_model_call_id,omitempty"`
	LastToolCallID   string `json:"last_tool_call_id,omitempty"`
	LastToolName     string `json:"last_tool_name,omitempty"`
	LastToolWasError bool   `json:"last_tool_was_error"`
	LastPolicyOutcome string `json:"last_policy_outcome,omitempty"`
}

// HandoffState tracks cross-agent handoff.
type HandoffState struct {
	InHandoff  bool   `json:"in_handoff"`
	FromAgent  string `json:"from_agent,omitempty"`
	ToAgent    string `json:"to_agent,omitempty"`
	ContextID  string `json:"context_id,omitempty"`
}

// Reducer applies events to a SnapshotState and decides when to emit snapshots.
type Reducer struct {
	TenantID   string
	SessionID  string
	State      SnapshotState
	eventCount uint32 // events since last snapshot
	lastSeq    uint64

	// Epic 06: per-session loop detector.
	loopDetector *loop.Detector
}

// New creates a fresh Reducer for a new session.
func New(tenantID, sessionID string) *Reducer {
	return NewWithBudget(tenantID, sessionID, loop.BudgetConfig{})
}

// NewWithBudget creates a Reducer with a custom budget configuration.
func NewWithBudget(tenantID, sessionID string, budget loop.BudgetConfig) *Reducer {
	now := time.Now().UnixMilli()
	r := &Reducer{
		TenantID: tenantID,
		SessionID: sessionID,
		State: SnapshotState{
			Budgets: BudgetState{
				SessionStartMs: now,
			},
		},
		loopDetector: loop.New(budget),
	}
	r.loopDetector.SetSessionStart(now)
	return r
}

// NewFromSnapshot restores a Reducer from a persisted snapshot.
func NewFromSnapshot(tenantID, sessionID string, snap *store.Snapshot) (*Reducer, error) {
	var state SnapshotState
	if err := json.Unmarshal(snap.StateJSON, &state); err != nil {
		return nil, fmt.Errorf("reducer: unmarshal snapshot: %w", err)
	}
	return &Reducer{
		TenantID:  tenantID,
		SessionID: sessionID,
		State:     state,
		lastSeq:   snap.LastSeq,
	}, nil
}

// Apply updates the SnapshotState for the given event.
// Returns a *store.Snapshot when a snapshot should be persisted (nil otherwise).
func (r *Reducer) Apply(e *eventlog.Envelope) (*store.Snapshot, error) {
	if err := r.applyEvent(e); err != nil {
		return nil, err
	}
	r.lastSeq = e.Seq
	r.eventCount++

	// Decide whether to emit a snapshot.
	needsSnapshot := r.eventCount >= SnapshotCadence ||
		e.EventType == eventlog.EventTypeTermination ||
		e.EventType == eventlog.EventTypeApprovalRequested

	if !needsSnapshot {
		return nil, nil
	}

	snap, err := r.buildSnapshot(e.Seq, e.TsUnixMs)
	if err != nil {
		return nil, err
	}
	r.eventCount = 0
	return snap, nil
}

// Snapshot forces a snapshot regardless of cadence.
func (r *Reducer) Snapshot(seq uint64, tsMs int64) (*store.Snapshot, error) {
	return r.buildSnapshot(seq, tsMs)
}

func (r *Reducer) applyEvent(e *eventlog.Envelope) error {
	r.State.Budgets.StepsConsumed++

	switch e.EventType {
	case eventlog.EventTypeModelCallStarted:
		r.State.Budgets.ModelCallsConsumed++
		if payload, ok := e.Payload.(map[string]any); ok {
			if id, _ := payload["call_id"].(string); id != "" {
				r.State.LastOutcomes.LastModelCallID = id
			}
		}
		// Epic 06: model-call budget check.
		if r.loopDetector != nil {
			if v := r.loopDetector.RecordModelCall(e.Seq); v != nil {
				r.State.LoopViolation = string(v.Reason)
			}
		}

	case eventlog.EventTypeToolCallProposed:
		r.State.Budgets.ToolCallsConsumed++
		var toolName string
		var toolArgs any
		if payload, ok := e.Payload.(map[string]any); ok {
			if id, _ := payload["call_id"].(string); id != "" {
				r.State.LastOutcomes.LastToolCallID = id
			}
			if name, _ := payload["tool_name"].(string); name != "" {
				r.State.LastOutcomes.LastToolName = name
				toolName = name
			}
			toolArgs = payload["args"]
		}
		// Epic 06: run loop detector.
		if toolName != "" && r.loopDetector != nil {
			if v := r.loopDetector.RecordToolCall(e.Seq, toolName, toolArgs, "", e.TsUnixMs); v != nil {
				r.State.LoopViolation = string(v.Reason)
			}
		}

	case eventlog.EventTypeToolCallAllowed:
		if payload, ok := e.Payload.(map[string]any); ok {
			toolName := r.State.LastOutcomes.LastToolName
			policyRef, _ := payload["policy_ref"].(string)
			// Add to active permissions (avoid duplicates).
			found := false
			for _, p := range r.State.ActiveToolPermissions {
				if p.ToolName == toolName {
					found = true
					break
				}
			}
			if !found && toolName != "" {
				r.State.ActiveToolPermissions = append(r.State.ActiveToolPermissions, ActiveToolPermission{
					ToolName:  toolName,
					GrantedBy: policyRef,
				})
			}
		}

	case eventlog.EventTypeToolCallDenied:
		r.State.LastOutcomes.LastPolicyOutcome = "DENY"

	case eventlog.EventTypeToolResult:
		if payload, ok := e.Payload.(map[string]any); ok {
			isError, _ := payload["is_error"].(bool)
			r.State.LastOutcomes.LastToolWasError = isError
		}
		// Epic 08: tool results taint the context.
		r.State.Taint.AddLabel(taint.LabelToolOutput)
		r.addTaintLabel(taint.LabelToolOutput) // keep legacy field in sync

	case eventlog.EventTypePolicyDecision:
		if payload, ok := e.Payload.(map[string]any); ok {
			if outcome, _ := payload["outcome"].(string); outcome != "" {
				r.State.LastOutcomes.LastPolicyOutcome = outcome
			}
		}

	case eventlog.EventTypeMemoryRead:
		// Epic 08: memory reads taint the context.
		r.State.Taint.AddLabel(taint.LabelMemoryRead)
		r.addTaintLabel(taint.LabelMemoryRead)

	case eventlog.EventTypeHandoffRequested:
		if payload, ok := e.Payload.(map[string]any); ok {
			r.State.Handoff.InHandoff = true
			r.State.Handoff.FromAgent, _ = payload["from_agent"].(string)
			r.State.Handoff.ToAgent, _ = payload["to_agent"].(string)
			r.State.Handoff.ContextID, _ = payload["context_id"].(string)
		}

	case eventlog.EventTypeHandoffCompleted:
		r.State.Handoff.InHandoff = false

	case eventlog.EventTypeTermination:
		// Compute wall time.
		if r.State.Budgets.SessionStartMs > 0 {
			r.State.Budgets.WallTimeMs = e.TsUnixMs - r.State.Budgets.SessionStartMs
		}
		// Epic 08: reset taint on clean termination.
		r.State.Taint.Reset()
	}

	return nil
}

func (r *Reducer) addTaintLabel(label string) {
	for _, l := range r.State.TaintLabels {
		if l == label {
			return
		}
	}
	r.State.TaintLabels = append(r.State.TaintLabels, label)
}

func (r *Reducer) buildSnapshot(lastSeq uint64, tsMs int64) (*store.Snapshot, error) {
	stateJSON, err := json.Marshal(r.State)
	if err != nil {
		return nil, fmt.Errorf("reducer: marshal state: %w", err)
	}

	// Canonical hash of the state for tamper-evidence and replay verification.
	var stateAny any
	if err := json.Unmarshal(stateJSON, &stateAny); err != nil {
		return nil, fmt.Errorf("reducer: canonical unmarshal: %w", err)
	}
	snapHash, err := canon.Hash(stateAny)
	if err != nil {
		return nil, fmt.Errorf("reducer: hash state: %w", err)
	}

	return &store.Snapshot{
		TenantID:     r.TenantID,
		SessionID:    r.SessionID,
		LastSeq:      lastSeq,
		TsUnixMs:     tsMs,
		StateJSON:    stateJSON,
		SnapshotHash: snapHash,
	}, nil
}
