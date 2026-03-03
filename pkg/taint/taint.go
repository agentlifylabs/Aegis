// Package taint implements Epic 08 taint tracking and prompt-injection controls.
//
// Taint sources:
//   - user_input: direct user-provided text
//   - tool_output: result from any external tool call
//   - memory_read: data retrieved from agent memory
//   - retrieved_doc: data from document retrieval
//
// Propagation rule: any model output derived from a tainted context inherits
// taint unless a SanitizedText event has been recorded for that content.
//
// High-risk sinks (default-deny when tainted):
//   - exec args
//   - filesystem write paths / content
//   - network destinations
//   - database writes
//
// Policy helpers exposed to Rego: is_tainted, requires_sanitization.
package taint

import (
	"fmt"
	"strings"
)

// ── Taint labels (stable string enum) ────────────────────────────────────────

const (
	LabelUserInput    = "user_input"
	LabelToolOutput   = "tool_output"
	LabelMemoryRead   = "memory_read"
	LabelRetrievedDoc = "retrieved_doc"
	LabelModelOutput  = "model_output" // propagated from tainted context
)

// HighRiskSinkPrefixes are tool-name prefixes considered high-risk sinks.
// Any tool whose name starts with one of these prefixes is a high-risk sink.
var HighRiskSinkPrefixes = []string{
	"exec",
	"fs.write",
	"write_file",
	"db.write",
	"database.write",
	"net.post",
	"net.put",
	"net.patch",
	"net.delete",
	"mcp.https.post",
	"mcp.https.put",
}

// ── Violation ─────────────────────────────────────────────────────────────────

// Violation is returned when a tainted value is about to flow into a high-risk sink.
type Violation struct {
	Reason      string   `json:"reason"`
	ToolName    string   `json:"tool_name"`
	TaintLabels []string `json:"taint_labels"`
	Detail      string   `json:"detail"`
}

func (v Violation) Error() string {
	return fmt.Sprintf("taint violation: %s tool=%s labels=%v", v.Reason, v.ToolName, v.TaintLabels)
}

const ReasonTaintedToHighRisk = "TAINTED_TO_HIGH_RISK"

// ── Tracker ───────────────────────────────────────────────────────────────────

// Tracker maintains the taint state for a single session.
// It is embedded in the reducer's SnapshotState (persisted as JSON).
type Tracker struct {
	// ActiveLabels is the current set of taint labels for this session context.
	ActiveLabels []string `json:"active_labels,omitempty"`

	// SanitizedKeys are keys/tokens for which a SanitizedText event has been
	// recorded; these bypass the high-risk-sink check.
	SanitizedKeys []string `json:"sanitized_keys,omitempty"`
}

// New creates an empty Tracker.
func New() *Tracker {
	return &Tracker{}
}

// AddLabel adds a taint label (idempotent).
func (t *Tracker) AddLabel(label string) {
	for _, l := range t.ActiveLabels {
		if l == label {
			return
		}
	}
	t.ActiveLabels = append(t.ActiveLabels, label)
}

// HasLabel reports whether the given label is currently active.
func (t *Tracker) HasLabel(label string) bool {
	for _, l := range t.ActiveLabels {
		if l == label {
			return true
		}
	}
	return false
}

// IsTainted reports whether any taint label is currently active.
func (t *Tracker) IsTainted() bool {
	return len(t.ActiveLabels) > 0
}

// RecordSanitization records that a sanitizer has processed content identified
// by key (e.g. a tool call ID or content hash). Future calls for this key
// bypass the taint sink check.
func (t *Tracker) RecordSanitization(key string) {
	for _, k := range t.SanitizedKeys {
		if k == key {
			return
		}
	}
	t.SanitizedKeys = append(t.SanitizedKeys, key)
}

// IsSanitized reports whether key has been through a sanitizer.
func (t *Tracker) IsSanitized(key string) bool {
	for _, k := range t.SanitizedKeys {
		if k == key {
			return true
		}
	}
	return false
}

// CheckSink evaluates a proposed tool call against the taint state.
// sanitizerKey is optional (empty = not sanitized). Returns a Violation if the
// call should be blocked.
func (t *Tracker) CheckSink(toolName, sanitizerKey string) *Violation {
	if !t.IsTainted() {
		return nil
	}
	if !IsHighRiskSink(toolName) {
		return nil
	}
	if sanitizerKey != "" && t.IsSanitized(sanitizerKey) {
		return nil
	}
	return &Violation{
		Reason:      ReasonTaintedToHighRisk,
		ToolName:    toolName,
		TaintLabels: append([]string{}, t.ActiveLabels...),
		Detail: fmt.Sprintf("tool %q is a high-risk sink; active taint labels: %s",
			toolName, strings.Join(t.ActiveLabels, ", ")),
	}
}

// PropagateModelOutput marks model output as tainted when the current context
// is already tainted (propagation rule).
func (t *Tracker) PropagateModelOutput() {
	if t.IsTainted() {
		t.AddLabel(LabelModelOutput)
	}
}

// Reset clears all taint labels and sanitized keys (call on session termination).
func (t *Tracker) Reset() {
	t.ActiveLabels = nil
	t.SanitizedKeys = nil
}

// ToMap returns the tracker state as a map suitable for Rego input.
func (t *Tracker) ToMap() map[string]any {
	labels := make([]any, len(t.ActiveLabels))
	for i, l := range t.ActiveLabels {
		labels[i] = l
	}
	sanitized := make([]any, len(t.SanitizedKeys))
	for i, k := range t.SanitizedKeys {
		sanitized[i] = k
	}
	return map[string]any{
		"active_labels":  labels,
		"sanitized_keys": sanitized,
		"is_tainted":     t.IsTainted(),
	}
}

// ── Package-level helpers (stateless, for use in policy/reducer) ──────────────

// IsHighRiskSink reports whether toolName is a high-risk sink.
func IsHighRiskSink(toolName string) bool {
	name := strings.ToLower(toolName)
	for _, prefix := range HighRiskSinkPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// LabelsFromEventType returns the taint labels that should be added when an
// event of the given type is processed (pure function, no state mutation).
func LabelsFromEventType(eventType string) []string {
	switch eventType {
	case "TOOL_RESULT":
		return []string{LabelToolOutput}
	case "MEMORY_READ":
		return []string{LabelMemoryRead}
	case "MODEL_CALL_FINISHED":
		return []string{} // propagation handled separately
	default:
		return nil
	}
}
