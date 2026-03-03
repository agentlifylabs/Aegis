// Package loop implements the Epic 06 loop detector and budget guard.
//
// Three loop conditions are detected:
//  1. Identical tool-call signature (tool_name + canonical args hash) repeated >= 2 times.
//  2. Snapshot hash unchanged for >= 3 consecutive ToolCallProposed events (no progress).
//  3. A repeating sequence of tool names of length 3–7 occurring twice in the recent window.
//
// A violation produces a LoopViolation value with reason code, action, and a minimal
// cycle trace (event seq numbers). The caller may then emit a TERMINATION event.
package loop

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// TerminationReason is the stable enum of stop reasons (Epic 06 taxonomy).
type TerminationReason string

const (
	ReasonBudgetSteps     TerminationReason = "BUDGET_STEPS_EXCEEDED"
	ReasonBudgetToolCalls TerminationReason = "BUDGET_TOOL_CALLS_EXCEEDED"
	ReasonBudgetWallTime  TerminationReason = "BUDGET_WALL_TIME_EXCEEDED"
	ReasonBudgetModelCalls TerminationReason = "BUDGET_MODEL_CALLS_EXCEEDED"
	ReasonLoopIdentical   TerminationReason = "LOOP_IDENTICAL_CALL"
	ReasonLoopNoProgress  TerminationReason = "LOOP_NO_PROGRESS"
	ReasonLoopSequence    TerminationReason = "LOOP_REPEATING_SEQUENCE"
)

// Action is the recommended action to take on a violation.
type Action string

const (
	ActionStop            Action = "STOP"
	ActionRequireApproval Action = "REQUIRE_APPROVAL"
	ActionDowngrade       Action = "DOWNGRADE"
)

// LoopViolation describes a detected loop or budget breach.
type LoopViolation struct {
	Reason     TerminationReason `json:"reason"`
	Action     Action            `json:"action"`
	CycleTrace []uint64          `json:"cycle_trace"` // seq numbers forming the cycle
	Detail     string            `json:"detail"`
}

func (v LoopViolation) Error() string {
	return fmt.Sprintf("loop violation: %s (%s) seqs=%v", v.Reason, v.Action, v.CycleTrace)
}

// ── BudgetConfig ──────────────────────────────────────────────────────────────

// BudgetConfig holds per-session limits. Zero means "use default".
type BudgetConfig struct {
	MaxSteps       uint32 // default 24
	MaxToolCalls   uint32 // default 12
	MaxModelCalls  uint32 // default 0 (unlimited)
	MaxWallTimeMs  int64  // default 120_000
}

func (b BudgetConfig) maxSteps() uint32 {
	if b.MaxSteps == 0 {
		return 24
	}
	return b.MaxSteps
}

func (b BudgetConfig) maxToolCalls() uint32 {
	if b.MaxToolCalls == 0 {
		return 12
	}
	return b.MaxToolCalls
}

func (b BudgetConfig) maxWallTimeMs() int64 {
	if b.MaxWallTimeMs == 0 {
		return 120_000
	}
	return b.MaxWallTimeMs
}

// ── ToolCallRecord ────────────────────────────────────────────────────────────

// ToolCallRecord captures a single tool call for loop detection.
type ToolCallRecord struct {
	Seq      uint64
	ToolName string
	ArgsHash string // SHA-256 of canonical args
}

// ── Detector ─────────────────────────────────────────────────────────────────

// Detector is stateful; one instance per session.
type Detector struct {
	Budget       BudgetConfig
	history      []ToolCallRecord // ordered ring for sequence detection
	snapshotSeqs []uint64         // seqs where snapshot hash was same as first
	lastSnapHash string
	snapInitialized bool

	stepsConsumed      uint32
	toolCallsConsumed  uint32
	modelCallsConsumed uint32
	sessionStartMs     int64
	startInitialized   bool
}

// New creates a fresh Detector.
func New(budget BudgetConfig) *Detector {
	return &Detector{Budget: budget}
}

// SetSessionStart sets the wall-clock start time (call once at session init).
func (d *Detector) SetSessionStart(tsMs int64) {
	if !d.startInitialized {
		d.sessionStartMs = tsMs
		d.startInitialized = true
	}
}

// RecordStep increments the step counter and checks budget.
func (d *Detector) RecordStep(seq uint64) *LoopViolation {
	d.stepsConsumed++
	if d.stepsConsumed > d.Budget.maxSteps() {
		return &LoopViolation{
			Reason:     ReasonBudgetSteps,
			Action:     ActionStop,
			CycleTrace: []uint64{seq},
			Detail:     fmt.Sprintf("steps=%d limit=%d", d.stepsConsumed, d.Budget.maxSteps()),
		}
	}
	return nil
}

// RecordModelCall increments the model-call counter and checks budget.
func (d *Detector) RecordModelCall(seq uint64) *LoopViolation {
	d.modelCallsConsumed++
	if d.Budget.MaxModelCalls > 0 && d.modelCallsConsumed > d.Budget.MaxModelCalls {
		return &LoopViolation{
			Reason:     ReasonBudgetModelCalls,
			Action:     ActionStop,
			CycleTrace: []uint64{seq},
			Detail:     fmt.Sprintf("model_calls=%d limit=%d", d.modelCallsConsumed, d.Budget.MaxModelCalls),
		}
	}
	return nil
}

// RecordToolCall records a tool call and checks all three loop conditions plus tool-call budget.
// args may be nil.
func (d *Detector) RecordToolCall(seq uint64, toolName string, args any, snapHash string, tsMs int64) *LoopViolation {
	d.toolCallsConsumed++

	// Budget: tool calls.
	if d.toolCallsConsumed > d.Budget.maxToolCalls() {
		return &LoopViolation{
			Reason:     ReasonBudgetToolCalls,
			Action:     ActionStop,
			CycleTrace: []uint64{seq},
			Detail:     fmt.Sprintf("tool_calls=%d limit=%d", d.toolCallsConsumed, d.Budget.maxToolCalls()),
		}
	}

	// Budget: wall time.
	if d.startInitialized && tsMs > 0 {
		elapsed := tsMs - d.sessionStartMs
		if elapsed > d.Budget.maxWallTimeMs() {
			return &LoopViolation{
				Reason:     ReasonBudgetWallTime,
				Action:     ActionStop,
				CycleTrace: []uint64{seq},
				Detail:     fmt.Sprintf("wall_time_ms=%d limit=%d", elapsed, d.Budget.maxWallTimeMs()),
			}
		}
	}

	argsHash := hashArgs(args)
	rec := ToolCallRecord{Seq: seq, ToolName: toolName, ArgsHash: argsHash}
	d.history = append(d.history, rec)

	// Keep history bounded to avoid unbounded growth (last 20 entries sufficient).
	const windowMax = 20
	if len(d.history) > windowMax {
		d.history = d.history[len(d.history)-windowMax:]
	}

	// Condition 3: repeating tool-name sequence (length 3–7, repeated twice).
	// Checked first so it takes priority over the identical-call check when
	// a sequence pattern has just completed its second cycle.
	if v := d.checkSequence(seq); v != nil {
		return v
	}

	// Condition 1: identical tool-call signature repeated >= 2.
	if v := d.checkIdentical(seq, toolName, argsHash); v != nil {
		return v
	}

	// Condition 2: snapshot hash unchanged for >= 3 steps.
	if v := d.checkNoProgress(seq, snapHash); v != nil {
		return v
	}

	return nil
}

// ── condition checkers ────────────────────────────────────────────────────────

func (d *Detector) checkIdentical(seq uint64, toolName, argsHash string) *LoopViolation {
	var prev []uint64
	for _, r := range d.history[:len(d.history)-1] { // exclude just-added
		if r.ToolName == toolName && r.ArgsHash == argsHash {
			prev = append(prev, r.Seq)
		}
	}
	if len(prev) >= 1 {
		return &LoopViolation{
			Reason:     ReasonLoopIdentical,
			Action:     ActionRequireApproval,
			CycleTrace: append(prev, seq),
			Detail:     fmt.Sprintf("tool=%s repeated %d times", toolName, len(prev)+1),
		}
	}
	return nil
}

func (d *Detector) checkNoProgress(seq uint64, snapHash string) *LoopViolation {
	if snapHash == "" {
		return nil
	}
	if !d.snapInitialized {
		// Record the very first hash and count it as step 1.
		d.lastSnapHash = snapHash
		d.snapInitialized = true
		d.snapshotSeqs = []uint64{seq}
		return nil
	}
	if snapHash == d.lastSnapHash {
		d.snapshotSeqs = append(d.snapshotSeqs, seq)
	} else {
		// Hash changed — progress made; reset.
		d.snapshotSeqs = []uint64{seq}
		d.lastSnapHash = snapHash
	}
	if len(d.snapshotSeqs) >= 3 {
		trace := make([]uint64, len(d.snapshotSeqs))
		copy(trace, d.snapshotSeqs)
		return &LoopViolation{
			Reason:     ReasonLoopNoProgress,
			Action:     ActionRequireApproval,
			CycleTrace: trace,
			Detail:     fmt.Sprintf("snapshot_hash=%s unchanged for %d steps", snapHash, len(trace)),
		}
	}
	return nil
}

func (d *Detector) checkSequence(seq uint64) *LoopViolation {
	names := make([]string, len(d.history))
	seqs := make([]uint64, len(d.history))
	for i, r := range d.history {
		names[i] = r.ToolName
		seqs[i] = r.Seq
	}
	n := len(names)
	for seqLen := 3; seqLen <= 7; seqLen++ {
		if n < seqLen*2 {
			continue
		}
		// Check if the last seqLen elements equal the seqLen elements before them.
		last := names[n-seqLen:]
		prev := names[n-seqLen*2 : n-seqLen]
		if slicesEqual(last, prev) {
			trace := seqs[n-seqLen*2:]
			return &LoopViolation{
				Reason:     ReasonLoopSequence,
				Action:     ActionRequireApproval,
				CycleTrace: append([]uint64{}, trace...),
				Detail:     fmt.Sprintf("repeating tool sequence len=%d: %v", seqLen, last),
			}
		}
	}
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func hashArgs(args any) string {
	if args == nil {
		return ""
	}
	b, err := json.Marshal(args)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8]) // 8-byte prefix is enough for identity detection
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
