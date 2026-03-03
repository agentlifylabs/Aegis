// Package policy wraps the embedded OPA runtime for Aegis decision evaluation.
// Every ToolCallProposed event is evaluated before the tool is forwarded upstream.
package policy

import (
	"context"
	"embed"
	"fmt"
	"io/fs"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"

	"github.com/aegis-framework/aegis/pkg/eventlog"
	"github.com/aegis-framework/aegis/pkg/store/reducer"
)

//go:embed bundle
var bundleFS embed.FS

// Outcome is the policy decision outcome.
type Outcome string

const (
	OutcomeAllow           Outcome = "allow"
	OutcomeDeny            Outcome = "deny"
	OutcomeRequireApproval Outcome = "require_approval"
)

// Reason codes emitted in policy decisions.
const (
	ReasonOK                  = "OK"
	ReasonPermissionUndeclared = "PERMISSION_UNDECLARED"
	ReasonEgressDeny          = "EGRESS_DENY"
	ReasonExecDeny            = "EXEC_DENY"
	ReasonBudgetExceeded      = "BUDGET_EXCEEDED"
	ReasonApprovalRequired    = "APPROVAL_REQUIRED"
	ReasonLoopDetected        = "LOOP_DETECTED"        // Epic 06
	ReasonTaintedToHighRisk   = "TAINTED_TO_HIGH_RISK" // Epic 08
)

// Decision is the full output of a policy evaluation.
type Decision struct {
	Outcome     Outcome        `json:"outcome"`
	Reason      string         `json:"reason"`
	Constraints map[string]any `json:"constraints"`
}

// Input is the structured input fed into the Rego policy.
type Input struct {
	Event    map[string]any `json:"event"`
	Snapshot map[string]any `json:"snapshot"`
	Manifest map[string]any `json:"manifest"`
}

// Engine is a compiled, reusable OPA policy evaluator.
type Engine struct {
	compiler *ast.Compiler
	store    storage.Store
}

// New loads and compiles the embedded policy bundle.
func New() (*Engine, error) {
	modules := map[string]*ast.Module{}

	err := fs.WalkDir(bundleFS, "bundle", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if len(path) < 5 || path[len(path)-5:] != ".rego" {
			return nil
		}
		raw, readErr := bundleFS.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("policy: read %s: %w", path, readErr)
		}
		mod, parseErr := ast.ParseModule(path, string(raw))
		if parseErr != nil {
			return fmt.Errorf("policy: parse %s: %w", path, parseErr)
		}
		modules[path] = mod
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("policy: walk bundle: %w", err)
	}

	compiler := ast.NewCompiler()
	compiler.Compile(modules)
	if compiler.Failed() {
		return nil, fmt.Errorf("policy: compile: %v", compiler.Errors)
	}

	return &Engine{
		compiler: compiler,
		store:    inmem.New(),
	}, nil
}

// Evaluate runs the decide policy against the given event, snapshot, and manifest.
func (e *Engine) Evaluate(ctx context.Context, in Input) (*Decision, error) {
	q := rego.New(
		rego.Query("data.aegis.decide.decision"),
		rego.Compiler(e.compiler),
		rego.Store(e.store),
		rego.Input(map[string]any{
			"event":    in.Event,
			"snapshot": in.Snapshot,
			"manifest": in.Manifest,
		}),
	)

	rs, err := q.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy: eval: %w", err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		// Undefined → deny by default.
		return &Decision{Outcome: OutcomeDeny, Reason: ReasonPermissionUndeclared, Constraints: nil}, nil
	}

	raw, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("policy: unexpected result type %T", rs[0].Expressions[0].Value)
	}

	d := &Decision{
		Outcome:     Outcome(str(raw["outcome"])),
		Reason:      str(raw["reason"]),
		Constraints: mapAny(raw["constraints"]),
	}
	return d, nil
}

// EvaluateEnvelope is a convenience wrapper that converts an Envelope + SnapshotState
// into the structured Input and calls Evaluate.
func (e *Engine) EvaluateEnvelope(
	ctx context.Context,
	env *eventlog.Envelope,
	snap *reducer.SnapshotState,
	manifest map[string]any,
) (*Decision, error) {
	evMap := map[string]any{
		"event_type": string(env.EventType),
		"seq":        env.Seq,
		"tenant_id":  env.TenantID,
		"session_id": env.SessionID,
		"payload":    env.Payload,
	}

	snapMap := map[string]any{}
	if snap != nil {
		snapMap = snap.PolicyInputSnapshot()
	}

	return e.Evaluate(ctx, Input{
		Event:    evMap,
		Snapshot: snapMap,
		Manifest: manifest,
	})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func mapAny(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}
