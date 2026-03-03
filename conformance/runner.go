// Package conformance implements Epic 12 — the Aegis conformance suite and compliance reports.
//
// Test definition format: YAML (tests only; never policy).
// Runner: executes against a live aegisd HTTP instance.
// Report: JSON with passed/failed tests, violated requirement IDs,
//
//	and evidence (event seq excerpts + policy explain codes).
//
// Conformance packs (v0.1):
//   - baseline-safety
//   - prompt-injection
//   - path-traversal
//   - telemetry-no-egress
//   - replay-determinism
//   - handoff-correctness
//
// Acceptance tests:
//   - Pack runs green on a reference-compliant aegisd.
//   - A deliberately "evil MCP server" fails with the expected reason codes.
package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ── Test definition format ────────────────────────────────────────────────────

// TestCase is a single conformance test loaded from YAML.
type TestCase struct {
	ID          string         `yaml:"id"`
	Description string         `yaml:"description"`
	ReqID       string         `yaml:"req_id"` // e.g. "SEC-001"
	Pack        string         `yaml:"pack"`
	Request     PolicyRequest  `yaml:"request"`
	Expect      Expectation    `yaml:"expect"`
}

// PolicyRequest mirrors the POST /v1/policy/decide body.
type PolicyRequest struct {
	Event    map[string]any `yaml:"event"`
	Snapshot map[string]any `yaml:"snapshot"`
	Manifest map[string]any `yaml:"manifest"`
}

// Expectation declares what a conformant server must return.
type Expectation struct {
	Outcome string `yaml:"outcome"` // "allow" | "deny" | "require_approval"
	Reason  string `yaml:"reason"`  // optional reason code substring
}

// Pack is a named collection of test cases.
type Pack struct {
	Name        string     `yaml:"name"`
	Description string     `yaml:"description"`
	Version     string     `yaml:"version"`
	Tests       []TestCase `yaml:"tests"`
}

// LoadPack parses a YAML conformance pack from r.
func LoadPack(r io.Reader) (*Pack, error) {
	var p Pack
	dec := yaml.NewDecoder(r)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("conformance: decode pack: %w", err)
	}
	if p.Name == "" {
		return nil, fmt.Errorf("conformance: pack missing name")
	}
	return &p, nil
}

// LoadPackBytes parses a YAML pack from a byte slice.
func LoadPackBytes(data []byte) (*Pack, error) {
	return LoadPack(bytes.NewReader(data))
}

// ── Result & Report ───────────────────────────────────────────────────────────

// Status of a single test.
type Status string

const (
	StatusPass Status = "PASS"
	StatusFail Status = "FAIL"
	StatusSkip Status = "SKIP"
)

// TestResult is the outcome of running one TestCase.
type TestResult struct {
	ID          string         `json:"id"`
	Pack        string         `json:"pack"`
	ReqID       string         `json:"req_id"`
	Description string         `json:"description"`
	Status      Status         `json:"status"`
	Outcome     string         `json:"outcome,omitempty"` // actual outcome from server
	Reason      string         `json:"reason,omitempty"`  // actual reason from server
	Expected    Expectation    `json:"expected"`
	Evidence    map[string]any `json:"evidence,omitempty"`
	Error       string         `json:"error,omitempty"`
}

// Report is the full machine-readable conformance report.
type Report struct {
	Pack          string       `json:"pack"`
	AegisdAddr    string       `json:"aegisd_addr"`
	RunAt         time.Time    `json:"run_at"`
	TotalTests    int          `json:"total_tests"`
	Passed        int          `json:"passed"`
	Failed        int          `json:"failed"`
	Skipped       int          `json:"skipped"`
	Compliant     bool         `json:"compliant"`
	Results       []TestResult `json:"results"`
	ViolatedReqs  []string     `json:"violated_reqs,omitempty"`
	BadgeMarkdown string       `json:"badge_markdown"`
}

// ── Runner ────────────────────────────────────────────────────────────────────

// Runner executes a conformance pack against a running aegisd.
type Runner struct {
	AegisdAddr string       // e.g. "http://localhost:8080"
	HTTPClient *http.Client // nil = default with 10s timeout
	// OnResult is called after each test (optional, for streaming output).
	OnResult func(TestResult)
}

func (r *Runner) client() *http.Client {
	if r.HTTPClient != nil {
		return r.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// Run executes all tests in pack and returns the Report.
func (r *Runner) Run(ctx context.Context, pack *Pack) (*Report, error) {
	report := &Report{
		Pack:       pack.Name,
		AegisdAddr: r.AegisdAddr,
		RunAt:      time.Now().UTC(),
		TotalTests: len(pack.Tests),
	}

	violatedReqs := make(map[string]bool)

	for _, tc := range pack.Tests {
		res := r.runOne(ctx, tc)
		report.Results = append(report.Results, res)
		switch res.Status {
		case StatusPass:
			report.Passed++
		case StatusFail:
			report.Failed++
			if res.ReqID != "" {
				violatedReqs[res.ReqID] = true
			}
		case StatusSkip:
			report.Skipped++
		}
		if r.OnResult != nil {
			r.OnResult(res)
		}
	}

	for req := range violatedReqs {
		report.ViolatedReqs = append(report.ViolatedReqs, req)
	}
	report.Compliant = report.Failed == 0
	report.BadgeMarkdown = generateBadge(pack.Name, report.Compliant, report.Passed, report.TotalTests)
	return report, nil
}

// runOne executes a single test case.
func (r *Runner) runOne(ctx context.Context, tc TestCase) TestResult {
	res := TestResult{
		ID:          tc.ID,
		Pack:        tc.Pack,
		ReqID:       tc.ReqID,
		Description: tc.Description,
		Expected:    tc.Expect,
	}

	// Build POST /v1/policy/decide body.
	body := map[string]any{
		"event":    tc.Request.Event,
		"snapshot": tc.Request.Snapshot,
		"manifest": tc.Request.Manifest,
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		res.Status = StatusFail
		res.Error = fmt.Sprintf("marshal request: %v", err)
		return res
	}

	url := strings.TrimRight(r.AegisdAddr, "/") + "/v1/policy/decide"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyJSON))
	if err != nil {
		res.Status = StatusFail
		res.Error = fmt.Sprintf("build request: %v", err)
		return res
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client().Do(req)
	if err != nil {
		res.Status = StatusFail
		res.Error = fmt.Sprintf("http: %v", err)
		return res
	}
	defer func() { _ = resp.Body.Close() }()

	var decision struct {
		Outcome string `json:"outcome"`
		Reason  string `json:"reason"`
	}
	if decErr := json.NewDecoder(resp.Body).Decode(&decision); decErr != nil {
		res.Status = StatusFail
		res.Error = fmt.Sprintf("decode response: %v", decErr)
		return res
	}

	res.Outcome = decision.Outcome
	res.Reason = decision.Reason
	res.Evidence = map[string]any{
		"outcome": decision.Outcome,
		"reason":  decision.Reason,
		"http_status": resp.StatusCode,
	}

	// Evaluate expectation.
	outcomeMatch := strings.EqualFold(decision.Outcome, tc.Expect.Outcome)
	reasonMatch := tc.Expect.Reason == "" ||
		strings.Contains(strings.ToUpper(decision.Reason), strings.ToUpper(tc.Expect.Reason))

	if outcomeMatch && reasonMatch {
		res.Status = StatusPass
	} else {
		res.Status = StatusFail
		if !outcomeMatch {
			res.Error = fmt.Sprintf("outcome: want %q got %q", tc.Expect.Outcome, decision.Outcome)
		} else {
			res.Error = fmt.Sprintf("reason: want substring %q got %q", tc.Expect.Reason, decision.Reason)
		}
	}
	return res
}

// ── Badge generator ───────────────────────────────────────────────────────────

// GenerateBadge returns a shields.io-style markdown badge snippet.
func GenerateBadge(packName string, compliant bool, passed, total int) string {
	return generateBadge(packName, compliant, passed, total)
}

func generateBadge(packName string, compliant bool, passed, total int) string {
	color := "brightgreen"
	label := "compliant"
	if !compliant {
		color = "red"
		label = "non-compliant"
	}
	// URL-encode the pack name for the badge label.
	safePack := strings.ReplaceAll(packName, " ", "%20")
	safePack = strings.ReplaceAll(safePack, "-", "--")
	msg := fmt.Sprintf("%d%%2F%d", passed, total)
	url := fmt.Sprintf("https://img.shields.io/badge/aegis%%3A%s-%s-%s", safePack, msg, color)
	return fmt.Sprintf("![Aegis %s %s](%s)", packName, label, url)
}

// ── ReportToJSON serializes a Report to indented JSON ─────────────────────────

// MarshalReport returns the canonical JSON for a Report.
func MarshalReport(report *Report) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}
