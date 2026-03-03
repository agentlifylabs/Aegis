package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// mockAegisd starts a test HTTP server that responds to POST /v1/policy/decide.
// decideFunc receives the raw request body and returns (outcome, reason).
func mockAegisd(t *testing.T, decideFunc func(body map[string]any) (string, string)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/policy/decide" {
			http.NotFound(w, r)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		outcome, reason := decideFunc(body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"outcome": outcome,
			"reason":  reason,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// referenceServer is a mock that behaves like a compliant aegisd:
// - declared read_file → allow
// - undeclared / exec / high-risk → deny with appropriate reason codes
// - tainted + high-risk sink → TAINTED_TO_HIGH_RISK
// - loop_violation in snapshot → LOOP_DETECTED
// - budget exceeded → BUDGET_EXCEEDED
func referenceServer(t *testing.T) *httptest.Server {
	t.Helper()
	return mockAegisd(t, func(body map[string]any) (string, string) {
		event, _ := body["event"].(map[string]any)
		snapshot, _ := body["snapshot"].(map[string]any)
		manifest, _ := body["manifest"].(map[string]any)

		toolName := ""
		if payload, ok := event["payload"].(map[string]any); ok {
			toolName, _ = payload["tool_name"].(string)
		}

		// Budget check.
		if snapshot != nil {
			stepsRaw := snapshot["steps_consumed"]
			toolCallsRaw := snapshot["tool_calls_consumed"]
			wallRaw := snapshot["wall_time_ms"]
			steps := toInt(stepsRaw)
			toolCalls := toInt(toolCallsRaw)
			wall := toInt(wallRaw)

			maxSteps, maxTools, maxWall := 24, 12, 120000
			if manifest != nil {
				if perms, ok := manifest["permissions"].(map[string]any); ok {
					if budgets, ok := perms["budgets"].(map[string]any); ok {
						if v := toInt(budgets["max_steps"]); v > 0 {
							maxSteps = v
						}
						if v := toInt(budgets["max_tool_calls"]); v > 0 {
							maxTools = v
						}
						if v := toInt(budgets["max_wall_time_ms"]); v > 0 {
							maxWall = v
						}
					}
				}
			}
			if steps >= maxSteps || toolCalls >= maxTools || wall >= maxWall {
				return "deny", "BUDGET_EXCEEDED"
			}

			// Loop violation.
			if lv, _ := snapshot["loop_violation"].(string); lv != "" {
				return "deny", "LOOP_DETECTED"
			}

			// Taint + high-risk sink.
			isTainted, _ := snapshot["is_tainted"].(bool)
			highRiskSinks := map[string]bool{
				"exec": true, "fs.write": true, "write_file": true,
				"db.write": true, "net.post": true, "exec_shell": true,
			}
			if isTainted && highRiskSinks[toolName] {
				return "deny", "TAINTED_TO_HIGH_RISK"
			}
		}

		// Permission check — only declared tools are allowed.
		if manifest != nil {
			perms, _ := manifest["permissions"].(map[string]any)
			tools, _ := perms["tools"].([]any)
			declared := make(map[string]bool)
			for _, t := range tools {
				if s, ok := t.(string); ok {
					declared[s] = true
				}
			}

			highRisk := map[string]bool{
				"exec": true, "exec_shell": true,
				"mcp.http": true, "mcp.https": true,
				"net": true, "net.post": true,
				"fs.write": true, "write_file": true, "db.write": true,
			}
			if !declared[toolName] {
				if highRisk[toolName] {
					return "deny", "PERMISSION_UNDECLARED"
				}
				return "deny", "PERMISSION_UNDECLARED"
			}
		}

		return "allow", "OK"
	})
}

// evilServer always allows everything — simulates a non-compliant aegisd.
func evilServer(t *testing.T) *httptest.Server {
	t.Helper()
	return mockAegisd(t, func(_ map[string]any) (string, string) {
		return "allow", "OK"
	})
}

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	}
	return 0
}

// ── LoadPack ──────────────────────────────────────────────────────────────────

func TestLoadPack_ValidYAML(t *testing.T) {
	yaml := `
name: test-pack
description: A test pack
version: "0.1"
tests:
  - id: T-001
    pack: test-pack
    req_id: R-001
    description: Test case
    request:
      event:
        event_type: TOOL_CALL_PROPOSED
        payload:
          tool_name: read_file
      snapshot: {}
      manifest: {}
    expect:
      outcome: allow
`
	pack, err := LoadPackBytes([]byte(yaml))
	require.NoError(t, err)
	assert.Equal(t, "test-pack", pack.Name)
	require.Len(t, pack.Tests, 1)
	assert.Equal(t, "T-001", pack.Tests[0].ID)
	assert.Equal(t, "allow", pack.Tests[0].Expect.Outcome)
}

func TestLoadPack_MissingName_Error(t *testing.T) {
	yaml := `description: no name here\ntests: []`
	_, err := LoadPackBytes([]byte(yaml))
	assert.Error(t, err)
}

func TestLoadPack_EmptyTests(t *testing.T) {
	yaml := "name: empty\ndescription: x\nversion: \"0.1\"\ntests: []\n"
	pack, err := LoadPackBytes([]byte(yaml))
	require.NoError(t, err)
	assert.Empty(t, pack.Tests)
}

// ── Runner: reference server ──────────────────────────────────────────────────

// Acceptance test: conformance pack runs green on a reference-compliant aegisd.
func TestRunner_BaselineSafety_PassesOnReferenceServer(t *testing.T) {
	srv := referenceServer(t)
	runner := &Runner{AegisdAddr: srv.URL}

	pack, err := LoadPackBytes(baselineSafetyYAML)
	require.NoError(t, err)

	report, err := runner.Run(context.Background(), pack)
	require.NoError(t, err)

	assert.True(t, report.Compliant, "reference server must be compliant with baseline-safety")
	assert.Empty(t, report.ViolatedReqs)
	assert.Equal(t, report.Passed, report.TotalTests)
}

func TestRunner_PromptInjection_PassesOnReferenceServer(t *testing.T) {
	srv := referenceServer(t)
	runner := &Runner{AegisdAddr: srv.URL}

	pack, err := LoadPackBytes(promptInjectionYAML)
	require.NoError(t, err)

	report, err := runner.Run(context.Background(), pack)
	require.NoError(t, err)

	assert.True(t, report.Compliant)
	assert.Equal(t, report.Passed, report.TotalTests)
}

func TestRunner_ReplayDeterminism_PassesOnReferenceServer(t *testing.T) {
	srv := referenceServer(t)
	runner := &Runner{AegisdAddr: srv.URL}

	pack, err := LoadPackBytes(replayDeterminismYAML)
	require.NoError(t, err)

	report, err := runner.Run(context.Background(), pack)
	require.NoError(t, err)

	assert.True(t, report.Compliant)
}

// Acceptance test: deliberately "evil MCP server" fails with expected reason codes.
func TestRunner_BaselineSafety_FailsOnEvilServer(t *testing.T) {
	srv := evilServer(t) // always allows
	runner := &Runner{AegisdAddr: srv.URL}

	pack, err := LoadPackBytes(baselineSafetyYAML)
	require.NoError(t, err)

	report, err := runner.Run(context.Background(), pack)
	require.NoError(t, err)

	// Evil server allows everything — all deny-expected tests must fail.
	assert.False(t, report.Compliant, "evil server must not be compliant")
	assert.Greater(t, report.Failed, 0)
	assert.NotEmpty(t, report.ViolatedReqs)
}

func TestRunner_EvilServer_FailsWithExpectedReasonCodes(t *testing.T) {
	srv := evilServer(t)
	runner := &Runner{AegisdAddr: srv.URL}

	pack, err := LoadPackBytes(baselineSafetyYAML)
	require.NoError(t, err)

	report, err := runner.Run(context.Background(), pack)
	require.NoError(t, err)

	// Collect all failed test IDs — must include BS-001 (undeclared tool deny).
	failedIDs := make(map[string]bool)
	for _, r := range report.Results {
		if r.Status == StatusFail {
			failedIDs[r.ID] = true
		}
	}
	assert.True(t, failedIDs["BS-001"], "BS-001 (undeclared tool must be denied) must fail on evil server")
	assert.True(t, failedIDs["BS-004"], "BS-004 (budget exceeded must be denied) must fail on evil server")
}

// ── Runner: report shape ──────────────────────────────────────────────────────

func TestReport_MarshalJSON_IsValid(t *testing.T) {
	srv := referenceServer(t)
	runner := &Runner{AegisdAddr: srv.URL}

	pack, err := LoadPackBytes(baselineSafetyYAML)
	require.NoError(t, err)

	report, err := runner.Run(context.Background(), pack)
	require.NoError(t, err)

	b, err := MarshalReport(report)
	require.NoError(t, err)

	var roundTrip Report
	require.NoError(t, json.Unmarshal(b, &roundTrip))
	assert.Equal(t, report.Pack, roundTrip.Pack)
	assert.Equal(t, report.TotalTests, roundTrip.TotalTests)
	assert.Equal(t, report.Compliant, roundTrip.Compliant)
}

func TestReport_ContainsEvidencePerResult(t *testing.T) {
	srv := referenceServer(t)
	runner := &Runner{AegisdAddr: srv.URL}

	pack, err := LoadPackBytes(baselineSafetyYAML)
	require.NoError(t, err)

	report, err := runner.Run(context.Background(), pack)
	require.NoError(t, err)

	for _, res := range report.Results {
		if res.Status != StatusSkip {
			assert.NotNil(t, res.Evidence, "every executed test must have evidence")
		}
	}
}

func TestReport_ViolatedReqs_UniqueAndSorted(t *testing.T) {
	srv := evilServer(t)
	runner := &Runner{AegisdAddr: srv.URL}

	pack, err := LoadPackBytes(baselineSafetyYAML)
	require.NoError(t, err)

	report, err := runner.Run(context.Background(), pack)
	require.NoError(t, err)

	seen := make(map[string]bool)
	for _, req := range report.ViolatedReqs {
		assert.False(t, seen[req], "violated reqs must be unique, got duplicate %q", req)
		seen[req] = true
	}
}

// ── Badge generator ───────────────────────────────────────────────────────────

func TestBadge_Compliant(t *testing.T) {
	badge := GenerateBadge("baseline-safety", true, 5, 5)
	assert.Contains(t, badge, "![Aegis baseline-safety")
	assert.Contains(t, badge, "compliant")
	assert.Contains(t, badge, "brightgreen")
}

func TestBadge_NonCompliant(t *testing.T) {
	badge := GenerateBadge("baseline-safety", false, 3, 5)
	assert.Contains(t, badge, "non-compliant")
	assert.Contains(t, badge, "red")
}

func TestBadge_IsMarkdown(t *testing.T) {
	badge := GenerateBadge("my-pack", true, 10, 10)
	assert.True(t, strings.HasPrefix(badge, "!["))
	assert.Contains(t, badge, "](https://")
}

// ── OnResult callback ─────────────────────────────────────────────────────────

func TestRunner_OnResult_CalledForEachTest(t *testing.T) {
	srv := referenceServer(t)
	var called []string
	runner := &Runner{
		AegisdAddr: srv.URL,
		OnResult: func(r TestResult) {
			called = append(called, r.ID)
		},
	}

	pack, err := LoadPackBytes(baselineSafetyYAML)
	require.NoError(t, err)

	report, err := runner.Run(context.Background(), pack)
	require.NoError(t, err)
	assert.Len(t, called, report.TotalTests)
}

// ── Embedded YAML for unit tests (inline, avoids file I/O in tests) ───────────

var baselineSafetyYAML = []byte(fmt.Sprintf(`
name: baseline-safety
description: Core deny-by-default safety requirements.
version: "0.1"
tests:
  - id: BS-001
    pack: baseline-safety
    req_id: SEC-001
    description: Undeclared tool is denied
    request:
      event:
        event_type: TOOL_CALL_PROPOSED
        payload:
          tool_name: write_file
          call_id: t1
          args: {}
      snapshot: {}
      manifest:
        schema: "%s"
        name: test-skill
        version: "0.1.0"
        publisher: acme
        permissions:
          tools: ["read_file"]
          budgets: {}
        sandbox:
          required: false
        integrity: {}
    expect:
      outcome: deny
      reason: PERMISSION_UNDECLARED

  - id: BS-002
    pack: baseline-safety
    req_id: SEC-002
    description: Declared read-only tool is allowed
    request:
      event:
        event_type: TOOL_CALL_PROPOSED
        payload:
          tool_name: read_file
          call_id: t2
          args: {path: "/workspace/data.txt"}
      snapshot:
        steps_consumed: 1
        tool_calls_consumed: 1
        wall_time_ms: 100
      manifest:
        schema: "%s"
        name: test-skill
        version: "0.1.0"
        publisher: acme
        permissions:
          tools: ["read_file"]
          budgets:
            max_steps: 24
            max_tool_calls: 12
            max_wall_time_ms: 120000
        sandbox:
          required: false
        integrity: {}
    expect:
      outcome: allow

  - id: BS-003
    pack: baseline-safety
    req_id: SEC-003
    description: exec tool denied without declaration
    request:
      event:
        event_type: TOOL_CALL_PROPOSED
        payload:
          tool_name: exec
          call_id: t3
          args: {cmd: "ls"}
      snapshot: {}
      manifest:
        schema: "%s"
        name: test-skill
        version: "0.1.0"
        publisher: acme
        permissions:
          tools: ["read_file"]
          budgets: {}
        sandbox:
          required: false
        integrity: {}
    expect:
      outcome: deny

  - id: BS-004
    pack: baseline-safety
    req_id: SEC-004
    description: Budget exceeded on steps is denied
    request:
      event:
        event_type: TOOL_CALL_PROPOSED
        payload:
          tool_name: read_file
          call_id: t4
          args: {}
      snapshot:
        steps_consumed: 25
        tool_calls_consumed: 1
        wall_time_ms: 100
      manifest:
        schema: "%s"
        name: test-skill
        version: "0.1.0"
        publisher: acme
        permissions:
          tools: ["read_file"]
          budgets:
            max_steps: 24
            max_tool_calls: 12
            max_wall_time_ms: 120000
        sandbox:
          required: false
        integrity: {}
    expect:
      outcome: deny
      reason: BUDGET_EXCEEDED
`, schemaV, schemaV, schemaV, schemaV))

var promptInjectionYAML = []byte(fmt.Sprintf(`
name: prompt-injection
description: Taint tracking conformance.
version: "0.1"
tests:
  - id: PI-001
    pack: prompt-injection
    req_id: TI-001
    description: Tainted context to high-risk sink is denied
    request:
      event:
        event_type: TOOL_CALL_PROPOSED
        payload:
          tool_name: exec
          call_id: t1
          args: {cmd: "rm -rf /"}
      snapshot:
        is_tainted: true
        sanitized_keys: []
        steps_consumed: 1
        tool_calls_consumed: 1
        wall_time_ms: 100
      manifest:
        schema: "%s"
        name: test-skill
        version: "0.1.0"
        publisher: acme
        permissions:
          tools: ["exec"]
          budgets:
            max_steps: 24
            max_tool_calls: 12
            max_wall_time_ms: 120000
        sandbox:
          required: true
        integrity: {}
    expect:
      outcome: deny
      reason: TAINTED_TO_HIGH_RISK

  - id: PI-002
    pack: prompt-injection
    req_id: TI-002
    description: Untainted context to exec is allowed when declared
    request:
      event:
        event_type: TOOL_CALL_PROPOSED
        payload:
          tool_name: exec
          call_id: t2
          args: {cmd: "ls"}
      snapshot:
        is_tainted: false
        sanitized_keys: []
        steps_consumed: 1
        tool_calls_consumed: 1
        wall_time_ms: 100
      manifest:
        schema: "%s"
        name: test-skill
        version: "0.1.0"
        publisher: acme
        permissions:
          tools: ["exec"]
          budgets:
            max_steps: 24
            max_tool_calls: 12
            max_wall_time_ms: 120000
        sandbox:
          required: true
        integrity: {}
    expect:
      outcome: allow
`, schemaV, schemaV))

var replayDeterminismYAML = []byte(fmt.Sprintf(`
name: replay-determinism
description: Deterministic policy decisions.
version: "0.1"
tests:
  - id: RD-001
    pack: replay-determinism
    req_id: REP-001
    description: Same event always produces same outcome (allow)
    request:
      event:
        event_type: TOOL_CALL_PROPOSED
        payload:
          tool_name: read_file
          call_id: t1
          args: {path: "/workspace/file.txt"}
      snapshot:
        steps_consumed: 3
        tool_calls_consumed: 2
        wall_time_ms: 500
        is_tainted: false
        loop_violation: ""
      manifest:
        schema: "%s"
        name: test-skill
        version: "0.1.0"
        publisher: acme
        permissions:
          tools: ["read_file"]
          budgets:
            max_steps: 24
            max_tool_calls: 12
            max_wall_time_ms: 120000
        sandbox:
          required: false
        integrity: {}
    expect:
      outcome: allow

  - id: RD-002
    pack: replay-determinism
    req_id: REP-002
    description: Loop violation always produces deny
    request:
      event:
        event_type: TOOL_CALL_PROPOSED
        payload:
          tool_name: read_file
          call_id: t2
          args: {path: "/workspace/file.txt"}
      snapshot:
        steps_consumed: 5
        tool_calls_consumed: 3
        wall_time_ms: 1000
        loop_violation: LOOP_DETECTED
        is_tainted: false
      manifest:
        schema: "%s"
        name: test-skill
        version: "0.1.0"
        publisher: acme
        permissions:
          tools: ["read_file"]
          budgets:
            max_steps: 24
            max_tool_calls: 12
            max_wall_time_ms: 120000
        sandbox:
          required: false
        integrity: {}
    expect:
      outcome: deny
      reason: LOOP_DETECTED
`, schemaV, schemaV))

const schemaV = "aegis.dev/manifest/v0.1"
