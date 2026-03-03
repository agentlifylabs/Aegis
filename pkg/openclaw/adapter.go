// Package openclaw implements Epic 11 — OpenClaw adapter (secure skills in practice).
//
// Three deliverables:
//  1. ManifestGenerator: static-scans a skill directory and produces a best-effort
//     aegis-manifest.json alongside an AuditReport with flagged patterns.
//  2. Scanner: detects known-bad patterns (download-and-exec, obfuscated shell,
//     credential harvesting, path-traversal attempts).
//  3. ConfigTemplate: emits the OpenClaw configuration snippet that points its
//     MCP client at the aegisd proxy address.
//
// Acceptance tests:
//   - A legacy skill without manifest runs only in "read-only audit mode" and
//     cannot exec/network (enforced by the generated manifest's zero permissions).
//   - A malicious skill attempting to read ~/.ssh is denied via scanner + policy.
package openclaw

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/aegis-framework/aegis/pkg/manifest"
)

// ── Scanner ───────────────────────────────────────────────────────────────────

// Severity classifies a scanner finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityInfo     Severity = "INFO"
)

// Finding is a single scanner hit.
type Finding struct {
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Pattern  string   `json:"pattern"`
	Snippet  string   `json:"snippet"`
	Severity Severity `json:"severity"`
	Category string   `json:"category"` // "download_exec" | "obfuscated_shell" | "path_traversal" | "credential_access" | "network_egress"
}

// knownBadPattern is a compiled bad-pattern entry.
type knownBadPattern struct {
	re       *regexp.Regexp
	category string
	severity Severity
	label    string
}

// knownBadPatterns is the master list of patterns checked by Scanner.
var knownBadPatterns = []knownBadPattern{
	// ── Download and execute ──────────────────────────────────────────────────
	{re: regexp.MustCompile(`(?i)(curl|wget)\s+.*\|\s*(ba)?sh`), category: "download_exec", severity: SeverityCritical, label: "download_pipe_shell"},
	{re: regexp.MustCompile(`(?i)subprocess.*shell\s*=\s*True`), category: "download_exec", severity: SeverityHigh, label: "subprocess_shell_true"},
	{re: regexp.MustCompile(`(?i)os\.system\s*\(`), category: "download_exec", severity: SeverityHigh, label: "os_system_call"},
	{re: regexp.MustCompile(`(?i)exec\s*\(\s*compile\s*\(`), category: "download_exec", severity: SeverityCritical, label: "dynamic_exec_compile"},
	{re: regexp.MustCompile(`(?i)eval\s*\(\s*(base64|__import__|compile)`), category: "obfuscated_shell", severity: SeverityCritical, label: "eval_obfuscated"},
	{re: regexp.MustCompile(`(?i)(urllib|requests).*\.(get|post)\s*\(.*exec`), category: "download_exec", severity: SeverityCritical, label: "download_and_exec"},

	// ── Obfuscated shell ─────────────────────────────────────────────────────
	{re: regexp.MustCompile(`(?i)base64\s*(-d|--decode)\s*\|`), category: "obfuscated_shell", severity: SeverityCritical, label: "base64_decode_pipe"},
	{re: regexp.MustCompile(`(?i)\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){7,}`), category: "obfuscated_shell", severity: SeverityHigh, label: "hex_obfuscation"},
	{re: regexp.MustCompile(`(?i)chr\s*\(\d+\)\s*\+`), category: "obfuscated_shell", severity: SeverityMedium, label: "chr_concat_obfuscation"},

	// ── Credential / secret access ────────────────────────────────────────────
	{re: regexp.MustCompile(`(?i)(~/\.ssh|/root/\.ssh)`), category: "credential_access", severity: SeverityCritical, label: "ssh_key_access"},
	{re: regexp.MustCompile(`(?i)os\.environ\[.*(SECRET|TOKEN|PASSWORD|KEY)`), category: "credential_access", severity: SeverityCritical, label: "env_secret_access"},
	{re: regexp.MustCompile(`(?i)/etc/(passwd|shadow|sudoers)`), category: "credential_access", severity: SeverityCritical, label: "sensitive_system_file"},
	{re: regexp.MustCompile(`(?i)(keychain|SecKeychainFind|CryptUnprotectData)`), category: "credential_access", severity: SeverityCritical, label: "keychain_access"},
	{re: regexp.MustCompile(`(?i)\.aws/(credentials|config)`), category: "credential_access", severity: SeverityCritical, label: "aws_credentials"},

	// ── Path traversal ────────────────────────────────────────────────────────
	{re: regexp.MustCompile(`\.\.\/\.\.\/`), category: "path_traversal", severity: SeverityHigh, label: "double_dotdot"},
	{re: regexp.MustCompile(`(?i)(open|read|write)\s*\([^)]*\.\./`), category: "path_traversal", severity: SeverityHigh, label: "file_open_traversal"},
	{re: regexp.MustCompile(`(?i)%2e%2e[%/]`), category: "path_traversal", severity: SeverityHigh, label: "url_encoded_traversal"},

	// ── Unexpected network egress ─────────────────────────────────────────────
	{re: regexp.MustCompile(`(?i)(nc|netcat)\s+-[a-z]*e`), category: "network_egress", severity: SeverityCritical, label: "netcat_exec"},
	{re: regexp.MustCompile(`(?i)socket\.(connect|bind)\s*\(\s*\([^)]*\d{1,3}\.\d{1,3}`), category: "network_egress", severity: SeverityHigh, label: "raw_socket_connect"},
}

// Scanner statically scans source files for known-bad patterns.
type Scanner struct {
	// Extensions is the set of file extensions to scan.
	// Defaults to {.py, .sh, .bash, .js, .ts, .rb, .go} when empty.
	Extensions []string
}

// DefaultExtensions scanned by the scanner.
var DefaultExtensions = []string{".py", ".sh", ".bash", ".js", ".ts", ".rb", ".go", ".php"}

func (sc *Scanner) exts() map[string]bool {
	exts := sc.Extensions
	if len(exts) == 0 {
		exts = DefaultExtensions
	}
	out := make(map[string]bool, len(exts))
	for _, e := range exts {
		out[e] = true
	}
	return out
}

// Scan walks dir and returns all findings.
func (sc *Scanner) Scan(dir string) ([]Finding, error) {
	exts := sc.exts()
	var findings []Finding

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			// Skip hidden dirs and common vendor dirs.
			base := d.Name()
			if base != "." && (strings.HasPrefix(base, ".") ||
				base == "node_modules" || base == "vendor" || base == "__pycache__") {
				return filepath.SkipDir
			}
			return nil
		}
		if !exts[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		ff, err := scanFile(path, rel)
		if err != nil {
			return nil // non-fatal: skip unreadable files
		}
		findings = append(findings, ff...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scanner: walk: %w", err)
	}
	return findings, nil
}

func scanFile(path, rel string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	var findings []Finding
	for i, line := range lines {
		for _, p := range knownBadPatterns {
			if p.re.MatchString(line) {
				snippet := strings.TrimSpace(line)
				if len(snippet) > 120 {
					snippet = snippet[:120] + "…"
				}
				findings = append(findings, Finding{
					File:     rel,
					Line:     i + 1,
					Pattern:  p.label,
					Snippet:  snippet,
					Severity: p.severity,
					Category: p.category,
				})
			}
		}
	}
	return findings, nil
}

// ── AuditReport ───────────────────────────────────────────────────────────────

// AuditReport is the output of the manifest generator for a legacy skill.
type AuditReport struct {
	SkillDir        string    `json:"skill_dir"`
	ManifestWritten bool      `json:"manifest_written"`
	ManifestPath    string    `json:"manifest_path,omitempty"`
	Mode            string    `json:"mode"`            // "read_only_audit" | "full"
	Findings        []Finding `json:"findings"`
	FindingCount    int       `json:"finding_count"`
	CriticalCount   int       `json:"critical_count"`
	HighCount       int       `json:"high_count"`
	Notes           []string  `json:"notes,omitempty"`
}

// ── ManifestGenerator ─────────────────────────────────────────────────────────

// ManifestGenerator produces a best-effort aegis-manifest.json for a legacy
// OpenClaw skill directory that has no existing manifest.
type ManifestGenerator struct {
	Scanner  *Scanner
	// AuditOnly, when true, generates a read-only audit manifest regardless of
	// what is found in the skill source. This is the safe default for legacy skills.
	AuditOnly bool
}

// Generate scans skillDir, classifies permissions, writes an aegis-manifest.json,
// and returns an AuditReport.
//
// Safety rule: if any CRITICAL findings are present, or if AuditOnly is true,
// the manifest is generated in "read-only audit mode":
//   - no exec, no net, no fs.write permissions
//   - tools limited to read-only set
//   - sandbox.required = true
func (g *ManifestGenerator) Generate(skillDir string) (*manifest.Manifest, *AuditReport, error) {
	sc := g.Scanner
	if sc == nil {
		sc = &Scanner{}
	}

	findings, err := sc.Scan(skillDir)
	if err != nil {
		return nil, nil, fmt.Errorf("generator: scan: %w", err)
	}

	report := &AuditReport{
		SkillDir: skillDir,
		Findings: findings,
	}
	for _, f := range findings {
		report.FindingCount++
		switch f.Severity {
		case SeverityCritical:
			report.CriticalCount++
		case SeverityHigh:
			report.HighCount++
		}
	}

	// Determine mode.
	auditOnly := g.AuditOnly || report.CriticalCount > 0
	if auditOnly {
		report.Mode = "read_only_audit"
		report.Notes = append(report.Notes,
			"Running in read-only audit mode: no exec/net/write permissions granted.",
			fmt.Sprintf("%d critical finding(s) require manual review before upgrading mode.", report.CriticalCount),
		)
	} else {
		report.Mode = "full"
	}

	// Infer skill name from dir basename.
	skillName := filepath.Base(skillDir)
	if skillName == "." || skillName == "" {
		skillName = "unknown-skill"
	}

	m := buildManifest(skillName, auditOnly)

	// Write manifest alongside skill.
	manifestPath := filepath.Join(skillDir, "aegis-manifest.json")
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("generator: marshal: %w", err)
	}
	if werr := os.WriteFile(manifestPath, data, 0o644); werr != nil {
		report.Notes = append(report.Notes, fmt.Sprintf("warning: could not write manifest: %v", werr))
	} else {
		report.ManifestWritten = true
		report.ManifestPath = manifestPath
	}

	return m, report, nil
}

// buildManifest constructs an aegis-manifest.json for the skill.
// In audit-only mode the manifest grants only read-only tool access.
func buildManifest(skillName string, auditOnly bool) *manifest.Manifest {
	m := &manifest.Manifest{
		Schema:    manifest.SchemaVersion,
		Name:      skillName,
		Version:   "0.0.1-generated",
		Publisher: "openclaw-legacy",
		Sandbox: manifest.Sandbox{
			Required: true, // always sandbox legacy skills
		},
		Permissions: manifest.Permissions{
			Budgets: manifest.BudgetLimits{
				MaxSteps:      24,
				MaxToolCalls:  12,
				MaxWallTimeMs: 120_000,
			},
		},
	}

	if auditOnly {
		// Read-only audit mode: only safe read operations allowed.
		m.Permissions.Tools = []string{"read_file", "list_dir"}
		m.Permissions.FS = manifest.FSPermissions{
			ReadRoots: []string{"/workspace"},
		}
		// No exec, no net, no fs.write.
	} else {
		// Full mode: declare intent-to-use common tools; operator must review.
		m.Permissions.Tools = []string{"read_file", "list_dir", "write_file"}
		m.Permissions.FS = manifest.FSPermissions{
			ReadRoots:  []string{"/workspace"},
			WriteRoots: []string{"/workspace/output"},
		}
		m.Permissions.ApprovalRequired = []string{"exec", "net"}
	}

	return m
}

// ── ConfigTemplate ────────────────────────────────────────────────────────────

// OpenClawConfig is the aegisd proxy configuration snippet for OpenClaw.
type OpenClawConfig struct {
	ProxyAddr   string `json:"aegisd_proxy_addr"`
	TrustMode   string `json:"trust_mode"`
	ManifestPath string `json:"manifest_path"`
}

// RenderConfigTemplate returns the JSON configuration that OpenClaw should use
// to point its MCP client at the aegisd proxy.
func RenderConfigTemplate(proxyAddr, trustMode, manifestPath string) (string, error) {
	if proxyAddr == "" {
		proxyAddr = "http://localhost:8081"
	}
	if trustMode == "" {
		trustMode = "dev"
	}
	cfg := OpenClawConfig{
		ProxyAddr:    proxyAddr,
		TrustMode:    trustMode,
		ManifestPath: manifestPath,
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ── Convenience: ReadOnlyAuditManifest ────────────────────────────────────────

// ReadOnlyAuditManifest returns a minimal manifest that grants only read-only
// tool access, for use in policy enforcement when no manifest is present.
// Acceptance test: a legacy skill without manifest must operate under these limits.
func ReadOnlyAuditManifest(skillName string) *manifest.Manifest {
	return buildManifest(skillName, true)
}

// ── SortFindings sorts findings for deterministic output ──────────────────────

// SortFindings sorts findings by file, then line, for deterministic reporting.
func SortFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})
}
