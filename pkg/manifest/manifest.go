// Package manifest implements the Aegis capability manifest spec (Epic 04).
// Manifests declare what permissions a skill/tool requires; the runtime verifier
// enforces them before any tool is forwarded to the upstream MCP server.
package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

const SchemaVersion = "aegis.dev/manifest/v0.1"

// TrustMode controls signature enforcement.
type TrustMode string

const (
	TrustModeDev  TrustMode = "dev"  // unsigned allowed; manifest still required
	TrustModeProd TrustMode = "prod" // signature required; publisher must be allowlisted
)

// Manifest is the top-level capability declaration for a skill/tool package.
type Manifest struct {
	Schema      string      `json:"schema"`
	Name        string      `json:"name"`
	Version     string      `json:"version"`
	Publisher   string      `json:"publisher"`
	Permissions Permissions `json:"permissions"`
	Sandbox     Sandbox     `json:"sandbox"`
	Integrity   Integrity   `json:"integrity"`
}

// Permissions declares what resources the skill may access.
type Permissions struct {
	Tools           []string        `json:"tools"`
	FS              FSPermissions   `json:"fs"`
	Net             NetPermissions  `json:"net"`
	Secrets         []string        `json:"secrets,omitempty"`
	Exec            ExecPermissions `json:"exec"`
	ApprovalRequired []string       `json:"approval_required,omitempty"`
	Budgets         BudgetLimits    `json:"budgets"`
}

// FSPermissions declares allowed filesystem paths.
type FSPermissions struct {
	ReadRoots  []string `json:"read_roots,omitempty"`
	WriteRoots []string `json:"write_roots,omitempty"`
}

// NetPermissions declares allowed egress domains.
type NetPermissions struct {
	Domains []string `json:"domains,omitempty"`
}

// ExecPermissions declares allowed executables.
type ExecPermissions struct {
	AllowedBins []string `json:"allowed_bins,omitempty"`
	ArgPatterns []string `json:"arg_patterns,omitempty"`
}

// BudgetLimits sets per-session consumption ceilings.
type BudgetLimits struct {
	MaxSteps       int   `json:"max_steps,omitempty"`
	MaxToolCalls   int   `json:"max_tool_calls,omitempty"`
	MaxOutputBytes int   `json:"max_output_bytes,omitempty"`
	TimeoutMs      int64 `json:"timeout_ms,omitempty"`
	MaxWallTimeMs  int64 `json:"max_wall_time_ms,omitempty"`
}

// Sandbox declares containerisation requirements.
type Sandbox struct {
	Required bool   `json:"required"`
	Image    string `json:"image,omitempty"`
	Mounts   []string `json:"mounts,omitempty"`
}

// Integrity holds content-addressable hashes and an optional Cosign signature.
type Integrity struct {
	Files     map[string]string `json:"files,omitempty"`   // relative path → sha256 hex
	TreeSHA256 string           `json:"tree_sha256,omitempty"`
	Signature string            `json:"signature,omitempty"` // cosign bundle reference
}

// ValidationError is returned when a manifest fails validation.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("manifest: %s: %s", e.Field, e.Message)
}

// Load reads and parses an aegis-manifest.json file.
func Load(path string) (*Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("manifest: open %s: %w", path, err)
	}
	defer f.Close()
	return decode(f)
}

// LoadBytes parses a manifest from raw JSON bytes.
func LoadBytes(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("manifest: parse: %w", err)
	}
	return &m, nil
}

func decode(r io.Reader) (*Manifest, error) {
	var m Manifest
	if err := json.NewDecoder(r).Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest: decode: %w", err)
	}
	return &m, nil
}

// Validate checks required fields and semantic constraints.
func Validate(m *Manifest) error {
	if m.Schema != SchemaVersion {
		return &ValidationError{Field: "schema", Message: fmt.Sprintf("expected %q, got %q", SchemaVersion, m.Schema)}
	}
	if m.Name == "" {
		return &ValidationError{Field: "name", Message: "required"}
	}
	if m.Version == "" {
		return &ValidationError{Field: "version", Message: "required"}
	}
	if m.Publisher == "" {
		return &ValidationError{Field: "publisher", Message: "required"}
	}
	// Sandbox required when any effectful permission is present.
	if hasEffectfulPermissions(m) && !m.Sandbox.Required {
		return &ValidationError{
			Field:   "sandbox.required",
			Message: "must be true when exec, fs.write, or net permissions are declared",
		}
	}
	return nil
}

func hasEffectfulPermissions(m *Manifest) bool {
	if len(m.Permissions.Exec.AllowedBins) > 0 {
		return true
	}
	if len(m.Permissions.FS.WriteRoots) > 0 {
		return true
	}
	if len(m.Permissions.Net.Domains) > 0 {
		return true
	}
	for _, t := range m.Permissions.Tools {
		switch t {
		case "exec", "fs.write", "mcp.http", "mcp.https", "net":
			return true
		}
	}
	return false
}

// ToMap converts the manifest to the map[string]any form expected by the policy engine.
func (m *Manifest) ToMap() map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

// ── Integrity verification ────────────────────────────────────────────────────

// VerifyTree computes the SHA-256 of every declared file under dir and compares
// it against the hashes stored in m.Integrity.Files.
// It returns an error listing all mismatches.
func VerifyTree(m *Manifest, dir string) error {
	if len(m.Integrity.Files) == 0 {
		return nil // no integrity data declared — skip (dev mode only)
	}
	var errs []string
	for relPath, wantHex := range m.Integrity.Files {
		abs := filepath.Join(dir, relPath)
		got, err := hashFile(abs)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", relPath, err))
			continue
		}
		if got != wantHex {
			errs = append(errs, fmt.Sprintf("%s: hash mismatch (want %s got %s)", relPath, wantHex, got))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("manifest: integrity: %v", errs)
	}
	return nil
}

// ComputeTree hashes all files in dir and returns the per-file map plus the
// aggregate tree hash (SHA-256 of sorted "path:hash\n" lines).
func ComputeTree(dir string) (files map[string]string, treeHash string, err error) {
	files = make(map[string]string)
	agg := sha256.New()

	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil || d.IsDir() {
			return werr
		}
		rel, _ := filepath.Rel(dir, path)
		h, herr := hashFile(path)
		if herr != nil {
			return herr
		}
		files[rel] = h
		fmt.Fprintf(agg, "%s:%s\n", rel, h)
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	treeHash = hex.EncodeToString(agg.Sum(nil))
	return files, treeHash, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifySignature verifies the publisher allowlist and, in prod mode, that a
// Cosign signature bundle is present. Full cryptographic bundle verification
// (sigstore/cosign) is wired in Epic 13 once the Cosign dependency is added.
func VerifySignature(m *Manifest, allowedPublishers []string, trustMode TrustMode) error {
	if trustMode == TrustModeDev {
		return nil // unsigned allowed in dev
	}
	// prod: publisher allowlist
	if len(allowedPublishers) > 0 {
		allowed := false
		for _, p := range allowedPublishers {
			if p == m.Publisher {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("manifest: publisher %q not in allowlist", m.Publisher)
		}
	}
	if m.Integrity.Signature == "" {
		return fmt.Errorf("manifest: prod mode requires a cosign signature")
	}
	// Cosign bundle cryptographic verification deferred to Epic 13.
	return nil
}
