package manifest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validManifest() *Manifest {
	return &Manifest{
		Schema:    SchemaVersion,
		Name:      "my-skill",
		Version:   "0.1.0",
		Publisher: "acme",
		Permissions: Permissions{
			Tools: []string{"read_file"},
			Budgets: BudgetLimits{
				MaxSteps:     24,
				MaxToolCalls: 12,
			},
		},
	}
}

func TestValidate_Happy(t *testing.T) {
	require.NoError(t, Validate(validManifest()))
}

func TestValidate_MissingSchema(t *testing.T) {
	m := validManifest()
	m.Schema = ""
	err := Validate(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "schema")
}

func TestValidate_MissingName(t *testing.T) {
	m := validManifest()
	m.Name = ""
	err := Validate(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name")
}

func TestValidate_MissingPublisher(t *testing.T) {
	m := validManifest()
	m.Publisher = ""
	err := Validate(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "publisher")
}

func TestValidate_EffectfulWithoutSandbox(t *testing.T) {
	m := validManifest()
	m.Permissions.Net = NetPermissions{Domains: []string{"api.example.com"}}
	m.Sandbox.Required = false
	err := Validate(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sandbox")
}

func TestValidate_EffectfulWithSandbox_OK(t *testing.T) {
	m := validManifest()
	m.Permissions.Net = NetPermissions{Domains: []string{"api.example.com"}}
	m.Sandbox.Required = true
	require.NoError(t, Validate(m))
}

func TestLoadBytes(t *testing.T) {
	raw := `{
		"schema": "aegis.dev/manifest/v0.1",
		"name": "test-skill",
		"version": "0.2.0",
		"publisher": "acme",
		"permissions": {"tools": ["read_file"], "budgets": {}}
	}`
	m, err := LoadBytes([]byte(raw))
	require.NoError(t, err)
	assert.Equal(t, "test-skill", m.Name)
	assert.Equal(t, "0.2.0", m.Version)
}

func TestToMap(t *testing.T) {
	m := validManifest()
	mp := m.ToMap()
	assert.Equal(t, SchemaVersion, mp["schema"])
	perms, ok := mp["permissions"].(map[string]any)
	require.True(t, ok)
	tools := perms["tools"].([]any)
	assert.Equal(t, "read_file", tools[0])
}

func TestVerifyTree_Match(t *testing.T) {
	dir := t.TempDir()
	content := []byte("hello aegis")
	err := os.WriteFile(filepath.Join(dir, "tool.py"), content, 0600)
	require.NoError(t, err)

	files, treeHash, err := ComputeTree(dir)
	require.NoError(t, err)
	assert.NotEmpty(t, treeHash)

	m := validManifest()
	m.Integrity.Files = files
	m.Integrity.TreeSHA256 = treeHash

	require.NoError(t, VerifyTree(m, dir))
}

func TestVerifyTree_Tamper(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tool.py"), []byte("original"), 0600))

	files, _, err := ComputeTree(dir)
	require.NoError(t, err)

	// Tamper the file.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tool.py"), []byte("tampered!"), 0600))

	m := validManifest()
	m.Integrity.Files = files

	err = VerifyTree(m, dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hash mismatch")
}

func TestVerifySignature_DevMode(t *testing.T) {
	m := validManifest()
	// No signature, but dev mode — must pass.
	require.NoError(t, VerifySignature(m, nil, TrustModeDev))
}

func TestVerifySignature_ProdMode_NoSignature(t *testing.T) {
	m := validManifest()
	err := VerifySignature(m, nil, TrustModeProd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cosign signature")
}

func TestVerifySignature_ProdMode_PublisherNotAllowlisted(t *testing.T) {
	m := validManifest()
	m.Integrity.Signature = "sha256:abc123"
	err := VerifySignature(m, []string{"other-publisher"}, TrustModeProd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not in allowlist")
}

func TestVerifySignature_ProdMode_AllowlistedPublisher(t *testing.T) {
	m := validManifest()
	m.Integrity.Signature = "sha256:abc123"
	// acme is allowlisted and signature present → should pass stub
	require.NoError(t, VerifySignature(m, []string{"acme"}, TrustModeProd))
}
