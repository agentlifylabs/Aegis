package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeYAML(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "aegis-*.yaml")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

func TestConfig_EmptyPath_ReturnsDefaults(t *testing.T) {
	cfg, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, &File{}, cfg)
}

func TestConfig_MissingFile_ReturnsError(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config: read")
}

func TestConfig_FullFile_ParsedCorrectly(t *testing.T) {
	path := writeYAML(t, `
dsn: "file:test.db"
addr: ":9090"
manifest: "/etc/aegis/manifest.json"
trust_mode: "prod"
mcp_addr: ":9091"
rate_limit: 60

telemetry:
  disabled: false
  path: "/var/log/aegis/traces.ndjson"

tls:
  enabled: true
  cert_file: "/etc/aegis/tls/cert.pem"
  key_file:  "/etc/aegis/tls/key.pem"
  ca_file:   "/etc/aegis/tls/ca.pem"

log:
  level: "info"
  format: "json"
`)
	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, "file:test.db", cfg.DSN)
	assert.Equal(t, ":9090", cfg.Addr)
	assert.Equal(t, "prod", cfg.TrustMode)
	assert.Equal(t, 60, cfg.RateLimit)
	assert.False(t, cfg.Telemetry.Disabled)
	assert.Equal(t, "/var/log/aegis/traces.ndjson", cfg.Telemetry.Path)
	assert.True(t, cfg.TLS.Enabled)
	assert.Equal(t, "/etc/aegis/tls/cert.pem", cfg.TLS.CertFile)
	assert.Equal(t, "info", cfg.Log.Level)
	assert.Equal(t, "json", cfg.Log.Format)
}

func TestConfig_TelemetryDisabled(t *testing.T) {
	path := writeYAML(t, `
telemetry:
  disabled: true
`)
	cfg, err := Load(path)
	require.NoError(t, err)
	assert.True(t, cfg.Telemetry.Disabled)
}

func TestConfig_InvalidTrustMode(t *testing.T) {
	path := writeYAML(t, `trust_mode: "superuser"`)
	_, err := Load(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "trust_mode")
}

func TestConfig_InvalidLogLevel(t *testing.T) {
	path := writeYAML(t, `
log:
  level: "verbose"
`)
	_, err := Load(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "log.level")
}

func TestConfig_InvalidLogFormat(t *testing.T) {
	path := writeYAML(t, `
log:
  format: "xml"
`)
	_, err := Load(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "log.format")
}

func TestConfig_TLS_EnabledWithoutCert_ReturnsError(t *testing.T) {
	path := writeYAML(t, `
tls:
  enabled: true
  cert_file: ""
  key_file: ""
`)
	_, err := Load(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tls.cert_file")
}

func TestConfig_TLS_DisabledNoCertRequired(t *testing.T) {
	path := writeYAML(t, `
tls:
  enabled: false
`)
	cfg, err := Load(path)
	require.NoError(t, err)
	assert.False(t, cfg.TLS.Enabled)
}

func TestConfig_NegativeRateLimit_ReturnsError(t *testing.T) {
	path := writeYAML(t, `rate_limit: -1`)
	_, err := Load(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rate_limit")
}

func TestConfig_InvalidYAML_ReturnsError(t *testing.T) {
	path := writeYAML(t, `dsn: [not a string`)
	_, err := Load(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config: parse")
}

func TestConfig_PartialFile_UnsetFieldsAreZero(t *testing.T) {
	path := writeYAML(t, `addr: ":7777"`)
	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, ":7777", cfg.Addr)
	assert.Empty(t, cfg.DSN)
	assert.Empty(t, cfg.Manifest)
	assert.Zero(t, cfg.RateLimit)
	assert.False(t, cfg.TLS.Enabled)
}
