// Package config loads and validates the aegis.yaml configuration file (Epic 13).
// CLI flags always override file values; the file provides ergonomic defaults.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// File is the parsed representation of aegis.yaml.
// All fields are optional; unset fields fall back to CLI flag defaults.
type File struct {
	DSN      string   `yaml:"dsn"`
	Addr     string   `yaml:"addr"`
	Manifest string   `yaml:"manifest"`
	TrustMode string  `yaml:"trust_mode"`
	MCPAddr  string   `yaml:"mcp_addr"`
	RateLimit int     `yaml:"rate_limit"`

	Telemetry struct {
		Disabled bool   `yaml:"disabled"`
		Path     string `yaml:"path"`
	} `yaml:"telemetry"`

	TLS struct {
		Enabled  bool   `yaml:"enabled"`
		CertFile string `yaml:"cert_file"`
		KeyFile  string `yaml:"key_file"`
		CAFile   string `yaml:"ca_file"` // mTLS: verify client certs
	} `yaml:"tls"`

	Log struct {
		Level  string `yaml:"level"`  // debug | info | warn | error
		Format string `yaml:"format"` // text | json
	} `yaml:"log"`
}

// Load reads and parses an aegis.yaml file.
// Returns an empty File (all zero values) if path is empty.
func Load(path string) (*File, error) {
	if path == "" {
		return &File{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("config: parse %q: %w", path, err)
	}
	if err := validate(&f); err != nil {
		return nil, fmt.Errorf("config: invalid %q: %w", path, err)
	}
	return &f, nil
}

// validate enforces semantic constraints on the parsed config.
func validate(f *File) error {
	if f.TrustMode != "" && f.TrustMode != "dev" && f.TrustMode != "prod" {
		return fmt.Errorf("trust_mode must be \"dev\" or \"prod\", got %q", f.TrustMode)
	}
	if f.Log.Level != "" {
		switch f.Log.Level {
		case "debug", "info", "warn", "error":
		default:
			return fmt.Errorf("log.level must be debug|info|warn|error, got %q", f.Log.Level)
		}
	}
	if f.Log.Format != "" && f.Log.Format != "text" && f.Log.Format != "json" {
		return fmt.Errorf("log.format must be text|json, got %q", f.Log.Format)
	}
	if f.TLS.Enabled {
		if f.TLS.CertFile == "" || f.TLS.KeyFile == "" {
			return fmt.Errorf("tls.cert_file and tls.key_file are required when tls.enabled is true")
		}
	}
	if f.RateLimit < 0 {
		return fmt.Errorf("rate_limit must be >= 0, got %d", f.RateLimit)
	}
	return nil
}
