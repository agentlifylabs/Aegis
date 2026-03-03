// Command aegisd is the Aegis agent control plane daemon.
// Epics 00-13: event log, policy engine, manifest loader, MCP proxy,
// loop/budget guard, approval router, taint tracking, replay, telemetry,
// operational hardening (aegis.yaml, TLS config).
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	aegisconfig "github.com/aegis-framework/aegis/internal/config"
	"github.com/aegis-framework/aegis/internal/server"
	"github.com/aegis-framework/aegis/pkg/manifest"
)

var (
	cfgFile           string
	dsn               string
	addr              string
	manifestPath      string
	trustMode         string
	mcpAddr           string
	rateLimit         int
	telemetryDisabled bool
	telemetryPath     string
)

func main() {
	root := &cobra.Command{
		Use:   "aegisd",
		Short: "Aegis agent control plane daemon",
		RunE:  run,
	}

	root.Flags().StringVar(&cfgFile, "config", "", "Path to aegis.yaml config file")
	root.Flags().StringVar(&dsn, "dsn", "", "Database DSN (SQLite or Postgres); overrides aegis.yaml")
	root.Flags().StringVar(&addr, "addr", "", "HTTP listen address; overrides aegis.yaml")
	root.Flags().StringVar(&manifestPath, "manifest", "", "Path to aegis-manifest.json (empty = dev permissive mode)")
	root.Flags().StringVar(&trustMode, "trust-mode", "", "Trust mode: dev or prod; overrides aegis.yaml")
	root.Flags().StringVar(&mcpAddr, "mcp-addr", "", "MCP proxy HTTP listen address (empty = disabled)")
	root.Flags().IntVar(&rateLimit, "rate-limit", -1, "Max tool calls per minute per tenant+tool (0 = unlimited, -1 = use config file)")
	root.Flags().BoolVar(&telemetryDisabled, "telemetry-disabled", false, "Disable Aegis NDJSON telemetry export (never sets OTEL_SDK_DISABLED)")
	root.Flags().StringVar(&telemetryPath, "telemetry-path", "", "Path for NDJSON span output; overrides aegis.yaml")

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, _ []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Load aegis.yaml if provided; CLI flags override file values.
	fileCfg, err := aegisconfig.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("aegisd: config: %w", err)
	}

	// Merge: CLI flag wins when explicitly set (non-zero / non-empty).
	resolvedDSN := coalesce(dsn, fileCfg.DSN, "file:aegis.db?mode=rwc&cache=shared")
	resolvedAddr := coalesce(addr, fileCfg.Addr, ":8080")
	resolvedManifest := coalesce(manifestPath, fileCfg.Manifest, "")
	resolvedTrustMode := coalesce(trustMode, fileCfg.TrustMode, "dev")
	resolvedMCPAddr := coalesce(mcpAddr, fileCfg.MCPAddr, "")
	resolvedTelPath := coalesce(telemetryPath, fileCfg.Telemetry.Path, "")

	// rate-limit: -1 sentinel means "not set via flag".
	resolvedRateLimit := fileCfg.RateLimit
	if rateLimit >= 0 {
		resolvedRateLimit = rateLimit
	}

	// telemetry-disabled: flag wins if true; otherwise use file value.
	resolvedTelDisabled := fileCfg.Telemetry.Disabled
	if cmd.Flags().Changed("telemetry-disabled") {
		resolvedTelDisabled = telemetryDisabled
	}

	srv, err := server.New(server.Config{
		DSN:               resolvedDSN,
		Addr:              resolvedAddr,
		ManifestPath:      resolvedManifest,
		TrustMode:         manifest.TrustMode(resolvedTrustMode),
		MCPAddr:           resolvedMCPAddr,
		RateLimit:         resolvedRateLimit,
		TelemetryDisabled: resolvedTelDisabled,
		TelemetryPath:     resolvedTelPath,
	})
	if err != nil {
		return fmt.Errorf("aegisd: init: %w", err)
	}
	defer srv.Close()

	_, _ = fmt.Fprintf(os.Stdout, "aegisd listening on %s\n", resolvedAddr)
	return srv.Run(ctx)
}

// coalesce returns the first non-empty string from the list.
func coalesce(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
