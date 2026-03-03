// Command aegisctl is the Aegis CLI management tool.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"github.com/aegis-framework/aegis/pkg/manifest"
)

func main() {
	root := &cobra.Command{
		Use:   "aegisctl",
		Short: "Aegis control plane CLI",
	}

	root.AddCommand(newVerifyCmd())
	root.AddCommand(newExportCmd())
	root.AddCommand(newManifestCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newVerifyCmd() *cobra.Command {
	var (
		tenantID  string
		sessionID string
		serverURL string
	)
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify hash chain integrity for a session",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(cmd, tenantID, sessionID, serverURL)
		},
	}
	cmd.Flags().StringVar(&tenantID, "tenant", "", "Tenant ID (required)")
	cmd.Flags().StringVar(&sessionID, "session", "", "Session ID (required)")
	cmd.Flags().StringVar(&serverURL, "server", "http://localhost:8080", "aegisd server URL")
	_ = cmd.MarkFlagRequired("tenant")
	_ = cmd.MarkFlagRequired("session")
	return cmd
}

func runVerify(cmd *cobra.Command, tenantID, sessionID, serverURL string) error {
	url := fmt.Sprintf("%s/v1/sessions/%s/verify?tenant_id=%s", serverURL, sessionID, tenantID)
	resp, err := http.Get(url) //nolint:noctx
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("verify: server returned %d: %s", resp.StatusCode, body)
	}
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n", body)
		return nil
	}
	valid, _ := result["valid"].(bool)
	if valid {
		fmt.Fprintf(cmd.OutOrStdout(), "OK: chain valid for session %s\n", sessionID)
	} else {
		errMsg, _ := result["error"].(string)
		badSeq, _ := result["first_bad_seq"].(float64)
		fmt.Fprintf(cmd.OutOrStdout(), "INVALID: first bad seq=%d error=%s\n", int(badSeq), errMsg)
	}
	return nil
}

func newExportCmd() *cobra.Command {
	var (
		tenantID  string
		sessionID string
		serverURL string
		outFile   string
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export audit events for a session to NDJSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExport(cmd, tenantID, sessionID, serverURL, outFile)
		},
	}
	cmd.Flags().StringVar(&tenantID, "tenant", "", "Tenant ID (required)")
	cmd.Flags().StringVar(&sessionID, "session", "", "Session ID (required)")
	cmd.Flags().StringVar(&serverURL, "server", "http://localhost:8080", "aegisd server URL")
	cmd.Flags().StringVar(&outFile, "out", "-", "Output file path (- for stdout)")
	_ = cmd.MarkFlagRequired("tenant")
	_ = cmd.MarkFlagRequired("session")
	return cmd
}

func runExport(cmd *cobra.Command, tenantID, sessionID, serverURL, outFile string) error {
	url := fmt.Sprintf("%s/v1/events?tenant_id=%s&session_id=%s", serverURL, tenantID, sessionID)
	resp, err := http.Get(url) //nolint:noctx
	if err != nil {
		return fmt.Errorf("export: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("export: server returned %d: %s", resp.StatusCode, body)
	}

	var out io.Writer = cmd.OutOrStdout()
	if outFile != "-" && outFile != "" {
		f, ferr := os.Create(outFile)
		if ferr != nil {
			return fmt.Errorf("export: create file: %w", ferr)
		}
		defer f.Close()
		out = f
	}

	// Server returns JSON; re-encode each event as NDJSON line.
	var page struct {
		Events []json.RawMessage `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return fmt.Errorf("export: decode: %w", err)
	}
	for _, ev := range page.Events {
		fmt.Fprintf(out, "%s\n", ev)
	}
	return nil
}

// ── manifest subcommand ───────────────────────────────────────────────────────

func newManifestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "manifest",
		Short: "Manage capability manifests",
	}
	cmd.AddCommand(newManifestValidateCmd())
	cmd.AddCommand(newManifestInstallCmd())
	cmd.AddCommand(newManifestShowCmd())
	return cmd
}

func newManifestValidateCmd() *cobra.Command {
	var trustMode string
	cmd := &cobra.Command{
		Use:   "validate <manifest.json>",
		Short: "Validate a capability manifest",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := manifest.Load(args[0])
			if err != nil {
				return err
			}
			if err := manifest.Validate(m); err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "INVALID: %v\n", err)
				return err
			}
			if err := manifest.VerifySignature(m, nil, manifest.TrustMode(trustMode)); err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "SIGNATURE INVALID: %v\n", err)
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "OK: manifest %q v%s by %s\n", m.Name, m.Version, m.Publisher)
			return nil
		},
	}
	cmd.Flags().StringVar(&trustMode, "trust-mode", "dev", "Trust mode: dev or prod")
	return cmd
}

func newManifestInstallCmd() *cobra.Command {
	var (
		dir       string
		trustMode string
	)
	cmd := &cobra.Command{
		Use:   "install <manifest.json>",
		Short: "Install and verify a capability manifest (tree hash + signature)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := manifest.Load(args[0])
			if err != nil {
				return err
			}
			if err := manifest.Validate(m); err != nil {
				return fmt.Errorf("manifest invalid: %w", err)
			}
			if dir != "" {
				if err := manifest.VerifyTree(m, dir); err != nil {
					return fmt.Errorf("tree integrity: %w", err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), "tree integrity: OK")
			}
			if err := manifest.VerifySignature(m, nil, manifest.TrustMode(trustMode)); err != nil {
				return fmt.Errorf("signature: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "installed: %s v%s\n", m.Name, m.Version)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "Skill directory to verify tree hash against")
	cmd.Flags().StringVar(&trustMode, "trust-mode", "dev", "Trust mode: dev or prod")
	return cmd
}

func newManifestShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <manifest.json>",
		Short: "Pretty-print a manifest",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := manifest.Load(args[0])
			if err != nil {
				return err
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(m)
		},
	}
}
