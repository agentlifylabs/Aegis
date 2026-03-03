// Package telemetry implements Epic 10 — observability with zero-egress default.
//
// Design constraints:
//   - Default exporter: local NDJSON file (zero network egress).
//   - Optional exporter: OTLP/gRPC to a user-configured endpoint only.
//   - Redaction: secrets and PII patterns are removed before any export.
//   - Critical constraint: NEVER set OTEL_SDK_DISABLED. Aegis telemetry toggle
//     only affects Aegis exporters; user app OTel spans are never touched.
//
// Span fields: trace_id, span_id, session_id, tenant_id, event_type, seq, ts_unix_ms.
// trace_id is also stored in events for correlation.
package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/aegis-framework/aegis/pkg/eventlog"
)

// ── Span ──────────────────────────────────────────────────────────────────────

// Span is the Aegis-internal span record written to the exporter.
// Fields map to standard OTel span attributes for easy ingestion.
type Span struct {
	TraceID   string         `json:"trace_id"`
	SpanID    string         `json:"span_id"`
	SessionID string         `json:"session_id"`
	TenantID  string         `json:"tenant_id"`
	EventType string         `json:"event_type"`
	Seq       uint64         `json:"seq"`
	TsUnixMs  int64          `json:"ts_unix_ms"`
	DurationMs int64         `json:"duration_ms,omitempty"`
	Attrs     map[string]any `json:"attrs,omitempty"` // redacted payload fields
}

// ── Exporter interface ────────────────────────────────────────────────────────

// Exporter receives a finalized Span. Implementations must be safe for
// concurrent use.
type Exporter interface {
	Export(ctx context.Context, span Span) error
	// Flush ensures any buffered spans are written. Safe to call multiple times.
	Flush() error
	// Close releases resources. After Close, Export must not be called.
	Close() error
}

// ── NDJSON exporter (default, zero-egress) ────────────────────────────────────

// NDJSONExporter writes one span per line as newline-delimited JSON.
// The default path is /var/lib/aegis/traces.ndjson; pass os.Stdout for tests.
type NDJSONExporter struct {
	mu     sync.Mutex
	w      io.WriteCloser
	owned  bool // if true, Close will close w
}

// NewNDJSONExporter opens (or creates) the file at path for appending.
// Pass an empty path to use the default location (/var/lib/aegis/traces.ndjson).
func NewNDJSONExporter(path string) (*NDJSONExporter, error) {
	if path == "" {
		path = "/var/lib/aegis/traces.ndjson"
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("telemetry: open %s: %w", path, err)
	}
	return &NDJSONExporter{w: f, owned: true}, nil
}

// NewNDJSONExporterFromWriter creates an exporter writing to an existing writer
// (e.g. bytes.Buffer or os.Stdout). The caller owns the writer lifecycle.
func NewNDJSONExporterFromWriter(w io.WriteCloser) *NDJSONExporter {
	return &NDJSONExporter{w: w, owned: false}
}

func (e *NDJSONExporter) Export(_ context.Context, span Span) error {
	b, err := json.Marshal(span)
	if err != nil {
		return fmt.Errorf("telemetry: marshal span: %w", err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	_, err = fmt.Fprintf(e.w, "%s\n", b)
	return err
}

func (e *NDJSONExporter) Flush() error { return nil }

func (e *NDJSONExporter) Close() error {
	if e.owned {
		return e.w.Close()
	}
	return nil
}

// ── No-op exporter (disabled telemetry) ──────────────────────────────────────

// NoopExporter discards all spans. Used when Aegis telemetry is disabled.
// IMPORTANT: this never touches OTEL_SDK_DISABLED — user app spans still flow.
type NoopExporter struct{}

func (NoopExporter) Export(_ context.Context, _ Span) error { return nil }
func (NoopExporter) Flush() error                           { return nil }
func (NoopExporter) Close() error                           { return nil }

// ── Redaction ─────────────────────────────────────────────────────────────────

// Redactor removes secrets and PII from a payload map before it enters a Span.
// It is pure (no mutation of the input) and safe for concurrent use.
type Redactor struct {
	// SecretKeys are exact field names whose values are always redacted.
	SecretKeys []string
}

// DefaultRedactor has a sensible default set of secret and PII field names.
var DefaultRedactor = &Redactor{
	SecretKeys: []string{
		"password", "passwd", "secret", "token", "api_key", "apikey",
		"authorization", "auth", "credential", "private_key", "access_token",
		"refresh_token", "session_token", "ssn", "credit_card",
	},
}

const redactedValue = "[REDACTED]"

// Redact returns a copy of m with secrets and PII patterns replaced.
func (r *Redactor) Redact(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if r.isSecretKey(k) {
			out[k] = redactedValue
			continue
		}
		switch val := v.(type) {
		case string:
			out[k] = redactPII(val)
		case map[string]any:
			out[k] = r.Redact(val)
		default:
			out[k] = v
		}
	}
	return out
}

func (r *Redactor) isSecretKey(key string) bool {
	for _, sk := range r.SecretKeys {
		if sk == key {
			return true
		}
	}
	return false
}

// redactPII replaces common PII patterns in a string value.
// Patterns: email addresses, phone numbers, token-like strings (32+ hex chars).
func redactPII(s string) string {
	if len(s) == 0 {
		return s
	}
	s = emailPattern.ReplaceAllString(s, "[EMAIL]")
	s = phonePattern.ReplaceAllString(s, "[PHONE]")
	s = hexTokenPattern.ReplaceAllString(s, "[TOKEN]")
	return s
}

// ── Tracer ────────────────────────────────────────────────────────────────────

// Tracer converts Aegis event envelopes into Spans and ships them to the Exporter.
// One Tracer is created per aegisd instance.
type Tracer struct {
	exporter Exporter
	redactor *Redactor
	disabled bool

	mu       sync.Mutex
	traceIDs map[string]string // sessionID → traceID (stable per session)
}

// Config holds Tracer configuration.
type Config struct {
	// Exporter to use. Defaults to NoopExporter if nil.
	Exporter Exporter
	// Redactor to use. Defaults to DefaultRedactor if nil.
	Redactor *Redactor
	// Disabled, when true, sends all spans to NoopExporter.
	// This NEVER sets OTEL_SDK_DISABLED.
	Disabled bool
}

// NewTracer creates a Tracer with the given config.
func NewTracer(cfg Config) *Tracer {
	exp := cfg.Exporter
	if exp == nil || cfg.Disabled {
		exp = NoopExporter{}
	}
	red := cfg.Redactor
	if red == nil {
		red = DefaultRedactor
	}
	return &Tracer{
		exporter: exp,
		redactor: red,
		disabled: cfg.Disabled,
		traceIDs: make(map[string]string),
	}
}

// TraceEvent converts an envelope to a Span and exports it.
// It is safe for concurrent use and always returns quickly (export is synchronous
// for the NDJSON backend; use a buffered writer for high-throughput scenarios).
func (t *Tracer) TraceEvent(ctx context.Context, e *eventlog.Envelope) error {
	if t.disabled {
		return nil
	}

	traceID := t.traceIDFor(e.SessionID)
	spanID := newSpanID()

	var attrs map[string]any
	if payload, ok := e.Payload.(map[string]any); ok {
		attrs = t.redactor.Redact(payload)
	}

	span := Span{
		TraceID:   traceID,
		SpanID:    spanID,
		SessionID: e.SessionID,
		TenantID:  e.TenantID,
		EventType: string(e.EventType),
		Seq:       e.Seq,
		TsUnixMs:  e.TsUnixMs,
		Attrs:     attrs,
	}

	return t.exporter.Export(ctx, span)
}

// Flush flushes the underlying exporter.
func (t *Tracer) Flush() error { return t.exporter.Flush() }

// Close closes the underlying exporter.
func (t *Tracer) Close() error { return t.exporter.Close() }

// TraceIDFor returns the stable trace ID for a session (for correlation in events).
func (t *Tracer) TraceIDFor(sessionID string) string {
	return t.traceIDFor(sessionID)
}

func (t *Tracer) traceIDFor(sessionID string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if id, ok := t.traceIDs[sessionID]; ok {
		return id
	}
	id := newTraceID()
	t.traceIDs[sessionID] = id
	return id
}

// ── ID generation (simple, no external deps) ──────────────────────────────────

func newTraceID() string {
	return randomHex(16) // 128-bit trace ID
}

func newSpanID() string {
	return randomHex(8) // 64-bit span ID
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := io.ReadFull(randReader, b); err != nil {
		// Fallback: use timestamp bits (should never happen).
		return fmt.Sprintf("%016x%016x", time.Now().UnixNano(), time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}

// randReader is a package-level rand.Reader alias, replaceable in tests.
var randReader io.Reader = nativeRandReader{}

type nativeRandReader struct{}

func (nativeRandReader) Read(b []byte) (int, error) {
	// Use crypto/rand.
	return cryptoRandRead(b)
}
