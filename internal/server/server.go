// Package server implements the aegisd HTTP server (Epics 00-05, 09-10).
// Provides the event ingest API, policy-gated MCP proxy, and query endpoints.
// Epic 10: emits an OTel-compatible span (via telemetry.Tracer) for every event.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aegis-framework/aegis/pkg/eventlog"
	"github.com/aegis-framework/aegis/pkg/manifest"
	"github.com/aegis-framework/aegis/pkg/policy"
	"github.com/aegis-framework/aegis/pkg/store"
	"github.com/aegis-framework/aegis/pkg/store/reducer"
	sqlitestore "github.com/aegis-framework/aegis/pkg/store/sqlite"
	"github.com/aegis-framework/aegis/pkg/telemetry"
)

// Config holds aegisd startup configuration.
type Config struct {
	DSN          string
	Addr         string
	ManifestPath string // path to aegis-manifest.json; empty = permissive dev mode
	TrustMode    manifest.TrustMode
	MCPAddr      string // address for MCP proxy HTTP server; empty = disabled
	RateLimit    int    // max tool calls/minute per tenant+tool; 0 = unlimited

	// Epic 10: telemetry.
	TelemetryDisabled bool   // when true, no Aegis spans are exported
	TelemetryPath     string // NDJSON output path; empty = /var/lib/aegis/traces.ndjson
}

// Server is the aegisd HTTP server.
type Server struct {
	cfg      Config
	store    store.EventStore
	mux      *http.ServeMux
	httpSrv  *http.Server
	reducers map[string]*reducer.Reducer // keyed by "tenantID/sessionID"

	policyEngine *policy.Engine
	manifest     *manifest.Manifest // nil = dev permissive mode
	tracer       *telemetry.Tracer  // Epic 10
}

// New creates and initialises a Server. Opens the database, loads policy engine,
// optionally loads the manifest, and registers routes.
func New(cfg Config) (*Server, error) {
	s := &Server{
		cfg:      cfg,
		mux:      http.NewServeMux(),
		reducers: make(map[string]*reducer.Reducer),
	}

	// Open storage backend.
	st, err := sqlitestore.New(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("server: open store: %w", err)
	}
	s.store = st

	// Compile policy bundle.
	eng, err := policy.New()
	if err != nil {
		return nil, fmt.Errorf("server: policy engine: %w", err)
	}
	s.policyEngine = eng

	// Load manifest if provided.
	if cfg.ManifestPath != "" {
		m, merr := manifest.Load(cfg.ManifestPath)
		if merr != nil {
			return nil, fmt.Errorf("server: manifest: %w", merr)
		}
		if verr := manifest.Validate(m); verr != nil {
			return nil, fmt.Errorf("server: manifest invalid: %w", verr)
		}
		s.manifest = m
	}

	// Epic 10: initialise telemetry tracer.
	tracerCfg := telemetry.Config{
		Disabled: cfg.TelemetryDisabled,
	}
	if !cfg.TelemetryDisabled && cfg.TelemetryPath != "" {
		exp, terr := telemetry.NewNDJSONExporter(cfg.TelemetryPath)
		if terr != nil {
			return nil, fmt.Errorf("server: telemetry: %w", terr)
		}
		tracerCfg.Exporter = exp
	}
	s.tracer = telemetry.NewTracer(tracerCfg)

	s.registerRoutes()

	s.httpSrv = &http.Server{
		Addr:         cfg.Addr,
		Handler:      s.mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return s, nil
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /readyz", s.handleReadyz)

	// Event ingest.
	s.mux.HandleFunc("POST /v1/events", s.handleAppendEvent)

	// Query API.
	s.mux.HandleFunc("GET /v1/events", s.handleListEvents)
	s.mux.HandleFunc("GET /v1/sessions/{sessionID}/snapshot", s.handleGetSnapshot)
	s.mux.HandleFunc("GET /v1/sessions/{sessionID}/verify", s.handleVerifyChain)

	// Policy decision API (Epic 03).
	s.mux.HandleFunc("POST /v1/policy/decide", s.handlePolicyDecide)
}

// Run starts the HTTP server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		if err := s.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.httpSrv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

// Close releases server resources.
func (s *Server) Close() {
	_ = s.store.Close()
	_ = s.tracer.Close()
}

// Mux returns the underlying ServeMux so tests can wrap it in httptest.NewServer.
func (s *Server) Mux() *http.ServeMux { return s.mux }

// SetTracer replaces the telemetry tracer. Useful for injecting test exporters.
func (s *Server) SetTracer(t *telemetry.Tracer) { s.tracer = t }

// PolicyDecideRequest is the body for POST /v1/policy/decide.
type PolicyDecideRequest struct {
	Event    map[string]any `json:"event"`
	Snapshot map[string]any `json:"snapshot"`
	Manifest map[string]any `json:"manifest,omitempty"`
}

func (s *Server) handlePolicyDecide(w http.ResponseWriter, r *http.Request) {
	var req PolicyDecideRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Use request manifest if provided; fall back to loaded server manifest.
	man := req.Manifest
	if man == nil && s.manifest != nil {
		man = s.manifest.ToMap()
	}
	if man == nil {
		man = map[string]any{} // permissive dev: empty manifest → policy will deny effectful tools
	}

	d, err := s.policyEngine.Evaluate(r.Context(), policy.Input{
		Event:    req.Event,
		Snapshot: req.Snapshot,
		Manifest: man,
	})
	if err != nil {
		jsonError(w, "policy eval: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(d)
}

// ── handlers ──────────────────────────────────────────────────────────────────

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	// Ping the DB with a quick query.
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	_, err := s.store.GetEvent(ctx, "_probe", "_probe", 0)
	if err != nil && err != store.ErrNotFound {
		http.Error(w, `{"status":"not ready","error":"db unreachable"}`, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
}

// AppendEventRequest is the JSON body for POST /v1/events.
type AppendEventRequest struct {
	TenantID  string          `json:"tenant_id"`
	UserID    string          `json:"user_id"`
	SessionID string          `json:"session_id"`
	Seq       uint64          `json:"seq"`
	TsUnixMs  int64           `json:"ts_unix_ms"`
	EventType string          `json:"event_type"`
	Payload   json.RawMessage `json:"payload"`
	PrevHash  []byte          `json:"prev_hash,omitempty"`
	Hash      []byte          `json:"hash,omitempty"`
}

func (s *Server) handleAppendEvent(w http.ResponseWriter, r *http.Request) {
	var req AppendEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.TenantID == "" || req.SessionID == "" {
		jsonError(w, "tenant_id and session_id are required", http.StatusBadRequest)
		return
	}

	var payload any
	if len(req.Payload) > 0 {
		if err := json.Unmarshal(req.Payload, &payload); err != nil {
			jsonError(w, "invalid payload JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	if req.TsUnixMs == 0 {
		req.TsUnixMs = time.Now().UnixMilli()
	}

	e := &eventlog.Envelope{
		TenantID:  req.TenantID,
		UserID:    req.UserID,
		SessionID: req.SessionID,
		Seq:       req.Seq,
		TsUnixMs:  req.TsUnixMs,
		EventType: eventlog.EventType(req.EventType),
		Payload:   payload,
		PrevHash:  req.PrevHash,
	}

	// If hash not supplied by client, compute it server-side.
	if len(req.Hash) == 0 {
		if err := e.Seal(); err != nil {
			jsonError(w, "seal: "+err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		e.Hash = req.Hash
		if err := e.Verify(); err != nil {
			jsonError(w, "hash verification failed: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	if err := s.store.AppendEvent(r.Context(), req.TenantID, e); err != nil {
		if err == store.ErrHashMismatch {
			jsonError(w, "hash chain mismatch", http.StatusConflict)
			return
		}
		jsonError(w, "store error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Epic 10: emit telemetry span (errors are non-fatal).
	_ = s.tracer.TraceEvent(r.Context(), e)

	// Drive the reducer and persist snapshot if due.
	snapKey := req.TenantID + "/" + req.SessionID
	red, ok := s.reducers[snapKey]
	if !ok {
		red = reducer.New(req.TenantID, req.SessionID)
		s.reducers[snapKey] = red
	}
	snap, err := red.Apply(e)
	if err == nil && snap != nil {
		_ = s.store.SaveSnapshot(r.Context(), snap) // best-effort
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"seq":  e.Seq,
		"hash": fmt.Sprintf("%x", e.Hash),
	})
}

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tenantID := q.Get("tenant_id")
	if tenantID == "" {
		jsonError(w, "tenant_id required", http.StatusBadRequest)
		return
	}

	f := store.EventFilter{
		SessionID:  q.Get("session_id"),
		EventType:  q.Get("event_type"),
		ToolName:   q.Get("tool_name"),
		PageToken:  q.Get("page_token"),
		Limit:      100,
	}

	page, err := s.store.ListEvents(r.Context(), tenantID, f)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(page)
}

func (s *Server) handleGetSnapshot(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenant_id")
	sessionID := r.PathValue("sessionID")
	if tenantID == "" {
		jsonError(w, "tenant_id required", http.StatusBadRequest)
		return
	}

	snap, err := s.store.GetSnapshot(r.Context(), tenantID, sessionID)
	if err != nil {
		if err == store.ErrNotFound {
			jsonError(w, "not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(snap)
}

func (s *Server) handleVerifyChain(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenant_id")
	sessionID := r.PathValue("sessionID")
	if tenantID == "" {
		jsonError(w, "tenant_id required", http.StatusBadRequest)
		return
	}

	badSeq, err := s.store.VerifyChain(r.Context(), tenantID, sessionID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"valid":         false,
			"first_bad_seq": badSeq,
			"error":         err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"valid": true})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": strings.TrimSpace(msg),
	})
}
