// Package proxy — Streamable HTTP transport for the MCP proxy (Epic 05).
// Implements the MCP Streamable HTTP spec:
//   - POST /mcp  → single JSON-RPC request → single JSON response
//   - GET  /mcp  → server-sent events stream (keepalive + push notifications)
package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// HTTPServer exposes the Proxy over Streamable HTTP.
type HTTPServer struct {
	proxy   *Proxy
	mux     *http.ServeMux
	httpSrv *http.Server
}

// NewHTTPServer creates an HTTPServer that listens on addr.
func NewHTTPServer(p *Proxy, addr string) *HTTPServer {
	s := &HTTPServer{
		proxy: p,
		mux:   http.NewServeMux(),
	}
	s.mux.HandleFunc("POST /mcp", s.handlePost)
	s.mux.HandleFunc("GET /mcp", s.handleSSE)
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)

	s.httpSrv = &http.Server{
		Addr:         addr,
		Handler:      s.mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	return s
}

// Run starts the HTTP server and blocks until ctx is cancelled.
func (s *HTTPServer) Run(ctx context.Context) error {
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

// Handler returns the underlying http.Handler for embedding in an existing mux.
func (s *HTTPServer) Handler() http.Handler { return s.mux }

// ── handlers ──────────────────────────────────────────────────────────────────

func (s *HTTPServer) handlePost(w http.ResponseWriter, r *http.Request) {
	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(errResponse(nil, -32700, "parse error: "+err.Error(), nil))
		return
	}

	resp := s.proxy.Handle(r.Context(), &req)
	w.Header().Set("Content-Type", "application/json")
	if resp.Error != nil {
		switch resp.Error.Code {
		case ErrCodeApprovalPending:
			w.WriteHeader(http.StatusAccepted)
		case ErrCodePolicyDeny:
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// handleSSE implements the MCP Streamable HTTP GET endpoint.
// Sends a keepalive comment every 15 seconds so proxies don't close the connection.
func (s *HTTPServer) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	// Send the initial endpoint event so the client knows where to POST.
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	endpoint := fmt.Sprintf("%s://%s/mcp", scheme, r.Host)
	_, _ = fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", endpoint)
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case t := <-ticker.C:
			_, _ = fmt.Fprintf(w, ": keepalive %d\n\n", t.Unix())
			flusher.Flush()
		}
	}
}

func (s *HTTPServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
