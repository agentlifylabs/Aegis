// Package proxy — stdio transport for the MCP proxy.
// Reads newline-delimited JSON-RPC requests from an io.Reader,
// writes responses to an io.Writer. Suitable for local agent frameworks.
package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
)

// StdioServer wraps a Proxy and serves it over a stdio pipe.
type StdioServer struct {
	proxy *Proxy
}

// NewStdioServer creates a StdioServer backed by p.
func NewStdioServer(p *Proxy) *StdioServer {
	return &StdioServer{proxy: p}
}

// Serve reads newline-delimited JSON-RPC requests from r and writes responses to w.
// It blocks until r is exhausted or ctx is cancelled.
func (s *StdioServer) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	enc := json.NewEncoder(w)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024) // 4 MiB max line

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			resp := errResponse(nil, -32700, fmt.Sprintf("parse error: %v", err), nil)
			_ = enc.Encode(resp)
			continue
		}

		resp := s.proxy.Handle(ctx, &req)
		if err := enc.Encode(resp); err != nil {
			return fmt.Errorf("stdio: write response: %w", err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("stdio: scan: %w", err)
	}
	return nil
}
