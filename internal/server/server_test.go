package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aegis-framework/aegis/pkg/eventlog"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(Config{DSN: ":memory:", Addr: ":0"})
	require.NoError(t, err)
	t.Cleanup(s.Close)
	return s
}

func TestHandleHealthz(t *testing.T) {
	s := newTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	s.mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"status"`)
}

func TestHandleReadyz(t *testing.T) {
	s := newTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	s.mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestAppendEventAndQuery(t *testing.T) {
	s := newTestServer(t)

	// Append a model_call_started event.
	body := AppendEventRequest{
		TenantID:  "t1",
		UserID:    "u1",
		SessionID: "session-test",
		Seq:       0,
		TsUnixMs:  time.Now().UnixMilli(),
		EventType: "MODEL_CALL_STARTED",
		Payload:   json.RawMessage(`{"model_id":"gpt-4o","call_id":"c1"}`),
	}
	bodyBytes, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	s.mux.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	var resp map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, float64(0), resp["seq"])

	// Query events.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/v1/events?tenant_id=t1&session_id=session-test", nil)
	s.mux.ServeHTTP(rec2, req2)
	require.Equal(t, http.StatusOK, rec2.Code)
	var listResp map[string]any
	require.NoError(t, json.Unmarshal(rec2.Body.Bytes(), &listResp))
	events := listResp["Events"].([]any)
	assert.Len(t, events, 1)
}

func TestAppendChainAndVerify(t *testing.T) {
	s := newTestServer(t)
	b := eventlog.NewBuilder("t1", "u1", "session-chain")

	types := []eventlog.EventType{
		eventlog.EventTypeModelCallStarted,
		eventlog.EventTypeModelCallFinished,
		eventlog.EventTypeTermination,
	}
	for _, et := range types {
		e, err := b.Append(et, nil)
		require.NoError(t, err)

		body, _ := json.Marshal(AppendEventRequest{
			TenantID:  "t1",
			UserID:    "u1",
			SessionID: "session-chain",
			Seq:       e.Seq,
			TsUnixMs:  e.TsUnixMs,
			EventType: string(et),
			Hash:      e.Hash,
			PrevHash:  e.PrevHash,
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		s.mux.ServeHTTP(rec, req)
		require.Equal(t, http.StatusCreated, rec.Code, "seq=%d: %s", e.Seq, rec.Body.String())
	}

	// Verify chain integrity.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sessions/session-chain/verify?tenant_id=t1", nil)
	s.mux.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var result map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
	assert.Equal(t, true, result["valid"])
}

func TestGetSnapshot(t *testing.T) {
	s := newTestServer(t)
	b := eventlog.NewBuilder("t1", "u1", "session-snap")

	// Append a Termination event to trigger snapshot.
	e0, _ := b.Append(eventlog.EventTypeModelCallStarted, nil)
	e1, _ := b.Append(eventlog.EventTypeTermination, nil)

	for _, e := range []*eventlog.Envelope{e0, e1} {
		body, _ := json.Marshal(AppendEventRequest{
			TenantID:  "t1",
			UserID:    "u1",
			SessionID: "session-snap",
			Seq:       e.Seq,
			TsUnixMs:  e.TsUnixMs,
			EventType: string(e.EventType),
			Hash:      e.Hash,
			PrevHash:  e.PrevHash,
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		s.mux.ServeHTTP(rec, req)
		require.Equal(t, http.StatusCreated, rec.Code)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sessions/session-snap/snapshot?tenant_id=t1", nil)
	s.mux.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var snap map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &snap))
	assert.Equal(t, "t1", snap["TenantID"])
}

func TestMissingTenantID(t *testing.T) {
	s := newTestServer(t)
	body, _ := json.Marshal(AppendEventRequest{
		UserID:    "u1",
		SessionID: "s1",
		EventType: "MODEL_CALL_STARTED",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestListEventsFilterByType(t *testing.T) {
	s := newTestServer(t)
	b := eventlog.NewBuilder("t1", "u1", "session-filter")

	for _, et := range []eventlog.EventType{
		eventlog.EventTypeModelCallStarted,
		eventlog.EventTypeModelCallFinished,
	} {
		e, _ := b.Append(et, nil)
		body, _ := json.Marshal(AppendEventRequest{
			TenantID: "t1", UserID: "u1", SessionID: "session-filter",
			Seq: e.Seq, TsUnixMs: e.TsUnixMs, EventType: string(et),
			Hash: e.Hash, PrevHash: e.PrevHash,
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		s.mux.ServeHTTP(rec, req)
		require.Equal(t, http.StatusCreated, rec.Code)
	}

	rec := httptest.NewRecorder()
	url := fmt.Sprintf("/v1/events?tenant_id=t1&session_id=session-filter&event_type=%s", "MODEL_CALL_STARTED")
	req := httptest.NewRequest(http.MethodGet, url, nil)
	s.mux.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var listResp map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &listResp))
	events := listResp["Events"].([]any)
	assert.Len(t, events, 1)
}
