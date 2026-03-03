// Package sqlite provides a SQLite-backed EventStore for Aegis (dev/test use).
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/aegis-framework/aegis/pkg/canon"
	"github.com/aegis-framework/aegis/pkg/eventlog"
	"github.com/aegis-framework/aegis/pkg/store"
)

// Store is a SQLite-backed EventStore.
type Store struct {
	db *sql.DB
}

// New opens (or creates) a SQLite database at dsn and runs migrations.
// Use dsn=":memory:" for in-process tests.
func New(dsn string) (*Store, error) {
	db, err := sql.Open("sqlite3", dsn+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS events (
    tenant_id    TEXT    NOT NULL,
    session_id   TEXT    NOT NULL,
    seq          INTEGER NOT NULL,
    ts_unix_ms   INTEGER NOT NULL,
    event_type   TEXT    NOT NULL,
    payload_json TEXT    NOT NULL,
    hash         BLOB    NOT NULL,
    prev_hash    BLOB,
    PRIMARY KEY (tenant_id, session_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_events_ts       ON events (tenant_id, ts_unix_ms);
CREATE INDEX IF NOT EXISTS idx_events_type     ON events (tenant_id, event_type);

CREATE TABLE IF NOT EXISTS snapshots (
    tenant_id      TEXT    NOT NULL,
    session_id     TEXT    NOT NULL,
    last_seq       INTEGER NOT NULL,
    ts_unix_ms     INTEGER NOT NULL,
    state_json     TEXT    NOT NULL,
    snapshot_hash  BLOB    NOT NULL,
    PRIMARY KEY (tenant_id, session_id)
);
`

func (s *Store) migrate() error {
	_, err := s.db.ExecContext(context.Background(), schema)
	if err != nil {
		return fmt.Errorf("sqlite: migrate: %w", err)
	}
	return nil
}

// AppendEvent implements store.EventStore.
func (s *Store) AppendEvent(ctx context.Context, tenantID string, e *eventlog.Envelope) error {
	payloadBytes, err := json.Marshal(e.Payload)
	if err != nil {
		return fmt.Errorf("sqlite: marshal payload: %w", err)
	}

	// Verify prev_hash consistency unless this is seq=0.
	if e.Seq > 0 {
		var lastHash []byte
		err := s.db.QueryRowContext(ctx,
			`SELECT hash FROM events WHERE tenant_id=? AND session_id=? ORDER BY seq DESC LIMIT 1`,
			tenantID, e.SessionID,
		).Scan(&lastHash)
		if err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("sqlite: fetch last hash: %w", err)
		}
		if err == nil {
			if string(lastHash) != string(e.PrevHash) {
				return fmt.Errorf("%w: session=%s seq=%d", store.ErrHashMismatch, e.SessionID, e.Seq)
			}
		}
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO events (tenant_id, session_id, seq, ts_unix_ms, event_type, payload_json, hash, prev_hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		tenantID, e.SessionID, e.Seq, e.TsUnixMs,
		string(e.EventType), string(payloadBytes),
		e.Hash, e.PrevHash,
	)
	if err != nil {
		return fmt.Errorf("sqlite: insert event: %w", err)
	}
	return nil
}

// GetEvent implements store.EventStore.
func (s *Store) GetEvent(ctx context.Context, tenantID, sessionID string, seq uint64) (*store.StoredEvent, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT tenant_id, session_id, seq, ts_unix_ms, event_type, payload_json, hash, prev_hash
         FROM events WHERE tenant_id=? AND session_id=? AND seq=?`,
		tenantID, sessionID, seq,
	)
	return scanStoredEvent(row)
}

// ListEvents implements store.EventStore.
func (s *Store) ListEvents(ctx context.Context, tenantID string, f store.EventFilter) (*store.EventPage, error) {
	var conds []string
	var args []any

	conds = append(conds, "tenant_id = ?")
	args = append(args, tenantID)

	if f.SessionID != "" {
		conds = append(conds, "session_id = ?")
		args = append(args, f.SessionID)
	}
	if f.FromTsMs > 0 {
		conds = append(conds, "ts_unix_ms >= ?")
		args = append(args, f.FromTsMs)
	}
	if f.ToTsMs > 0 {
		conds = append(conds, "ts_unix_ms <= ?")
		args = append(args, f.ToTsMs)
	}
	if f.EventType != "" {
		conds = append(conds, "event_type = ?")
		args = append(args, f.EventType)
	}
	if f.ToolName != "" {
		// Best-effort: match tool_name substring in payload_json.
		conds = append(conds, "payload_json LIKE ?")
		args = append(args, "%"+f.ToolName+"%")
	}
	if f.PageToken != "" {
		// page_token is the last seen seq (base-10 uint64 as string).
		conds = append(conds, "seq > ?")
		args = append(args, f.PageToken)
	}

	limit := uint32(100)
	if f.Limit > 0 && f.Limit <= 1000 {
		limit = f.Limit
	}

	query := "SELECT tenant_id, session_id, seq, ts_unix_ms, event_type, payload_json, hash, prev_hash FROM events"
	if len(conds) > 0 {
		query += " WHERE " + strings.Join(conds, " AND ")
	}
	query += fmt.Sprintf(" ORDER BY session_id, seq LIMIT %d", limit+1)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var events []*store.StoredEvent
	for rows.Next() {
		e, err := scanStoredEventRow(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: rows: %w", err)
	}

	page := &store.EventPage{}
	if uint32(len(events)) > limit {
		last := events[limit-1]
		page.NextToken = fmt.Sprintf("%d", last.Seq)
		page.Events = events[:limit]
	} else {
		page.Events = events
	}
	return page, nil
}

// VerifyChain implements store.EventStore.
func (s *Store) VerifyChain(ctx context.Context, tenantID, sessionID string) (uint64, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT seq, hash, prev_hash FROM events
         WHERE tenant_id=? AND session_id=?
         ORDER BY seq ASC`,
		tenantID, sessionID,
	)
	if err != nil {
		return 0, fmt.Errorf("sqlite: verify chain query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	type chainRow struct {
		seq      uint64
		hash     []byte
		prevHash []byte
	}

	var prev *chainRow
	for rows.Next() {
		var r chainRow
		if err := rows.Scan(&r.seq, &r.hash, &r.prevHash); err != nil {
			return 0, fmt.Errorf("sqlite: verify chain scan: %w", err)
		}
		if prev != nil {
			if string(r.prevHash) != string(prev.hash) {
				return r.seq, fmt.Errorf("%w: seq=%d prev_hash mismatch", store.ErrHashMismatch, r.seq)
			}
			if r.seq != prev.seq+1 {
				return r.seq, fmt.Errorf("sqlite: seq gap: expected %d got %d", prev.seq+1, r.seq)
			}
		}
		prev = &r
	}
	return 0, rows.Err()
}

// SaveSnapshot implements store.EventStore.
func (s *Store) SaveSnapshot(ctx context.Context, snap *store.Snapshot) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO snapshots (tenant_id, session_id, last_seq, ts_unix_ms, state_json, snapshot_hash)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT (tenant_id, session_id) DO UPDATE SET
             last_seq=excluded.last_seq,
             ts_unix_ms=excluded.ts_unix_ms,
             state_json=excluded.state_json,
             snapshot_hash=excluded.snapshot_hash`,
		snap.TenantID, snap.SessionID, snap.LastSeq,
		snap.TsUnixMs, string(snap.StateJSON), snap.SnapshotHash,
	)
	if err != nil {
		return fmt.Errorf("sqlite: save snapshot: %w", err)
	}
	return nil
}

// GetSnapshot implements store.EventStore.
func (s *Store) GetSnapshot(ctx context.Context, tenantID, sessionID string) (*store.Snapshot, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT tenant_id, session_id, last_seq, ts_unix_ms, state_json, snapshot_hash
         FROM snapshots WHERE tenant_id=? AND session_id=?`,
		tenantID, sessionID,
	)
	var snap store.Snapshot
	if err := row.Scan(
		&snap.TenantID, &snap.SessionID, &snap.LastSeq,
		&snap.TsUnixMs, &snap.StateJSON, &snap.SnapshotHash,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("sqlite: get snapshot: %w", err)
	}
	return &snap, nil
}

// Close implements store.EventStore.
func (s *Store) Close() error {
	return s.db.Close()
}

// ── helpers ───────────────────────────────────────────────────────────────────


func scanStoredEvent(row *sql.Row) (*store.StoredEvent, error) {
	var e store.StoredEvent
	var payloadStr string
	if err := row.Scan(
		&e.TenantID, &e.SessionID, &e.Seq, &e.TsUnixMs,
		&e.EventType, &payloadStr, &e.Hash, &e.PrevHash,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("sqlite: scan event: %w", err)
	}
	e.PayloadJSON = []byte(payloadStr)
	return &e, nil
}

func scanStoredEventRow(rows *sql.Rows) (*store.StoredEvent, error) {
	var e store.StoredEvent
	var payloadStr string
	if err := rows.Scan(
		&e.TenantID, &e.SessionID, &e.Seq, &e.TsUnixMs,
		&e.EventType, &payloadStr, &e.Hash, &e.PrevHash,
	); err != nil {
		return nil, fmt.Errorf("sqlite: scan event row: %w", err)
	}
	e.PayloadJSON = []byte(payloadStr)
	return &e, nil
}

// EnvelopeToStoredEvent converts an eventlog.Envelope to a store.StoredEvent.
func EnvelopeToStoredEvent(tenantID string, e *eventlog.Envelope) (*store.StoredEvent, error) {
	payloadBytes, err := json.Marshal(e.Payload)
	if err != nil {
		return nil, fmt.Errorf("sqlite: marshal payload: %w", err)
	}
	return &store.StoredEvent{
		TenantID:    tenantID,
		SessionID:   e.SessionID,
		Seq:         e.Seq,
		TsUnixMs:    e.TsUnixMs,
		EventType:   string(e.EventType),
		PayloadJSON: payloadBytes,
		Hash:        e.Hash,
		PrevHash:    e.PrevHash,
	}, nil
}

// StoredEventToEnvelope converts a store.StoredEvent back to an eventlog.Envelope.
func StoredEventToEnvelope(se *store.StoredEvent) (*eventlog.Envelope, error) {
	var payload any
	if err := json.Unmarshal(se.PayloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("sqlite: unmarshal payload: %w", err)
	}
	return &eventlog.Envelope{
		TenantID:  se.TenantID,
		UserID:    "",
		SessionID: se.SessionID,
		Seq:       se.Seq,
		TsUnixMs:  se.TsUnixMs,
		EventType: eventlog.EventType(se.EventType),
		Payload:   payload,
		Hash:      se.Hash,
		PrevHash:  se.PrevHash,
	}, nil
}

// NowMs returns the current time in Unix milliseconds.
func NowMs() int64 {
	return time.Now().UnixMilli()
}

// ComputeSnapshotHash returns the SHA-256 of the canonical JSON of stateJSON.
func ComputeSnapshotHash(stateJSON []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(stateJSON, &v); err != nil {
		return nil, err
	}
	return canon.Hash(v)
}
