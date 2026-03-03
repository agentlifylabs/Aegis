// Package postgres provides a PostgreSQL-backed EventStore for Aegis (production use).
package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aegis-framework/aegis/pkg/canon"
	"github.com/aegis-framework/aegis/pkg/eventlog"
	"github.com/aegis-framework/aegis/pkg/store"
)

// Store is a PostgreSQL-backed EventStore.
type Store struct {
	pool *pgxpool.Pool
}

// New creates a new Postgres-backed Store and runs migrations.
// dsn is a PostgreSQL connection string (postgres://user:pass@host/db).
func New(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}
	s := &Store{pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS events (
    tenant_id    TEXT        NOT NULL,
    session_id   TEXT        NOT NULL,
    seq          BIGINT      NOT NULL,
    ts_unix_ms   BIGINT      NOT NULL,
    event_type   TEXT        NOT NULL,
    payload_json JSONB       NOT NULL,
    hash         BYTEA       NOT NULL,
    prev_hash    BYTEA,
    PRIMARY KEY (tenant_id, session_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_events_ts      ON events (tenant_id, ts_unix_ms);
CREATE INDEX IF NOT EXISTS idx_events_type    ON events (tenant_id, event_type);
CREATE INDEX IF NOT EXISTS idx_events_payload ON events USING gin (payload_json);

CREATE TABLE IF NOT EXISTS snapshots (
    tenant_id      TEXT    NOT NULL,
    session_id     TEXT    NOT NULL,
    last_seq       BIGINT  NOT NULL,
    ts_unix_ms     BIGINT  NOT NULL,
    state_json     JSONB   NOT NULL,
    snapshot_hash  BYTEA   NOT NULL,
    PRIMARY KEY (tenant_id, session_id)
);
`

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, schema)
	if err != nil {
		return fmt.Errorf("postgres: migrate: %w", err)
	}
	return nil
}

// AppendEvent implements store.EventStore.
func (s *Store) AppendEvent(ctx context.Context, tenantID string, e *eventlog.Envelope) error {
	payloadBytes, err := json.Marshal(e.Payload)
	if err != nil {
		return fmt.Errorf("postgres: marshal payload: %w", err)
	}

	// Verify hash chain consistency.
	if e.Seq > 0 {
		var lastHash []byte
		err := s.pool.QueryRow(ctx,
			`SELECT hash FROM events WHERE tenant_id=$1 AND session_id=$2 ORDER BY seq DESC LIMIT 1`,
			tenantID, e.SessionID,
		).Scan(&lastHash)
		if err != nil && err != pgx.ErrNoRows {
			return fmt.Errorf("postgres: fetch last hash: %w", err)
		}
		if err == nil && string(lastHash) != string(e.PrevHash) {
			return fmt.Errorf("%w: session=%s seq=%d", store.ErrHashMismatch, e.SessionID, e.Seq)
		}
	}

	_, err = s.pool.Exec(ctx,
		`INSERT INTO events (tenant_id, session_id, seq, ts_unix_ms, event_type, payload_json, hash, prev_hash)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)`,
		tenantID, e.SessionID, e.Seq, e.TsUnixMs,
		string(e.EventType), string(payloadBytes),
		e.Hash, e.PrevHash,
	)
	if err != nil {
		return fmt.Errorf("postgres: insert event: %w", err)
	}
	return nil
}

// GetEvent implements store.EventStore.
func (s *Store) GetEvent(ctx context.Context, tenantID, sessionID string, seq uint64) (*store.StoredEvent, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT tenant_id, session_id, seq, ts_unix_ms, event_type, payload_json, hash, prev_hash
         FROM events WHERE tenant_id=$1 AND session_id=$2 AND seq=$3`,
		tenantID, sessionID, seq,
	)
	return scanStoredEvent(row)
}

// ListEvents implements store.EventStore.
func (s *Store) ListEvents(ctx context.Context, tenantID string, f store.EventFilter) (*store.EventPage, error) {
	var conds []string
	var args []any
	argIdx := 1

	conds = append(conds, fmt.Sprintf("tenant_id = $%d", argIdx))
	args = append(args, tenantID)
	argIdx++

	if f.SessionID != "" {
		conds = append(conds, fmt.Sprintf("session_id = $%d", argIdx))
		args = append(args, f.SessionID)
		argIdx++
	}
	if f.FromTsMs > 0 {
		conds = append(conds, fmt.Sprintf("ts_unix_ms >= $%d", argIdx))
		args = append(args, f.FromTsMs)
		argIdx++
	}
	if f.ToTsMs > 0 {
		conds = append(conds, fmt.Sprintf("ts_unix_ms <= $%d", argIdx))
		args = append(args, f.ToTsMs)
		argIdx++
	}
	if f.EventType != "" {
		conds = append(conds, fmt.Sprintf("event_type = $%d", argIdx))
		args = append(args, f.EventType)
		argIdx++
	}
	if f.ToolName != "" {
		conds = append(conds, fmt.Sprintf("payload_json->>'tool_name' = $%d", argIdx))
		args = append(args, f.ToolName)
		argIdx++
	}
	if f.PageToken != "" {
		conds = append(conds, fmt.Sprintf("seq > $%d", argIdx))
		args = append(args, f.PageToken)
		argIdx++
	}

	limit := uint32(100)
	if f.Limit > 0 && f.Limit <= 1000 {
		limit = f.Limit
	}

	query := `SELECT tenant_id, session_id, seq, ts_unix_ms, event_type, payload_json, hash, prev_hash FROM events`
	if len(conds) > 0 {
		query += " WHERE " + strings.Join(conds, " AND ")
	}
	query += fmt.Sprintf(" ORDER BY session_id, seq LIMIT %d", limit+1)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list events: %w", err)
	}
	defer rows.Close()

	var events []*store.StoredEvent
	for rows.Next() {
		var e store.StoredEvent
		var payloadJSON []byte
		if err := rows.Scan(
			&e.TenantID, &e.SessionID, &e.Seq, &e.TsUnixMs,
			&e.EventType, &payloadJSON, &e.Hash, &e.PrevHash,
		); err != nil {
			return nil, fmt.Errorf("postgres: scan: %w", err)
		}
		e.PayloadJSON = payloadJSON
		events = append(events, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: rows: %w", err)
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
	rows, err := s.pool.Query(ctx,
		`SELECT seq, hash, prev_hash FROM events
         WHERE tenant_id=$1 AND session_id=$2
         ORDER BY seq ASC`,
		tenantID, sessionID,
	)
	if err != nil {
		return 0, fmt.Errorf("postgres: verify chain query: %w", err)
	}
	defer rows.Close()

	type chainRow struct {
		seq      uint64
		hash     []byte
		prevHash []byte
	}

	var prev *chainRow
	for rows.Next() {
		var r chainRow
		if err := rows.Scan(&r.seq, &r.hash, &r.prevHash); err != nil {
			return 0, fmt.Errorf("postgres: verify chain scan: %w", err)
		}
		if prev != nil {
			if string(r.prevHash) != string(prev.hash) {
				return r.seq, fmt.Errorf("%w: seq=%d prev_hash mismatch", store.ErrHashMismatch, r.seq)
			}
			if r.seq != prev.seq+1 {
				return r.seq, fmt.Errorf("postgres: seq gap: expected %d got %d", prev.seq+1, r.seq)
			}
		}
		prev = &r
	}
	return 0, rows.Err()
}

// SaveSnapshot implements store.EventStore.
func (s *Store) SaveSnapshot(ctx context.Context, snap *store.Snapshot) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO snapshots (tenant_id, session_id, last_seq, ts_unix_ms, state_json, snapshot_hash)
         VALUES ($1, $2, $3, $4, $5::jsonb, $6)
         ON CONFLICT (tenant_id, session_id) DO UPDATE SET
             last_seq=EXCLUDED.last_seq,
             ts_unix_ms=EXCLUDED.ts_unix_ms,
             state_json=EXCLUDED.state_json,
             snapshot_hash=EXCLUDED.snapshot_hash`,
		snap.TenantID, snap.SessionID, snap.LastSeq,
		snap.TsUnixMs, string(snap.StateJSON), snap.SnapshotHash,
	)
	if err != nil {
		return fmt.Errorf("postgres: save snapshot: %w", err)
	}
	return nil
}

// GetSnapshot implements store.EventStore.
func (s *Store) GetSnapshot(ctx context.Context, tenantID, sessionID string) (*store.Snapshot, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT tenant_id, session_id, last_seq, ts_unix_ms, state_json, snapshot_hash
         FROM snapshots WHERE tenant_id=$1 AND session_id=$2`,
		tenantID, sessionID,
	)
	var snap store.Snapshot
	var stateJSON []byte
	if err := row.Scan(
		&snap.TenantID, &snap.SessionID, &snap.LastSeq,
		&snap.TsUnixMs, &stateJSON, &snap.SnapshotHash,
	); err != nil {
		if err == pgx.ErrNoRows {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: get snapshot: %w", err)
	}
	snap.StateJSON = stateJSON
	return &snap, nil
}

// Close implements store.EventStore.
func (s *Store) Close() error {
	s.pool.Close()
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func scanStoredEvent(row pgx.Row) (*store.StoredEvent, error) {
	var e store.StoredEvent
	var payloadJSON []byte
	if err := row.Scan(
		&e.TenantID, &e.SessionID, &e.Seq, &e.TsUnixMs,
		&e.EventType, &payloadJSON, &e.Hash, &e.PrevHash,
	); err != nil {
		if err == pgx.ErrNoRows {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan event: %w", err)
	}
	e.PayloadJSON = payloadJSON
	return &e, nil
}

// ComputeSnapshotHash returns the SHA-256 of the canonical JSON of stateJSON.
func ComputeSnapshotHash(stateJSON []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(stateJSON, &v); err != nil {
		return nil, err
	}
	return canon.Hash(v)
}
