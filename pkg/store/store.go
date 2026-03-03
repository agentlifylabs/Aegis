// Package store defines the EventStore interface and shared types for the Aegis
// event persistence layer (Epic 02).
package store

import (
	"context"
	"errors"

	"github.com/aegis-framework/aegis/pkg/eventlog"
)

// ErrNotFound is returned when a requested record does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrHashMismatch is returned when hash-chain verification fails.
var ErrHashMismatch = errors.New("store: hash chain mismatch")

// StoredEvent is the DB projection of an eventlog.Envelope.
type StoredEvent struct {
	TenantID    string
	SessionID   string
	Seq         uint64
	TsUnixMs    int64
	EventType   string
	PayloadJSON []byte
	Hash        []byte
	PrevHash    []byte
}

// EventFilter holds optional query parameters for ListEvents.
type EventFilter struct {
	SessionID     string
	FromTsMs      int64
	ToTsMs        int64
	EventType     string
	ToolName      string  // substring match on ToolCallProposed payloads
	PolicyOutcome string  // "ALLOW" | "DENY" | "REQUIRE_APPROVAL"
	Limit         uint32
	PageToken     string
}

// EventPage is a page of results from ListEvents.
type EventPage struct {
	Events    []*StoredEvent
	NextToken string
}

// EventStore is the interface that Postgres and SQLite adapters implement.
type EventStore interface {
	// AppendEvent persists a sealed envelope. Returns ErrHashMismatch if prev_hash
	// does not match the last stored event for the session.
	AppendEvent(ctx context.Context, tenantID string, e *eventlog.Envelope) error

	// GetEvent retrieves a single event by (tenantID, sessionID, seq).
	GetEvent(ctx context.Context, tenantID, sessionID string, seq uint64) (*StoredEvent, error)

	// ListEvents returns a filtered, paginated page of events for a tenant.
	ListEvents(ctx context.Context, tenantID string, f EventFilter) (*EventPage, error)

	// VerifyChain verifies the hash chain for a session and returns the first bad seq.
	VerifyChain(ctx context.Context, tenantID, sessionID string) (firstBadSeq uint64, err error)

	// SaveSnapshot persists a snapshot for a session.
	SaveSnapshot(ctx context.Context, snap *Snapshot) error

	// GetSnapshot retrieves the latest snapshot for (tenantID, sessionID).
	GetSnapshot(ctx context.Context, tenantID, sessionID string) (*Snapshot, error)

	// Close releases resources held by the store.
	Close() error
}

// Snapshot is the DB row for a session's latest reduced state.
type Snapshot struct {
	TenantID     string
	SessionID    string
	LastSeq      uint64
	TsUnixMs     int64
	StateJSON    []byte // canonical JSON of SnapshotState
	SnapshotHash []byte // SHA-256 of StateJSON
}
