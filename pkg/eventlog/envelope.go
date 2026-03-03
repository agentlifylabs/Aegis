// Package eventlog provides the event envelope builder, hash-chain computation,
// and the event transition validator for Aegis.
package eventlog

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aegis-framework/aegis/pkg/canon"
)

// EventType mirrors the proto enum as a Go string constant for use before
// proto codegen is available (and as a human-readable form in JSON storage).
type EventType string

const (
	EventTypeModelCallStarted   EventType = "MODEL_CALL_STARTED"
	EventTypeModelCallFinished  EventType = "MODEL_CALL_FINISHED"
	EventTypeToolCallProposed   EventType = "TOOL_CALL_PROPOSED"
	EventTypeToolCallAllowed    EventType = "TOOL_CALL_ALLOWED"
	EventTypeToolCallDenied     EventType = "TOOL_CALL_DENIED"
	EventTypeToolCallExecuted   EventType = "TOOL_CALL_EXECUTED"
	EventTypeToolResult         EventType = "TOOL_RESULT"
	EventTypePolicyDecision     EventType = "POLICY_DECISION"
	EventTypeApprovalRequested  EventType = "APPROVAL_REQUESTED"
	EventTypeApprovalDecided    EventType = "APPROVAL_DECIDED"
	EventTypeMemoryRead         EventType = "MEMORY_READ"
	EventTypeMemoryWrite        EventType = "MEMORY_WRITE"
	EventTypeHandoffRequested   EventType = "HANDOFF_REQUESTED"
	EventTypeHandoffCompleted   EventType = "HANDOFF_COMPLETED"
	EventTypeCheckpointCreated  EventType = "CHECKPOINT_CREATED"
	EventTypeTermination        EventType = "TERMINATION"
	EventTypeErrorRaised        EventType = "ERROR_RAISED"
)

// Envelope is the canonical in-memory representation of an event before
// proto serialization. It is used for hashing and storage.
type Envelope struct {
	TenantID  string    `json:"tenant_id"`
	UserID    string    `json:"user_id"`
	SessionID string    `json:"session_id"`
	Seq       uint64    `json:"seq"`
	TsUnixMs  int64     `json:"ts_unix_ms"`
	EventType EventType `json:"event_type"`
	Payload   any       `json:"payload"`
	PrevHash  []byte    `json:"prev_hash,omitempty"`
	Hash      []byte    `json:"hash,omitempty"`
}

// hashableEnvelope is Envelope with Hash zeroed for computing the envelope hash.
type hashableEnvelope struct {
	TenantID  string    `json:"tenant_id"`
	UserID    string    `json:"user_id"`
	SessionID string    `json:"session_id"`
	Seq       uint64    `json:"seq"`
	TsUnixMs  int64     `json:"ts_unix_ms"`
	EventType EventType `json:"event_type"`
	Payload   any       `json:"payload"`
	PrevHash  []byte    `json:"prev_hash,omitempty"`
}

// Seal computes and sets the envelope's Hash field (SHA-256 of canonical JSON
// of the envelope without the hash field). It also validates that PrevHash is
// consistent: the first event (seq==0) must have nil PrevHash.
func (e *Envelope) Seal() error {
	if e.Seq == 0 && len(e.PrevHash) != 0 {
		return fmt.Errorf("eventlog: seq=0 must have empty prev_hash")
	}
	h := hashableEnvelope{
		TenantID:  e.TenantID,
		UserID:    e.UserID,
		SessionID: e.SessionID,
		Seq:       e.Seq,
		TsUnixMs:  e.TsUnixMs,
		EventType: e.EventType,
		Payload:   e.Payload,
		PrevHash:  e.PrevHash,
	}
	hash, err := canon.Hash(h)
	if err != nil {
		return fmt.Errorf("eventlog: seal: %w", err)
	}
	e.Hash = hash
	return nil
}

// Verify checks that e.Hash is correct for the envelope content.
func (e *Envelope) Verify() error {
	saved := e.Hash
	e.Hash = nil
	if err := e.Seal(); err != nil {
		e.Hash = saved
		return err
	}
	if !hmac.Equal(e.Hash, saved) {
		e.Hash = saved
		return fmt.Errorf("eventlog: hash mismatch at seq=%d", e.Seq)
	}
	return nil
}

// Builder constructs a series of chained envelopes for a session.
type Builder struct {
	TenantID  string
	UserID    string
	SessionID string
	nextSeq   uint64
	lastHash  []byte
}

// NewBuilder creates a Builder for a fresh session.
func NewBuilder(tenantID, userID, sessionID string) *Builder {
	return &Builder{
		TenantID:  tenantID,
		UserID:    userID,
		SessionID: sessionID,
	}
}

// NewBuilderFromSeq creates a Builder that continues an existing session at a given
// sequence number with the previous event's hash.
func NewBuilderFromSeq(tenantID, userID, sessionID string, nextSeq uint64, prevHash []byte) *Builder {
	return &Builder{
		TenantID:  tenantID,
		UserID:    userID,
		SessionID: sessionID,
		nextSeq:   nextSeq,
		lastHash:  prevHash,
	}
}

// Append creates and seals a new envelope, advancing the chain.
func (b *Builder) Append(evType EventType, payload any) (*Envelope, error) {
	e := &Envelope{
		TenantID:  b.TenantID,
		UserID:    b.UserID,
		SessionID: b.SessionID,
		Seq:       b.nextSeq,
		TsUnixMs:  time.Now().UnixMilli(),
		EventType: evType,
		Payload:   payload,
		PrevHash:  b.lastHash,
	}
	if err := e.Seal(); err != nil {
		return nil, err
	}
	b.lastHash = e.Hash
	b.nextSeq++
	return e, nil
}

// MarshalJSON returns the canonical JSON for an Envelope. Useful for storage.
func MarshalEnvelope(e *Envelope) ([]byte, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("eventlog: marshal: %w", err)
	}
	return b, nil
}

// UnmarshalEnvelope decodes JSON into an Envelope.
func UnmarshalEnvelope(data []byte) (*Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("eventlog: unmarshal: %w", err)
	}
	return &e, nil
}

// VerifyChain verifies hash-chain integrity across a slice of sequentially
// ordered envelopes. Returns the first bad sequence number or 0.
func VerifyChain(events []*Envelope) (firstBadSeq uint64, err error) {
	for i, e := range events {
		if err := e.Verify(); err != nil {
			return e.Seq, err
		}
		if i > 0 {
			prev := events[i-1]
			if !hmac.Equal(e.PrevHash, prev.Hash) {
				return e.Seq, fmt.Errorf("eventlog: broken chain at seq=%d (prev_hash mismatch)", e.Seq)
			}
			if e.Seq != prev.Seq+1 {
				return e.Seq, fmt.Errorf("eventlog: seq gap: expected %d got %d", prev.Seq+1, e.Seq)
			}
		}
	}
	return 0, nil
}

// ComputeSHA256 is a convenience function exposed for use in tests.
func ComputeSHA256(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
