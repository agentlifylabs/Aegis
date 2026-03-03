package eventlog

import (
	"fmt"
)

// terminalEvents are event types after which no further events are permitted.
var terminalEvents = map[EventType]bool{
	EventTypeTermination: true,
}

// validTransitions defines which event types are valid successors for a given
// event type within a session.
var validTransitions = map[EventType]map[EventType]bool{
	EventTypeModelCallStarted: {
		EventTypeModelCallFinished: true,
		EventTypeErrorRaised:       true,
		EventTypeTermination:       true,
	},
	EventTypeModelCallFinished: {
		EventTypeToolCallProposed:  true,
		EventTypeModelCallStarted:  true,
		EventTypeCheckpointCreated: true,
		EventTypeTermination:       true,
		EventTypeHandoffRequested:  true,
		EventTypeErrorRaised:       true,
	},
	EventTypeToolCallProposed: {
		EventTypePolicyDecision: true,
		EventTypeErrorRaised:    true,
		EventTypeTermination:    true,
	},
	EventTypePolicyDecision: {
		EventTypeToolCallAllowed:   true,
		EventTypeToolCallDenied:    true,
		EventTypeApprovalRequested: true,
		EventTypeTermination:       true,
	},
	EventTypeToolCallAllowed: {
		EventTypeToolCallExecuted: true,
		EventTypeErrorRaised:      true,
	},
	EventTypeToolCallDenied: {
		EventTypeToolCallProposed:  true,
		EventTypeModelCallStarted:  true,
		EventTypeCheckpointCreated: true,
		EventTypeTermination:       true,
		EventTypeErrorRaised:       true,
	},
	EventTypeToolCallExecuted: {
		EventTypeToolResult:  true,
		EventTypeErrorRaised: true,
	},
	EventTypeToolResult: {
		EventTypeToolCallProposed:  true,
		EventTypeModelCallStarted:  true,
		EventTypeCheckpointCreated: true,
		EventTypeTermination:       true,
		EventTypeHandoffRequested:  true,
		EventTypeErrorRaised:       true,
	},
	EventTypeApprovalRequested: {
		EventTypeApprovalDecided: true,
		EventTypeTermination:     true,
	},
	EventTypeApprovalDecided: {
		EventTypeToolCallAllowed:  true,
		EventTypeToolCallDenied:   true,
		EventTypeTermination:      true,
	},
	EventTypeMemoryRead: {
		EventTypeToolCallProposed:  true,
		EventTypeModelCallStarted:  true,
		EventTypeMemoryRead:        true,
		EventTypeMemoryWrite:       true,
		EventTypeCheckpointCreated: true,
		EventTypeTermination:       true,
		EventTypeErrorRaised:       true,
	},
	EventTypeMemoryWrite: {
		EventTypeToolCallProposed:  true,
		EventTypeModelCallStarted:  true,
		EventTypeMemoryRead:        true,
		EventTypeMemoryWrite:       true,
		EventTypeCheckpointCreated: true,
		EventTypeTermination:       true,
		EventTypeErrorRaised:       true,
	},
	EventTypeHandoffRequested: {
		EventTypeHandoffCompleted: true,
		EventTypeErrorRaised:      true,
		EventTypeTermination:      true,
	},
	EventTypeHandoffCompleted: {
		EventTypeModelCallStarted:  true,
		EventTypeCheckpointCreated: true,
		EventTypeTermination:       true,
	},
	EventTypeCheckpointCreated: {
		EventTypeToolCallProposed:  true,
		EventTypeModelCallStarted:  true,
		EventTypeCheckpointCreated: true,
		EventTypeTermination:       true,
		EventTypeErrorRaised:       true,
	},
	EventTypeErrorRaised: {
		EventTypeTermination: true,
	},
}

// startEvents are valid first events in a session.
var startEvents = map[EventType]bool{
	EventTypeModelCallStarted:  true,
	EventTypeToolCallProposed:  true,
	EventTypeCheckpointCreated: true,
}

// ValidationError records a transition violation.
type ValidationError struct {
	Seq  uint64
	Prev EventType
	Next EventType
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf(
		"eventlog: invalid transition at seq=%d: %s -> %s",
		e.Seq, e.Prev, e.Next,
	)
}

// Validator tracks state for incremental event stream validation.
// Use NewValidator for a fresh session, or advance it using Validate.
type Validator struct {
	sessionID string
	lastType  *EventType
	lastSeq   uint64
}

// NewValidator creates a fresh validator for a session.
func NewValidator(sessionID string) *Validator {
	return &Validator{sessionID: sessionID}
}

// Validate checks that the given event is a valid successor to the last seen
// event in this session. Returns a *ValidationError on violation.
func (v *Validator) Validate(e *Envelope) error {
	if e.SessionID != v.sessionID {
		return fmt.Errorf("eventlog: validator session mismatch: got %s want %s", e.SessionID, v.sessionID)
	}
	if v.lastType == nil {
		// First event in session.
		if !startEvents[e.EventType] {
			return fmt.Errorf(
				"eventlog: invalid start event at seq=%d: %s is not a valid session-start event",
				e.Seq, e.EventType,
			)
		}
		v.lastType = &e.EventType
		v.lastSeq = e.Seq
		return nil
	}

	// Check seq is monotonically increasing.
	if e.Seq != v.lastSeq+1 {
		return fmt.Errorf(
			"eventlog: non-monotonic seq: expected %d got %d in session %s",
			v.lastSeq+1, e.Seq, v.sessionID,
		)
	}

	// Terminal events have no valid successors.
	if terminalEvents[*v.lastType] {
		return &ValidationError{Seq: e.Seq, Prev: *v.lastType, Next: e.EventType}
	}

	// Check transition.
	allowed, ok := validTransitions[*v.lastType]
	if !ok {
		// Unknown predecessor type — treat as error.
		return &ValidationError{Seq: e.Seq, Prev: *v.lastType, Next: e.EventType}
	}
	if !allowed[e.EventType] {
		return &ValidationError{Seq: e.Seq, Prev: *v.lastType, Next: e.EventType}
	}

	v.lastType = &e.EventType
	v.lastSeq = e.Seq
	return nil
}

// ValidateSequence validates an ordered slice of envelopes in one call.
// Returns the first ValidationError encountered.
func ValidateSequence(events []*Envelope) error {
	if len(events) == 0 {
		return nil
	}
	v := NewValidator(events[0].SessionID)
	for _, e := range events {
		if err := v.Validate(e); err != nil {
			return err
		}
	}
	return nil
}
