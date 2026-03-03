package telemetry

import (
	"crypto/rand"
	"regexp"
)

// PII redaction patterns.
var (
	emailPattern    = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	phonePattern    = regexp.MustCompile(`\b(\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b`)
	hexTokenPattern = regexp.MustCompile(`\b[0-9a-fA-F]{32,}\b`)
)

// cryptoRandRead delegates to crypto/rand.Read.
func cryptoRandRead(b []byte) (int, error) {
	return rand.Read(b)
}
