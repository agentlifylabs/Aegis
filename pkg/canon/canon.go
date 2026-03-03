// Package canon implements RFC 8785 (JCS) canonical JSON encoding
// and SHA-256 hashing for Aegis event envelopes.
package canon

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
)

// Canonicalize returns the RFC 8785 (JCS) canonical JSON encoding of v.
// v must be JSON-serializable. The output is deterministic across platforms.
func Canonicalize(v any) ([]byte, error) {
	// First encode to a generic map via the standard library.
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canon: marshal: %w", err)
	}
	var raw any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("canon: unmarshal to any: %w", err)
	}
	return canonicalizeValue(raw)
}

// Hash returns SHA-256(Canonicalize(v)). Returns nil,err on any failure.
func Hash(v any) ([]byte, error) {
	b, err := Canonicalize(v)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	return h[:], nil
}

// HashBytes returns SHA-256 of already-canonicalized bytes.
func HashBytes(canonical []byte) []byte {
	h := sha256.Sum256(canonical)
	return h[:]
}

func canonicalizeValue(v any) ([]byte, error) {
	switch val := v.(type) {
	case nil:
		return []byte("null"), nil
	case bool:
		if val {
			return []byte("true"), nil
		}
		return []byte("false"), nil
	case float64:
		return canonicalizeNumber(val)
	case string:
		return json.Marshal(val) // Go's stdlib produces correct escaped JSON strings
	case []any:
		return canonicalizeArray(val)
	case map[string]any:
		return canonicalizeObject(val)
	default:
		return nil, fmt.Errorf("canon: unsupported type %T", v)
	}
}

func canonicalizeNumber(f float64) ([]byte, error) {
	// JCS numbers: use the shortest decimal representation that round-trips.
	b, err := json.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("canon: number marshal: %w", err)
	}
	return b, nil
}

func canonicalizeArray(arr []any) ([]byte, error) {
	out := []byte{'['}
	for i, item := range arr {
		b, err := canonicalizeValue(item)
		if err != nil {
			return nil, err
		}
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, b...)
	}
	out = append(out, ']')
	return out, nil
}

func canonicalizeObject(obj map[string]any) ([]byte, error) {
	// JCS requires keys sorted by Unicode code point order.
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := []byte{'{'}
	for i, k := range keys {
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, fmt.Errorf("canon: key marshal: %w", err)
		}
		vb, err := canonicalizeValue(obj[k])
		if err != nil {
			return nil, err
		}
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, kb...)
		out = append(out, ':')
		out = append(out, vb...)
	}
	out = append(out, '}')
	return out, nil
}
