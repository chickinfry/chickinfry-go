// Package host implements the byte contract used by server host calls.
package host

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

const MaxFrame = 4 << 20
const MaxHandle = 1<<53 - 1

// Error preserves a sanitized host error, including SQLSTATE and commit_unknown.
type Error struct {
	Code   string
	Status int
}

func (err *Error) Error() string { return err.Code }

// Decode rejects duplicate keys, trailing data and unknown struct fields.
func Decode(frame []byte, output any) error {
	if !utf8.Valid(frame) {
		return errors.New("invalid host frame")
	}
	check := json.NewDecoder(bytes.NewReader(frame))
	check.UseNumber()
	if err := unique(check, 0); err != nil {
		return err
	}
	if _, err := check.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing host data")
	}
	decoder := json.NewDecoder(bytes.NewReader(frame))
	decoder.DisallowUnknownFields()
	return decoder.Decode(output)
}

func unique(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("host frame too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim != '{' && delim != '[' {
		return errors.New("invalid host frame")
	}
	keys := map[string]bool{}
	for decoder.More() {
		if delim == '{' {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || keys[name] {
				return errors.New("duplicate host key")
			}
			keys[name] = true
		}
		if err := unique(decoder, depth+1); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

// Envelope checks the exact response shape before decoding its payload.
func Envelope(frame []byte, field string, output any) error {
	return EnvelopeLimit(frame, field, output, MaxFrame)
}

// EnvelopeLimit applies Envelope within an operation-specific frame budget.
func EnvelopeLimit(frame []byte, field string, output any, limit int) error {
	if limit != MaxFrame && limit != StorageFrame {
		return errors.New("invalid host frame limit")
	}
	if len(frame) > limit {
		return errors.New("host response too large")
	}
	var object map[string]json.RawMessage
	if err := Decode(frame, &object); err != nil || object == nil {
		return errors.New("invalid host response")
	}
	if value, ok := object["error"]; ok {
		var code string
		if json.Unmarshal(value, &code) != nil || !validError(code) {
			return errors.New("invalid host error")
		}
		failure := &Error{Code: code}
		if raw, exists := object["status"]; exists {
			if len(object) != 2 || json.Unmarshal(raw, &failure.Status) != nil || failure.Status < 400 || failure.Status > 599 {
				return errors.New("invalid host error")
			}
		} else if len(object) != 1 {
			return errors.New("invalid host error")
		}
		return failure
	}
	if field == "" {
		if len(object) != 0 {
			return errors.New("invalid host acknowledgement")
		}
		return nil
	}
	value, ok := object[field]
	if len(object) != 1 || !ok {
		return errors.New("invalid host response")
	}
	return Decode(value, output)
}

func validError(code string) bool {
	switch code {
	case "database_failed", "commit_unknown", "invalid_host_call", "binding_unavailable", "log_failed", "storage_failed", "service_unavailable":
		return true
	}
	// Realtime port errors carry validated public operation codes.
	if len(code) >= 1 && len(code) <= 64 && strings.Trim(code, "abcdefghijklmnopqrstuvwxyz_") == "" {
		return true
	}
	if len(code) != 5 {
		return false
	}
	for _, c := range code {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// StorageFrame is the extended frame budget of the storage port; object bytes
// are base64-encoded inside JSON, so a 4 MiB object needs transport headroom.
const StorageFrame = MaxFrame * 2

// Call sends one frame through the selected host binding.
func Call(name string, input any) ([]byte, error) {
	frame, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	limit := MaxFrame
	if name == "storage" {
		limit = StorageFrame
	}
	if len(frame) == 0 || len(frame) > limit {
		return nil, errors.New("invalid host frame size")
	}
	return exchange(name, frame)
}
