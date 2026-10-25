// Package server dispatches generated operations inside a request-owned reactor.
package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"unicode/utf8"

	"github.com/chickinfry/chickinfry-go/server/host"
)

// OperationError is an explicit application failure safe to return to a caller.
type OperationError struct {
	Status int
	Code   string
}

// Error returns the operation code without adding response details.
func (err *OperationError) Error() string { return err.Code }

// ErrNotImplemented marks an explicitly unimplemented operation when returned.
var ErrNotImplemented error = errors.New("not_implemented")

// Request contains the transport metadata and validated request handle.
type Request struct {
	Authorization *string         `json:"authorization"`
	Cookie        *string         `json:"cookie"`
	RID           int64           `json:"rid"`
	Method        string          `json:"method"`
	Path          string          `json:"path"`
	Body          json.RawMessage `json:"body"`
	call          func(string, any) ([]byte, error)
}

// User contains public authenticated identity values.
type User struct{ ID, Email string }

// Session contains public session identity, never credentials.
type Session struct {
	ID   string
	User User
}

// Public returns request metadata without authentication credentials.
func (request Request) Public() Request {
	request.Authorization = nil
	request.Cookie = nil
	return request
}

// Handler is the generated dispatcher installed by the customer entry.
type Handler func(Request) (any, error)

var handler Handler
var input, output []byte

// Register installs the generated application during reactor initialization.
func Register(value Handler) { handler = value }

// Allocate retains the input buffer until the request completes.
func Allocate(size int32) *byte {
	if size <= 0 || size > host.MaxFrame+1024 {
		return nil
	}
	input = make([]byte, int(size))
	return &input[0]
}

// Handle dispatches one request and retains its encoded response for the loader.
func Handle(size int32) (status int32) {
	status = 500
	defer func() {
		if recover() != nil {
			status = 500
			output = []byte(`{"error":"operation_failed"}`)
		}
		input = nil
	}()
	if size < 1 || int(size) != len(input) {
		output = []byte(`{"error":"invalid_input"}`)
		return 400
	}
	var request Request
	if err := decodeRequest(input, &request); err != nil || request.RID < 1 || request.RID > host.MaxHandle {
		output = []byte(`{"error":"invalid_input"}`)
		return 400
	}
	if Initialize() != nil {
		output = []byte(`{"error":"operation_failed"}`)
		return 500
	}
	request.call = host.Call
	value, err := handler(request)
	if err != nil {
		failure, ok := errors.AsType[*OperationError](err)
		if errors.Is(err, ErrNotImplemented) {
			failure = &OperationError{Status: 501, Code: "not_implemented"}
		} else if !ok || failure == nil || failure.Status < 400 || failure.Status > 599 || failure.Code == "" {
			failure = &OperationError{Status: 500, Code: "operation_failed"}
		}
		output, _ = json.Marshal(map[string]string{"error": failure.Code})
		return int32(failure.Status)
	}
	output, err = json.Marshal(value)
	if err != nil {
		output = []byte(`{"error":"operation_failed"}`)
		return 500
	}
	return 200
}

func decodeRequest(frame []byte, request *Request) error {
	decoder := json.NewDecoder(bytes.NewReader(frame))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return errors.New("invalid request frame")
	}
	var bodySize *int64
	for decoder.More() {
		name, err := decoder.Token()
		if err != nil {
			return err
		}
		var raw json.RawMessage
		var start, end int64
		if name == "body" && bodySize != nil {
			// The byte length separates an unparsed body from the validated envelope.
			tail := bytes.TrimLeft(frame[decoder.InputOffset():], " \t\r\n")
			if len(tail) == 0 || tail[0] != ':' {
				return errors.New("invalid request frame")
			}
			start = int64(len(frame) - len(tail) + 1)
			if *bodySize > int64(len(frame))-start {
				return errors.New("invalid request body size")
			}
			end = start + *bodySize
			raw = frame[start:end]
		} else {
			if err := decoder.Decode(&raw); err != nil {
				return err
			}
			end = decoder.InputOffset()
			start = end - int64(len(raw))
		}
		if name == "body_size" {
			if err := json.Unmarshal(raw, &bodySize); err != nil || bodySize == nil || *bodySize < 0 {
				return errors.New("invalid request body size")
			}
		}
		if name == "body" {
			// Keep the envelope's protection limit independent of the operation body.
			metadata := append(bytes.Clone(frame[:start]), "null"...)
			metadata = append(metadata, frame[end:]...)
			wire := struct {
				*Request
				BodySize json.RawMessage `json:"body_size"`
			}{Request: request}
			if err := host.Decode(metadata, &wire); err != nil {
				return err
			}
			if wire.BodySize != nil && bodySize == nil {
				return errors.New("invalid request body size")
			}
			request.Body = raw
			return nil
		}
	}
	return host.Decode(frame, request)
}

// Output returns the response buffer; the loader copies it before releasing the instance.
func Output() (*byte, int32) {
	if len(output) == 0 {
		return nil, 0
	}
	return &output[0], int32(len(output))
}

// DecodeInput validates request structure and required string fields before business dispatch.
func DecodeInput(data []byte, fields []string, value any) error {
	if err := validateInputStructure(data); err != nil {
		return err
	}
	var object map[string]json.RawMessage
	if host.Decode(data, &object) != nil || object == nil || !validUnicodeJSON(data) {
		return &OperationError{Status: 400, Code: "invalid_input"}
	}
	for _, field := range fields {
		var text string
		if raw, ok := object[field]; !ok || string(raw) == "null" || json.Unmarshal(raw, &text) != nil {
			return &OperationError{Status: 400, Code: "invalid_input"}
		}
	}
	// API inputs permit extra fields; generated models discard them.
	if err := json.Unmarshal(data, value); err != nil {
		return &OperationError{Status: 400, Code: "invalid_input"}
	}
	return nil
}

func validateInputStructure(data []byte) error {
	if !utf8.Valid(data) || !validJSON(data) {
		return &OperationError{Status: 400, Code: "invalid_json"}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	depth := 0
	for {
		token, err := decoder.Token()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return &OperationError{Status: 400, Code: "invalid_input"}
			}
			return nil
		}
		switch token {
		case json.Delim('{'), json.Delim('['):
			depth++
			if depth > 64 {
				return &OperationError{Status: 400, Code: "invalid_input"}
			}
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
	}
}

func validJSON(data []byte) bool {
	// Reducing each child to null keeps total work linear and avoids the decoder's depth limit.
	flat := make([]byte, 0, len(data))
	var starts []int
	inside, escaped := false, false
	for _, c := range data {
		if !inside {
			switch c {
			case '{', '[':
				starts = append(starts, len(flat))
			case '}', ']':
				if len(starts) == 0 {
					return false
				}
				start := starts[len(starts)-1]
				starts = starts[:len(starts)-1]
				flat = append(flat, c)
				if !json.Valid(flat[start:]) {
					return false
				}
				flat = append(flat[:start], "null"...)
				continue
			}
		}
		flat = append(flat, c)
		if c == '"' && !escaped {
			inside = !inside
		}
		escaped = inside && c == '\\' && !escaped
	}
	return len(starts) == 0 && json.Valid(flat)
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ValidUUID reports whether value has the case-insensitive UUID shape used by id inputs.
func ValidUUID(value string) bool {
	return uuidPattern.MatchString(value)
}

// Environment reads an explicitly allowed logical binding.
func (request Request) Environment(name string) (*string, error) {
	frame, err := request.call("env", struct {
		RID  int64  `json:"rid"`
		Name string `json:"name"`
	}{request.RID, name})
	if err != nil {
		return nil, err
	}
	var value *string
	err = host.Envelope(frame, "value", &value)
	return value, err
}

// Log hands a message to the request's host logging policy.
func (request Request) Log(level, message string) error {
	if !slices.Contains([]string{"debug", "info", "warn", "error"}, level) {
		return fmt.Errorf("invalid log level")
	}
	frame, err := request.call("log", struct {
		RID     int64  `json:"rid"`
		Level   string `json:"level"`
		Message string `json:"message"`
	}{request.RID, level, message})
	if err != nil {
		return err
	}
	return host.Envelope(frame, "", nil)
}

// encoding/json replaces unpaired surrogate escapes; reject them before dispatch.
func validUnicodeJSON(data []byte) bool {
	inside := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inside = !inside
			continue
		}
		if !inside || data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		value, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if value >= 0xdc00 && value <= 0xdfff {
			return false
		}
		if value < 0xd800 || value > 0xdbff {
			continue
		}
		if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
			return false
		}
		low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}
