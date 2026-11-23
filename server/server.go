// Package server dispatches generated operations inside a request-owned reactor.
package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/chickinfry/chickinfry-go/internal/errorwire"
	"github.com/chickinfry/chickinfry-go/server/host"
)

// OperationError is an explicit application failure safe to return to a caller.
type OperationError struct {
	Code    string
	Status  int
	Message *string
	Fields  []FieldError
}

// FieldError describes an invalid input at a declared wire path.
type FieldError struct {
	Path string `json:"path"`
	Code string `json:"code"`
}

// NewOperationError creates a failure with optional public response details.
func NewOperationError(code string, status int, message *string, fields []FieldError) *OperationError {
	return &OperationError{Code: code, Status: status, Message: message, Fields: fields}
}

// BEGIN generated operation errors

// NotFound creates the not_found operation error.
func NotFound() *OperationError {
	return &OperationError{Code: "not_found", Status: 404}
}

// InvalidInput creates the invalid_input operation error.
func InvalidInput() *OperationError {
	return &OperationError{Code: "invalid_input", Status: 400}
}

// Conflict creates the conflict operation error.
func Conflict() *OperationError {
	return &OperationError{Code: "conflict", Status: 409}
}

// Forbidden creates the forbidden operation error.
func Forbidden() *OperationError {
	return &OperationError{Code: "forbidden", Status: 403}
}

// NotImplemented creates the not_implemented operation error.
func NotImplemented() *OperationError {
	return &OperationError{Code: "not_implemented", Status: 501}
}

// END generated operation errors

// Error returns the operation code without adding response details.
func (err *OperationError) Error() string { return err.Code }

// ErrNotImplemented marks an explicitly unimplemented operation when returned.
var ErrNotImplemented error = errors.New("not_implemented")

// Request contains the transport metadata and validated request handle.
type Request struct {
	Authorization  *string         `json:"authorization"`
	Cookie         *string         `json:"cookie"`
	Origin         *string         `json:"origin"`
	Authorize      json.RawMessage `json:"authorize"`
	RID            int64           `json:"rid"`
	Method         string          `json:"method"`
	Path           string          `json:"path"`
	Headers        Headers         `json:"headers"`
	Body           json.RawMessage `json:"body"`
	call           func(string, any) ([]byte, error)
	authentication *requestAuthentication
}

// Headers holds the HTTP header values in a request.
type Headers map[string][]string

// Get returns the first value for a case-insensitive header name.
func (headers Headers) Get(name string) string {
	for key, values := range headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
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
	request.Authorize = nil
	request.authentication = nil
	if request.Headers != nil {
		headers := make(Headers, len(request.Headers))
		for name, values := range request.Headers {
			if !strings.EqualFold(name, "Authorization") && !strings.EqualFold(name, "Proxy-Authorization") && !strings.EqualFold(name, "Cookie") {
				headers[name] = slices.Clone(values)
			}
		}
		request.Headers = headers
	}
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
	const maxRequestMetadata = 64 << 10
	if size <= 0 || size > host.MaxFrame+maxRequestMetadata {
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
	err := decodeRequest(input, &request)
	if errors.Is(err, errInvalidAuthenticationFrame) {
		output = []byte(`{"error":"operation_failed"}`)
		return 500
	}
	if err != nil || request.RID < 1 || request.RID > host.MaxHandle {
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
		} else if !ok || failure == nil || failure.Status < 400 || failure.Status > 599 || !errorwire.ValidCode(failure.Code) {
			failure = &OperationError{Status: 500, Code: "operation_failed"}
		}
		response := struct {
			Error   string       `json:"error"`
			Message *string      `json:"message,omitempty"`
			Fields  []FieldError `json:"fields,omitempty"`
		}{Error: failure.Code}
		if failure.Message != nil && errorwire.ValidMessage(*failure.Message) {
			response.Message = failure.Message
		}
		if failure.Code == "invalid_input" && len(failure.Fields) <= errorwire.MaxFields {
			if !slices.ContainsFunc(failure.Fields, func(field FieldError) bool {
				return !errorwire.ValidField(field.Path, field.Code)
			}) {
				response.Fields = failure.Fields
			}
		}
		output, _ = json.Marshal(response)
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
				if key, ok := name.(string); ok && strings.EqualFold(key, "auth") {
					return errInvalidAuthenticationFrame
				}
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
			if err := decodeRequestMetadata(metadata, request, bodySize); err != nil {
				return err
			}
			request.Body = raw
			return nil
		}
	}
	return decodeRequestMetadata(frame, request, nil)
}

func decodeRequestMetadata(frame []byte, request *Request, bodySize *int64) error {
	wire := struct {
		*Request
		BodySize json.RawMessage `json:"body_size"`
		Auth     json.RawMessage `json:"auth"`
	}{Request: request}
	frameError := host.Decode(frame, &wire)
	if frameError != nil || wire.Auth != nil {
		// Inspect keys before values so a truncated auth value can still be classified.
		decoder := json.NewDecoder(bytes.NewReader(frame))
		_, _ = decoder.Token() // decodeRequest already checked the opening object.
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				break
			}
			if name, ok := token.(string); ok && strings.EqualFold(name, "auth") && (name != "auth" || frameError != nil) {
				return errInvalidAuthenticationFrame
			}
			var raw json.RawMessage
			if decoder.Decode(&raw) != nil {
				break
			}
		}
	}
	if frameError != nil {
		return frameError
	}
	if wire.BodySize != nil && bodySize == nil {
		return errors.New("invalid request body size")
	}
	if wire.Auth != nil {
		authentication := decodeAuthenticationFrame(wire.Auth)
		if authentication == nil {
			return errInvalidAuthenticationFrame
		}
		request.Authorization = nil
		request.Cookie = nil
		request.Authorize = nil
		request.authentication = authentication
	}
	for name := range request.Headers {
		if strings.EqualFold(name, "Proxy-Authorization") ||
			(request.authentication != nil && (strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Cookie"))) {
			delete(request.Headers, name)
		}
	}
	return nil
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
	if host.Decode(data, &object) != nil || object == nil || !errorwire.ValidUnicodeJSON(data) {
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

// binding reads one allowlisted host environment value.
func (request Request) binding(name string) (*string, error) {
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

// Environment reads an explicitly allowed logical binding. Platform-reserved
// names are not part of the public environment surface.
func (request Request) Environment(name string) (*string, error) {
	if strings.HasPrefix(name, "CHIK_") {
		return nil, &host.Error{Code: "binding_unavailable"}
	}
	return request.binding(name)
}

// Secret reads a declared secret binding, failing closed when it is absent.
func (request Request) Secret(name string) (string, error) {
	value, err := request.Environment(name)
	if err != nil {
		if failure, ok := errors.AsType[*host.Error](err); ok && failure.Code == "binding_unavailable" {
			return "", &OperationError{Status: 503, Code: "service_unavailable"}
		}
		return "", err
	}
	if value == nil || *value == "" {
		return "", &OperationError{Status: 503, Code: "service_unavailable"}
	}
	return *value, nil
}

// Log hands a record to the request's host logging policy. Invalid records
// are dropped; logging never fails the request.
func Log(request Request, level, message string, fields map[string]any) {
	if request.call == nil || !slices.Contains([]string{"debug", "info", "warn", "error"}, level) {
		return
	}
	frame, err := request.call("log", struct {
		RID     int64          `json:"rid"`
		Level   string         `json:"level"`
		Message string         `json:"message"`
		Fields  map[string]any `json:"fields,omitempty"`
	}{request.RID, level, message, fields})
	if err != nil {
		return
	}
	_ = host.Envelope(frame, "", nil)
}
