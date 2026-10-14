// Package server dispatches generated operations inside a request-owned reactor.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/chickinfry/chickinfry-go/server/host"
)

// Error is an explicit application failure safe to return to a caller.
type Error struct {
	Status int
	Code   string
}

func (err *Error) Error() string { return err.Code }

// Request contains the transport metadata and validated request handle.
type Request struct {
	RID    int64           `json:"rid"`
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body"`
	call   func(string, any) ([]byte, error)
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
	if err := host.Decode(input, &request); err != nil || request.RID < 1 || request.RID > host.MaxHandle {
		output = []byte(`{"error":"invalid_input"}`)
		return 400
	}
	if handler == nil {
		output = []byte(`{"error":"operation_failed"}`)
		return 500
	}
	request.call = host.Call
	value, err := handler(request)
	if err != nil {
		failure, ok := errors.AsType[*Error](err)
		if !ok || failure.Status < 400 || failure.Status > 599 || failure.Code == "" {
			failure = &Error{500, "operation_failed"}
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

// Output returns the response buffer; the loader copies it before releasing the instance.
func Output() (*byte, int32) {
	if len(output) == 0 {
		return nil, 0
	}
	return &output[0], int32(len(output))
}

// DecodeInput validates all required string fields before business dispatch.
func DecodeInput(data []byte, fields []string, value any) error {
	var object map[string]json.RawMessage
	if host.Decode(data, &object) != nil || object == nil {
		return &Error{400, "invalid_input"}
	}
	for _, field := range fields {
		var text string
		if raw, ok := object[field]; !ok || string(raw) == "null" || json.Unmarshal(raw, &text) != nil {
			return &Error{400, "invalid_input"}
		}
	}
	// API inputs permit extra fields; generated models discard them.
	if err := json.Unmarshal(data, value); err != nil {
		return &Error{400, "invalid_input"}
	}
	return nil
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
