package server

import "sync"

var startup func() (Handler, error)
var initialized = sync.OnceValue(initialize)

// RegisterStartup registers initialization instead of Register during reactor initialization.
// It does not run startup. Registration must finish before Initialize or Handle.
// The callback must not call Initialize, InitializeStatus, or Handle, directly or
// indirectly: reentering initialization waits on itself and deadlocks.
func RegisterStartup(value func() (Handler, error)) { startup = value }

// Initialize waits for initialization and remembers its result for this instance.
// Failures are sanitized and never retried. Legacy Register handlers need no startup.
// Calling Initialize, InitializeStatus, or Handle from the startup callback,
// directly or indirectly, deadlocks and is not supported.
func Initialize() error { return initialized() }

// InitializeStatus returns 0 on successful initialization or 500 on failure.
// Generated WASM entries can expose it without serializing initialization errors.
func InitializeStatus() int32 {
	if Initialize() != nil {
		return 500
	}
	return 0
}

func initialize() (err error) {
	defer func() {
		if recover() != nil {
			err = &Error{Status: 500, Code: "operation_failed"}
		}
	}()
	if startup != nil {
		value, failure := startup()
		if failure != nil || value == nil {
			return &Error{Status: 500, Code: "operation_failed"}
		}
		handler = value
	}
	if handler == nil {
		return &Error{Status: 500, Code: "operation_failed"}
	}
	return nil
}
