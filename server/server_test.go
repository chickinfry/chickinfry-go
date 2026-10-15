package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"testing"
)

func resetRuntime(t testing.TB) {
	t.Helper()
	previousHandler, previousStartup, previousInitialized := handler, startup, initialized
	previousInput, previousOutput := input, output
	t.Cleanup(func() {
		handler, startup, initialized = previousHandler, previousStartup, previousInitialized
		input, output = previousInput, previousOutput
	})
	handler, startup = nil, nil
	initialized = sync.OnceValue(initialize)
	input, output = nil, nil
}

func handleFrame(frame []byte) int32 {
	Allocate(int32(len(frame)))
	copy(input, frame)
	return Handle(int32(len(frame)))
}

func requireFailure(t *testing.T, status, want int32, code string) {
	t.Helper()
	var body map[string]string
	if status != want || json.Unmarshal(output, &body) != nil || len(body) != 1 || body["error"] != code {
		t.Fatalf("failure contract mismatch: status=%d want=%d", status, want)
	}
}

func TestRequestCredentialBoundary(t *testing.T) {
	resetRuntime(t)
	for _, test := range []struct {
		name, credentials string
		authenticated     bool
		want              map[string]*string
		status            int32
	}{
		{"platform auth", `,"authorization":"Bearer custom","cookie":"session=custom"`, true, map[string]*string{"authorization": nil, "cookie": nil}, 200},
		{"customer auth", `,"authorization":"Bearer custom","cookie":"session=custom"`, false, map[string]*string{"authorization": new("Bearer custom"), "cookie": new("session=custom")}, 200},
		{"missing", "", false, map[string]*string{"authorization": nil, "cookie": nil}, 200},
		{"null", `,"authorization":null,"cookie":null`, false, map[string]*string{"authorization": nil, "cookie": nil}, 200},
		{"empty", `,"authorization":"","cookie":""`, false, map[string]*string{"authorization": new(""), "cookie": new("")}, 200},
		{"unknown field", `,"unknown":true`, false, nil, 400},
		{"duplicate cookie", `,"cookie":"session=first","cookie":"session=second"`, false, nil, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			Register(func(request Request) (any, error) {
				called = true
				if test.authenticated {
					public := request.Public()
					if request.Authorization == nil || request.Cookie == nil {
						t.Fatal("sanitizing the handler request changed the original authentication request")
					}
					request = public
				}
				return map[string]*string{"authorization": request.Authorization, "cookie": request.Cookie}, nil
			})
			frame := []byte(`{"rid":1,"method":"POST","path":"/probe.run","body":{}` + test.credentials + `}`)
			Allocate(int32(len(frame)))
			copy(input, frame)
			if status := Handle(int32(len(frame))); status != test.status {
				t.Errorf("request status=%d, want=%d", status, test.status)
			}
			if test.status == 400 {
				if string(output) != `{"error":"invalid_input"}` {
					t.Error("rejection response contract mismatch")
				}
				if called {
					t.Error("handler called for rejected request")
				}
				return
			}
			var got map[string]*string
			if err := json.Unmarshal(output, &got); err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatal("handler credential boundary mismatch")
			}
		})
	}
}

func TestDispatchErrors(t *testing.T) {
	log, err := os.CreateTemp(t.TempDir(), "dispatch-log")
	if err != nil {
		t.Fatal("create log capture failed")
	}
	previousOut, previousErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = log, log
	t.Cleanup(func() {
		os.Stdout, os.Stderr = previousOut, previousErr
		log.Close()
	})
	for _, test := range []struct {
		name   string
		run    Handler
		status int32
		code   string
	}{
		{"sentinel", func(Request) (any, error) { return nil, ErrNotImplemented }, 501, "not_implemented"},
		{"wrapped sentinel", func(Request) (any, error) { return nil, fmt.Errorf("private: %w", ErrNotImplemented) }, 501, "not_implemented"},
		{"explicit error", func(Request) (any, error) { return nil, &Error{Status: 409, Code: "conflict"} }, 409, "conflict"},
		{"wrapped explicit error", func(Request) (any, error) {
			return nil, fmt.Errorf("private: %w", &Error{Status: 403, Code: "forbidden"})
		}, 403, "forbidden"},
		{"ordinary error", func(Request) (any, error) { return nil, errors.New("private failure") }, 500, "operation_failed"},
		{"same error text", func(Request) (any, error) { return nil, errors.New("not_implemented") }, 500, "operation_failed"},
		{"ordinary panic", func(Request) (any, error) { panic("private failure") }, 500, "operation_failed"},
		{"same panic text", func(Request) (any, error) { panic("not_implemented") }, 500, "operation_failed"},
		{"sentinel panic", func(Request) (any, error) { panic(ErrNotImplemented) }, 500, "operation_failed"},
		{"nil explicit error", func(Request) (any, error) { return nil, (*Error)(nil) }, 500, "operation_failed"},
		{"invalid status", func(Request) (any, error) { return nil, &Error{Status: 200, Code: "private"} }, 500, "operation_failed"},
		{"invalid code", func(Request) (any, error) { return nil, &Error{Status: 501} }, 500, "operation_failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			resetRuntime(t)
			Register(test.run)
			requireFailure(t, handleFrame([]byte(`{"rid":1}`)), test.status, test.code)
		})
	}
	if info, err := log.Stat(); err != nil || info.Size() != 0 {
		t.Fatal("dispatch failure wrote to a process log")
	}
}

func TestInputUnicodeIsNotSilentlyReplaced(t *testing.T) {
	for _, test := range []struct {
		body  string
		valid bool
	}{
		{`{"password":"123456789012345"}`, true},
		{`{"password":"123456789012345\ud83d\ude00"}`, true},
		{`{"password":"123456789012345\ud800"}`, false},
		{`{"password":"123456789012345\udc00"}`, false},
		{`{"password":"123456789012345\\ud800"}`, true},
	} {
		var value struct {
			Password string `json:"password"`
		}
		if (DecodeInput([]byte(test.body), []string{"password"}, &value) == nil) != test.valid {
			t.Fatalf("Unicode validity mismatch valid=%t", test.valid)
		}
	}
}
