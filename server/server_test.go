package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
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
		t.Fatalf("failure contract mismatch: status=%d body=%s, want status=%d error=%s", status, output, want, code)
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
		{"explicit error", func(Request) (any, error) { return nil, &OperationError{Status: 409, Code: "conflict"} }, 409, "conflict"},
		{"wrapped explicit error", func(Request) (any, error) {
			return nil, fmt.Errorf("private: %w", &OperationError{Status: 403, Code: "forbidden"})
		}, 403, "forbidden"},
		{"ordinary error", func(Request) (any, error) { return nil, errors.New("private failure") }, 500, "operation_failed"},
		{"same error text", func(Request) (any, error) { return nil, errors.New("not_implemented") }, 500, "operation_failed"},
		{"ordinary panic", func(Request) (any, error) { panic("private failure") }, 500, "operation_failed"},
		{"same panic text", func(Request) (any, error) { panic("not_implemented") }, 500, "operation_failed"},
		{"sentinel panic", func(Request) (any, error) { panic(ErrNotImplemented) }, 500, "operation_failed"},
		{"nil explicit error", func(Request) (any, error) { return nil, (*OperationError)(nil) }, 500, "operation_failed"},
		{"invalid status", func(Request) (any, error) { return nil, &OperationError{Status: 200, Code: "private"} }, 500, "operation_failed"},
		{"redirect status", func(Request) (any, error) { return nil, &OperationError{Status: 302, Code: "private"} }, 500, "operation_failed"},
		{"below error status", func(Request) (any, error) { return nil, &OperationError{Status: 399, Code: "private"} }, 500, "operation_failed"},
		{"first error status", func(Request) (any, error) { return nil, &OperationError{Status: 400, Code: "invalid_input"} }, 400, "invalid_input"},
		{"last error status", func(Request) (any, error) { return nil, &OperationError{Status: 599, Code: "operation_failed"} }, 599, "operation_failed"},
		{"above error status", func(Request) (any, error) { return nil, &OperationError{Status: 600, Code: "private"} }, 500, "operation_failed"},
		{"invalid code", func(Request) (any, error) { return nil, &OperationError{Status: 501} }, 500, "operation_failed"},
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
		{`{"password":"123456789012345","\ud800":"value"}`, false},
		{`{"password":"123456789012345\ud800\u0041"}`, false},
		{`{"password":"123456789012345\\ud800"}`, true},
	} {
		var value struct {
			Password string `json:"password"`
		}
		err := DecodeInput([]byte(test.body), []string{"password"}, &value)
		if (err == nil) != test.valid {
			t.Fatalf("Unicode validity mismatch valid=%t", test.valid)
		}
		if !test.valid {
			failure, ok := errors.AsType[*OperationError](err)
			if !ok || failure.Status != 400 || failure.Code != "invalid_input" {
				t.Fatalf("unpaired surrogate failure = %v, want invalid_input / 400", err)
			}
		}
	}
}

func TestRequestBodyStructure(t *testing.T) {
	for _, test := range []struct {
		name, body, extra string
		status            int32
		code              string
	}{
		{"finite", `{"ignored":1.7976931348623157e308}`, "", 200, ""},
		{"overflow", `{"ignored":1e999}`, "", 400, "invalid_input"},
		{"nested overflow", `{"ignored":[{"value":-1e999}]}`, "", 400, "invalid_input"},
		{"depth 64 scalar", `{"ignored":` + strings.Repeat("[", 63) + `null` + strings.Repeat("]", 63) + `}`, "", 200, ""},
		{"depth 64 empty", `{"ignored":` + strings.Repeat("[", 63) + strings.Repeat("]", 63) + `}`, "", 200, ""},
		{"depth 65 empty", `{"ignored":` + strings.Repeat("[", 64) + strings.Repeat("]", 64) + `}`, "", 400, "invalid_input"},
		{"depth 20000", strings.Repeat("[", 20000) + `null` + strings.Repeat("]", 20000), "", 400, "invalid_input"},
		{"duplicate body key", `{"ignored":1,"ignored":2}`, "", 400, "invalid_input"},
		{"overwritten overflow", `{"ignored":1e999,"ignored":0}`, "", 400, "invalid_input"},
		{"escaped duplicate key", `{"ignored":{"na\u006de":0,"name":1}}`, "", 400, "invalid_input"},
		{"same key in separate objects", `{"ignored":[{"name":"a\"}:[{\\\\x"},{"name":"b"}]}`, "", 200, ""},
		{"duplicate key at depth 60", `{"ignored":` + strings.Repeat("[", 58) + `{"value":1,"value":2}` + strings.Repeat("]", 58) + `}`, "", 400, "invalid_input"},
		{"overwritten depth 20000", `{"ignored":` + strings.Repeat("[", 19999) + `null` + strings.Repeat("]", 19999) + `,"ignored":0}`, "", 400, "invalid_input"},
		{"long integer", `{"ignored":` + strings.Repeat("9", 5000) + `}`, "", 400, "invalid_input"},
		{"finite long integer", `{"ignored":` + strings.Repeat("9", 300) + `}`, "", 200, ""},
		{"unpaired high surrogate", `{"ignored":"\ud800"}`, "", 400, "invalid_input"},
		{"unpaired low surrogate", `{"ignored":"\udc00"}`, "", 400, "invalid_input"},
		{"unpaired key surrogate", `{"\ud800":0}`, "", 400, "invalid_input"},
		{"unpaired low key surrogate", `{"\udc00":0}`, "", 400, "invalid_input"},
		{"high surrogate before non-low escape", `{"ignored":"\ud800\u0041"}`, "", 400, "invalid_input"},
		{"duplicate envelope body", `{}`, `,"body":{}`, 400, "invalid_input"},
		{"deep envelope", `{}`, `,"authorization":` + strings.Repeat("[", 65) + `null` + strings.Repeat("]", 65), 400, "invalid_input"},
		{"malformed envelope suffix", `{}`, `,"cookie":`, 400, "invalid_input"},
		{"body string cannot escape envelope", `{"text":"},\"rid\":7"}`, "", 200, ""},
		{"invalid body UTF-8", "{\"text\":\"\xff\"}", "", 400, "invalid_json"},
		{"syntax error", `{"ignored":!}`, "", 400, "invalid_json"},
		{"truncated body", `{"ignored":`, "", 400, "invalid_json"},
		{"truncated string", `{"ignored":"`, "", 400, "invalid_json"},
		{"empty body", ``, "", 400, "invalid_json"},
		{"trailing body data", `{} false`, "", 400, "invalid_json"},
		{"trailing comma", `{},`, "", 400, "invalid_json"},
		{"trailing closing brace", `{} }`, "", 400, "invalid_json"},
		{"body cannot inject cookie", `{},"cookie":42`, "", 400, "invalid_json"},
		{"body cannot inject body", `{},"body":{}`, "", 400, "invalid_json"},
		{"brackets and escapes in string", `{"text":"[{}]\\\"[{}]"}`, "", 200, ""},
		{"unclosed depth 65", strings.Repeat("[", 65), "", 400, "invalid_json"},
		{"invalid token after depth 65", strings.Repeat("[", 65) + `null` + strings.Repeat("]", 65) + `!`, "", 400, "invalid_json"},
		{"syntax after overflow", `{"ignored":1e999,"broken":!}`, "", 400, "invalid_json"},
		{"syntax after depth 20000", strings.Repeat("[", 20000) + `!` + strings.Repeat("]", 20000), "", 400, "invalid_json"},
	} {
		t.Run(test.name, func(t *testing.T) {
			resetRuntime(t)
			calls := 0
			Register(func(request Request) (any, error) {
				var input map[string]json.RawMessage
				if err := DecodeInput(request.Body, nil, &input); err != nil {
					return nil, err
				}
				calls++
				return struct{}{}, nil
			})
			frame := []byte(fmt.Sprintf(`{"rid":1,"method":"POST","path":"/probe.run","body_size":%d,"body":`, len(test.body)) + test.body + test.extra + `}`)
			status := handleFrame(frame)
			if test.status != 200 {
				requireFailure(t, status, test.status, test.code)
				if calls != 0 {
					t.Fatal("invalid body reached business handler")
				}
			} else if status != 200 || calls != 1 {
				t.Fatalf("valid body rejected: status=%d calls=%d", status, calls)
			}
		})
	}
}

func TestRequestBodyFraming(t *testing.T) {
	for _, frame := range []string{
		`{"rid":1,"body_size":-1,"body":{}}`,
		`{"rid":1,"body_size":null,"body":{}}`,
		`{"rid":1,"body_size":"2","body":{}}`,
		`{"rid":1,"body_size":2.5,"body":{}}`,
		`{"rid":1,"body_size":100,"body":{}}`,
		`{"rid":1,"body_size":1,"body":{}}`,
		`{"rid":1,"body_size":3,"body":{}}`,
		`{"rid":1,"body_size":2,"body":{}`,
		`{"rid":1,"body_size":1,"body":!,"rid":0}`,
		`{"rid":1,"body_size":1,"body":!,"cookie":42}`,
		`{"rid":1,"body_size":1,"body":!,"unknown":true}`,
		`{"rid":1,"body_size":1,"body_size":1,"body":!}`,
		`{"rid":1,"body":{},"body_size":null}`,
		`{"rid":1,"body":{},"body_size":2}`,
		`{"rid":1,"body":!,"rid":0}`,
		`{"rid":1,"body":{},"cookie":42}`,
	} {
		t.Run(frame, func(t *testing.T) {
			resetRuntime(t)
			Register(func(Request) (any, error) {
				t.Fatal("invalid envelope reached dispatcher")
				return nil, nil
			})
			requireFailure(t, handleFrame([]byte(frame)), 400, "invalid_input")
		})
	}
}

func TestDecodeInputIDs(t *testing.T) {
	for _, test := range []struct {
		name, id string
		valid    bool
	}{
		{"lowercase", "550e8400-e29b-41d4-a716-446655440000", true},
		{"uppercase", "550E8400-E29B-41D4-A716-446655440000", true},
		{"shape only", "00000000-0000-0000-0000-000000000000", true},
		{"malformed", "not-a-uuid", false},
		{"non-hexadecimal", "550g8400-e29b-41d4-a716-446655440000", false},
		{"wrong separator", "550e8400_e29b-41d4-a716-446655440000", false},
		{"empty", "", false},
		{"trailing newline", "550e8400-e29b-41d4-a716-446655440000\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if ValidUUID(test.id) != test.valid {
				t.Fatalf("UUID validity did not match %t", test.valid)
			}
		})
	}
	var value map[string]string
	err := DecodeInput([]byte(`{"id":"opaque","note":""}`), []string{"id", "note"}, &value)
	if err != nil || value["id"] != "opaque" || value["note"] != "" {
		t.Fatal("ordinary string field was rejected or changed")
	}
}

func BenchmarkInputJSONDepth(b *testing.B) {
	for _, depth := range []int{20000, 40000, 80000} {
		b.Run(fmt.Sprint(depth), func(b *testing.B) {
			body := []byte(strings.Repeat("[", depth) + "null" + strings.Repeat("]", depth))
			b.SetBytes(int64(len(body)))
			for b.Loop() {
				if !validJSON(body) {
					b.Fatal("valid deep JSON rejected")
				}
			}
		})
	}
}

func BenchmarkInputJSONShape(b *testing.B) {
	for _, size := range []int{100000, 200000, 400000} {
		for _, shape := range []struct{ name, body string }{
			{"wide", `[` + strings.TrimSuffix(strings.Repeat(`{},`, size), ",") + `]`},
			{"escaped", `{"text":"` + strings.Repeat(`[]{}\"\\`, size) + `"}`},
		} {
			b.Run(fmt.Sprintf("%s/%d", shape.name, size), func(b *testing.B) {
				body := []byte(shape.body)
				b.SetBytes(int64(len(body)))
				for b.Loop() {
					if !validJSON(body) {
						b.Fatal("valid JSON rejected")
					}
				}
			})
		}
	}
}
