package server

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestRequestCredentialBoundary(t *testing.T) {
	previous := handler
	t.Cleanup(func() { handler = previous })
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
					original := request
					request = request.Public()
					if original.Authorization == nil || original.Cookie == nil {
						t.Fatal("sanitizing the handler request changed the original authentication request")
					}
				}
				return map[string]*string{"authorization": request.Authorization, "cookie": request.Cookie}, nil
			})
			frame := []byte(`{"rid":1,"method":"POST","path":"/probe.run","body":{}` + test.credentials + `}`)
			Allocate(int32(len(frame)))
			copy(input, frame)
			if status := Handle(int32(len(frame))); status != test.status {
				t.Errorf("request status=%d, want=%d, body=%s", status, test.status, output)
			}
			if test.status == 400 {
				if string(output) != `{"error":"invalid_input"}` {
					t.Errorf("rejection body=%s, want invalid_input", output)
				}
				if called {
					t.Error("handler called for rejected request")
				}
				return
			}
			var got map[string]*string
			if err := json.Unmarshal(output, &got); err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("handler credentials=%v, want=%v: %v", got, test.want, err)
			}
		})
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
