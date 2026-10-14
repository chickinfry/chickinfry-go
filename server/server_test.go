package server

import "testing"

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
