package auth

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/chickinfry/chickinfry-go/server"
	"github.com/chickinfry/chickinfry-go/server/database"
)

func TestAuthenticationRejectsInvalidInputStructure(t *testing.T) {
	for _, path := range []string{"/auth.signup", "/auth.signin", "/auth.refresh", "/auth.identity", "/auth.session", "/auth.logout"} {
		for _, test := range []struct{ value, code string }{
			{"1e999", "invalid_input"},
			{`"\ud800"`, "invalid_input"},
			{`"\udc00"`, "invalid_input"},
			{`{"\ud800":0}`, "invalid_input"},
			{`"\ud800\u0041"`, "invalid_input"},
			{strings.Repeat("[", 64) + strings.Repeat("]", 64), "invalid_input"},
			{"!", "invalid_json"},
			{"\"\xff\"", "invalid_json"},
			{strings.Repeat("[", 65), "invalid_json"},
			{strings.Repeat("[", 65) + "null" + strings.Repeat("]", 65) + "!", "invalid_json"},
		} {
			authentication := New(database.New(1), Hooks{})
			body := json.RawMessage(`{"email":"public@example.test","password":"public test vector","refresh_token":"token","provider":"test","credential":"test","ignored":` + test.value + `}`)
			_, err := authentication.Handle(server.Request{RID: 1, Path: path, Body: body}, true)
			failure, ok := errors.AsType[*server.OperationError](err)
			if !ok || failure.Status != 400 || failure.Code != test.code {
				t.Fatalf("%s rejected %q with %v, want %s / 400", path, test.value, err, test.code)
			}
		}
	}
}

func TestAuthenticationFailureCannotReturnSuccess(t *testing.T) {
	// The native host refuses I/O; both minting paths must preserve that failure.
	for _, path := range []string{"/auth.signup", "/auth.signin"} {
		authentication := New(database.New(1), Hooks{})
		_, err := authentication.Handle(server.Request{RID: 1, Path: path, Body: json.RawMessage(`{"email":"public@example.test","password":"public test vector"}`)}, true)
		if err == nil {
			t.Fatalf("%s swallowed a failed authentication attempt", path)
		}
	}
}

func TestSignupRateLimitConfiguration(t *testing.T) {
	const email = "public@example.test"
	options := Options{LookupEnv: func(string) (*string, error) { return nil, nil }}
	read := func(options Options) signupRateLimit {
		t.Helper()
		runtime, err := NewWithOptions(database.New(1), Hooks{}, options)
		if err != nil {
			t.Fatal(err)
		}
		return runtime.signupRateLimit
	}
	defaults := read(options)
	if defaults.subject(email) != email || defaults.max != 10 || defaults.windowSeconds != 900 {
		t.Fatal("unexpected default signup rate limit")
	}
	options.SignupRateLimit = SignupRateLimitOptions{Signal: new("global"), Max: new(1), WindowSeconds: new(2)}
	declared := read(options)
	if declared.subject(email) != declared.subject("other@example.test") ||
		declared.subject(email) == email || declared.max != 1 || declared.windowSeconds != 2 {
		t.Fatal("declared signup rate limit was not applied")
	}
	t.Setenv("AUTH_RATE_LIMITS_SIGNUP_SIGNAL", "email")
	t.Setenv("AUTH_RATE_LIMITS_SIGNUP_MAX", "2")
	t.Setenv("AUTH_RATE_LIMITS_SIGNUP_WINDOW_SECONDS", "3")
	options.LookupEnv = nil
	overridden := read(options)
	if overridden.subject(email) != email || overridden.max != 2 || overridden.windowSeconds != 3 {
		t.Fatal("environment did not override individual declared fields")
	}
}

func TestSignupRateLimitRejectsInvalidConfiguration(t *testing.T) {
	const maxName = "AUTH_RATE_LIMITS_SIGNUP_MAX"
	noEnv := func(string) (*string, error) { return nil, nil }
	check := func(options Options, field string) {
		t.Helper()
		_, err := NewWithOptions(database.New(1), Hooks{}, options)
		if err == nil || !strings.Contains(err.Error(), field) || strings.Contains(err.Error(), "fixture-invalid") {
			t.Fatalf("invalid signup rate limit must return a safe error for %s", field)
		}
	}
	check(Options{SignupRateLimit: SignupRateLimitOptions{Signal: new("fixture-invalid")}, LookupEnv: noEnv},
		"auth.rate_limits.signup.signal")
	check(Options{SignupRateLimit: SignupRateLimitOptions{Max: new(0)}, LookupEnv: noEnv},
		"auth.rate_limits.signup.max")
	check(Options{SignupRateLimit: SignupRateLimitOptions{WindowSeconds: new(-1)}, LookupEnv: noEnv},
		"auth.rate_limits.signup.window_seconds")
	for _, value := range []string{"", "0", " 2", "2\n", "1e2", "2147483648", "fixture-invalid"} {
		check(Options{LookupEnv: func(name string) (*string, error) {
			if name == maxName {
				return new(value), nil
			}
			return nil, nil
		}}, maxName)
	}
	check(Options{LookupEnv: func(string) (*string, error) { return nil, errors.New("fixture-invalid") }},
		"AUTH_RATE_LIMITS_SIGNUP_SIGNAL")
}

func TestUnavailableAuthenticationOperations(t *testing.T) {
	for _, path := range []string{"/auth.signup", "/auth.signin", "/auth.unknown"} {
		t.Run(path, func(t *testing.T) {
			authentication := New(database.New(1), Hooks{})
			_, err := authentication.Handle(server.Request{RID: 1, Path: path}, false)
			failure, ok := errors.AsType[*server.OperationError](err)
			if !ok || failure.Status != 404 || failure.Code != "not_found" {
				t.Fatalf("unavailable operation = %v, want not_found / 404", err)
			}
		})
	}
}

func TestSessionFailureCannotBecomeAnonymous(t *testing.T) {
	authentication := New(database.New(1), Hooks{})
	if session, err := authentication.Session(nil); session != nil || err != nil {
		t.Fatal("missing authorization did not remain anonymous")
	}
	for _, valid := range []bool{false, true} {
		bearer := ""
		if valid {
			value, err := token()
			if err != nil {
				t.Fatal("create session probe failed")
			}
			bearer = "Bearer " + value
		}
		// A valid bearer reaches the unsupported native host and must preserve its failure.
		session, err := authentication.Session(&bearer)
		if session != nil || err == nil {
			t.Fatalf("session failure became anonymous: valid=%t", valid)
		}
		if !valid {
			failure, ok := errors.AsType[*server.OperationError](err)
			if !ok || failure.Status != 401 || failure.Code != "invalid_token" {
				t.Fatal("invalid bearer lost its rejection")
			}
		}
	}
}

func TestHookPanicStaysWithinItsCommitBoundary(t *testing.T) {
	for _, code := range []string{"user_creation_failed", "user_created_effect_failed"} {
		err := runHook(code, func() error { panic("private fixture error") })
		failure, ok := errors.AsType[*server.OperationError](err)
		if !ok || failure.Status != 500 || failure.Code != code {
			t.Fatal("hook panic lost its safe error classification")
		}
	}
}
