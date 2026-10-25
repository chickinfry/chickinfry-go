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
