package auth

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/chickinfry/chickinfry-go/server"
	"github.com/chickinfry/chickinfry-go/server/database"
)

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

func TestHookPanicStaysWithinItsCommitBoundary(t *testing.T) {
	for _, code := range []string{"user_creation_failed", "user_created_effect_failed"} {
		err := runHook(code, func() error { panic("private fixture error") })
		failure, ok := errors.AsType[*server.Error](err)
		if !ok || failure.Status != 500 || failure.Code != code {
			t.Fatal("hook panic lost its safe error classification")
		}
	}
}
