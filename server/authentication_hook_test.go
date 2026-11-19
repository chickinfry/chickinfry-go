package server

import (
	"errors"
	"strings"
	"testing"

	"github.com/chickinfry/chickinfry-go/server/database"
	"github.com/chickinfry/chickinfry-go/server/host"
)

const creatingHookFrame = `{"version":1,"hook":"userCreating","user":{"id":"fixture-user","email":"fixture@example.test","createdAt":"2026-11-20T00:00:00.123456Z"}}`

func invokeAuthHook(frame string, rid, lease int64, create func(*database.Connection, AuthHookUser) error, created func(AuthHookUser) error) int32 {
	size := int32(len(frame))
	Allocate(size)
	copy(input, frame)
	return HandleAuthHook(size, rid, lease, create, created)
}

func TestAuthHookDispatchDoesNotReachBusinessHandler(t *testing.T) {
	resetRuntime(t)
	var startupCalls int
	RegisterStartup(func() (Handler, error) {
		startupCalls++
		return func(Request) (any, error) {
			t.Fatal("hook invoked the business dispatcher")
			return nil, nil
		}, nil
	})

	want := AuthHookUser{ID: "fixture-user", Email: "fixture@example.test", CreatedAt: "2026-11-20T00:00:00.123456Z"}
	var creatingCalls, createdCalls int
	create := func(db *database.Connection, user AuthHookUser) error {
		creatingCalls++
		if db == nil || user != want {
			t.Fatal("creating hook did not receive the expected user and transaction")
		}
		return nil
	}
	created := func(user AuthHookUser) error {
		createdCalls++
		if user != want {
			t.Fatal("created hook did not receive the expected user")
		}
		return nil
	}
	if status := invokeAuthHook(creatingHookFrame, 41, 93, create, created); status != 200 || string(output) != "{}" {
		t.Fatalf("creating status=%d body=%s", status, output)
	}
	if creatingCalls != 1 || createdCalls != 0 {
		t.Fatal("creating also invoked the post-commit hook")
	}
	frame := strings.Replace(creatingHookFrame, "userCreating", "userCreated", 1)
	if status := invokeAuthHook(frame, 41, 0, create, created); status != 200 || string(output) != "{}" {
		t.Fatalf("created status=%d body=%s", status, output)
	}
	if startupCalls != 1 || creatingCalls != 1 || createdCalls != 1 {
		t.Fatalf("startup=%d creating=%d created=%d", startupCalls, creatingCalls, createdCalls)
	}
}

func TestAuthHookRejectsInvalidHostInvocation(t *testing.T) {
	resetRuntime(t)
	Register(func(Request) (any, error) { return nil, nil })
	create := func(*database.Connection, AuthHookUser) error {
		t.Fatal("invalid frame reached the creating hook")
		return nil
	}
	created := func(AuthHookUser) error {
		t.Fatal("invalid frame reached the created hook")
		return nil
	}
	for _, test := range []struct {
		name, frame string
		rid, lease  int64
	}{
		{"wrong version", strings.Replace(creatingHookFrame, ":1", ":2", 1), 41, 93},
		{"duplicate hook key", strings.Replace(creatingHookFrame, `"hook":`, `"hook":"userCreated","hook":`, 1), 41, 93},
		{"noncanonical user key", strings.Replace(creatingHookFrame, `"email":`, `"Email":`, 1), 41, 93},
		{"invalid Unicode", strings.Replace(creatingHookFrame, "fixture@example.test", `\ud800`, 1), 41, 93},
		{"unexpected user value", strings.Replace(creatingHookFrame, `"id":"fixture-user"`, `"id":null`, 1), 41, 93},
		{"unknown hook", strings.Replace(creatingHookFrame, "userCreating", "unknown", 1), 41, 93},
		{"no creating lease", creatingHookFrame, 41, 0},
		{"lease on post-commit hook", strings.Replace(creatingHookFrame, "userCreating", "userCreated", 1), 41, 93},
		{"bad request handle", creatingHookFrame, 0, 93},
		{"unsafe lease number", creatingHookFrame, 41, host.MaxHandle + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			status := invokeAuthHook(test.frame, test.rid, test.lease, create, created)
			requireFailure(t, status, 500, "operation_failed")
		})
	}
}

func TestAuthHookSanitizesCallbackFailures(t *testing.T) {
	resetRuntime(t)
	Register(func(Request) (any, error) { return nil, nil })
	create := func(*database.Connection, AuthHookUser) error {
		return errors.New("private business details")
	}
	created := func(AuthHookUser) error {
		panic("private effect details")
	}
	status := invokeAuthHook(creatingHookFrame, 41, 93, create, created)
	requireFailure(t, status, 500, "user_creation_failed")
	frame := strings.Replace(creatingHookFrame, "userCreating", "userCreated", 1)
	status = invokeAuthHook(frame, 41, 0, create, created)
	requireFailure(t, status, 500, "user_created_effect_failed")
}

func TestAuthHookStopsOnStartupFailure(t *testing.T) {
	resetRuntime(t)
	RegisterStartup(func() (Handler, error) {
		return nil, errors.New("private startup details")
	})
	create := func(*database.Connection, AuthHookUser) error {
		t.Fatal("failed startup reached the hook")
		return nil
	}
	status := invokeAuthHook(creatingHookFrame, 41, 93, create, nil)
	requireFailure(t, status, 500, "operation_failed")
}
