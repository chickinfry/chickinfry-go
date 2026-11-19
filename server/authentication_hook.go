package server

import (
	"encoding/json"

	"github.com/chickinfry/chickinfry-go/internal/errorwire"
	"github.com/chickinfry/chickinfry-go/server/database"
	"github.com/chickinfry/chickinfry-go/server/host"
	"github.com/chickinfry/chickinfry-go/server/internal/authhook"
)

// AuthHookUser carries the public user fields copied into a hosted signup hook.
type AuthHookUser struct{ ID, Email, CreatedAt string }

// HandleAuthHook dispatches the generated host entry's callback using the
// existing reactor input and output buffers. The host owns the transaction.
func HandleAuthHook(size int32, rid, lease int64, creating func(*database.Connection, AuthHookUser) error, created func(AuthHookUser) error) (status int32) {
	code := "operation_failed"
	defer func() {
		input = nil
		if recover() != nil {
			status = 500
		}
		if status == 200 {
			output = []byte(`{}`)
		} else {
			output = []byte(`{"error":"` + code + `"}`)
		}
	}()
	if size < 1 || size > host.MaxFrame || int(size) != len(input) || rid < 1 || rid > host.MaxHandle {
		return 500
	}
	hook, user, ok := decodeAuthHook(input)
	if !ok || lease < 0 || lease > host.MaxHandle || (hook == "userCreating") != (lease != 0) || Initialize() != nil {
		return 500
	}
	if hook == "userCreating" && creating != nil {
		code = "user_creation_failed"
		transaction := authhook.NewTransaction(rid, lease)
		if err := database.WithAuthHookTransaction(transaction, func(db *database.Connection) error {
			return creating(db, user)
		}); err != nil {
			return 500
		}
	}
	if hook == "userCreated" && created != nil {
		code = "user_created_effect_failed"
		if err := created(user); err != nil {
			return 500
		}
	}
	return 200
}

func decodeAuthHook(raw []byte) (string, AuthHookUser, bool) {
	var frame, fields map[string]json.RawMessage
	if !errorwire.ValidUnicodeJSON(raw) || host.Decode(raw, &frame) != nil || len(frame) != 3 || string(frame["version"]) != "1" {
		return "", AuthHookUser{}, false
	}
	var hook string
	if json.Unmarshal(frame["hook"], &hook) != nil || (hook != "userCreating" && hook != "userCreated") {
		return "", AuthHookUser{}, false
	}
	var user AuthHookUser
	if json.Unmarshal(frame["user"], &fields) != nil || len(fields) != 3 ||
		json.Unmarshal(fields["id"], &user.ID) != nil || user.ID == "" ||
		json.Unmarshal(fields["email"], &user.Email) != nil || user.Email == "" ||
		json.Unmarshal(fields["createdAt"], &user.CreatedAt) != nil || user.CreatedAt == "" {
		return "", AuthHookUser{}, false
	}
	return hook, user, true
}
