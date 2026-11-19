package server

import (
	"encoding/json"
	"errors"

	"github.com/chickinfry/chickinfry-go/internal/errorwire"
)

var errInvalidAuthenticationFrame = errors.New("invalid authentication frame")

type requestAuthentication struct {
	session *Session
}

// AuthenticationSession supplies the host-verified session to the generated dispatcher.
func AuthenticationSession(request Request) (*Session, error) {
	if request.authentication == nil {
		return nil, &OperationError{Status: 500, Code: "operation_failed"}
	}
	if request.authentication.session == nil {
		return nil, nil
	}
	return new(*request.authentication.session), nil
}

func decodeAuthenticationFrame(raw json.RawMessage) *requestAuthentication {
	var frame map[string]json.RawMessage
	if !errorwire.ValidUnicodeJSON(raw) || json.Unmarshal(raw, &frame) != nil || len(frame) != 2 || string(frame["version"]) != "1" {
		return nil
	}
	if string(frame["session"]) == "null" {
		return &requestAuthentication{}
	}
	var session, user map[string]json.RawMessage
	if json.Unmarshal(frame["session"], &session) != nil || len(session) != 2 || json.Unmarshal(session["user"], &user) != nil || len(user) != 2 {
		return nil
	}
	var result Session
	if json.Unmarshal(session["id"], &result.ID) != nil || json.Unmarshal(user["id"], &result.User.ID) != nil || json.Unmarshal(user["email"], &result.User.Email) != nil {
		return nil
	}
	if result.ID == "" || result.User.ID == "" || result.User.Email == "" {
		return nil
	}
	return &requestAuthentication{session: &result}
}
