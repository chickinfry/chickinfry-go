package driver

import (
	"encoding/json"

	"github.com/chickinfry/chickinfry-go"
)

type callKey struct{}
type storeKey struct{}

type storeBinding struct {
	memory           *chickinfry.MemoryStore
	origin           string
	clearAttempts    []observedClear
	traceUnavailable bool
}

type observedClear struct {
	CallID             string `json:"callId"`
	ExpectedAccessRef  string `json:"expectedAccessRef"`
	ExpectedRefreshRef string `json:"expectedRefreshRef"`
	Removed            *bool  `json:"removed"`
}

func (s *server) sessionStore(req request, a args) *Error {
	if !supportsSession() {
		return failure("unimplemented", "unimplemented")
	}
	if a.StoreRef == "" {
		return failure("driver", "invalid_args")
	}
	store := s.stores[a.StoreRef]
	if req.Command == "session.store.create" {
		if store != nil {
			return failure("driver", "invalid_reference")
		}
		store = &storeBinding{memory: new(chickinfry.MemoryStore), origin: a.Origin, clearAttempts: []observedClear{}}
	} else if store == nil {
		return failure("driver", "invalid_reference")
	}
	if req.Command != "session.store.read" {
		record, e := s.credentials.resolve(a.RecordRef)
		if e != nil {
			return e
		}
		var fields map[string]json.RawMessage
		var data struct {
			Origin           string `json:"origin"`
			AccessToken      string `json:"access_token"`
			RefreshToken     string `json:"refresh_token"`
			ExpiresAt        string `json:"expires_at"`
			RefreshExpiresAt string `json:"refresh_expires_at"`
			UserID           string `json:"user_id"`
			SessionID        string `json:"session_id"`
		}
		if validateJSON([]byte(record)) != nil || json.Unmarshal([]byte(record), &fields) != nil || len(fields) != 7 || decode([]byte(record), &data, "origin", "access_token", "refresh_token", "expires_at", "refresh_expires_at", "user_id", "session_id") != nil {
			return failure("driver", "invalid_args")
		}
		for _, value := range fields {
			var text string
			if json.Unmarshal(value, &text) != nil || text == "" {
				return failure("driver", "invalid_args")
			}
		}
		access, e := s.credentials.resolve(a.AccessRef)
		if e != nil {
			return e
		}
		refresh, e := s.credentials.resolve(a.RefreshRef)
		if e != nil {
			return e
		}
		if data.Origin != store.origin || data.AccessToken != access || data.RefreshToken != refresh {
			return failure("driver", "invalid_args")
		}
		if _, err := chickinfry.NewHTTPTransport(store.origin); err != nil {
			return failure("driver", "invalid_args")
		}
		if err := store.memory.Set(chickinfry.SessionCredentials{AccessToken: data.AccessToken, RefreshToken: data.RefreshToken, ExpiresAt: data.ExpiresAt, RefreshExpiresAt: data.RefreshExpiresAt, UserID: data.UserID, SessionID: data.SessionID}); err != nil {
			return failure("driver", "invalid_args")
		}
		s.stores[a.StoreRef] = store
		result := map[string]any{"revision": store.revision()}
		if req.Command == "session.store.create" {
			result["storeRef"] = a.StoreRef
		} else {
			result["accessRef"], result["refreshRef"] = a.AccessRef, a.RefreshRef
		}
		s.reply(req.ID, result, nil)
		return nil
	}
	current := store.memory.Credentials()
	result := map[string]any{"present": current.AccessToken != "" || current.RefreshToken != "", "revision": store.revision(), "accessRef": s.credentials.reference(current.AccessToken), "refreshRef": s.credentials.reference(current.RefreshToken)}
	if a.IncludeTrace != nil && *a.IncludeTrace {
		s.sessionMu.Lock()
		unavailable := store.traceUnavailable
		result["clearAttempts"] = append([]observedClear{}, store.clearAttempts...)
		s.sessionMu.Unlock()
		if unavailable {
			return failure("unimplemented", "unimplemented")
		}
	}
	s.reply(req.ID, result, nil)
	return nil
}
