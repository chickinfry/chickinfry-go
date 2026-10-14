package chik

import (
	"context"
	"errors"
	"sync"
)

// MemoryStore holds one session in memory and is safe for concurrent use.
// Its zero value is empty; Set adopts login credentials. Share the same pointer
// among clients for one refresh flight. A MemoryStore must not be copied after use.
// Use a store only with clients for the same origin.
// It does not persist credentials or coordinate across processes.
type MemoryStore struct {
	mu          sync.Mutex
	refreshMu   sync.Mutex
	credentials SessionCredentials
	revision    uint64
	refreshes   refreshFlights
}

// Credentials returns a snapshot of the current credentials, or zero when empty.
func (store *MemoryStore) Credentials() SessionCredentials {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.credentials
}

// Set replaces the session with login credentials without waiting for a refresh.
// In-flight refresh results cannot overwrite this replacement, even if it uses
// the same credentials as the previous session.
func (store *MemoryStore) Set(credentials SessionCredentials) error {
	if !validCredentials(credentials) {
		return errors.New("invalid session credential")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.credentials = credentials
	store.revision++
	return nil
}

// Refresh serializes callbacks against the latest credentials and saves success
// before returning. Clear or Set during the callback discards its success with
// an error. Callbacks must honor ctx and must not call Refresh on the same store.
func (store *MemoryStore) Refresh(ctx context.Context, operation func(context.Context, SessionCredentials) (SessionCredentials, error)) (SessionCredentials, error) {
	store.refreshMu.Lock()
	defer store.refreshMu.Unlock()
	if err := ctx.Err(); err != nil {
		return SessionCredentials{}, err
	}
	store.mu.Lock()
	latest, revision := store.credentials, store.revision
	store.mu.Unlock()
	if latest == (SessionCredentials{}) {
		return SessionCredentials{}, &OperationError{Code: "invalid_token", Status: 401}
	}
	refreshed, err := operation(ctx, latest)
	if err != nil {
		return SessionCredentials{}, err
	}
	if err := ctx.Err(); err != nil {
		return SessionCredentials{}, err
	}
	if !validCredentials(refreshed) {
		return SessionCredentials{}, errors.New("invalid refresh response")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.revision != revision {
		return SessionCredentials{}, errors.New("session changed during refresh")
	}
	store.credentials = refreshed
	store.revision++
	return refreshed, nil
}

// Clear atomically removes the session only if the complete credentials match expected.
func (store *MemoryStore) Clear(ctx context.Context, expected SessionCredentials) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.clear(expected)
	return nil
}

func (store *MemoryStore) clear(expected SessionCredentials) (matched, removed bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.credentials != expected {
		return false, false
	}
	conformanceClearMatched(store)
	if store.credentials == (SessionCredentials{}) {
		return true, false
	}
	store.credentials = SessionCredentials{}
	store.revision++
	return true, true
}

func validCredentials(credentials SessionCredentials) bool {
	return tokenPattern.MatchString(credentials.AccessToken) && tokenPattern.MatchString(credentials.RefreshToken) &&
		credentials.ExpiresAt != "" && credentials.RefreshExpiresAt != "" && credentials.UserID != "" && credentials.SessionID != ""
}
