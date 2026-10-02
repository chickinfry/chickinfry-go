package chik

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPRefreshesOnceAndRetriesOnce(t *testing.T) {
	store := newRefreshStore()
	var refreshes atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/catalog.create":
			if request.Header.Get("Authorization") != "Bearer "+strings.Repeat("c", 43) {
				writeRefreshResponse(t, response, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
				return
			}
			writeRefreshResponse(t, response, http.StatusOK, map[string]string{})
		case "/auth.refresh":
			if request.Header.Get("Authorization") != "" {
				t.Errorf("refresh request was not unauthenticated: %q", request.Header.Get("Authorization"))
			}
			if refreshes.Add(1) != 1 {
				writeRefreshResponse(t, response, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
				return
			}
			writeRefreshResponse(t, response, http.StatusOK, map[string]string{
				"access_token": strings.Repeat("c", 43), "refresh_token": strings.Repeat("d", 43),
				"expires_at": "2099-01-01T00:00:00Z", "refresh_expires_at": "2099-01-02T00:00:00Z",
				"user_id": "user", "session_id": "session",
			})
		default:
			t.Errorf("unexpected operation: %s", request.URL.Path)
		}
	}))
	defer server.Close()

	transport, err := NewHTTP(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := transport.WithSession(store)
	if err != nil {
		t.Fatal(err)
	}
	secondTransport, err := NewHTTP(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	secondSigned, err := secondTransport.WithSession(store)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	start := make(chan struct{})
	failures := make(chan error, 8)
	for worker := range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			client := signed
			if worker%2 == 1 {
				client = secondSigned
			}
			if err := client.Invoke(t.Context(), "catalog.create", map[string]string{}, &struct{}{}); err != nil {
				failures <- err
			}
		}()
	}
	close(start)
	workers.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	if refreshes.Load() != 1 {
		t.Fatalf("refresh count = %d", refreshes.Load())
	}
	if store.Credentials().AccessToken != strings.Repeat("c", 43) || store.Credentials().RefreshToken != strings.Repeat("d", 43) {
		t.Fatal("refreshed credentials were not stored")
	}
}

func TestHTTPRefreshFailureEndsSessionWithoutRetryLoop(t *testing.T) {
	store := newRefreshStore()
	var operations atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		operations.Add(1)
		if request.URL.Path == "/auth.refresh" {
			writeRefreshResponse(t, response, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
			return
		}
		writeRefreshResponse(t, response, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
	}))
	defer server.Close()

	transport, err := NewHTTP(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := transport.WithSession(store)
	if err != nil {
		t.Fatal(err)
	}
	err = signed.Invoke(t.Context(), "catalog.create", map[string]string{}, &struct{}{})
	var failure *OperationError
	if !errors.As(err, &failure) || failure.Status != http.StatusUnauthorized || failure.Code != "invalid_token" {
		t.Fatalf("refresh failure was not returned: %v", err)
	}
	if operations.Load() != 2 {
		t.Fatalf("operation count = %d", operations.Load())
	}
	if !store.Cleared() || store.Credentials().AccessToken != "" {
		t.Fatal("rejected session was not cleared")
	}
}

func TestHTTPRejectsRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, "https://redirect.example", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	transport, err := NewHTTP(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	err = transport.Invoke(t.Context(), "catalog.create", map[string]string{}, &struct{}{})
	var operation *OperationError
	if !errors.As(err, &operation) || operation.Code != "redirect_not_allowed" || operation.Status != http.StatusTemporaryRedirect {
		t.Fatalf("redirect was not rejected explicitly: %v", err)
	}
}

func TestHTTPAppliesConfiguredTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		time.Sleep(20 * time.Millisecond)
	}))
	defer server.Close()
	transport, err := NewHTTPWithTimeout(server.URL, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	err = transport.Invoke(t.Context(), "catalog.create", map[string]string{}, &struct{}{})
	if err == nil {
		t.Fatal("configured timeout was not applied")
	}
}

type refreshStore struct {
	mu          sync.RWMutex
	refreshMu   sync.Mutex
	credentials SessionCredentials
	cleared     bool
}

func newRefreshStore() *refreshStore {
	return &refreshStore{credentials: SessionCredentials{
		AccessToken: strings.Repeat("a", 43), RefreshToken: strings.Repeat("b", 43),
		ExpiresAt: "2099-01-01T00:00:00Z", RefreshExpiresAt: "2099-01-02T00:00:00Z",
		UserID: "user", SessionID: "session",
	}}
}

func (store *refreshStore) Credentials() SessionCredentials {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.credentials
}

func (store *refreshStore) Refresh(ctx context.Context, operation func(context.Context, SessionCredentials) (SessionCredentials, error)) (SessionCredentials, error) {
	store.refreshMu.Lock()
	defer store.refreshMu.Unlock()
	store.mu.RLock()
	latest := store.credentials
	store.mu.RUnlock()
	refreshed, err := operation(ctx, latest)
	if err != nil {
		return SessionCredentials{}, err
	}
	store.mu.Lock()
	store.credentials = refreshed
	store.cleared = false
	store.mu.Unlock()
	return refreshed, nil
}

func (store *refreshStore) Clear(_ context.Context, expected SessionCredentials) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.credentials.AccessToken != expected.AccessToken || store.credentials.RefreshToken != expected.RefreshToken {
		return nil
	}
	store.credentials = SessionCredentials{}
	store.cleared = true
	return nil
}

func (store *refreshStore) Cleared() bool {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.cleared
}

func writeRefreshResponse(t *testing.T, response http.ResponseWriter, status int, value any) {
	t.Helper()
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	if err := json.NewEncoder(response).Encode(value); err != nil {
		t.Errorf("write response: %v", err)
	}
}
