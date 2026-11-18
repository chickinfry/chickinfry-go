package chickinfry

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestHTTPSessionChangeBeforeRefreshDoesNotResend(t *testing.T) {
	for _, mode := range []string{"memory logout", "memory account", "memory session", "custom account", "custom tokens only", "memory rotation"} {
		t.Run(mode, func(t *testing.T) {
			original := newRefreshStore().Credentials()
			replacement := original
			replacement.AccessToken = strings.Repeat("b", 43)
			replacement.RefreshToken = newRefreshStore().Credentials().RefreshToken
			var store SessionStore
			var replace func() error
			if strings.HasPrefix(mode, "custom") {
				if mode == "custom tokens only" {
					original = SessionCredentials{AccessToken: original.AccessToken, RefreshToken: original.RefreshToken}
					replacement = SessionCredentials{AccessToken: replacement.AccessToken, RefreshToken: replacement.RefreshToken}
				} else {
					replacement.UserID = "other-user"
				}
				custom := &refreshStore{credentials: original}
				store = custom
				replace = func() error {
					custom.mu.Lock()
					defer custom.mu.Unlock()
					custom.credentials = replacement
					return nil
				}
			} else {
				memory := new(MemoryStore)
				if err := memory.Set(original); err != nil {
					t.Fatal(err)
				}
				store = memory
				switch mode {
				case "memory logout":
					replacement = SessionCredentials{}
				case "memory account":
					replacement.UserID = "other-user"
				case "memory session":
					replacement.SessionID = "other-session"
				}
				replace = func() error { return memory.Set(replacement) }
				switch mode {
				case "memory logout":
					replace = func() error { return memory.Clear(t.Context(), original) }
				case "memory rotation":
					replace = func() error {
						_, err := memory.Refresh(t.Context(), func(context.Context, SessionCredentials) (SessionCredentials, error) { return replacement, nil })
						return err
					}
				}
			}
			var calls atomic.Int64
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					if err := replace(); err != nil {
						t.Error(err)
					}
					writeRefreshResponse(t, w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
					return
				}
				writeRefreshResponse(t, w, http.StatusOK, struct{}{})
			}))
			defer peer.Close()
			transport, err := NewHTTPTransport(peer.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer transport.client.CloseIdleConnections()
			signed, err := transport.WithSession(store)
			if err != nil {
				t.Fatal(err)
			}
			err = signed.Invoke(t.Context(), "account.update", map[string]string{"name": "updated"}, &struct{}{})
			if mode == "memory rotation" {
				if err != nil || calls.Load() != 2 {
					t.Fatalf("same-session rotation failed: calls=%d error=%v", calls.Load(), err)
				}
				return
			}
			failure, ok := errors.AsType[*ClientError](err)
			if calls.Load() != 1 || !ok || failure.Code != CodeUnauthenticated || failure.Status != nil {
				t.Fatalf("session replacement was not stopped: calls=%d error=%v", calls.Load(), err)
			}
			if store.Credentials() != replacement {
				t.Fatal("replacement session was modified")
			}
		})
	}
}

type failedWriteConn struct {
	net.Conn
	partial int
	writes  atomic.Int64
}

func (conn *failedWriteConn) Write([]byte) (int, error) {
	conn.writes.Add(1)
	return conn.partial, syscall.EPIPE
}

func TestHTTPWriteFailureOutcomeUsesActualBytes(t *testing.T) {
	for _, partial := range []int{0, 1} {
		t.Run(string(rune('0'+partial)), func(t *testing.T) {
			local, remote := net.Pipe()
			defer remote.Close()
			conn := &failedWriteConn{Conn: local, partial: partial}
			original := http.DefaultTransport
			standard := original.(*http.Transport).Clone()
			standard.Proxy = nil
			standard.DialContext = func(context.Context, string, string) (net.Conn, error) { return conn, nil }
			http.DefaultTransport = standard
			t.Cleanup(func() { http.DefaultTransport = original; standard.CloseIdleConnections() })
			transport, err := NewHTTPTransport("http://127.0.0.1:12345")
			if err != nil {
				t.Fatal(err)
			}
			defer transport.client.CloseIdleConnections()
			err = transport.Invoke(t.Context(), "account.update", struct{}{}, &struct{}{})
			failure, ok := errors.AsType[*ClientError](err)
			if !ok || failure.Code != CodeUnavailable || failure.Status != nil || failure.OutcomeUnknown != (partial > 0) || conn.writes.Load() != 1 {
				t.Fatalf("incorrect write outcome: partial=%d writes=%d error=%v", partial, conn.writes.Load(), err)
			}
		})
	}
}

func TestHTTPRefreshDialFailureDoesNotBlockUnsentToken(t *testing.T) {
	store := new(MemoryStore)
	if err := store.Set(newRefreshStore().Credentials()); err != nil {
		t.Fatal(err)
	}
	rotated := newRefreshStore().Credentials()
	rotated.AccessToken = strings.Repeat("b", 43)
	var refreshes, dials atomic.Int64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		if r.URL.Path == "/auth.refresh" {
			refreshes.Add(1)
			writeSessionCredentials(t, w, rotated)
		} else if r.Header.Get("Authorization") == "Bearer "+rotated.AccessToken {
			writeRefreshResponse(t, w, http.StatusOK, struct{}{})
		} else {
			writeRefreshResponse(t, w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		}
	}))
	defer peer.Close()
	original := http.DefaultTransport
	standard := original.(*http.Transport).Clone()
	standard.Proxy = nil
	standard.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if dials.Add(1) == 2 {
			return nil, errors.New("dial failed before sending")
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	http.DefaultTransport = standard
	t.Cleanup(func() { http.DefaultTransport = original; standard.CloseIdleConnections() })
	transport, err := NewHTTPTransport(peer.URL, WithTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer transport.client.CloseIdleConnections()
	signed, err := transport.WithSession(store)
	if err != nil {
		t.Fatal(err)
	}
	err = signed.Invoke(t.Context(), "account.update", struct{}{}, &struct{}{})
	failure, ok := errors.AsType[*ClientError](err)
	if !ok || failure.Code != CodeUnavailable || failure.OutcomeUnknown || failure.Status != nil {
		t.Fatalf("unexpected pre-send failure: %v", err)
	}
	if err := signed.Invoke(t.Context(), "account.update", struct{}{}, &struct{}{}); err != nil || refreshes.Load() != 1 {
		t.Fatalf("unsent refresh remained blocked: refreshes=%d error=%v", refreshes.Load(), err)
	}
}

func TestHTTPPublicCallsAndReloginOnSameTransport(t *testing.T) {
	first, second := newRefreshStore().Credentials(), newRefreshStore().Credentials()
	second.AccessToken = strings.Repeat("b", 43)
	second.SessionID = "replacement"
	type request struct {
		path, bearer string
	}
	requests := make(chan request, 16)
	var signins atomic.Int64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- request{r.URL.Path, r.Header.Get("Authorization")}
		switch r.URL.Path {
		case "/auth.signin":
			if signins.Add(1) == 1 {
				writeSessionCredentials(t, w, first)
			} else {
				writeSessionCredentials(t, w, second)
			}
		case "/probe.echo":
			active := first
			if signins.Load() == 2 {
				active = second
			}
			if r.Header.Get("Authorization") != "Bearer "+active.AccessToken {
				writeRefreshResponse(t, w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
				return
			}
			writeRefreshResponse(t, w, http.StatusOK, struct{}{})
		case "/auth.signup":
			writeRefreshResponse(t, w, http.StatusOK, map[string]any{"accepted": true, "attempt": "pending"})
		case "/probe.list", "/auth.logout":
			writeRefreshResponse(t, w, http.StatusOK, struct{}{})
		default:
			t.Errorf("unexpected request operation: %s", r.URL.Path)
			writeRefreshResponse(t, w, http.StatusBadRequest, map[string]string{"error": "invalid_input"})
		}
	}))
	defer peer.Close()
	transport, err := NewHTTPTransport(peer.URL)
	if err != nil {
		t.Fatal(err)
	}
	store := new(MemoryStore)
	client, err := transport.WithSession(store)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		operation string
		public    bool
		bearer    string
		state     SessionCredentials
	}{
		{"auth.signup", true, "", SessionCredentials{}},
		{"auth.signin", true, "", first},
		{"probe.echo", false, "Bearer " + first.AccessToken, first},
		{"auth.logout", false, "Bearer " + first.AccessToken, SessionCredentials{}},
		{"auth.signin", true, "", second},
		{"probe.echo", false, "Bearer " + second.AccessToken, second},
		{"probe.list", true, "Bearer " + second.AccessToken, second},
		{"auth.logout", false, "Bearer " + second.AccessToken, SessionCredentials{}},
		{"probe.list", true, "", SessionCredentials{}},
	} {
		invoke := client.Invoke
		if step.public {
			invoke = client.InvokePublic
		}
		if err := invoke(t.Context(), step.operation, struct{}{}, &struct{}{}); err != nil {
			t.Fatalf("%s: %v", step.operation, err)
		}
		if len(requests) != 1 || <-requests != (request{"/" + step.operation, step.bearer}) {
			t.Fatalf("%s: expected one request with the current authorization", step.operation)
		}
		if store.Credentials() != step.state {
			t.Fatalf("%s: unexpected stored session", step.operation)
		}
	}
	err = client.Invoke(t.Context(), "probe.echo", struct{}{}, &struct{}{})
	failure, ok := errors.AsType[*ClientError](err)
	if len(requests) != 0 || !ok || failure.Code != CodeUnauthenticated || failure.Status != nil {
		t.Fatal("empty session was not rejected locally")
	}
}

func TestHTTPLateLoginDoesNotOverwriteNewSession(t *testing.T) {
	store := new(MemoryStore)
	transport, err := NewHTTPTransport("https://api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	client, err := transport.WithSession(store)
	if err != nil {
		t.Fatal(err)
	}
	replacement := newRefreshStore().Credentials()
	client.client.Transport = responseTransport(func(*http.Request) (*http.Response, error) {
		if err := store.Set(replacement); err != nil {
			t.Fatal(err)
		}
		peer := httptest.NewRecorder()
		writeSessionCredentials(t, peer, newRefreshStore().Credentials())
		return peer.Result(), nil
	})
	var output refreshResponse
	err = client.InvokePublic(t.Context(), "auth.signin", struct{}{}, &output)
	var zero refreshResponse
	failure, ok := errors.AsType[*ClientError](err)
	if !ok || failure.Code != CodeUnauthenticated || !failure.OutcomeUnknown || store.Credentials() != replacement || output != zero {
		t.Fatal("late login replaced a newer session or returned successful output")
	}
}
