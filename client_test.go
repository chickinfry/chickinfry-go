package chik

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestHTTPOriginLoopbackSpellings(t *testing.T) {
	for _, test := range []struct {
		origin string
		accept bool
	}{
		{"http://127.0.0.1", true},
		{"http://127.0.0.0", true},
		{"http://127.255.255.255:8080/", true},
		{"http://[::1]", true},
		{"http://[::1]:8080/", true},
		{"http://127.1", false},
		{"http://127.0.1", false},
		{"http://0x7f000001", false},
		{"http://0x7f.0.0.1", false},
		{"http://0177.0.0.1", false},
		{"http://127.00.0.1", false},
		{"http://127.0.0.01", false},
		{"http://2130706433", false},
		{"http://[::ffff:127.0.0.1]", false},
		{"http://[::ffff:7f00:1]", false},
		{"http://[0:0:0:0:0:0:0:1]", false},
		{"http://[::0:1]", false},
		{"http://[::1%25lo0]", false},
		{"http://::1", false},
		{"http://localhost", false},
		{"http://128.0.0.1", false},
		{"http://126.255.255.255", false},
		{"https://localhost", true},
		{"https://[::ffff:127.0.0.1]", true},
		{"https://[0:0:0:0:0:0:0:1]", true},
		{"https://[::1%25lo0]", true},
		{"https://example.com/", true},
		{"https://user@example.com", false},
		{"https://example.com/path", false},
		{"https://example.com?query=value", false},
		{"https://example.com#fragment", false},
		{"https://example.test?", false},
		{"https://example.test#", false},
		{"https://example.test/?", false},
		{"https://example.test/#", false},
		{"http://127.0.0.1?", false},
		{"http://[::1]#", false},
		{"https://example.test/", true},
	} {
		t.Run(test.origin, func(t *testing.T) {
			_, err := NewHTTP(test.origin)
			if (err == nil) != test.accept {
				t.Fatalf("origin acceptance = %t, want %t: %v", err == nil, test.accept, err)
			}
		})
	}
}

func TestHTTPClassifiesInvalidErrorResponses(t *testing.T) {
	for _, test := range []struct {
		body string
		code string
	}{
		{"not JSON", "invalid_response"},
		{"{}", "invalid_response"},
		{`{"message":"failure"}`, "invalid_response"},
		{`{"error":"Bad-code1"}`, "invalid_response"},
		{`{"error":null}`, "invalid_response"},
		{`{"error":42}`, "invalid_response"},
		{`{"error":"invalid_token"}`, "invalid_token"},
		{`{"error":"operation_failed"}`, "operation_failed"},
	} {
		t.Run(test.body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				response.WriteHeader(http.StatusBadGateway)
				fmt.Fprint(response, test.body)
			}))
			defer server.Close()
			transport, err := NewHTTP(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			err = transport.Invoke(t.Context(), "catalog.create", map[string]string{}, &struct{}{})
			failure, ok := errors.AsType[*OperationError](err)
			if !ok || failure.Code != test.code || failure.Status != http.StatusBadGateway {
				t.Fatalf("response classification = %v, want %s / 502", err, test.code)
			}
		})
	}
}

func TestHTTPUnknownRefreshOutcomeBlocksReuseAcrossTransports(t *testing.T) {
	type refreshOutcome struct {
		name       string
		status     int
		body, code string
	}
	outcomes := []refreshOutcome{
		{name: "connection closed"}, {name: "timeout"}, {name: "unreadable body"},
		{name: "unreadable 401"}, {name: "invalid JSON"},
		{"invalid credentials", http.StatusAccepted, `{}`, "invalid_response"},
		{"null credentials", http.StatusAccepted, `null`, "invalid_response"},
		{"non-JSON 401", 401, "not JSON", "invalid_response"},
		{"missing error 401", 401, "{}", "invalid_response"},
		{"invalid code 401", 401, `{"error":"Bad-code"}`, "invalid_response"},
	}
	for _, field := range []string{
		"access_token", "refresh_token", "expires_at", "refresh_expires_at", "user_id", "session_id",
	} {
		for _, variant := range []string{"missing", "null", "invalid"} {
			body := map[string]any{
				"access_token": strings.Repeat("c", 43), "refresh_token": strings.Repeat("d", 43),
				"expires_at": "2099-01-01T00:00:00Z", "refresh_expires_at": "2099-01-02T00:00:00Z",
				"user_id": "user", "session_id": "session",
			}
			switch variant {
			case "missing":
				delete(body, field)
			case "null":
				body[field] = nil
			case "invalid":
				body[field] = ""
			}
			data, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			outcomes = append(outcomes, refreshOutcome{
				variant + " " + field, http.StatusAccepted, string(data), "invalid_response",
			})
		}
	}
	for _, status := range []int{400, 403, 429, 500} {
		outcomes = append(outcomes,
			refreshOutcome{fmt.Sprintf("valid envelope %d", status), status, `{"error":"refresh_failed"}`, "refresh_failed"},
			refreshOutcome{fmt.Sprintf("malformed envelope %d", status), status, "{}", "invalid_response"},
		)
	}
	for _, outcome := range outcomes {
		t.Run(outcome.name, func(t *testing.T) {
			store := newRefreshStore()
			var refreshToken [32]byte
			rand.Read(refreshToken[:])
			store.credentials.RefreshToken = base64.RawURLEncoding.EncodeToString(refreshToken[:])
			original := store.Credentials()
			var refreshes atomic.Int64
			releaseTimeout := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path != "/auth.refresh" {
					if request.Header.Get("Authorization") == "Bearer "+strings.Repeat("c", 43) {
						writeRefreshResponse(t, response, http.StatusOK, map[string]string{})
					} else {
						writeRefreshResponse(t, response, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
					}
					return
				}
				if refreshes.Add(1) != 1 {
					writeRefreshResponse(t, response, http.StatusOK, map[string]string{
						"access_token": strings.Repeat("c", 43), "refresh_token": strings.Repeat("d", 43),
						"expires_at": "2099-01-01T00:00:00Z", "refresh_expires_at": "2099-01-02T00:00:00Z",
						"user_id": "user", "session_id": "session",
					})
					return
				}
				switch outcome.name {
				case "connection closed", "unreadable body", "unreadable 401":
					connection, _, err := response.(http.Hijacker).Hijack()
					if err != nil {
						t.Errorf("hijack refresh response: %v", err)
						return
					}
					if outcome.name == "unreadable body" {
						fmt.Fprint(connection, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{")
					}
					if outcome.name == "unreadable 401" {
						fmt.Fprint(connection, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 100\r\n\r\n{")
					}
					connection.Close()
				case "timeout":
					<-releaseTimeout
				case "invalid JSON":
					fmt.Fprint(response, "not JSON")
				default:
					response.WriteHeader(outcome.status)
					fmt.Fprint(response, outcome.body)
				}
			}))
			defer server.Close()
			defer close(releaseTimeout)
			timeout := 30 * time.Second
			if outcome.name == "timeout" {
				timeout = 50 * time.Millisecond
			}
			transport, err := NewHTTPWithTimeout(server.URL, timeout)
			if err != nil {
				t.Fatal(err)
			}
			signed, err := transport.WithSession(store)
			if err != nil {
				t.Fatal(err)
			}
			output := struct{ Value string }{Value: "unchanged"}
			err = signed.Invoke(t.Context(), "catalog.create", map[string]string{}, &output)
			if err == nil {
				t.Fatal("unknown refresh outcome succeeded")
			}
			if output.Value != "unchanged" {
				t.Fatal("failed refresh changed the caller output")
			}
			if outcome.status != 0 {
				failure, ok := errors.AsType[*OperationError](err)
				if !ok || failure.Status != outcome.status || failure.Code != outcome.code {
					t.Fatalf("refresh error = %v, want %s / %d", err, outcome.code, outcome.status)
				}
				if err.Error() != fmt.Sprintf("operation failed (%s, HTTP %d)", outcome.code, outcome.status) {
					t.Fatal("refresh error exposed response details")
				}
			}
			secondTransport, err := NewHTTP(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			secondSigned, err := secondTransport.WithSession(store)
			if err != nil {
				t.Fatal(err)
			}
			for _, client := range []*HTTP{signed, secondSigned} {
				err := client.Invoke(t.Context(), "catalog.create", map[string]string{}, &struct{}{})
				failure, ok := errors.AsType[*OperationError](err)
				if !ok || failure.Code != "invalid_token" || failure.Status != http.StatusUnauthorized {
					t.Fatalf("blocked refresh = %v, want invalid_token / 401", err)
				}
			}
			if refreshes.Load() != 1 || store.Credentials() != original || store.Cleared() {
				t.Fatalf("unknown outcome reused refresh or changed session: refreshes=%d cleared=%t", refreshes.Load(), store.Cleared())
			}
			store.mu.Lock()
			store.credentials.AccessToken = strings.Repeat("l", 43)
			rand.Read(refreshToken[:])
			store.credentials.RefreshToken = base64.RawURLEncoding.EncodeToString(refreshToken[:])
			store.mu.Unlock()
			if err := secondSigned.Invoke(t.Context(), "catalog.create", map[string]string{}, &struct{}{}); err != nil {
				t.Fatalf("new login did not refresh normally: %v", err)
			}
			if refreshes.Load() != 2 || store.Credentials().AccessToken != strings.Repeat("c", 43) || store.Cleared() {
				t.Fatal("new login refresh was not saved")
			}
		})
	}
}

func TestHTTPRefreshesOnceAndRetriesOnce(t *testing.T) {
	for _, name := range []string{"memory", "custom pointer", "equal custom value", "custom rejection"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				custom := name != "memory"
				rejected := name == "custom rejection"
				var store SessionStore = new(MemoryStore)
				original, rotated := newRefreshStore().Credentials(), newRefreshStore().Credentials()
				rotated.AccessToken = strings.Repeat("c", 43)
				var customStore *concurrentRefreshStore
				if custom {
					customStore = &concurrentRefreshStore{refreshStore: &refreshStore{credentials: original}}
					store = customStore
					if name == "equal custom value" {
						store = customValueStore{concurrentRefreshStore: customStore}
					}
				} else if err := store.(*MemoryStore).Set(original); err != nil {
					t.Fatal(err)
				}
				var refreshes, requests atomic.Int64
				originals, release := make(chan struct{}), make(chan struct{})
				peer := responseTransport(func(request *http.Request) (*http.Response, error) {
					status, body := http.StatusOK, "{}"
					if request.URL.Path == "/auth.refresh" {
						refreshes.Add(1)
						if request.Header.Get("Authorization") != "" {
							t.Error("refresh request was authenticated")
						}
						<-release
						data, err := json.Marshal(map[string]string{
							"access_token": rotated.AccessToken, "refresh_token": rotated.RefreshToken,
							"expires_at": rotated.ExpiresAt, "refresh_expires_at": rotated.RefreshExpiresAt,
							"user_id": rotated.UserID, "session_id": rotated.SessionID,
						})
						if err != nil {
							t.Fatal(err)
						}
						body = string(data)
						if rejected {
							status, body = http.StatusUnauthorized, `{"error":"invalid_token"}`
						}
					} else {
						requests.Add(1)
						if request.Header.Get("Authorization") != "Bearer "+rotated.AccessToken {
							if request.Header.Get("Authorization") != "Bearer "+original.AccessToken {
								t.Error("original request used unexpected credentials")
							}
							<-originals
							status, body = http.StatusUnauthorized, `{"error":"invalid_token"}`
						}
					}
					return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
				})
				results := make(chan error, 2)
				for range 2 {
					transport, err := NewHTTP("https://fixture.example")
					if err != nil {
						t.Fatal(err)
					}
					transport.client.Transport = peer
					signed, err := transport.WithSession(store)
					if err != nil {
						t.Fatal(err)
					}
					go func() { results <- signed.Invoke(t.Context(), "catalog.create", map[string]string{}, &struct{}{}) }()
				}
				synctest.Wait()
				if requests.Load() != 2 || refreshes.Load() != 0 {
					t.Fatal("both clients did not send their originals before refresh")
				}
				close(originals)
				synctest.Wait()
				if requests.Load() != 2 || refreshes.Load() != 1 {
					t.Fatal("clients did not wait for one shared refresh")
				}
				close(release)
				for range 2 {
					if err := <-results; rejected && !isInvalidToken(err) || !rejected && err != nil {
						t.Fatalf("shared refresh result=%v, rejected=%t", err, rejected)
					}
				}
				wantRequests, wantCredentials := int64(4), rotated
				if rejected {
					wantRequests, wantCredentials = 2, SessionCredentials{}
				}
				if refreshes.Load() != 1 || requests.Load() != wantRequests || store.Credentials() != wantCredentials {
					t.Fatalf("refreshes=%d originals=%d credentials=%+v; want 1 refresh, %d originals and expected session", refreshes.Load(), requests.Load(), store.Credentials(), wantRequests)
				}
				if custom {
					if customStore.calls.Load() != 1 {
						t.Fatalf("store Refresh calls=%d, want 1", customStore.calls.Load())
					}
					wantClears := int64(0)
					if rejected {
						wantClears = 1
					}
					if customStore.clears.Load() != wantClears {
						t.Fatalf("store Clear calls=%d, want %d", customStore.clears.Load(), wantClears)
					}
					customRefreshes.mu.Lock()
					remaining := len(customRefreshes.flights)
					customRefreshes.mu.Unlock()
					if remaining != 0 {
						t.Fatal("completed refresh retained a store in the registry")
					}
				}
			})
		})
	}
}

func TestHTTPDoesNotRefreshAgainWhenRetryIsRejected(t *testing.T) {
	store := newRefreshStore()
	rotated := newRefreshStore().Credentials()
	rotated.AccessToken = strings.Repeat("c", 43)
	var refreshes, requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/auth.refresh" {
			refreshes.Add(1)
			writeSessionCredentials(t, response, rotated)
			return
		}
		requests.Add(1)
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
	failure, ok := errors.AsType[*OperationError](err)
	if !ok || failure.Code != "invalid_token" || failure.Status != http.StatusUnauthorized {
		t.Fatalf("retry rejection = %v, want invalid_token / 401", err)
	}
	if refreshes.Load() != 1 || requests.Load() != 2 {
		t.Fatalf("refreshes=%d requests=%d, want 1 refresh and 2 original requests", refreshes.Load(), requests.Load())
	}
}

func TestHTTPRefreshFailureEndsSessionWithoutRetryLoop(t *testing.T) {
	store := new(MemoryStore)
	if err := store.Set(newRefreshStore().Credentials()); err != nil {
		t.Fatal(err)
	}
	var operations atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		operations.Add(1)
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
	failure, ok := errors.AsType[*OperationError](err)
	if !ok || failure.Status != http.StatusUnauthorized || failure.Code != "invalid_token" {
		t.Fatalf("refresh failure was not returned: %v", err)
	}
	if operations.Load() != 2 {
		t.Fatalf("operation count = %d", operations.Load())
	}
	if store.Credentials() != (SessionCredentials{}) {
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

func TestHTTPRedactsTransportFailureDetail(t *testing.T) {
	for name, malformed := range map[string]string{
		"garbage status line": "SECRET-TOKEN-abc123 hunter2 http://10.0.0.5:8080",
		"malformed version":   "INVALID/1.1 200 OK",
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				conn, _, err := response.(http.Hijacker).Hijack()
				if err != nil {
					t.Errorf("hijack response: %v", err)
					return
				}
				if _, err := conn.Write([]byte(malformed + "\r\n\r\n")); err != nil {
					t.Errorf("write malformed response: %v", err)
				}
				conn.Close()
			}))
			defer server.Close()

			transport, err := NewHTTP(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			err = transport.Invoke(t.Context(), "catalog.create", map[string]string{}, &struct{}{})
			message := err.Error()
			for _, secret := range []string{malformed, "hunter2", "10.0.0.5", server.URL} {
				if strings.Contains(message, secret) {
					t.Fatalf("transport error leaked response detail %q: %s", secret, message)
				}
			}
			if !strings.Contains(message, "malformed HTTP response") {
				t.Fatalf("transport failure cause was not classified: %s", message)
			}
			var urlFailure *url.Error
			if !errors.As(err, &urlFailure) {
				t.Fatal("transport error no longer unwraps to the original transport failure")
			}
		})
	}
}

func TestHTTPTransportFailurePreservesCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		time.Sleep(50 * time.Millisecond)
	}))
	defer server.Close()
	transport, err := NewHTTP(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	err = transport.Invoke(ctx, "catalog.create", map[string]string{}, &struct{}{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation was not preserved: %v", err)
	}
	if strings.Contains(err.Error(), server.URL) {
		t.Fatalf("transport error leaked the request URL: %v", err)
	}
}

func TestHTTPClassifiesNetworkFailureWithMalformedURLOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		conn, _, err := response.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack response: %v", err)
			return
		}
		conn.Close()
	}))
	defer server.Close()

	transport, err := NewHTTP(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	// "malformed" appears only in the request URL, and the connection closed
	// without any response bytes, so this is not a response parse failure.
	err = transport.Invoke(t.Context(), "malformed.create", map[string]string{}, &struct{}{})
	if !strings.Contains(err.Error(), "network error") {
		t.Fatalf("transport failure without a response was misclassified: %v", err)
	}
}

func TestHTTPRedactsIPv6ZoneOriginDetail(t *testing.T) {
	transport, err := NewHTTP("https://[fe80::1%25fixture-private-zone]")
	if err != nil {
		t.Fatalf("zone origin was rejected: %v", err)
	}
	err = transport.Invoke(t.Context(), "catalog.create", map[string]string{}, &struct{}{})
	if err == nil {
		t.Fatal("zone origin without a matching interface should fail")
	}
	if strings.Contains(err.Error(), "fe80::1") || strings.Contains(err.Error(), "fixture-private-zone") {
		t.Fatalf("request failure leaked the origin: %v", err)
	}
}

func TestHTTPDoesNotClassifyProxyStatusReasonAsMalformed(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect {
			t.Errorf("unexpected proxy method: %s", request.Method)
		}
		connection, _, err := response.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack proxy response: %v", err)
			return
		}
		connection.Write([]byte("HTTP/1.1 407 malformed HTTP fixture status\r\nContent-Length: 0\r\n\r\n"))
		connection.Close()
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := &HTTP{
		origin: "https://fixture.example",
		client: &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}},
	}
	err = transport.Invoke(t.Context(), "catalog.create", map[string]string{}, &struct{}{})
	message := err.Error()
	if strings.Contains(message, "malformed HTTP response") {
		t.Fatalf("well-formed proxy status was classified as malformed: %s", message)
	}
	if !strings.Contains(message, "network error") {
		t.Fatalf("proxy failure cause was not classified: %s", message)
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
	if !strings.Contains(err.Error(), "deadline exceeded") && !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("timeout cause was not classified: %v", err)
	}
}

type refreshStore struct {
	mu          sync.RWMutex
	refreshMu   sync.Mutex
	credentials SessionCredentials
	cleared     bool
}

func newRefreshStore() *refreshStore {
	var refreshToken [32]byte
	rand.Read(refreshToken[:])
	return &refreshStore{credentials: SessionCredentials{
		AccessToken: strings.Repeat("a", 43), RefreshToken: base64.RawURLEncoding.EncodeToString(refreshToken[:]),
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

type failingRefreshStore struct {
	*refreshStore
	mode   string
	failed bool
}

func (store *failingRefreshStore) Refresh(ctx context.Context, operation func(context.Context, SessionCredentials) (SessionCredentials, error)) (credentials SessionCredentials, err error) {
	if store.failed || store.mode == "clear panic" {
		return store.refreshStore.Refresh(ctx, operation)
	}
	store.failed = true
	if store.mode == "recovered save panic" {
		defer func() {
			if recover() != nil {
				err = errors.New("could not save session")
			}
		}()
	}
	if store.mode == "refresh panic" {
		panic("fixture secret in Refresh")
	}
	credentials, err = operation(ctx, store.Credentials())
	if err != nil {
		return SessionCredentials{}, err
	}
	if store.mode == "save failure" {
		return SessionCredentials{}, errors.New("could not save session")
	}
	panic("fixture secret while saving")
}

func (store *failingRefreshStore) Clear(ctx context.Context, expected SessionCredentials) error {
	if store.mode == "clear panic" {
		panic("fixture secret in Clear")
	}
	return store.refreshStore.Clear(ctx, expected)
}

func writeSessionCredentials(t *testing.T, response http.ResponseWriter, credentials SessionCredentials) {
	t.Helper()
	writeRefreshResponse(t, response, http.StatusOK, map[string]string{
		"access_token": credentials.AccessToken, "refresh_token": credentials.RefreshToken,
		"expires_at": credentials.ExpiresAt, "refresh_expires_at": credentials.RefreshExpiresAt,
		"user_id": credentials.UserID, "session_id": credentials.SessionID,
	})
}

func TestHTTPRefreshStoreFailuresKeepTokenBlocked(t *testing.T) {
	for _, mode := range []string{"save failure", "recovered save panic", "save panic", "refresh panic", "clear panic"} {
		t.Run(mode, func(t *testing.T) {
			store := &failingRefreshStore{refreshStore: newRefreshStore(), mode: mode}
			original := store.Credentials()
			rotated := newRefreshStore().Credentials()
			var refreshes atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path != "/auth.refresh" {
					writeRefreshResponse(t, response, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
					return
				}
				refreshes.Add(1)
				if mode == "clear panic" {
					writeRefreshResponse(t, response, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
					return
				}
				writeSessionCredentials(t, response, rotated)
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
			want := "session refresh failed; sign in again"
			if mode == "save failure" || mode == "recovered save panic" {
				want = "could not save session"
			}
			if err == nil || err.Error() != want {
				t.Fatalf("store failure = %v, want %s", err, want)
			}
			secondTransport, err := NewHTTP(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			secondSigned, err := secondTransport.WithSession(store)
			if err != nil {
				t.Fatal(err)
			}
			for _, client := range []*HTTP{signed, secondSigned} {
				err := client.Invoke(t.Context(), "catalog.create", map[string]string{}, &struct{}{})
				failure, ok := errors.AsType[*OperationError](err)
				if !ok || failure.Code != "invalid_token" || failure.Status != 401 {
					t.Fatalf("blocked token failure = %v", err)
				}
			}
			wantRefreshes := int64(1)
			if mode == "refresh panic" {
				wantRefreshes = 0
			}
			if refreshes.Load() != wantRefreshes || store.Credentials() != original || store.Cleared() {
				t.Fatalf("old token reused or credentials changed: refreshes=%d", refreshes.Load())
			}
			signed.refreshes.mu.Lock()
			remaining := len(signed.refreshes.flights)
			signed.refreshes.mu.Unlock()
			if remaining != 0 {
				t.Fatal("failed refresh flight was not removed")
			}
		})
	}
}

type cachedRefreshStore struct {
	*refreshStore
	unit    *refreshStore
	entered chan struct{}
}

func (store *cachedRefreshStore) Refresh(ctx context.Context, operation func(context.Context, SessionCredentials) (SessionCredentials, error)) (SessionCredentials, error) {
	if store.entered != nil {
		close(store.entered)
	}
	store.unit.refreshMu.Lock()
	defer store.unit.refreshMu.Unlock()
	latest := store.unit.Credentials()
	refreshed, err := operation(ctx, latest)
	if err != nil {
		return SessionCredentials{}, err
	}
	store.unit.mu.Lock()
	store.unit.credentials = refreshed
	store.unit.mu.Unlock()
	store.mu.Lock()
	store.credentials = refreshed
	store.mu.Unlock()
	return refreshed, nil
}

func TestHTTPRefreshSynchronizesDistinctStoreCaches(t *testing.T) {
	unit := newRefreshStore()
	firstStore := &cachedRefreshStore{refreshStore: &refreshStore{credentials: unit.Credentials()}, unit: unit}
	secondStore := &cachedRefreshStore{refreshStore: &refreshStore{credentials: unit.Credentials()}, unit: unit, entered: make(chan struct{})}
	rotated := newRefreshStore().Credentials()
	rotated.AccessToken = strings.Repeat("c", 43)
	var refreshes atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/auth.refresh" {
			if refreshes.Add(1) == 1 {
				close(started)
			}
			<-release
			writeSessionCredentials(t, response, rotated)
			return
		}
		if request.Header.Get("Authorization") == "Bearer "+rotated.AccessToken {
			writeRefreshResponse(t, response, http.StatusOK, map[string]string{})
		} else {
			writeRefreshResponse(t, response, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		}
	}))
	defer server.Close()
	defer unblock()
	transport, err := NewHTTP(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	first, err := transport.WithSession(firstStore)
	if err != nil {
		t.Fatal(err)
	}
	second, err := transport.WithSession(secondStore)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	go func() { results <- first.Invoke(t.Context(), "catalog.create", map[string]string{}, &struct{}{}) }()
	<-started
	go func() { results <- second.Invoke(t.Context(), "catalog.create", map[string]string{}, &struct{}{}) }()
	select {
	case <-secondStore.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("second store never entered its synchronization path")
	}
	unblock()
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if refreshes.Load() != 1 || firstStore.Credentials() != rotated || secondStore.Credentials() != rotated {
		t.Fatalf("stores did not independently observe rotated credentials: refreshes=%d", refreshes.Load())
	}
}

func TestHTTPRefreshOverlapDoesNotClearOrBlockNewLogin(t *testing.T) {
	for _, knownRejection := range []bool{false, true} {
		t.Run(fmt.Sprintf("known rejection=%t", knownRejection), func(t *testing.T) {
			store := new(MemoryStore)
			if err := store.Set(newRefreshStore().Credentials()); err != nil {
				t.Fatal(err)
			}
			login := newRefreshStore().Credentials()
			login.AccessToken = strings.Repeat("l", 43)
			rotated := newRefreshStore().Credentials()
			rotated.AccessToken = strings.Repeat("c", 43)
			var refreshes atomic.Int64
			started := make(chan struct{})
			release := make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/auth.refresh" {
					if refreshes.Add(1) == 1 {
						close(started)
						<-release
						if knownRejection {
							writeRefreshResponse(t, response, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
						} else {
							response.WriteHeader(http.StatusBadGateway)
							fmt.Fprint(response, "not JSON")
						}
					} else {
						writeSessionCredentials(t, response, rotated)
					}
					return
				}
				if request.Header.Get("Authorization") == "Bearer "+rotated.AccessToken {
					writeRefreshResponse(t, response, http.StatusOK, map[string]string{})
				} else {
					writeRefreshResponse(t, response, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
				}
			}))
			defer server.Close()
			defer unblock()
			transport, err := NewHTTP(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			signed, err := transport.WithSession(store)
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() { result <- signed.Invoke(t.Context(), "catalog.create", map[string]string{}, &struct{}{}) }()
			<-started
			if err := store.Set(login); err != nil {
				t.Fatal(err)
			}
			unblock()
			if err := <-result; err == nil {
				t.Fatal("old refresh unexpectedly succeeded")
			}
			if store.Credentials() != login {
				t.Fatal("stale refresh cleared or replaced new login")
			}
			if err := signed.Invoke(t.Context(), "catalog.create", map[string]string{}, &struct{}{}); err != nil {
				t.Fatalf("new login was blocked: %v", err)
			}
			if refreshes.Load() != 2 || store.Credentials() != rotated {
				t.Fatal("new login did not refresh normally")
			}
		})
	}
}

type refreshWaitContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (ctx *refreshWaitContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.waiting) })
	return ctx.Context.Done()
}

func TestHTTPRefreshCancellationDoesNotCancelSharedWork(t *testing.T) {
	store := newRefreshStore()
	original := store.Credentials()
	rotated := newRefreshStore().Credentials()
	rotated.AccessToken = strings.Repeat("c", 43)
	var refreshes atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/auth.refresh" {
			if refreshes.Add(1) == 1 {
				close(started)
			}
			<-release
			if request.Context().Err() != nil {
				t.Error("waiter cancellation canceled refresh")
			}
			writeSessionCredentials(t, response, rotated)
			return
		}
		writeRefreshResponse(t, response, http.StatusOK, map[string]string{})
	}))
	defer server.Close()
	defer unblock()
	transport, err := NewHTTP(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := transport.WithSession(store)
	if err != nil {
		t.Fatal(err)
	}
	second, err := transport.WithSession(store)
	if err != nil {
		t.Fatal(err)
	}
	leaderCtx, cancelLeader := context.WithCancel(t.Context())
	defer cancelLeader()
	leader := make(chan error, 1)
	go func() { _, err := signed.refreshSession(leaderCtx, original); leader <- err }()
	<-started
	followerCtx, cancelFollower := context.WithCancel(t.Context())
	defer cancelFollower()
	followerWait := &refreshWaitContext{Context: followerCtx, waiting: make(chan struct{})}
	follower := make(chan error, 1)
	go func() { _, err := second.refreshSession(followerWait, original); follower <- err }()
	<-followerWait.waiting
	cancelLeader()
	cancelFollower()
	if err := <-leader; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader cancellation = %v", err)
	}
	if err := <-follower; !errors.Is(err, context.Canceled) {
		t.Fatalf("follower cancellation = %v", err)
	}
	lastWait := &refreshWaitContext{Context: t.Context(), waiting: make(chan struct{})}
	last := make(chan error, 1)
	go func() { _, err := second.refreshSession(lastWait, original); last <- err }()
	<-lastWait.waiting
	unblock()
	if err := <-last; err != nil {
		t.Fatal(err)
	}
	if refreshes.Load() != 1 || store.Credentials() != rotated {
		t.Fatal("cancellation abandoned or repeated the shared refresh")
	}
}

func TestRefreshFlightPanicNotifiesWaiters(t *testing.T) {
	flights := new(refreshFlights)
	token := newRefreshStore().Credentials().RefreshToken
	started := make(chan struct{})
	release := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		_, err := flights.Do(t.Context(), refreshKey{token: token}, func() (string, error) { close(started); <-release; panic("fixture secret") })
		results <- err
	}()
	<-started
	ctx := &refreshWaitContext{Context: t.Context(), waiting: make(chan struct{})}
	go func() {
		_, err := flights.Do(ctx, refreshKey{token: token}, func() (string, error) { return "", errors.New("unexpected second flight") })
		results <- err
	}()
	<-ctx.waiting
	close(release)
	for range 2 {
		if err := <-results; err == nil || err.Error() != "session refresh failed; sign in again" {
			t.Fatalf("panic waiter result = %v", err)
		}
	}
	flights.mu.Lock()
	remaining := len(flights.flights)
	flights.mu.Unlock()
	if remaining != 0 {
		t.Fatal("panic left a stuck flight")
	}
}

type concurrentRefreshStore struct {
	*refreshStore
	calls  atomic.Int64
	clears atomic.Int64
}

func (store *concurrentRefreshStore) Clear(ctx context.Context, expected SessionCredentials) error {
	store.clears.Add(1)
	return store.refreshStore.Clear(ctx, expected)
}

type customValueStore struct {
	*concurrentRefreshStore
	identity any
}

type customSliceStore []*concurrentRefreshStore

func (store customSliceStore) Credentials() SessionCredentials {
	return store[0].Credentials()
}

func (store customSliceStore) Refresh(ctx context.Context, operation func(context.Context, SessionCredentials) (SessionCredentials, error)) (SessionCredentials, error) {
	return store[0].Refresh(ctx, operation)
}

func (store customSliceStore) Clear(ctx context.Context, expected SessionCredentials) error {
	return store[0].Clear(ctx, expected)
}

func TestHTTPRefreshStoreValueBoundaries(t *testing.T) {
	for _, name := range []string{"different pointers", "slice", "interface containing slice", "NaN"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				firstStore := &concurrentRefreshStore{refreshStore: newRefreshStore()}
				original := firstStore.Credentials()
				secondStore := firstStore
				var first, second SessionStore = firstStore, secondStore
				switch name {
				case "different pointers":
					secondStore = &concurrentRefreshStore{refreshStore: &refreshStore{credentials: original}}
					second = secondStore
				case "slice":
					first = customSliceStore{firstStore}
					second = first
				case "interface containing slice":
					first = customValueStore{concurrentRefreshStore: firstStore, identity: []int{1}}
					second = first
				case "NaN":
					first = customValueStore{concurrentRefreshStore: firstStore, identity: math.NaN()}
					second = first
				}
				rotated := newRefreshStore().Credentials()
				rotated.AccessToken = strings.Repeat("c", 43)
				var refreshes atomic.Int64
				release := make(chan struct{})
				peer := responseTransport(func(request *http.Request) (*http.Response, error) {
					status, body := http.StatusOK, "{}"
					if request.URL.Path == "/auth.refresh" {
						refreshes.Add(1)
						<-release
						response := httptest.NewRecorder()
						writeSessionCredentials(t, response, rotated)
						body = response.Body.String()
					} else if request.Header.Get("Authorization") != "Bearer "+rotated.AccessToken {
						status, body = http.StatusUnauthorized, `{"error":"invalid_token"}`
					}
					return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
				})
				results := make(chan error, 2)
				for _, store := range []SessionStore{first, second} {
					transport, err := NewHTTP("https://fixture.example")
					if err != nil {
						t.Fatal(err)
					}
					transport.client.Transport = peer
					signed, err := transport.WithSession(store)
					if err != nil {
						t.Fatal(err)
					}
					go func() { results <- signed.Invoke(t.Context(), "catalog.create", map[string]string{}, &struct{}{}) }()
					synctest.Wait()
				}
				if err := <-results; !isInvalidToken(err) {
					t.Fatalf("independent flight reused a consumed token: %v", err)
				}
				if firstStore == secondStore {
					if firstStore.calls.Load() != 2 {
						t.Fatal("non-keyable store did not enter both per-binding Refresh paths")
					}
				} else if firstStore.calls.Load() != 1 || secondStore.calls.Load() != 1 {
					t.Fatal("different store values shared a refresh flight")
				}
				close(release)
				if err := <-results; err != nil {
					t.Fatal(err)
				}
				if refreshes.Load() != 1 || firstStore.Credentials() != rotated {
					t.Fatal("independent flight bypassed the existing token reuse guard")
				}
				customRefreshes.mu.Lock()
				remaining := len(customRefreshes.flights)
				customRefreshes.mu.Unlock()
				if remaining != 0 {
					t.Fatal("store registry retained a completed flight")
				}
			})
		})
	}
}

func (store *concurrentRefreshStore) Refresh(ctx context.Context, operation func(context.Context, SessionCredentials) (SessionCredentials, error)) (SessionCredentials, error) {
	store.calls.Add(1)
	refreshed, err := operation(ctx, store.Credentials())
	if err != nil {
		return SessionCredentials{}, err
	}
	store.mu.Lock()
	store.credentials = refreshed
	store.mu.Unlock()
	return refreshed, nil
}

func TestHTTPRefreshJoinsWithoutStoreSerialization(t *testing.T) {
	store := &concurrentRefreshStore{refreshStore: newRefreshStore()}
	original := store.Credentials()
	rotated := newRefreshStore().Credentials()
	rotated.AccessToken = strings.Repeat("c", 43)
	var refreshes atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/auth.refresh" {
			if refreshes.Add(1) == 1 {
				close(started)
			}
			<-release
			writeSessionCredentials(t, response, rotated)
			return
		}
		if request.Header.Get("Authorization") == "Bearer "+rotated.AccessToken {
			writeRefreshResponse(t, response, http.StatusOK, map[string]string{})
		} else {
			writeRefreshResponse(t, response, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		}
	}))
	defer server.Close()
	defer unblock()
	transport, err := NewHTTP(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := transport.WithSession(store)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	go func() { results <- signed.Invoke(t.Context(), "catalog.create", map[string]string{}, &struct{}{}) }()
	<-started
	waitCtx := &refreshWaitContext{Context: t.Context(), waiting: make(chan struct{})}
	go func() {
		_, err := signed.refreshSession(waitCtx, original)
		if err == nil {
			err = signed.Invoke(t.Context(), "catalog.create", map[string]string{}, &struct{}{})
		}
		results <- err
	}()
	select {
	case <-waitCtx.waiting:
	case <-time.After(3 * time.Second):
		t.Fatal("follower did not enter the SDK flight wait")
	}
	unblock()
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("concurrent business request failed: %v", err)
		}
	}
	if refreshes.Load() != 1 || store.calls.Load() != 1 || store.Credentials() != rotated {
		t.Fatalf("SDK join failed: refreshes=%d store calls=%d", refreshes.Load(), store.calls.Load())
	}
}

type responseTransport func(*http.Request) (*http.Response, error)

func (transport responseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

type countingResponseBody struct {
	io.Reader
	readBytes int
	maxBuffer int
	reads     int
	closed    bool
}

func (body *countingResponseBody) Read(buffer []byte) (int, error) {
	body.reads++
	body.maxBuffer = max(body.maxBuffer, cap(buffer))
	n, err := body.Reader.Read(buffer)
	body.readBytes += n
	return n, err
}

func (body *countingResponseBody) Close() error {
	body.closed = true
	return nil
}

func TestHTTPBoundsResponseRetentionAndStopsReading(t *testing.T) {
	const limit = 1 << 20
	for _, test := range []struct {
		name      string
		status    int
		bodyBytes int
		wantRead  int
		wantError string
	}{
		{"at limit", 200, limit, limit, ""},
		{"one byte over limit", 200, limit + 1, limit + 1, "operation response is too large"},
		{"stop before tail", 200, limit + 65536, limit + 1, "operation response is too large"},
		{"large redirect", 307, limit + 65536, 0, "redirect_not_allowed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &countingResponseBody{Reader: strings.NewReader("{}" + strings.Repeat(" ", test.bodyBytes-2))}
			transport, err := NewHTTP("https://fixture.example")
			if err != nil {
				t.Fatal(err)
			}
			transport.client.Transport = responseTransport(func(request *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: test.status, Body: body, Header: make(http.Header), Request: request}, nil
			})
			err = transport.Invoke(t.Context(), "catalog.create", map[string]string{}, &struct{}{})
			if test.status == 307 {
				failure, ok := errors.AsType[*OperationError](err)
				if !ok || failure.Code != test.wantError || failure.Status != test.status {
					t.Fatalf("redirect error = %v", err)
				}
			} else if test.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || err.Error() != test.wantError {
				t.Fatalf("response error = %v", err)
			}
			if body.readBytes != test.wantRead || body.maxBuffer > limit || !body.closed {
				t.Fatalf("read=%d maxBuffer=%d closed=%t", body.readBytes, body.maxBuffer, body.closed)
			}
			if test.status == 307 && body.reads != 0 {
				t.Fatalf("redirect body read %d times", body.reads)
			}
			if test.wantRead == limit+1 && body.reads != 2 {
				t.Fatalf("overflow read %d times, want 2", body.reads)
			}
		})
	}
}

func TestHTTPUsesHTTP1AgainstHTTP2CapableTLSOrigin(t *testing.T) {
	var protocol atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		protocol.Store(int64(request.ProtoMajor))
		writeRefreshResponse(t, response, http.StatusOK, map[string]string{})
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	transport, err := NewHTTP(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	owned := transport.client.Transport.(*http.Transport)
	owned.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	if err := transport.Invoke(t.Context(), "catalog.create", map[string]string{}, &struct{}{}); err != nil {
		t.Fatal(err)
	}
	if protocol.Load() != 1 {
		t.Fatalf("negotiated HTTP/%d, want HTTP/1", protocol.Load())
	}
	if owned == http.DefaultTransport {
		t.Fatal("runtime modified the shared default transport")
	}
}

func TestHTTPRejectsReplacedDefaultTransportWithoutPanic(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	http.DefaultTransport = responseTransport(func(request *http.Request) (*http.Response, error) {
		t.Fatal("constructor sent a request through the replaced default")
		return nil, errors.New("unexpected request")
	})
	transport, err := NewHTTP("https://fixture.example")
	if transport != nil || err == nil || err.Error() != "default transport is not a standard *http.Transport; required to bound response buffering" {
		t.Fatalf("replaced default constructor result = %v, %v", transport, err)
	}
}

type responseFailureReader struct{ remaining int }

func (reader *responseFailureReader) Read(buffer []byte) (int, error) {
	if reader.remaining == 0 {
		return 0, errors.New("fixture read failure")
	}
	n := min(len(buffer), reader.remaining)
	for index := range n {
		buffer[index] = ' '
	}
	reader.remaining -= n
	return n, nil
}

func TestHTTPPreservesInvalidAndUnreadableResponseErrors(t *testing.T) {
	for _, test := range []struct {
		name   string
		reader io.Reader
		want   string
	}{
		{"invalid JSON", strings.NewReader("not JSON"), "operation failed (invalid_response, HTTP 200)"},
		{"body read failure", &responseFailureReader{remaining: 16}, "could not read operation response"},
		{"overflow probe read failure", &responseFailureReader{remaining: 1 << 20}, "could not read operation response"},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &countingResponseBody{Reader: test.reader}
			transport, err := NewHTTP("https://fixture.example")
			if err != nil {
				t.Fatal(err)
			}
			transport.client.Transport = responseTransport(func(request *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: body, Header: make(http.Header), Request: request}, nil
			})
			err = transport.Invoke(t.Context(), "catalog.create", map[string]string{}, &struct{}{})
			if err == nil || err.Error() != test.want || !body.closed {
				t.Fatalf("response error=%v closed=%t", err, body.closed)
			}
		})
	}
}

func TestHTTPInvalidSuccessDoesNotPublishPartialOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		io.WriteString(w, `{"wire_value":"partial","observed_at":42}`)
	}))
	defer server.Close()
	transport, err := NewHTTP(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	output := struct {
		WireValue  string `json:"wire_value"`
		ObservedAt string `json:"observed_at"`
	}{WireValue: "previous", ObservedAt: "previous"}
	previous := output
	err = transport.Invoke(t.Context(), "probe.echo", map[string]any{}, &output)
	failure, ok := errors.AsType[*OperationError](err)
	if !ok || failure.Code != "invalid_response" || failure.Status != http.StatusAccepted || output != previous {
		t.Fatalf("invalid success error=%v, partial output published=%t", err, output != previous)
	}
}
