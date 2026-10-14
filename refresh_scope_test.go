package chik

import (
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestHTTPRefreshStateAcrossMemoryStores(t *testing.T) {
	for _, mode := range []string{"401", "disconnect"} {
		t.Run(mode, func(t *testing.T) {
			original := newRefreshStore().Credentials()
			rotated := newRefreshStore().Credentials()
			rotated.AccessToken = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			var attempts atomic.Int64
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/auth.refresh" {
					if r.Header.Get("Authorization") == "Bearer "+rotated.AccessToken {
						writeRefreshResponse(t, w, http.StatusOK, map[string]string{})
					} else {
						writeRefreshResponse(t, w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
					}
					return
				}
				if attempts.Add(1) != 1 {
					writeSessionCredentials(t, w, rotated)
					return
				}
				switch mode {
				case "401":
					writeRefreshResponse(t, w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
				case "disconnect":
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					conn.Close()
				}
			}))
			defer peer.Close()
			transport, err := NewHTTP(peer.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer transport.client.CloseIdleConnections()
			stores := []*MemoryStore{new(MemoryStore), new(MemoryStore)}
			clients := make([]*HTTP, len(stores))
			for i, store := range stores {
				if err := store.Set(original); err != nil {
					t.Fatal(err)
				}
				clients[i], err = transport.WithSession(store)
				if err != nil {
					t.Fatal(err)
				}
			}
			errA := clients[0].Invoke(t.Context(), "catalog.create", map[string]string{}, &struct{}{})
			if errA == nil {
				t.Fatal("store A refresh unexpectedly succeeded")
			}
			_, pending := unknownRefreshes.Load(sha256.Sum256([]byte(original.RefreshToken)))
			if stores[1].Credentials() != original || attempts.Load() != 1 {
				t.Fatal("store A refresh changed store B credentials or repeated the request")
			}
			if mode == "401" {
				if !isInvalidToken(errA) || pending || stores[0].Credentials() != (SessionCredentials{}) {
					t.Fatal("confirmed rejection did not end only store A's session")
				}
				if err := clients[1].Invoke(t.Context(), "catalog.create", map[string]string{}, &struct{}{}); err != nil {
					t.Fatalf("store B refresh was affected by store A's rejection: %v", err)
				}
				if attempts.Load() != 2 || stores[1].Credentials() != rotated {
					t.Fatal("store B did not independently refresh and save credentials")
				}
				return
			}
			if _, ok := errors.AsType[*transportError](errA); !ok || !pending || stores[0].Credentials() != original {
				t.Fatal("lost refresh response did not retain its unknown outcome")
			}
			clients[0], err = transport.WithSession(stores[0])
			if err != nil {
				t.Fatal(err)
			}
			for i, client := range clients {
				if err := client.Invoke(t.Context(), "catalog.create", map[string]string{}, &struct{}{}); !isInvalidToken(err) {
					t.Fatalf("store %d reused a possibly consumed refresh token: %v", i, err)
				}
				if stores[i].Credentials() != original || attempts.Load() != 1 {
					t.Fatal("unknown refresh outcome cleared credentials or repeated the refresh")
				}
			}
		})
	}
}
