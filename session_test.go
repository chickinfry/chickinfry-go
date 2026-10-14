package chik

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
)

func TestMemoryStoreRefreshCannotOverwriteConcurrentChange(t *testing.T) {
	for _, change := range []string{"clear", "login", "same login"} {
		t.Run(change, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				store := new(MemoryStore)
				original := newRefreshStore().Credentials()
				if err := store.Set(original); err != nil {
					t.Fatal(err)
				}
				rotated := newRefreshStore().Credentials()
				started, release := make(chan struct{}), make(chan struct{})
				result := make(chan error, 1)
				go func() {
					_, err := store.Refresh(t.Context(), func(context.Context, SessionCredentials) (SessionCredentials, error) {
						close(started)
						<-release
						return rotated, nil
					})
					result <- err
				}()
				<-started
				want := SessionCredentials{}
				if change == "clear" {
					if err := store.Clear(t.Context(), original); err != nil {
						t.Fatal(err)
					}
				} else {
					want = newRefreshStore().Credentials()
					if change == "same login" {
						want = original
					}
					if err := store.Set(want); err != nil {
						t.Fatal(err)
					}
				}
				close(release)
				if err := <-result; err == nil {
					t.Fatal("stale refresh succeeded")
				}
				if store.Credentials() != want {
					t.Fatal("stale refresh overwrote concurrent change")
				}
			})
		})
	}
}

func TestMemoryStoreInvalidWritesPreserveSession(t *testing.T) {
	store := new(MemoryStore)
	original := newRefreshStore().Credentials()
	if err := store.Set(original); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []SessionCredentials{{}, {AccessToken: "invalid", RefreshToken: original.RefreshToken}, {AccessToken: original.AccessToken, RefreshToken: original.RefreshToken}} {
		if err := store.Set(invalid); err == nil {
			t.Fatal("invalid login accepted")
		}
		if _, err := store.Refresh(t.Context(), func(context.Context, SessionCredentials) (SessionCredentials, error) { return invalid, nil }); err == nil {
			t.Fatal("invalid refresh accepted")
		}
		if store.Credentials() != original {
			t.Fatal("invalid write changed login")
		}
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := store.Clear(canceled, original); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled clear: %v", err)
	}
	if _, err := store.Refresh(canceled, func(context.Context, SessionCredentials) (SessionCredentials, error) {
		t.Fatal("canceled callback ran")
		return SessionCredentials{}, nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled refresh: %v", err)
	}
	stale := original
	stale.SessionID = "another-session"
	if err := store.Clear(t.Context(), stale); err != nil {
		t.Fatal(err)
	}
	if store.Credentials() != original {
		t.Fatal("canceled or mismatched clear removed session")
	}
}
