package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/chickinfry/chickinfry-go/server"
	"github.com/chickinfry/chickinfry-go/server/auth/internal/private"
)

var sessionStart = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

func sessionFixture(t *testing.T, absolute int) (SessionPolicy, private.AppAuthSessionsRow, private.AppAuthRefreshTokensRow, private.AppAuthUsersRow) {
	t.Helper()
	policy, err := NewSessionPolicy(2592000, absolute)
	if err != nil {
		t.Fatal(err)
	}
	access, family := tokenExpirations(sessionStart, sessionStart, policy)
	return policy, private.AppAuthSessionsRow{CreatedAt: timestamp(sessionStart), FirstLoginAt: new(timestamp(sessionStart)), LastRenewedAt: new(timestamp(sessionStart)), ExpiresAt: access, Transport: "native", UserSessionVersion: 1}, private.AppAuthRefreshTokensRow{CreatedAt: timestamp(sessionStart), ExpiresAt: family}, private.AppAuthUsersRow{SessionVersion: 1}
}

func rotateFixture(t *testing.T, checked time.Time, policy SessionPolicy, session *private.AppAuthSessionsRow, latest *private.AppAuthRefreshTokensRow, user *private.AppAuthUsersRow) {
	t.Helper()
	patch, family, err := refreshExpirations(checked, policy, *session, latest, latest, user)
	if err != nil {
		t.Fatal(err)
	}
	if patch.FirstLoginAt.Set && session.FirstLoginAt != nil {
		t.Fatal("rotation rewrote the first login time")
	}
	if patch.FirstLoginAt.Set {
		session.FirstLoginAt = new(patch.FirstLoginAt.Value)
	}
	access, err := expiry(patch.ExpiresAt.Value)
	if err != nil || access.Before(checked) {
		t.Fatal("access expiry preceded its issuance time")
	}
	session.LastRenewedAt = new(patch.LastRenewedAt.Value)
	session.ExpiresAt = patch.ExpiresAt.Value
	*latest = private.AppAuthRefreshTokensRow{CreatedAt: timestamp(checked), ExpiresAt: family}
}

func requireRejected(t *testing.T, checked time.Time, policy SessionPolicy, session private.AppAuthSessionsRow, current, latest *private.AppAuthRefreshTokensRow, user *private.AppAuthUsersRow) {
	t.Helper()
	patch, family, err := refreshExpirations(checked, policy, session, current, latest, user)
	failure, ok := errors.AsType[*server.OperationError](err)
	if !ok || failure.Status != 401 {
		t.Fatalf("expected rejection, got %v", err)
	}
	if patch.ExpiresAt.Set || patch.FirstLoginAt.Set || patch.LastRenewedAt.Set || family != "" {
		t.Fatal("failed refresh returned an extension")
	}
}

func TestA05Rolling(t *testing.T) {
	policy, session, latest, user := sessionFixture(t, 0)
	if policy.absoluteLifetimeSeconds != 0 || latest.ExpiresAt != timestamp(sessionStart.Add(30*24*time.Hour)) {
		t.Fatal("default policy changed")
	}
	for _, days := range []int{29, 31} {
		rotateFixture(t, sessionStart.Add(time.Duration(days)*24*time.Hour), policy, &session, &latest, &user)
		if latest.ExpiresAt != timestamp(sessionStart.Add(time.Duration(days+30)*24*time.Hour)) || *session.FirstLoginAt != timestamp(sessionStart) {
			t.Fatal("rolling expiry or first login changed")
		}
	}
	for _, reason := range []string{"consumed", "revoked", "disabled", "version", "missing-credential", "missing-user"} {
		t.Run(reason, func(t *testing.T) {
			policy, session, latest, user := sessionFixture(t, 0)
			current, account := &latest, &user
			switch reason {
			case "consumed":
				latest.ConsumedAt = new(timestamp(sessionStart))
			case "revoked":
				session.RevokedAt = new(timestamp(sessionStart))
			case "disabled":
				user.DisabledAt = new(timestamp(sessionStart))
			case "version":
				user.SessionVersion++
			case "missing-credential":
				current = nil
			case "missing-user":
				account = nil
			}
			requireRejected(t, sessionStart.Add(29*24*time.Hour), policy, session, current, &latest, account)
		})
	}
}

func TestA06IdleBoundary(t *testing.T) {
	for _, delta := range []time.Duration{-time.Second, 0, time.Second} {
		t.Run(delta.String(), func(t *testing.T) {
			policy, session, latest, user := sessionFixture(t, 0)
			rotateFixture(t, sessionStart.Add(29*24*time.Hour), policy, &session, &latest, &user)
			checked := sessionStart.Add(59*24*time.Hour + delta)
			if delta < 0 {
				rotateFixture(t, checked, policy, &session, &latest, &user)
			} else {
				requireRejected(t, checked, policy, session, &latest, &latest, &user)
				if _, err := sessionExpiry(checked, policy, session, &latest); err == nil {
					t.Fatal("access accepted an expired family")
				}
			}
		})
	}
	policy, session, latest, _ := sessionFixture(t, 0)
	for _, seconds := range []int{899, 900} {
		checked := sessionStart.Add(time.Duration(seconds) * time.Second)
		ended, err := expiredAt(checked, session.ExpiresAt)
		if err != nil || ended != (seconds == 900) {
			t.Fatal("access lifetime boundary changed")
		}
		if _, err := sessionExpiry(checked, policy, session, &latest); err != nil || *session.LastRenewedAt != timestamp(sessionStart) || latest.ExpiresAt != timestamp(sessionStart.Add(30*24*time.Hour)) {
			t.Fatal("plain access renewed or invalidated the family")
		}
	}
}

func TestA07AbsoluteBoundary(t *testing.T) {
	for _, delta := range []time.Duration{-time.Second, 0, time.Second} {
		t.Run(delta.String(), func(t *testing.T) {
			policy, session, latest, user := sessionFixture(t, 60*86400)
			for _, days := range []int{29, 58} {
				rotateFixture(t, sessionStart.Add(time.Duration(days)*24*time.Hour), policy, &session, &latest, &user)
			}
			if latest.ExpiresAt != timestamp(sessionStart.Add(60*24*time.Hour)) {
				t.Fatal("absolute lifetime moved after rotation")
			}
			checked := sessionStart.Add(60*24*time.Hour + delta)
			if delta < 0 {
				rotateFixture(t, checked, policy, &session, &latest, &user)
				if session.ExpiresAt != latest.ExpiresAt {
					t.Fatal("access outlived the absolute cap")
				}
				if ended, err := expiredAt(checked.Add(time.Second), session.ExpiresAt); err != nil || !ended {
					t.Fatal("access accepted at the absolute cap")
				}
			} else {
				requireRejected(t, checked, policy, session, &latest, &latest, &user)
				if _, err := sessionExpiry(checked, policy, session, &latest); err == nil {
					t.Fatal("access accepted at or after the absolute cap")
				}
			}
		})
	}
	policy, session, latest, user := sessionFixture(t, 3600)
	if latest.ExpiresAt != timestamp(sessionStart.Add(time.Hour)) {
		t.Fatal("absolute lifetime shorter than idle was ignored")
	}
	rotateFixture(t, sessionStart.Add(time.Hour-time.Second), policy, &session, &latest, &user)
	requireRejected(t, sessionStart.Add(time.Hour), policy, session, &latest, &latest, &user)
}

func TestSESS1LegacyAndPolicyChanges(t *testing.T) {
	for _, transport := range []string{"access", "refresh"} {
		for _, change := range []string{"legacy-default", "recent-legacy", "old-legacy", "stored-expired", "revoked", "absolute-enabled", "absolute-changed", "absolute-disabled", "idle-shortened", "idle-expanded"} {
			t.Run(transport+"/"+change, func(t *testing.T) {
				policy, session, latest, user := sessionFixture(t, 0)
				checked := sessionStart.Add(2*24*time.Hour + 3599*time.Second)
				latest.CreatedAt = timestamp(sessionStart.Add(2 * 24 * time.Hour))
				latest.ExpiresAt = timestamp(sessionStart.Add(7 * 24 * time.Hour))
				session.FirstLoginAt, session.LastRenewedAt = nil, nil
				accepted := false
				switch change {
				case "legacy-default":
					accepted = true
				case "recent-legacy":
					policy, _ = NewSessionPolicy(3600, 0)
					accepted = true
				case "old-legacy":
					policy, _ = NewSessionPolicy(3600, 0)
					latest.CreatedAt = timestamp(sessionStart)
				case "stored-expired":
					checked = sessionStart.Add(7 * 24 * time.Hour)
					// The expired stored deadline must reject before parsing migration bases.
					session.CreatedAt, latest.CreatedAt = "invalid", "invalid"
				case "revoked":
					session.RevokedAt = new(timestamp(sessionStart))
				case "absolute-enabled":
					policy, _ = NewSessionPolicy(2592000, 86400)
				case "absolute-changed":
					session.FirstLoginAt = new(timestamp(sessionStart))
					session.LastRenewedAt = new(latest.CreatedAt)
					previous, _ := NewSessionPolicy(2592000, 60*86400)
					_, latest.ExpiresAt = tokenExpirations(sessionStart.Add(2*24*time.Hour), sessionStart, previous)
					policy, _ = NewSessionPolicy(2592000, 86400)
				case "absolute-disabled":
					latest.ExpiresAt = timestamp(sessionStart.Add(24 * time.Hour))
				case "idle-expanded":
					latest.CreatedAt = timestamp(sessionStart)
					latest.ExpiresAt = timestamp(sessionStart.Add(time.Hour))
					checked = sessionStart.Add(2 * time.Hour)
				case "idle-shortened":
					session.FirstLoginAt = new(timestamp(sessionStart))
					session.LastRenewedAt = new(latest.CreatedAt)
					policy, _ = NewSessionPolicy(3600, 0)
					checked = checked.Add(time.Second)
				}
				if transport == "access" {
					_, err := sessionExpiry(checked, policy, session, &latest)
					if accepted != (err == nil) {
						t.Fatalf("policy validation: %v", err)
					}
				} else if accepted {
					rotateFixture(t, checked, policy, &session, &latest, &user)
					if *session.FirstLoginAt != timestamp(sessionStart) || *session.LastRenewedAt != timestamp(checked) || latest.ExpiresAt != timestamp(checked.Add(time.Duration(policy.idleTimeoutSeconds)*time.Second)) {
						t.Fatal("legacy timestamps did not preserve their recorded origins")
					}
				} else {
					requireRejected(t, checked, policy, session, &latest, &latest, &user)
				}
			})
		}
	}
}

func TestSessionPolicyValidation(t *testing.T) {
	if got := New(nil, Hooks{}).policy; got.idleTimeoutSeconds != 2592000 || got.absoluteLifetimeSeconds != 0 {
		t.Fatal("runtime policy defaults differ from the contract")
	}
	for _, idle := range []int{-1, 0, 3599, 3600, 2592000, 31536000, 31536001} {
		for _, absolute := range []int{-1, 0, 1, 3599, 3600, 31536000, 31536001} {
			_, err := NewSessionPolicy(idle, absolute)
			valid := idle >= 3600 && idle <= 31536000 && (absolute == 0 || absolute >= 3600 && absolute <= 31536000)
			if valid != (err == nil) {
				t.Fatalf("idle=%d absolute=%d: %v", idle, absolute, err)
			}
		}
	}
}
