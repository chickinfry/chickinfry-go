package auth

import (
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"testing"
	"time"

	"github.com/chickinfry/chickinfry-go/server/auth/internal/private"
)

// Evaluate the actual ORM predicate without adding a production host hook.
func cleanupFilterMatches(t *testing.T, filter reflect.Value, row map[string]any) bool {
	t.Helper()
	operator := filter.FieldByName("operator").String()
	children := filter.FieldByName("children")
	if operator == "and" || operator == "or" {
		result := operator == "and"
		for index := range children.Len() {
			match := cleanupFilterMatches(t, children.Index(index), row)
			if operator == "and" {
				result = result && match
			} else {
				result = result || match
			}
		}
		return result
	}
	value := row[filter.FieldByName("column").String()]
	if operator == "is null" {
		return value == nil
	}
	if operator == "is not null" {
		return value != nil
	}
	if value == nil {
		return false
	}
	want := filter.FieldByName("value").Elem().String()
	switch operator {
	case "=":
		return value.(string) == want
	case "<":
		return value.(string) < want
	default:
		t.Fatalf("unsupported cleanup predicate %q", operator)
		return false
	}
}

func TestCleanupSessionCandidates(t *testing.T) {
	checked := sessionStart.Add(48 * time.Hour)
	fields := private.New(nil).AppAuthSessions.Columns()
	for _, mode := range []string{"live-old-credentials", "recent-legacy", "old-legacy", "legacy-seven-day-cap", "idle-boundary", "absolute-boundary", "legacy-absolute", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			policy, session, latest, user := sessionFixture(t, 0)
			policy, _ = NewSessionPolicy(3600, 0)
			session.LastRenewedAt = new(timestamp(checked.Add(-30 * time.Minute)))
			session.ExpiresAt = timestamp(checked.Add(-15 * time.Minute))
			latest.CreatedAt = *session.LastRenewedAt
			latest.ExpiresAt = timestamp(checked.Add(24 * time.Hour))
			selected := false
			switch mode {
			case "recent-legacy":
				session.LastRenewedAt, session.FirstLoginAt = nil, nil
			case "old-legacy":
				session.LastRenewedAt, session.FirstLoginAt = nil, nil
				latest.CreatedAt = timestamp(checked.Add(-2 * time.Hour))
				session.ExpiresAt = timestamp(checked.Add(-105 * time.Minute))
				selected = true
			case "legacy-seven-day-cap":
				session.LastRenewedAt, session.FirstLoginAt = nil, nil
				session.CreatedAt = timestamp(checked.Add(-7 * 24 * time.Hour))
				session.ExpiresAt = timestamp(checked.Add(24 * time.Hour))
				latest.ExpiresAt = timestamp(checked)
				selected = true
			case "idle-boundary":
				session.LastRenewedAt = new(timestamp(checked.Add(-time.Hour)))
				selected = true
			case "absolute-boundary", "legacy-absolute":
				policy, _ = NewSessionPolicy(3600, 48*3600)
				if mode == "legacy-absolute" {
					session.FirstLoginAt = nil
				}
				selected = true
			case "revoked":
				session.RevokedAt = new(timestamp(checked))
				selected = true
			}
			data, err := json.Marshal(session)
			if err != nil {
				t.Fatal(err)
			}
			var row map[string]any
			if err := json.Unmarshal(data, &row); err != nil {
				t.Fatal(err)
			}
			filter := reflect.ValueOf(cleanupSessionFilter(fields, checked, policy))
			if cleanupFilterMatches(t, filter, row) != selected {
				t.Fatal("cleanup selected a live family or missed an ended family")
			}
			if mode == "live-old-credentials" || mode == "recent-legacy" {
				if _, err := sessionExpiry(checked, policy, session, &latest); err != nil {
					t.Fatal("excluded family is not live")
				}
				consumed := latest
				consumed.ConsumedAt = new(timestamp(checked.Add(-time.Hour)))
				consumed.ExpiresAt = timestamp(checked.Add(-time.Minute))
				requireRejected(t, checked, policy, session, &consumed, &latest, &user)
			} else if _, err := sessionExpiry(checked, policy, session, &latest); err == nil {
				t.Fatal("cleanup candidate passed the locked expiry check")
			}
		})
	}
}

func TestCleanupLegacySelectionDoesNotReplaceQ1(t *testing.T) {
	policy, session, latest, _ := sessionFixture(t, 0)
	policy, _ = NewSessionPolicy(3600, 0)
	checked := sessionStart.Add(2 * time.Hour)
	session.FirstLoginAt, session.LastRenewedAt = nil, nil
	latest.CreatedAt = timestamp(checked.Add(-65 * time.Minute))
	session.ExpiresAt = timestamp(checked.Add(-50 * time.Minute))
	if _, err := sessionExpiry(checked, policy, session, &latest); err == nil {
		t.Fatal("Q1 accepted an expired family inside the cleanup selection delay")
	}
	filter := reflect.ValueOf(cleanupSessionFilter(private.New(nil).AppAuthSessions.Columns(), checked, policy))
	row := map[string]any{"created_at": session.CreatedAt, "expires_at": session.ExpiresAt}
	if cleanupFilterMatches(t, filter, row) {
		t.Fatal("legacy family was selected before the conservative delay ended")
	}
}

func TestCleanupSelectedLiveFamilies(t *testing.T) {
	checked := sessionStart.Add(8 * 24 * time.Hour)
	policy, err := NewSessionPolicy(3600, 0)
	if err != nil {
		t.Fatal(err)
	}
	filter := reflect.ValueOf(cleanupSessionFilter(private.New(nil).AppAuthSessions.Columns(), checked, policy))
	for _, mode := range []string{"broken-access-expiry", "seven-day-live", "renewed-after-selection"} {
		t.Run(mode, func(t *testing.T) {
			renewalPolicy, session, latest, user := sessionFixture(t, 0)
			session.FirstLoginAt, session.LastRenewedAt = nil, nil
			session.CreatedAt = timestamp(checked.Add(-2 * 24 * time.Hour))
			session.ExpiresAt = timestamp(checked.Add(-2 * time.Hour))
			latest.CreatedAt = timestamp(checked.Add(-30 * time.Minute))
			latest.ExpiresAt = timestamp(checked.Add(24 * time.Hour))
			if mode != "broken-access-expiry" {
				session.CreatedAt = timestamp(checked.Add(-8 * 24 * time.Hour))
				session.ExpiresAt = timestamp(checked.Add(24 * time.Hour))
			}
			if mode == "renewed-after-selection" {
				latest.CreatedAt = timestamp(checked.Add(-2 * time.Hour))
			}
			row := map[string]any{"created_at": session.CreatedAt, "expires_at": session.ExpiresAt}
			if !cleanupFilterMatches(t, filter, row) {
				t.Fatal("fixture did not enter cleanup selection")
			}
			if mode == "renewed-after-selection" {
				requireRejected(t, checked, policy, session, &latest, &latest, &user)
				// A concurrent request can renew under a longer policy before cleanup locks.
				rotateFixture(t, checked, renewalPolicy, &session, &latest, &user)
			}
			if _, err := sessionExpiry(checked, policy, session, &latest); err != nil {
				t.Fatalf("selected family must survive the locked Q1 check: %v", err)
			}
			rotateFixture(t, checked.Add(time.Minute), policy, &session, &latest, &user)

			dead := latest
			dead.ExpiresAt = timestamp(checked)
			requireRejected(t, checked, policy, session, &dead, &dead, &user)
		})
	}
}

func TestCleanupStart(t *testing.T) {
	runtime := New(nil, Hooks{})
	generate := runtime.cleanupStart
	starts := []string{}
	runtime.cleanupStart = func() (string, error) {
		value, err := generate()
		starts = append(starts, value)
		return value, err
	}
	// A missing connection stops the pass after generating its start.
	for range 2 {
		if err := runtime.cleanup(now()); err == nil {
			t.Fatal("cleanup unexpectedly queried without a connection")
		}
	}
	format := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if len(starts) != 2 || !format.MatchString(starts[0]) || !format.MatchString(starts[1]) || starts[0] == starts[1] {
		t.Fatal("each cleanup pass must use a fresh UUID v4 start from the generator")
	}
	failure := errors.New("random source unavailable")
	runtime.cleanupStart = func() (string, error) { return "", failure }
	if err := runtime.cleanup(now()); !errors.Is(err, failure) {
		t.Fatal("cleanup must stop before querying when the start generator fails")
	}
}
