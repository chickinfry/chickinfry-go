package auth

import (
	"errors"
	"time"

	"github.com/chickinfry/chickinfry-go/server/auth/internal/private"
	"github.com/chickinfry/chickinfry-go/server/orm"
)

// SessionPolicy is an immutable, validated policy in integer seconds.
type SessionPolicy struct {
	idleTimeoutSeconds      int
	absoluteLifetimeSeconds int
}

// NewSessionPolicy validates policy input before the application starts serving.
// Idle timeout is 3600..31536000 seconds; absolute lifetime is 0 or that range.
// Zero disables the cap; an enabled cap may be shorter than idle timeout.
func NewSessionPolicy(idleTimeoutSeconds, absoluteLifetimeSeconds int) (SessionPolicy, error) {
	if idleTimeoutSeconds < 3600 || idleTimeoutSeconds > 31536000 {
		return SessionPolicy{}, errors.New("idleTimeoutSeconds must be an integer between 3600 and 31536000 seconds")
	}
	if absoluteLifetimeSeconds != 0 && (absoluteLifetimeSeconds < 3600 || absoluteLifetimeSeconds > 31536000) {
		return SessionPolicy{}, errors.New("absoluteLifetimeSeconds must be 0 (disabled) or an integer between 3600 and 31536000 seconds")
	}
	return SessionPolicy{idleTimeoutSeconds, absoluteLifetimeSeconds}, nil
}

const accessLifetime = 15 * time.Minute

func tokenExpirations(issued, firstLogin time.Time, policy SessionPolicy) (string, string) {
	family := issued.Add(time.Duration(policy.idleTimeoutSeconds) * time.Second)
	if policy.absoluteLifetimeSeconds != 0 {
		absolute := firstLogin.Add(time.Duration(policy.absoluteLifetimeSeconds) * time.Second)
		if absolute.Before(family) {
			family = absolute
		}
	}
	access := issued.Add(accessLifetime)
	if family.Before(access) {
		access = family
	}
	return timestamp(access), timestamp(family)
}

func expiredAt(checked time.Time, value string) (bool, error) {
	deadline, err := expiry(value)
	return !deadline.After(checked), err
}

func latestRefresh(db *private.Database, sessionID string) (*private.AppAuthRefreshTokensRow, error) {
	repo := db.AppAuthRefreshTokens
	fields := repo.Columns()
	rows, err := repo.FindMany(orm.FindMany{Where: fields.SessionID.Eq(sessionID), OrderBy: []orm.Order{fields.CreatedAt.Desc(), fields.ID.Desc()}, Limit: new(int32(1))})
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return &rows[0], nil
}

type sessionLifetime struct {
	firstLogin time.Time
	expiresAt  time.Time
}

func sessionExpiry(checked time.Time, policy SessionPolicy, session private.AppAuthSessionsRow, latest *private.AppAuthRefreshTokensRow) (sessionLifetime, error) {
	if session.RevokedAt != nil || session.Transport != "native" || latest == nil {
		return sessionLifetime{}, fail(401, "session_revoked")
	}
	// Stored expiry is a separate gate: a longer policy cannot revive old sessions.
	stored, err := expiry(latest.ExpiresAt)
	if err != nil {
		return sessionLifetime{}, err
	}
	if !stored.After(checked) {
		return sessionLifetime{}, fail(401, "session_revoked")
	}
	first := session.CreatedAt
	if session.FirstLoginAt != nil {
		first = *session.FirstLoginAt
	}
	firstLogin, err := expiry(first)
	if err != nil {
		return sessionLifetime{}, err
	}
	base := latest.CreatedAt
	if session.LastRenewedAt != nil {
		base = *session.LastRenewedAt
	}
	issued, err := expiry(base)
	if err != nil {
		return sessionLifetime{}, err
	}
	_, family := tokenExpirations(issued, firstLogin, policy)
	deadline, err := expiry(family)
	if err != nil {
		return sessionLifetime{}, err
	}
	if !deadline.After(checked) {
		return sessionLifetime{}, fail(401, "session_revoked")
	}
	if stored.Before(deadline) {
		deadline = stored
	}
	return sessionLifetime{firstLogin: firstLogin, expiresAt: deadline}, nil
}

func refreshExpirations(checked time.Time, policy SessionPolicy, session private.AppAuthSessionsRow, current, latest *private.AppAuthRefreshTokensRow, user *private.AppAuthUsersRow) (private.AppAuthSessionsUpdate, string, error) {
	lifetime, err := sessionExpiry(checked, policy, session, latest)
	if err != nil {
		return private.AppAuthSessionsUpdate{}, "", err
	}
	if current == nil || current.ConsumedAt != nil || user == nil || user.DisabledAt != nil || user.SessionVersion != session.UserSessionVersion {
		return private.AppAuthSessionsUpdate{}, "", fail(401, "session_revoked")
	}
	access, family := tokenExpirations(checked, lifetime.firstLogin, policy)
	patch := private.AppAuthSessionsUpdate{ExpiresAt: set(access), LastRenewedAt: set(timestamp(checked))}
	if session.FirstLoginAt == nil {
		patch.FirstLoginAt = set(timestamp(lifetime.firstLogin))
	}
	return patch, family, nil
}
