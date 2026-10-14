package auth

import (
	"errors"
	"time"

	"github.com/chickinfry/chickinfry-go/server"
	"github.com/chickinfry/chickinfry-go/server/auth/internal/private"
	"github.com/chickinfry/chickinfry-go/server/orm"
)

func cleanupSessionFilter(fields private.AppAuthSessionsColumns, checked time.Time, policy SessionPolicy) orm.Filter {
	// Legacy access expiry only bounds selection; the locked check still uses Q1.
	idle := timestamp(checked.Add(-time.Duration(policy.idleTimeoutSeconds) * time.Second))
	atOrBefore := func(field orm.Field[string], cutoff string) orm.Filter {
		return orm.Or(field.Less(cutoff), field.Equal(cutoff))
	}
	ended := orm.Or(fields.RevokedAt.IsNotNull(),
		orm.And(fields.LastRenewedAt.IsNotNull(), atOrBefore(fields.LastRenewedAt, idle)),
		orm.And(fields.LastRenewedAt.IsNull(), orm.Or(atOrBefore(fields.ExpiresAt, idle),
			atOrBefore(fields.CreatedAt, timestamp(checked.Add(-7*24*time.Hour))))))
	if policy.absoluteLifetimeSeconds != 0 {
		absolute := timestamp(checked.Add(-time.Duration(policy.absoluteLifetimeSeconds) * time.Second))
		ended = orm.Or(ended,
			orm.And(fields.FirstLoginAt.IsNotNull(), atOrBefore(fields.FirstLoginAt, absolute)),
			orm.And(fields.FirstLoginAt.IsNull(), atOrBefore(fields.CreatedAt, absolute)))
	}
	return ended
}

// One foreground pass considers at most 32 candidates per table, never the
// finished signup lease. Row bounds do not provide a wall-clock deadline.
func (auth *Auth) cleanup(cutoff string) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("authentication cleanup failed")
		}
	}()
	recordCleanup("pass")
	checked, err := expiry(cutoff)
	if err != nil {
		return err
	}
	limit := new(int32(32))
	sessions := auth.db.AppAuthSessions
	sf := sessions.Columns()
	ended := cleanupSessionFilter(sf, checked, auth.policy)
	rows, err := sessions.FindMany(orm.FindMany{Where: ended, Order: []orm.Order{sf.ExpiresAt.Asc(), sf.ID.Asc()}, Limit: limit})
	if err != nil {
		return err
	}
	remainingRefresh := int32(32)
	for _, candidate := range rows {
		err := auth.db.Transaction(func(db *private.Database) error {
			sessions := db.AppAuthSessions
			session, err := sessions.UpdateIf(private.AppAuthSessionsPrimaryKey{ID: candidate.ID}, orm.And(sf.ExpiresAt.Equal(candidate.ExpiresAt), ended), private.AppAuthSessionsUpdate{ExpiresAt: set(candidate.ExpiresAt)})
			if err != nil {
				return err
			}
			if session == nil {
				return nil
			}
			if session.RevokedAt == nil {
				latest, err := latestRefresh(db, session.ID)
				if err != nil {
					return err
				}
				if _, err := sessionExpiry(checked, auth.policy, *session, latest); err == nil {
					return nil
				} else if failure, ok := errors.AsType[*server.Error](err); !ok || failure.Status != 401 {
					return err
				}
			}
			refresh := db.AppAuthRefreshTokens
			rf := refresh.Columns()
			children, err := refresh.FindMany(orm.FindMany{Where: rf.SessionID.Equal(session.ID), Order: []orm.Order{rf.ExpiresAt.Asc(), rf.ID.Asc()}, Limit: new(remainingRefresh)})
			if err != nil {
				return err
			}
			for _, child := range children {
				row, err := refresh.UpdateIf(private.AppAuthRefreshTokensPrimaryKey{ID: child.ID}, orm.And(rf.SessionID.Equal(session.ID), rf.ExpiresAt.Equal(child.ExpiresAt)), private.AppAuthRefreshTokensUpdate{ExpiresAt: set(child.ExpiresAt)})
				if err != nil {
					return err
				}
				if row == nil {
					continue
				}
				recordCleanup("delete")
				remainingRefresh--
				if _, err := refresh.Delete(private.AppAuthRefreshTokensPrimaryKey{ID: row.ID}); err != nil {
					return err
				}
			}
			refs, err := refresh.FindMany(orm.FindMany{Where: rf.SessionID.Equal(session.ID), Limit: new(int32(1))})
			if err != nil || len(refs) > 0 {
				return err
			}
			recordCleanup("delete")
			_, err = sessions.Delete(private.AppAuthSessionsPrimaryKey{ID: session.ID})
			return err
		})
		if err != nil {
			return err
		}
	}
	rates := auth.db.AppAuthRateLimits
	lf := rates.Columns()
	expiredRate := orm.Or(lf.ExpiresAt.Less(cutoff), lf.ExpiresAt.Equal(cutoff))
	rateRows, err := rates.FindMany(orm.FindMany{Where: expiredRate, Order: []orm.Order{lf.ExpiresAt.Asc(), lf.Action.Asc(), lf.KeyHash.Asc()}, Limit: limit})
	if err != nil {
		return err
	}
	for _, candidate := range rateRows {
		err := auth.db.Transaction(func(db *private.Database) error {
			key := private.AppAuthRateLimitsPrimaryKey{Action: candidate.Action, KeyHash: candidate.KeyHash}
			row, err := db.AppAuthRateLimits.UpdateIf(key, orm.And(lf.ExpiresAt.Equal(candidate.ExpiresAt), lf.AttemptCount.Equal(candidate.AttemptCount), expiredRate), private.AppAuthRateLimitsUpdate{AttemptCount: set(candidate.AttemptCount)})
			if err != nil || row == nil {
				return err
			}
			recordCleanup("delete")
			_, err = db.AppAuthRateLimits.Delete(key)
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}
