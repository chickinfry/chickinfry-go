package auth

import (
	"errors"
	"github.com/chickinfry/chickinfry-go/server/auth/internal/private"
	"github.com/chickinfry/chickinfry-go/server/orm"
)

// One foreground pass considers at most 32 candidates per table, never the
// finished signup lease. Row bounds do not provide a wall-clock deadline.
func (auth *Auth) cleanup(cutoff string) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("authentication cleanup failed")
		}
	}()
	recordCleanup("pass")
	limit := new(int32(32))
	refresh := auth.db.AppAuthRefreshTokens
	rf := refresh.Columns()
	expiredRefresh := orm.Or(rf.ExpiresAt.Less(cutoff), rf.ExpiresAt.Equal(cutoff))
	rows, err := refresh.FindMany(orm.FindMany{Where: expiredRefresh, Order: []orm.Order{rf.ExpiresAt.Asc(), rf.ID.Asc()}, Limit: limit})
	if err != nil {
		return err
	}
	for _, candidate := range rows {
		err := auth.db.Transaction(func(db *private.Database) error {
			row, err := db.AppAuthRefreshTokens.UpdateIf(private.AppAuthRefreshTokensPrimaryKey{ID: candidate.ID}, orm.And(rf.ExpiresAt.Equal(candidate.ExpiresAt), expiredRefresh), private.AppAuthRefreshTokensUpdate{ExpiresAt: set(candidate.ExpiresAt)})
			if err != nil || row == nil {
				return err
			}
			recordCleanup("delete")
			_, err = db.AppAuthRefreshTokens.Delete(private.AppAuthRefreshTokensPrimaryKey{ID: row.ID})
			return err
		})
		if err != nil {
			return err
		}
	}
	sessions := auth.db.AppAuthSessions
	sf := sessions.Columns()
	expiredSession := orm.Or(sf.ExpiresAt.Less(cutoff), sf.ExpiresAt.Equal(cutoff))
	sessionRows, err := sessions.FindMany(orm.FindMany{Where: expiredSession, Order: []orm.Order{sf.ExpiresAt.Asc(), sf.ID.Asc()}, Limit: limit})
	if err != nil {
		return err
	}
	for _, candidate := range sessionRows {
		err := auth.db.Transaction(func(db *private.Database) error {
			row, err := db.AppAuthSessions.UpdateIf(private.AppAuthSessionsPrimaryKey{ID: candidate.ID}, orm.And(sf.ExpiresAt.Equal(candidate.ExpiresAt), expiredSession), private.AppAuthSessionsUpdate{ExpiresAt: set(candidate.ExpiresAt)})
			if err != nil || row == nil {
				return err
			}
			refs, err := db.AppAuthRefreshTokens.FindMany(orm.FindMany{Where: rf.SessionID.Equal(row.ID), Limit: new(int32(1))})
			if err != nil || len(refs) > 0 {
				return err
			}
			recordCleanup("delete")
			_, err = db.AppAuthSessions.Delete(private.AppAuthSessionsPrimaryKey{ID: row.ID})
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
