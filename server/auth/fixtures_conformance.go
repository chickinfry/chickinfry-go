//go:build chik_conformance

package auth

import (
	"errors"
	"time"

	"github.com/chickinfry/chickinfry-go/server/auth/internal/private"
	"github.com/chickinfry/chickinfry-go/server/database"
)

// ConformanceAuthFixture prepares private states through the generated ORM only.
// It is absent from normal builds and is never an operation exposed by the runtime.
func ConformanceAuthFixture(connection *database.Connection, mode, userID string) error {
	db := private.New(connection)
	switch mode {
	case "vector":
		_, err := db.AppAuthUsers.Update(private.AppAuthUsersPrimaryKey{ID: userID}, private.AppAuthUsersUpdate{PasswordHash: set("scrypt$32768$8$3$00000000000000000000000000000000$5bfe0288362511a467ab22d2e7756cf7c4af8a82aecedbf80a5e68c478a48807")})
		return err
	case "conditional":
		repo := db.AppAuthUsers
		row, err := repo.UpdateIf(private.AppAuthUsersPrimaryKey{ID: userID}, repo.Columns().SessionVersion.Equal(int32(-1)), private.AppAuthUsersUpdate{SessionVersion: set(int32(1))})
		if err != nil {
			return err
		}
		if row != nil {
			return errors.New("unmatched update returned a row")
		}
		return nil
	case "access-expired":
		_, err := db.AppAuthSessions.Update(private.AppAuthSessionsPrimaryKey{ID: userID}, private.AppAuthSessionsUpdate{ExpiresAt: set(timestamp(time.Now().Add(-time.Hour)))})
		return err
	case "cleanup-boundary":
		cutoff := "2020-01-01T00:00:00.000Z"
		for index, until := range []string{"2019-12-31T23:59:59.999999Z", cutoff, "2020-01-01T00:00:00.000001Z"} {
			_, err := db.AppAuthRateLimits.Insert(private.AppAuthRateLimitsInsert{Action: "boundary", KeyHash: digest(until), AttemptCount: int32(index + 1), ExpiresAt: until})
			if err != nil {
				return err
			}
		}
		if err := New(connection, Hooks{}).cleanup(cutoff); err != nil {
			return err
		}
		for index, until := range []string{"2019-12-31T23:59:59.999999Z", cutoff, "2020-01-01T00:00:00.000001Z"} {
			row, err := db.AppAuthRateLimits.FindByID(private.AppAuthRateLimitsPrimaryKey{Action: "boundary", KeyHash: digest(until)})
			if err != nil {
				return err
			}
			if (row != nil) != (index == 2) {
				return errors.New("cleanup expiration boundary")
			}
		}
		return nil

	case "corrupt":
		_, err := db.AppAuthUsers.Update(private.AppAuthUsersPrimaryKey{ID: userID}, private.AppAuthUsersUpdate{PasswordHash: set("corrupt")})
		return err
	case "disabled":
		_, err := db.AppAuthUsers.Update(private.AppAuthUsersPrimaryKey{ID: userID}, private.AppAuthUsersUpdate{DisabledAt: set(now())})
		return err
	case "version":
		_, err := db.AppAuthUsers.Update(private.AppAuthUsersPrimaryKey{ID: userID}, private.AppAuthUsersUpdate{SessionVersion: set(int32(2))})
		return err
	case "cleanup":
		cutoff := timestamp(time.Now().Add(-time.Hour))
		for range 40 {
			value, err := token()
			if err != nil {
				return err
			}
			session, err := db.AppAuthSessions.Insert(private.AppAuthSessionsInsert{UserID: userID, TokenHash: digest(value), UserSessionVersion: 1, ExpiresAt: cutoff})
			if err != nil {
				return err
			}
			_, err = db.AppAuthRefreshTokens.Insert(private.AppAuthRefreshTokensInsert{SessionID: session.ID, TokenHash: digest(value), ExpiresAt: cutoff})
			if err != nil {
				return err
			}
			_, err = db.AppAuthRateLimits.Insert(private.AppAuthRateLimitsInsert{Action: "fixture", KeyHash: digest(value), AttemptCount: 1, ExpiresAt: cutoff})
			if err != nil {
				return err
			}
		}
		return nil
	}
	return errors.New("unknown authentication fixture")
}
