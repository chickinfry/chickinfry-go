// Package auth implements native authentication using the generated private ORM.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/chickinfry/chickinfry-go/server"
	"github.com/chickinfry/chickinfry-go/server/auth/internal/private"
	"github.com/chickinfry/chickinfry-go/server/database"
	"github.com/chickinfry/chickinfry-go/server/host"
	"github.com/chickinfry/chickinfry-go/server/orm"
)

// User contains only public values copied from the newly created account.
type User struct{ ID, Email, CreatedAt string }

// Hooks are connected to public application contexts by the generated adapter.
type Hooks struct {
	UserCreating func(*database.Connection, User) error
	UserCreated  func(User) error
}

// Tokens is the native wire response; raw credentials are never stored in the DB.
type Tokens struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresAt        string `json:"expires_at"`
	RefreshExpiresAt string `json:"refresh_expires_at"`
	UserID           string `json:"user_id"`
	SessionID        string `json:"session_id"`
}

// Auth owns the private repositories for one live request.
type Auth struct {
	connection *database.Connection
	db         *private.Database
	hooks      Hooks
}

// New binds the private repositories and generated hook adapter to a request.
func New(connection *database.Connection, hooks Hooks) *Auth {
	return &Auth{connection, private.New(connection), hooks}
}

func fail(status int, code string) error     { return &server.Error{Status: status, Code: code} }
func set[T any](value T) orm.Optional[T]     { return orm.Optional[T]{Set: true, Value: value} }
func null[T any]() orm.Optional[T]           { return orm.Optional[T]{Set: true, Null: true} }
func timestamp(value time.Time) string       { return value.UTC().Format("2006-01-02T15:04:05.000000Z") }
func now() string                            { return timestamp(time.Now()) }
func expiry(value string) (time.Time, error) { return time.Parse(time.RFC3339Nano, value) }
func expired(value string) (bool, error) {
	deadline, err := expiry(value)
	return !deadline.After(time.Now()), err
}
func digest(value string) string {
	result := sha256.Sum256([]byte(value))
	return hex.EncodeToString(result[:])
}
func token() (string, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
func validToken(value string) bool {
	data, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(data) == 32 && base64.RawURLEncoding.EncodeToString(data) == value
}
func unique(err error) bool {
	value, ok := errors.AsType[*host.Error](err)
	return ok && value.Code == "23505"
}

var emailFormat = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

func normalizeEmail(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if !utf8.ValidString(value) || strings.ContainsRune(value, 0) || len(value) > 320 || !emailFormat.MatchString(value) {
		return "", fail(400, "invalid_input")
	}
	return value, nil
}

func (auth *Auth) rateLimit(action, email string) error {
	key := private.AppAuthRateLimitsPrimaryKey{Action: action, KeyHash: digest(email)}
	repo := auth.db.AppAuthRateLimits
	fields := repo.Columns()
	for range 4 {
		row, err := repo.FindByID(key)
		if err != nil {
			return err
		}
		if row == nil {
			_, err = repo.Insert(private.AppAuthRateLimitsInsert{Action: action, KeyHash: key.KeyHash, AttemptCount: 1, ExpiresAt: timestamp(time.Now().Add(900 * time.Second))})
			if err == nil {
				return nil
			}
			if !unique(err) {
				return err
			}
			continue
		}
		ended, err := expired(row.ExpiresAt)
		if err != nil {
			return err
		}
		if !ended && row.AttemptCount >= 10 {
			return fail(429, "rate_limited")
		}
		count, until := row.AttemptCount+1, row.ExpiresAt
		if ended {
			count = 1
			until = timestamp(time.Now().Add(900 * time.Second))
		}
		updated, err := repo.UpdateIf(key, orm.And(fields.AttemptCount.Equal(row.AttemptCount), fields.ExpiresAt.Equal(row.ExpiresAt)), private.AppAuthRateLimitsUpdate{AttemptCount: set(count), ExpiresAt: set(until)})
		if err != nil {
			return err
		}
		if updated != nil {
			return nil
		}
	}
	return fail(429, "rate_limited")
}

const (
	accessLifetime        = 15 * time.Minute
	refreshFamilyLifetime = 7 * 24 * time.Hour
)

func tokenExpirations(issued time.Time, family string) (string, string) {
	if family == "" {
		family = timestamp(issued.Add(refreshFamilyLifetime))
	}
	return timestamp(issued.Add(accessLifetime)), family
}

func issue(db *private.Database, user private.AppAuthUsersRow) (Tokens, error) {
	access, err := token()
	if err != nil {
		return Tokens{}, err
	}
	refresh, err := token()
	if err != nil {
		return Tokens{}, err
	}
	issued := time.Now()
	until, family := tokenExpirations(issued, "")
	session, err := db.AppAuthSessions.Insert(private.AppAuthSessionsInsert{UserID: user.ID, TokenHash: digest(access), UserSessionVersion: user.SessionVersion, ExpiresAt: until, Transport: set("native")})
	if err != nil {
		return Tokens{}, err
	}
	refreshRow, err := db.AppAuthRefreshTokens.Insert(private.AppAuthRefreshTokensInsert{SessionID: session.ID, TokenHash: digest(refresh), ExpiresAt: family})
	return Tokens{access, refresh, session.ExpiresAt, refreshRow.ExpiresAt, user.ID, session.ID}, err
}

func (auth *Auth) signup(email, password string) (Tokens, error) {
	if err := auth.rateLimit("signup", email); err != nil {
		return Tokens{}, err
	}
	stored, err := hashPassword(password)
	if err != nil {
		return Tokens{}, err
	}
	var result Tokens
	var public User
	err = auth.connection.Transaction(func(connection *database.Connection) error {
		db := private.New(connection)
		user, err := db.AppAuthUsers.Insert(private.AppAuthUsersInsert{Email: email, PasswordHash: set(stored)})
		if unique(err) {
			return fail(409, "account_exists")
		}
		if err != nil {
			return err
		}
		public = User{user.ID, user.Email, user.CreatedAt}
		if auth.hooks.UserCreating != nil {
			if err := runHook("user_creation_failed", func() error { return auth.hooks.UserCreating(connection, public) }); err != nil {
				return err
			}
		}
		result, err = issue(db, user)
		return err
	})
	if err != nil {
		return Tokens{}, err
	}
	if auth.hooks.UserCreated != nil {
		if err := runHook("user_created_effect_failed", func() error { return auth.hooks.UserCreated(public) }); err != nil {
			return Tokens{}, err
		}
	}
	return result, nil
}

func (auth *Auth) signin(email, password string) (Tokens, error) {
	if err := auth.rateLimit("signin", email); err != nil {
		return Tokens{}, err
	}
	repo := auth.db.AppAuthUsers
	rows, err := repo.FindMany(orm.FindMany{Where: repo.Columns().Email.Equal(email), Limit: new(int32(1))})
	if err != nil {
		return Tokens{}, err
	}
	var stored *string
	if len(rows) > 0 {
		stored = rows[0].PasswordHash
	}
	matched, err := verifyPassword(password, stored)
	if err != nil {
		return Tokens{}, err
	}
	if !matched || len(rows) == 0 || rows[0].DisabledAt != nil {
		return Tokens{}, fail(401, "invalid_credentials")
	}
	var result Tokens
	err = auth.db.Transaction(func(db *private.Database) error { var err error; result, err = issue(db, rows[0]); return err })
	return result, err
}

// Session validates a provided bearer; it never falls back to anonymous access.
func (auth *Auth) Session(authorization *string) (*server.Session, error) {
	if authorization == nil {
		return nil, nil
	}
	bearer, ok := strings.CutPrefix(*authorization, "Bearer ")
	if !ok || !validToken(bearer) {
		return nil, fail(401, "invalid_token")
	}
	repo := auth.db.AppAuthSessions
	rows, err := repo.FindMany(orm.FindMany{Where: repo.Columns().TokenHash.Equal(digest(bearer)), Limit: new(int32(1))})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 || rows[0].RevokedAt != nil || rows[0].Transport != "native" {
		return nil, fail(401, "invalid_token")
	}
	row := rows[0]
	ended, err := expired(row.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if ended {
		return nil, fail(401, "invalid_token")
	}
	user, err := auth.db.AppAuthUsers.FindByID(private.AppAuthUsersPrimaryKey{ID: row.UserID})
	if err != nil {
		return nil, err
	}
	if user == nil || user.DisabledAt != nil || user.SessionVersion != row.UserSessionVersion {
		return nil, fail(401, "invalid_token")
	}
	return &server.Session{ID: row.ID, User: server.User{ID: user.ID, Email: user.Email}}, nil
}

func (auth *Auth) refresh(value string) (Tokens, error) {
	if !validToken(value) {
		return Tokens{}, fail(401, "invalid_token")
	}
	repo := auth.db.AppAuthRefreshTokens
	rows, err := repo.FindMany(orm.FindMany{Where: repo.Columns().TokenHash.Equal(digest(value)), Limit: new(int32(1))})
	if err != nil {
		return Tokens{}, err
	}
	if len(rows) == 0 {
		return Tokens{}, fail(401, "invalid_token")
	}
	candidate := rows[0]
	var result Tokens
	revoked := false
	err = auth.db.Transaction(func(db *private.Database) error {
		sessions := db.AppAuthSessions
		session, err := sessions.UpdateIf(private.AppAuthSessionsPrimaryKey{ID: candidate.SessionID}, sessions.Columns().RevokedAt.IsNull(), private.AppAuthSessionsUpdate{RevokedAt: null[string]()})
		if err != nil {
			return err
		}
		if session == nil || session.Transport != "native" {
			revoked = true
			return nil
		}
		current, err := db.AppAuthRefreshTokens.FindByID(private.AppAuthRefreshTokensPrimaryKey{ID: candidate.ID})
		if err != nil {
			return err
		}
		user, err := db.AppAuthUsers.FindByID(private.AppAuthUsersPrimaryKey{ID: session.UserID})
		if err != nil {
			return err
		}
		invalid := current == nil || current.ConsumedAt != nil || user == nil || user.DisabledAt != nil || user.SessionVersion != session.UserSessionVersion
		if current != nil {
			ended, err := expired(current.ExpiresAt)
			if err != nil {
				return err
			}
			invalid = invalid || ended
		}
		revoke := func() error {
			revoked = true
			_, err := sessions.Update(private.AppAuthSessionsPrimaryKey{ID: session.ID}, private.AppAuthSessionsUpdate{RevokedAt: set(now())})
			return err
		}
		if invalid {
			return revoke()
		}
		consumed, err := db.AppAuthRefreshTokens.UpdateIf(private.AppAuthRefreshTokensPrimaryKey{ID: current.ID}, repo.Columns().ConsumedAt.IsNull(), private.AppAuthRefreshTokensUpdate{ConsumedAt: set(now())})
		if err != nil {
			return err
		}
		if consumed == nil {
			return revoke()
		}
		access, err := token()
		if err != nil {
			return err
		}
		refresh, err := token()
		if err != nil {
			return err
		}
		until, _ := tokenExpirations(time.Now(), current.ExpiresAt)
		updated, updateErr := sessions.Update(private.AppAuthSessionsPrimaryKey{ID: session.ID}, private.AppAuthSessionsUpdate{TokenHash: set(digest(access)), ExpiresAt: set(until)})
		err = updateErr
		if err != nil {
			return err
		}
		_, err = db.AppAuthRefreshTokens.Insert(private.AppAuthRefreshTokensInsert{SessionID: session.ID, TokenHash: digest(refresh), ExpiresAt: current.ExpiresAt})
		result = Tokens{access, refresh, updated.ExpiresAt, current.ExpiresAt, user.ID, session.ID}
		return err
	})
	if err != nil {
		return Tokens{}, err
	}
	if revoked {
		return Tokens{}, fail(401, "session_revoked")
	}
	return result, nil
}

// Handle validates the selected built-in operation before accessing authentication data.
func (auth *Auth) Handle(request server.Request, emailPassword bool) (any, error) {
	var result any
	var err error
	switch request.Path {
	case "/auth.signup", "/auth.signin":
		if !emailPassword {
			return nil, fail(404, "operation_not_found")
		}
		var input struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err = server.DecodeInput(request.Body, []string{"email", "password"}, &input); err != nil {
			return nil, err
		}
		var email string
		email, err = normalizeEmail(input.Email)
		if err != nil {
			return nil, err
		}
		if err = validatePassword(input.Password); err != nil {
			return nil, err
		}
		if request.Path == "/auth.signup" {
			result, err = auth.signup(email, input.Password)
		} else {
			result, err = auth.signin(email, input.Password)
		}
	case "/auth.refresh":
		var input struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err = server.DecodeInput(request.Body, []string{"refresh_token"}, &input); err != nil {
			return nil, err
		}
		result, err = auth.refresh(input.RefreshToken)
	case "/auth.identity":
		var input struct {
			Provider   string `json:"provider"`
			Credential string `json:"credential"`
		}
		if err = server.DecodeInput(request.Body, []string{"provider", "credential"}, &input); err != nil {
			return nil, err
		}
		return nil, fail(400, "unsupported_identity_provider")
	case "/auth.session", "/auth.logout":
		if err = server.DecodeInput(request.Body, nil, &struct{}{}); err != nil {
			return nil, err
		}
		session, err := auth.Session(request.Authorization)
		if err != nil {
			return nil, err
		}
		if session == nil {
			return nil, fail(401, "unauthenticated")
		}
		if request.Path == "/auth.session" {
			return map[string]string{"id": session.User.ID, "email": session.User.Email, "session_id": session.ID}, nil
		}
		_, err = auth.db.AppAuthSessions.UpdateIf(private.AppAuthSessionsPrimaryKey{ID: session.ID}, auth.db.AppAuthSessions.Columns().RevokedAt.IsNull(), private.AppAuthSessionsUpdate{RevokedAt: set(now())})
		return map[string]string{"status": "signed_out"}, err
	default:
		return nil, fail(404, "operation_not_found")
	}
	if err != nil {
		return nil, err
	}
	if err := auth.cleanup(now()); err != nil {
		recordCleanup("failed")
		_ = request.Log("warn", "Authentication cleanup failed.")
	}
	return result, nil
}

func runHook(code string, run func() error) (err error) {
	defer func() {
		if recover() != nil {
			err = fail(500, code)
		}
	}()
	if run() != nil {
		return fail(500, code)
	}
	return nil
}
