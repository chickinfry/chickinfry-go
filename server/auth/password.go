package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"regexp"
	"unicode/utf8"

	"github.com/chickinfry/chickinfry-go/server"
	"golang.org/x/crypto/scrypt"
)

var passwordFormat = regexp.MustCompile(`^scrypt\$32768\$8\$3\$([a-f0-9]{32})\$([a-f0-9]{64})$`)

func validatePassword(password string) error {
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < 15 || len(password) > 1024 {
		return &server.Error{Status: 400, Code: "invalid_input"}
	}
	return nil
}

func derive(password string, salt []byte) ([]byte, error) {
	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 3, 32)
	recordKDF(32768, 8, 3, len(salt), 32, err == nil)
	return key, err
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := derive(password, salt)
	if err != nil {
		return "", err
	}
	return "scrypt$32768$8$3$" + hex.EncodeToString(salt) + "$" + hex.EncodeToString(key), nil
}

func verifyPassword(password string, stored *string) (bool, error) {
	salt, expected := make([]byte, 16), make([]byte, 32)
	var parts []string
	if stored != nil {
		parts = passwordFormat.FindStringSubmatch(*stored)
	}
	if parts != nil {
		salt, _ = hex.DecodeString(parts[1])
		expected, _ = hex.DecodeString(parts[2])
	}
	actual, err := derive(password, salt)
	if err != nil {
		return false, err
	}
	matched := subtle.ConstantTimeCompare(actual, expected)
	return parts != nil && matched == 1, nil
}
