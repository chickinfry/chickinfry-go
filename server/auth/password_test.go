package auth

import (
	"strings"
	"testing"
)

const passwordVector = "scrypt$32768$8$3$00000000000000000000000000000000$5bfe0288362511a467ab22d2e7756cf7c4af8a82aecedbf80a5e68c478a48807"

func TestPasswordCostAndUnicode(t *testing.T) {
	for _, test := range []struct {
		name     string
		stored   *string
		password string
		want     bool
	}{
		{"vector", new(passwordVector), "public test vector", true},
		{"mismatch", new(passwordVector), "different test vector", false},
		{"absent", nil, "public test vector", false},
		{"corrupt", new("scrypt$2$8$3$00$00"), "public test vector", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			matched, err := verifyPassword(test.password, test.stored)
			if err != nil || matched != test.want {
				t.Fatalf("verification matched=%t error=%v", matched, err)
			}
		})
	}
	for _, test := range []struct {
		password string
		valid    bool
	}{
		{strings.Repeat("界", 14), false}, {strings.Repeat("界", 15), true},
		{strings.Repeat("x", 1024), true}, {strings.Repeat("x", 1025), false},
		{string([]byte{0xff}) + strings.Repeat("x", 15), false},
	} {
		if (validatePassword(test.password) == nil) != test.valid {
			t.Fatalf("Unicode/byte boundary bytes=%d", len(test.password))
		}
	}
	hashed, err := hashPassword("public test vector")
	if err != nil || !passwordFormat.MatchString(hashed) {
		t.Fatal("password storage format")
	}
	if hashed == passwordVector {
		t.Fatal("hashing reused the vector salt")
	}
}
