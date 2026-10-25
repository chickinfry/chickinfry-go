package auth

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/chickinfry/chickinfry-go/server"
)

func TestEmailCorpus(t *testing.T) {
	const sourceCommit = "1365d4ca9e962b87374741417fefb50ae665b915"
	const sourceSHA256 = "26e5f184b31eca32b1cbac279fb59d9042610ec15ef92f13bbf5f595ff809595"
	data, err := os.ReadFile("testdata/emails.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != sourceSHA256 {
		t.Fatalf("corpus differs from the pinned shared email corpus (commit %s): SHA-256 %s, want %s", sourceCommit, got, sourceSHA256)
	}
	t.Logf("pinned shared email corpus commit %s; SHA-256 %s", sourceCommit, sourceSHA256)
	if path, ok := os.LookupEnv("CHIK_EMAIL_CORPUS"); ok {
		data, err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	var cases []struct {
		Name       string  `json:"name"`
		Input      string  `json:"input"`
		Normalized *string `json:"normalized"`
		Error      string  `json:"error"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("email corpus is empty")
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			got, err := normalizeEmail(c.Input)
			if c.Normalized != nil {
				if c.Error != "" || err != nil || got != *c.Normalized {
					t.Fatalf("normalizeEmail(%q) = %q, %v; want %q", c.Input, got, err, *c.Normalized)
				}
				if again, err := normalizeEmail(got); err != nil || again != got {
					t.Fatalf("normalized email is not a fixed point: %q, %v", again, err)
				}
				return
			}
			failure, ok := errors.AsType[*server.OperationError](err)
			if c.Error != "invalid_input" || !ok || failure.Status != 400 || failure.Code != c.Error || got != "" {
				t.Fatalf("normalizeEmail(%q) = %q, %v; want 400 invalid_input", c.Input, got, err)
			}
		})
	}
	t.Logf("validated %d email normalization cases", len(cases))
}

func TestEmailSigmaContext(t *testing.T) {
	for _, c := range []struct{ input, want string }{
		{"A.Σ@example.test", "a.ς@example.test"},
		{"AΣ’A@example.test", "aσ’a@example.test"},
		{"\u2160Σ@example.test", "\u2170ς@example.test"},
		{"\u24d0Σ@example.test", "\u24d0ς@example.test"},
		{"\u0345Σ@example.test", "\u0345σ@example.test"},
		{"AΣ\u0345@example.test", "aς\u0345@example.test"},
		{"AΣ\u0345A@example.test", "aσ\u0345a@example.test"},
		{"A1Σ@example.test", "a1σ@example.test"},
	} {
		t.Run(c.input, func(t *testing.T) {
			got, err := normalizeEmail(c.input)
			if err != nil || got != c.want {
				t.Fatalf("normalizeEmail(%q) = %q, %v; want %q", c.input, got, err, c.want)
			}
		})
	}
}

func TestEmailRejectsInvalidUTF8(t *testing.T) {
	_, err := normalizeEmail("\xff@example.test")
	failure, ok := errors.AsType[*server.OperationError](err)
	if !ok || failure.Status != 400 || failure.Code != "invalid_input" {
		t.Fatalf("invalid UTF-8 email: %v; want 400 invalid_input", err)
	}
}
