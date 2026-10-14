package driver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	chik "github.com/chickinfry/chickinfry-go"
)

func TestInvalidRequestIDIsNeverEchoed(t *testing.T) {
	for name, id := range map[string]string{"space": "c:bad id", "reverse-space": "d:bad id", "unicode": "c:한글", "over-limit": "c:" + strings.Repeat("x", 255)} {
		t.Run(name, func(t *testing.T) {
			control := strings.Replace(hello, "c:hello", id, 1)
			var stdout bytes.Buffer
			err := Run(t.Context(), strings.NewReader(control), &stdout, strings.NewReader(""), nil)
			e, ok := errors.AsType[*Error](err)
			if !ok || *e.Code != "protocol_violation" || stdout.Len() != 0 {
				t.Fatal("invalid envelope ID accepted or echoed")
			}
		})
	}
	id := "c:" + strings.Repeat("x", 254)
	results, err := execute(t, strings.Replace(hello, "c:hello", id, 1), "", nil)
	if err != nil || len(results) != 1 || results[0].ID != id {
		t.Fatal("256-character ID rejected")
	}
}

func TestStdoutRejectsEncodedCredentials(t *testing.T) {
	secret := "sensitive-credential-?ÿ"
	patterns := []string{secret, base64.StdEncoding.EncodeToString([]byte(secret)), base64.RawStdEncoding.EncodeToString([]byte(secret)), base64.URLEncoding.EncodeToString([]byte(secret)), base64.RawURLEncoding.EncodeToString([]byte(secret)), hex.EncodeToString([]byte(secret)), strings.ToUpper(hex.EncodeToString([]byte(secret)))}
	for i, pattern := range patterns {
		for _, path := range []string{"key", "nested", "error", "escaped", "large-number"} {
			t.Run(fmt.Sprintf("representation-%d/%s", i, path), func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var stdout bytes.Buffer
				s := &server{writer: &stdout, ctx: ctx, cancel: cancel, credentials: &credentials{values: map[string]string{"registered": secret}}}
				var result any
				var e *Error
				switch path {
				case "key":
					result = map[string]any{"prefix" + pattern + "suffix": "ordinary"}
				case "nested":
					result = map[string]any{"values": []any{map[string]any{"value": "prefix" + pattern + "suffix"}}}
				case "error":
					e = failure("sdk", pattern)
				case "large-number":
					encoded, _ := json.Marshal(pattern)
					result = json.RawMessage(`{"number":1e999,"value":` + string(encoded) + `}`)
				case "escaped":
					var escaped strings.Builder
					escaped.WriteByte('"')
					for _, r := range pattern {
						fmt.Fprintf(&escaped, `\u%04x`, r)
					}
					escaped.WriteByte('"')
					result = json.RawMessage(escaped.String())
				}
				s.reply("c:call", result, e)
				var reply response
				if json.Unmarshal(stdout.Bytes(), &reply) != nil || reply.Error == nil || reply.Error.Code == nil || *reply.Error.Code != "driver_failed" || reply.Result != nil {
					t.Fatal("credential representation crossed the stdout boundary")
				}
				for _, forbidden := range patterns {
					if strings.Contains(stdout.String(), forbidden) {
						t.Fatal("credential representation leaked in fallback output")
					}
				}
			})
		}
	}
}

func TestOversizedResultReturnsBoundedErrorWithSameID(t *testing.T) {
	control := hello + command("c:client", "client.create", map[string]any{"clientRef": "client", "origin": "https://example.test", "fixture": "plain", "requestTimeoutMs": 1000}) +
		command("c:call", "client.call", map[string]any{"clientRef": "client", "operation": "probe.echo", "input": map[string]any{}})
	var stdout bytes.Buffer
	err := Run(t.Context(), strings.NewReader(control), &stdout, strings.NewReader(""), func(context.Context, *chik.HTTP, string, json.RawMessage) (any, error) {
		return map[string]any{"value": strings.Repeat("x", MaxLineBytes)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(stdout.Bytes()), []byte{'\n'})
	if len(lines) != 3 {
		t.Fatal("missing protocol response")
	}
	for _, line := range lines {
		if len(line)+1 > MaxLineBytes || !json.Valid(line) {
			t.Fatal("invalid or oversized stdout line")
		}
	}
	var result response
	if json.Unmarshal(lines[2], &result) != nil || result.ID != "c:call" || result.Result != nil || result.Error == nil || *result.Error.Code != "driver_failed" {
		t.Fatal("oversized output did not preserve the ID in a bounded error")
	}
}

type failingWriter struct {
	short  bool
	writes int
}

func (w *failingWriter) Write(line []byte) (int, error) {
	w.writes++
	if w.short {
		return len(line) - 1, nil
	}
	return 0, errors.New("sensitive I/O details")
}

func TestStdoutFailureStopsFurtherWrites(t *testing.T) {
	for _, short := range []bool{false, true} {
		name := "error"
		if short {
			name = "short-write"
		}
		t.Run(name, func(t *testing.T) {
			writer := &failingWriter{short: short}
			control := hello + command("c:unknown", "unknown", map[string]any{})
			err := Run(t.Context(), strings.NewReader(control), writer, strings.NewReader(""), nil)
			failure, ok := errors.AsType[*Error](err)
			if !ok || failure.Code == nil || *failure.Code != "driver_failed" || writer.writes != 1 {
				t.Fatal("stdout failure was lost or another write was attempted")
			}
			if strings.Contains(err.Error(), "sensitive") {
				t.Fatal("raw write error leaked")
			}
		})
	}
}

func TestJSONNestingLimit(t *testing.T) {
	for _, depth := range []int{1000, 1001} {
		data := []byte(strings.Repeat("[", depth) + "0" + strings.Repeat("]", depth))
		err := validateJSON(data)
		if depth == 1000 && err != nil {
			t.Fatal("at-limit JSON nesting rejected")
		}
		if depth == 1001 && err == nil {
			t.Fatal("excessive JSON nesting accepted")
		}
	}
}
