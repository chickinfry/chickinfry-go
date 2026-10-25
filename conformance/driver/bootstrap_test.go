package driver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chickinfry/chickinfry-go"
)

func TestCredentialBootstrapLimits(t *testing.T) {
	row := func(ref string, size int) string {
		encoded, _ := json.Marshal(map[string]string{"ref": ref, "value": "x"})
		encoded, _ = json.Marshal(map[string]string{"ref": ref, "value": strings.Repeat("x", size-len(encoded))})
		return string(encoded) + "\n"
	}
	var complete strings.Builder
	for i := range 16 {
		complete.WriteString(row(fmt.Sprintf("r%d", i), maxCredentialLine))
	}
	if complete.Len() != maxCredentialBytes {
		t.Fatal("bootstrap is not exactly at total limit")
	}
	for name, input := range map[string]string{
		"line at limit":  row("ref", maxCredentialLine),
		"total at limit": complete.String(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadCredentials(strings.NewReader(input)); err != nil {
				t.Fatal("valid boundary rejected")
			}
		})
	}
	for name, input := range map[string]string{
		"line over limit":     row("ref", maxCredentialLine+1),
		"total over limit":    complete.String() + row("extra", 40),
		"duplicate reference": protectedTokens() + protectedTokens(),
		"unknown field":       "{\"ref\":\"ref\",\"value\":\"value\",\"extra\":true}\n",
		"duplicate key":       "{\"ref\":\"first\",\"ref\":\"second\",\"value\":\"value\"}\n",
		"truncated":           "{\"ref\":\"ref\",\"value\":\"value\"}",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadCredentials(strings.NewReader(input))
			e, ok := errors.AsType[*Error](err)
			if !ok || *e.Code != "protocol_violation" {
				t.Fatal("invalid protected bootstrap accepted")
			}
		})
	}
}

func TestNilProtectedInputIsRejectedBeforeHandshake(t *testing.T) {
	var output strings.Builder
	err := Run(t.Context(), strings.NewReader(hello), &output, nil, nil)
	e, ok := errors.AsType[*Error](err)
	if !ok || *e.Code != "driver_failed" || output.Len() != 0 {
		t.Fatal("missing protected pipe accepted")
	}
}

func TestCreateRejectsStoreAndBearerTogether(t *testing.T) {
	for _, values := range [][2]string{{"store", "access"}, {"", "access"}, {"store", ""}, {"", ""}} {
		control := hello + command("c:create", "client.create", map[string]any{"clientRef": "client", "origin": "https://example.test", "fixture": "plain", "requestTimeoutMs": 1000, "storeRef": values[0], "bearerRef": values[1]})
		results, err := execute(t, control, protectedTokens(), nil)
		if err != nil || len(results) != 2 || results[1].Error == nil || *results[1].Error.Code != "invalid_args" {
			t.Fatal("mixed authentication bindings accepted")
		}
	}
}

func TestClientCopyUsesBearerWithoutChangingSource(t *testing.T) {
	observed := make(chan string, 2)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer " + strings.Repeat("A", 43):
			observed <- "signed"
		case "":
			observed <- "anonymous"
		default:
			observed <- "unexpected"
		}
		json.NewEncoder(w).Encode(map[string]string{"wire_value": "ok", "observed_at": "unchanged"})
	}))
	defer peer.Close()
	create := hello + command("c:create", "client.create", map[string]any{"clientRef": "base", "origin": peer.URL, "fixture": "plain", "requestTimeoutMs": 1000}) +
		command("c:copy", "client.copy", map[string]any{"sourceClientRef": "base", "clientRef": "signed", "bearerRef": "access"})
	control := create + command("c:signed", "client.call", map[string]any{"clientRef": "signed", "operation": "probe.echo", "input": map[string]any{}}) +
		command("c:base", "client.call", map[string]any{"clientRef": "base", "operation": "probe.echo", "input": map[string]any{}})
	results, err := execute(t, control, protectedTokens(), runtimeCall)
	if err != nil || len(results) != 5 {
		t.Fatal("copy or call failed")
	}
	for _, r := range results {
		if r.Error != nil {
			t.Fatal("copy or call failed")
		}
	}
	counts := map[string]int{}
	for range 2 {
		counts[<-observed]++
	}
	if counts["signed"] != 1 || counts["anonymous"] != 1 {
		t.Fatal("copy changed source authentication")
	}
}

func TestClientFixtureIsExplicitAndCopyPreservesIt(t *testing.T) {
	for _, fixture := range []string{"", "plain", "auth", "unknown"} {
		t.Run("fixture="+fixture, func(t *testing.T) {
			args := map[string]any{"clientRef": "client", "origin": "https://example.test", "requestTimeoutMs": 1000}
			if fixture != "" {
				args["fixture"] = fixture
			}
			control := hello + command("c:create", "client.create", args)
			if fixture == "unknown" || fixture == "" {
				results, err := execute(t, control, "", nil)
				if err != nil || *results[1].Error.Code != "invalid_args" {
					t.Fatal("unsupported fixture accepted")
				}
				return
			}
			control += command("c:copy", "client.copy", map[string]any{"sourceClientRef": "client", "clientRef": "copy", "bearerRef": "access"}) +
				command("c:call", "client.call", map[string]any{"clientRef": "copy", "operation": "probe.echo", "input": map[string]any{}})
			selected := ""
			results, err := execute(t, control, protectedTokens(), func(ctx context.Context, _ *chickinfry.HTTPTransport, _ string, _ json.RawMessage) (any, error) {
				selected = Fixture(ctx)
				return map[string]any{}, nil
			})
			want := fixture
			if err != nil || len(results) != 4 || selected != want {
				t.Fatal("fixture lost or inferred from the operation")
			}
		})
	}
}

func TestHandshakeAcceptsExactNativeTarget(t *testing.T) {
	control := strings.Replace(hello, `"runId":"run"`, `"runId":"run","target":{"language":"go","role":"sdk","environment":"native"}`, 1)
	results, err := execute(t, control, "", nil)
	if err != nil || len(results) != 1 || results[0].Error != nil {
		t.Fatal("coordinator target rejected")
	}
	_, err = execute(t, strings.Replace(control, `"language"`, `"LANGUAGE"`, 1), "", nil)
	e, ok := errors.AsType[*Error](err)
	if !ok || *e.Code != "protocol_violation" {
		t.Fatal("case-variant target field accepted")
	}
}

func TestReferenceGrammarAtEveryInputBoundary(t *testing.T) {
	commands := map[string]map[string]any{
		"client.create":        {"clientRef": "client", "origin": "https://example.test", "fixture": "plain", "requestTimeoutMs": 1000},
		"client.copy":          {"sourceClientRef": "base", "clientRef": "copy", "bearerRef": "access"},
		"client.call":          {"clientRef": "base", "operation": "probe.echo", "input": map[string]any{}, "inputRefs": map[string]string{}, "outputRefs": map[string]string{}},
		"session.store.create": {"storeRef": "store", "origin": "https://example.test", "accessRef": "access", "refreshRef": "refresh", "recordRef": "record"},
		"session.store.write":  {"storeRef": "store", "accessRef": "access", "refreshRef": "refresh", "recordRef": "record"},
		"session.store.read":   {"storeRef": "store"},
		"barrier.arm":          {"barrierRef": "barrier", "point": "sdk-entered", "participants": []string{"c:call"}},
	}
	prefix := hello + command("c:base", "client.create", map[string]any{"clientRef": "base", "origin": "https://example.test", "fixture": "plain", "requestTimeoutMs": 1000})
	for name, ref := range map[string]string{"space": "bad ref", "unicode": "\uD55C\uAE00", "leading-punctuation": ":bad", "empty": "", "over-limit": strings.Repeat("x", 257)} {
		t.Run(name, func(t *testing.T) {
			row, _ := json.Marshal(map[string]string{"ref": ref, "value": "protected-value"})
			if _, err := loadCredentials(strings.NewReader(string(row) + "\n")); err == nil {
				t.Fatal("invalid bootstrap reference accepted")
			}
			for cmd, original := range commands {
				for key := range original {
					values := maps.Clone(original)
					switch key {
					case "clientRef", "sourceClientRef", "storeRef", "bearerRef", "accessRef", "refreshRef", "recordRef", "barrierRef":
						values[key] = ref
					case "inputRefs", "outputRefs":
						values[key] = map[string]string{"field": ref}
					case "participants":
						values[key] = []string{ref}
					default:
						continue
					}
					results, err := execute(t, prefix+command("c:check", cmd, values), protectedTokens(), nil)
					if err != nil || len(results) != 3 || results[2].Error == nil || *results[2].Error.Code != "invalid_args" {
						t.Fatal("invalid argument reference accepted")
					}
				}
			}
		})
	}
	ref := "a" + strings.Repeat(":._/-0Z", 36) + "xyz"
	if len(ref) != 256 {
		t.Fatal("incorrect reference boundary fixture")
	}
	row, _ := json.Marshal(map[string]string{"ref": ref, "value": "protected-value"})
	if _, err := loadCredentials(strings.NewReader(string(row) + "\n")); err != nil {
		t.Fatal("valid 256-character reference rejected")
	}
	results, err := execute(t, hello+command("c:create", "client.create", map[string]any{"clientRef": ref, "origin": "https://example.test", "fixture": "plain", "requestTimeoutMs": 1000}), "", nil)
	if err != nil || len(results) != 2 || results[1].Error != nil {
		t.Fatal("valid client reference rejected")
	}
	if _, _, e := (&credentials{values: map[string]string{}}).output(map[string]any{"field": "output-value"}, map[string]string{"field": ref}); e != nil {
		t.Fatal("valid output reference rejected")
	}
}

func TestOutputRegistrationRejectsIdenticalDuplicates(t *testing.T) {
	for name, requested := range map[string]map[string]string{"registered": {"first": "existing"}, "within-request": {"first": "fresh", "second": "fresh"}} {
		t.Run(name, func(t *testing.T) {
			c := &credentials{values: map[string]string{"existing": "same-protected-value"}}
			_, _, e := c.output(map[string]any{"first": "same-protected-value", "second": "same-protected-value"}, requested)
			if e == nil || *e.Code != "invalid_reference" || len(c.values) != 1 {
				t.Fatal("duplicate output registration accepted or partially committed")
			}
			if ref := c.reference("same-protected-value"); ref == nil || *ref != "existing" {
				t.Fatal("registered value lookup changed")
			}
		})
	}
}

func TestRefreshHTTPStatusDoesNotResolveUnknownOutcome(t *testing.T) {
	for _, status := range []int{429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var token [32]byte
			rand.Read(token[:])
			// Unknown refresh outcomes retain a token fingerprint across stores and runs.
			access, refresh := strings.Repeat("E", 43), base64.RawURLEncoding.EncodeToString(token[:])
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/auth.refresh" {
					w.WriteHeader(status)
					io.WriteString(w, `{"error":"unavailable"}`)
					return
				}
				w.WriteHeader(401)
				io.WriteString(w, `{"error":"invalid_token"}`)
			}))
			defer peer.Close()
			transport, err := chickinfry.NewHTTPTransport(peer.URL)
			if err != nil {
				t.Fatal("runtime transport construction failed")
			}
			store := &chickinfry.MemoryStore{}
			if err := store.Set(chickinfry.SessionCredentials{AccessToken: access, RefreshToken: refresh, ExpiresAt: "2099-01-01T00:00:00Z", RefreshExpiresAt: "2099-02-01T00:00:00Z", UserID: "user", SessionID: "session"}); err != nil {
				t.Fatal("runtime store setup failed")
			}
			transport, err = transport.WithSession(store)
			if err != nil {
				t.Fatal("runtime session construction failed")
			}
			var output map[string]any
			err = transport.Invoke(t.Context(), "probe.echo", map[string]any{}, &output)
			got := normalize(err)
			if err == nil || got.HTTPStatus == nil || *got.HTTPStatus != status || got.OutcomeUnknown != nil {
				t.Fatal("refresh status fabricated a resolved runtime outcome")
			}
			encoded, _ := json.Marshal(got)
			if !strings.Contains(string(encoded), `"outcomeUnknown":null`) {
				t.Fatal("unobservable outcome was not encoded as null")
			}
		})
	}
}

func TestRevision3FieldsRejectInvalidValues(t *testing.T) {
	for _, value := range []any{"", nil, 3, true} {
		results, err := execute(t, hello+command("c:create", "client.create", map[string]any{
			"clientRef": "client", "origin": "https://example.test", "requestTimeoutMs": 1000, "fixture": value,
		}), "", nil)
		if err != nil || len(results) != 2 || results[1].Error == nil || *results[1].Error.Code != "invalid_args" {
			t.Fatalf("invalid fixture accepted: %v", value)
		}
	}
	for name, values := range map[string]map[string]any{
		"missing call":         {"afterSequence": 0},
		"null call":            {"callId": nil, "afterSequence": 0},
		"empty call":           {"callId": "", "afterSequence": 0},
		"malformed call":       {"callId": "c:bad ref", "afterSequence": 0},
		"wrong direction":      {"callId": "d:call", "afterSequence": 0},
		"empty suffix":         {"callId": "c:", "afterSequence": 0},
		"numeric call":         {"callId": 3, "afterSequence": 0},
		"missing watermark":    {"callId": "c:call"},
		"null watermark":       {"callId": "c:call", "afterSequence": nil},
		"negative watermark":   {"callId": "c:call", "afterSequence": -1},
		"fractional watermark": {"callId": "c:call", "afterSequence": 0.5},
		"string watermark":     {"callId": "c:call", "afterSequence": "0"},
		"overflow watermark":   {"callId": "c:call", "afterSequence": json.RawMessage("18446744073709551616")},
	} {
		t.Run(name, func(t *testing.T) {
			results, err := execute(t, hello+command("c:observe", "client.observe", values), "", nil)
			if err != nil || len(results) != 2 || results[1].Error == nil || *results[1].Error.Code != "invalid_args" {
				t.Fatalf("invalid observation args accepted: %+v, %v", results, err)
			}
		})
	}
	for _, field := range []string{"callID", "AfterSequence", "extra"} {
		values := map[string]any{"callId": "c:call", "afterSequence": 0, field: 0}
		_, err := execute(t, hello+command("c:observe", "client.observe", values), "", nil)
		e, ok := errors.AsType[*Error](err)
		if !ok || *e.Code != "protocol_violation" {
			t.Fatal("unknown or case-variant observation field accepted")
		}
	}
	results, err := execute(t, hello+command("c:observe", "client.observe", map[string]any{"callId": "c:call", "afterSequence": 0}), "", nil)
	want := "unimplemented"
	if supportsTransport() {
		want = "driver"
	}
	if err != nil || results[1].Error == nil || results[1].Error.Kind != want {
		t.Fatal("unavailable transport observations fabricated")
	}
}
