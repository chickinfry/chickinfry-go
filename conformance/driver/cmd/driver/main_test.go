//go:build chik_conformance

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	chik "github.com/chickinfry/chickinfry-go"
	"github.com/chickinfry/chickinfry-go/conformance/driver"
)

func TestGeneratedFixtureBridges(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/probe.echo":
			io.WriteString(w, `{"wire_value":"ok","observed_at":"2026-01-02T03:04:05.123456Z"}`)
		case "/probe.list":
			io.WriteString(w, `{"rows":[]}`)
		case "/auth.refresh":
			json.NewEncoder(w).Encode(map[string]string{"access_token": strings.Repeat("A", 43), "refresh_token": strings.Repeat("B", 43), "expires_at": "later", "refresh_expires_at": "later", "user_id": "user", "session_id": "session"})
		default:
			t.Error("unexpected generated operation")
		}
	}))
	defer peer.Close()
	transport, err := chik.NewHTTP(peer.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []string{"plain", "auth"} {
		invoke := callPlain
		if fixture == "auth" {
			invoke = callAuth
		}
		for _, op := range []string{"probe.echo", "probe.list", "auth.refresh"} {
			result, err := invoke(t.Context(), transport, op, json.RawMessage(`{"wire_value":"ok","refresh_token":"input"}`))
			if fixture == "plain" && op == "auth.refresh" {
				e, ok := errors.AsType[*driver.Error](err)
				if !ok || *e.Code != "unimplemented" {
					t.Fatal("plain fixture selected auth SDK")
				}
			} else if err != nil || result == nil {
				t.Fatalf("%s/%s bridge failed", fixture, op)
			}
		}
	}
	if _, err := call(t.Context(), transport, "probe.echo", json.RawMessage(`{}`)); err == nil {
		t.Fatal("unselected fixture accepted")
	}
	for _, fixture := range []string{"plain", "auth"} {
		control := fmt.Sprintf(`{"id":"c:hello","command":"handshake","args":{"protocolVersions":[1],"runId":"run","requiredCapabilities":[]}}
{"id":"c:create","command":"client.create","args":{"caseId":"case","timeoutMs":2000,"clientRef":"client","fixture":%q,"origin":%q,"requestTimeoutMs":1000}}
{"id":"c:call","command":"client.call","args":{"caseId":"case","timeoutMs":2000,"clientRef":"client","operation":"auth.refresh","input":{"refresh_token":"input"}}}
`, fixture, peer.URL)
		var output bytes.Buffer
		if err := driver.Run(t.Context(), strings.NewReader(control), &output, strings.NewReader(""), call); err != nil {
			t.Fatal(err)
		}
		d := json.NewDecoder(&output)
		var result struct {
			Error *driver.Error `json:"error"`
		}
		for range 3 {
			if err := d.Decode(&result); err != nil {
				t.Fatal(err)
			}
		}
		if fixture == "plain" && (result.Error == nil || result.Error.Kind != "unimplemented") || fixture == "auth" && result.Error != nil {
			t.Fatal("explicit fixture did not select its generated bridge")
		}
	}
}

func TestGeneratedInputKeepsAbsentAndNull(t *testing.T) {
	observed := make(chan json.RawMessage, 3)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		observed <- body
		io.WriteString(w, `{"wire_value":"ok","observed_at":"unchanged"}`)
	}))
	defer peer.Close()
	transport, err := chik.NewHTTP(peer.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{`{}`, `{"wire_value":null}`, `null`} {
		if _, err := callPlain(t.Context(), transport, "probe.echo", json.RawMessage(input)); err != nil {
			t.Fatal(err)
		}
		var got, want any
		json.Unmarshal(<-observed, &got)
		json.Unmarshal([]byte(input), &want)
		encoded, _ := json.Marshal(got)
		expected, _ := json.Marshal(want)
		if !bytes.Equal(encoded, expected) {
			t.Fatal("input presence changed")
		}
	}
}

func TestMainRejectsRegularCredentialDescriptor(t *testing.T) {
	if os.Getenv("DRIVER_MAIN_TEST") == "1" {
		main()
		os.Exit(0)
	}
	file, err := os.CreateTemp(t.TempDir(), "not-a-pipe")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(t.Context(), executable, "-test.run=^TestMainRejectsRegularCredentialDescriptor$")
	child.Env = append(os.Environ(), "DRIVER_MAIN_TEST=1")
	child.ExtraFiles = []*os.File{file}
	var stdout, stderr bytes.Buffer
	child.Stdout, child.Stderr = &stdout, &stderr
	err = child.Run()
	exit, ok := errors.AsType[*exec.ExitError](err)
	if !ok || exit.ExitCode() != 2 || stdout.Len() != 0 || stderr.String() != "driver requires a protected credential pipe on descriptor 3\n" {
		t.Fatal("regular credential descriptor accepted")
	}
}
