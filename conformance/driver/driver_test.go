package driver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	chik "github.com/chickinfry/chickinfry-go"
)

const hello = `{"id":"c:hello","command":"handshake","args":{"protocolVersions":[1],"runId":"run","requiredCapabilities":[]}}` + "\n"

func command(id, name string, values map[string]any) string {
	values["caseId"], values["timeoutMs"] = "case", 2000
	data, _ := json.Marshal(map[string]any{"id": id, "command": name, "args": values})
	return string(data) + "\n"
}

func execute(t *testing.T, control, protected string, call Call) ([]response, error) {
	t.Helper()
	var output bytes.Buffer
	err := Run(t.Context(), strings.NewReader(control), &output, strings.NewReader(protected), call)
	var results []response
	d := json.NewDecoder(&output)
	for {
		var result response
		if err := d.Decode(&result); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		results = append(results, result)
	}
	return results, err
}

func TestProtocolBoundaries(t *testing.T) {
	for name, control := range map[string]string{
		"truncated":              strings.TrimSuffix(hello, "\n"),
		"duplicate key":          strings.Replace(hello, `"runId":"run"`, `"runId":"run","runId":"other"`, 1),
		"nested duplicate":       hello + `{"id":"c:call","command":"client.call","args":{"input":{"x":1,"x":2}}}` + "\n",
		"unknown envelope field": strings.Replace(hello, `"command"`, `"unknown":true,"command"`, 1),
		"duplicate ID":           hello + hello,
		"unknown response ID":    hello + `{"id":"d:absent","result":{},"error":null}` + "\n",
		"wrong direction":        strings.Replace(hello, "c:hello", "d:hello", 1),
		"before negotiation":     command("c:call", "client.call", map[string]any{}),
		"unknown args field":     hello + command("c:new", "session.store.create", map[string]any{"storeRef": "store", "unknown": "unused"}),
		"invalid UTF8":           hello + "\xff\n",
		"empty stream":           "",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := execute(t, control, "", nil)
			var e *Error
			if !errors.As(err, &e) || *e.Code != "protocol_violation" {
				t.Fatalf("expected protocol_violation, got %v", err)
			}
		})
	}
	for name, input := range map[string]string{
		"unknown command": command("c:no", "unknown", map[string]any{}),
		"barrier":         command("c:no", "barrier.arm", map[string]any{"point": "unknown-point"}),
	} {
		t.Run(name, func(t *testing.T) {
			results, err := execute(t, hello+input, "", nil)
			if err != nil || len(results) != 2 || results[1].Error == nil || results[1].Error.Kind != "unimplemented" {
				t.Fatalf("expected unimplemented: %+v, %v", results, err)
			}
		})
	}
	for _, pair := range [][2]string{{`"protocolVersions":[1]`, `"protocolVersions":[2]`}, {`"requiredCapabilities":[]`, `"requiredCapabilities":["client.observe"]`}} {
		results, err := execute(t, strings.Replace(hello, pair[0], pair[1], 1), "", nil)
		if err == nil || len(results) != 1 || results[0].Error == nil {
			t.Fatalf("negotiation failure lost: %+v, %v", results, err)
		}
	}
}

func TestLineSize(t *testing.T) {
	for _, size := range []int{MaxLineBytes - 1, MaxLineBytes} {
		r := bufio.NewReader(io.MultiReader(bytes.NewReader(bytes.Repeat([]byte{' '}, size)), strings.NewReader("\n")))
		line, err := readLine(r)
		if size == MaxLineBytes-1 && (err != nil || len(line) != size) {
			t.Fatalf("at-limit line rejected: %v", err)
		}
		if size >= MaxLineBytes && err == nil {
			t.Fatal("oversize line accepted")
		}
	}
}

func TestMultiplexedCallsDoNotBlockReader(t *testing.T) {
	input, control := io.Pipe()
	output, writer := io.Pipe()
	t.Cleanup(func() { input.Close(); control.Close(); output.Close(); writer.Close() })
	entered := make(chan string, 2)
	first, second := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, input, writer, strings.NewReader(""), func(ctx context.Context, _ *chik.HTTP, op string, raw json.RawMessage) (any, error) {
			entered <- op
			wait := first
			if op == "second" {
				wait = second
			}
			select {
			case <-wait:
				return map[string]any{"input": json.RawMessage(raw)}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})
		writer.Close()
	}()
	d := json.NewDecoder(output)
	send := func(line string) {
		t.Helper()
		if _, err := io.WriteString(control, line); err != nil {
			t.Fatal(err)
		}
	}
	read := func(id string) response {
		t.Helper()
		var result response
		if err := d.Decode(&result); err != nil || result.ID != id || result.Error != nil {
			t.Fatalf("expected %s: %+v, %v", id, result, err)
		}
		return result
	}
	send(hello)
	read("c:hello")
	send(command("c:create", "client.create", map[string]any{"clientRef": "client", "origin": "https://example.test", "requestTimeoutMs": 1000}))
	read("c:create")
	send(command("c:first", "client.call", map[string]any{"clientRef": "client", "operation": "first", "input": map[string]any{"absent": nil}}))
	send(command("c:second", "client.call", map[string]any{"clientRef": "client", "operation": "second", "input": map[string]any{}}))
	for range 2 {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("calls were serialized")
		}
	}
	send(command("c:read", "client.create", map[string]any{"clientRef": "second", "origin": "https://example.test", "requestTimeoutMs": 1000}))
	read("c:read")
	close(second)
	read("c:second")
	close(first)
	result := read("c:first").Result.(map[string]any)["output"].(map[string]any)["input"].(map[string]any)
	if _, exists := result["absent"]; !exists || result["absent"] != nil {
		t.Fatal("null input presence lost")
	}
	control.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSDKErrorNormalization(t *testing.T) {
	results, err := execute(t, hello+command("c:invalid-origin", "client.create", map[string]any{
		"clientRef": "client", "origin": "http://localhost", "requestTimeoutMs": 1000,
	}), "", nil)
	if err != nil || len(results) != 2 || results[1].Error == nil || results[1].Error.Kind != "sdk" || results[1].Error.Code != nil {
		t.Fatalf("unstructured SDK constructor failure lost: %+v %v", results, err)
	}
	results, err = execute(t, hello+command("c:empty-origin", "client.create", map[string]any{
		"clientRef": "client", "origin": "", "requestTimeoutMs": 1000,
	}), "", nil)
	if err != nil || len(results) != 2 || results[1].Error == nil || results[1].Error.Kind != "sdk" {
		t.Fatalf("empty origin rejected before SDK construction: %+v %v", results, err)
	}
	for _, tc := range []struct {
		err     error
		code    *string
		status  *int
		unknown *bool
	}{
		{fmt.Errorf("wrapped: %w", &chik.OperationError{Code: "conflict", Status: 409}), new("conflict"), new(409), nil},
		{errors.New("invalid_token HTTP 401 SECRET"), nil, nil, nil},
		{errors.New("timeout SECRET"), nil, nil, nil},
		{&chik.OperationError{Code: "server SECRET", Status: 503}, nil, new(503), nil},
		{&chik.OperationError{Code: "conflict", Status: 99}, new("conflict"), nil, nil},
		{&chik.OperationError{Code: "conflict", Status: 600}, new("conflict"), nil, nil},
	} {
		got := normalize(tc.err)
		data, _ := json.Marshal(got)
		want, _ := json.Marshal(&Error{Kind: "sdk", Code: tc.code, HTTPStatus: tc.status, OutcomeUnknown: tc.unknown})
		if !bytes.Equal(data, want) || bytes.Contains(data, []byte("SECRET")) {
			t.Fatalf("got %s, want %s", data, want)
		}
	}
	control := hello + command("c:create", "client.create", map[string]any{"clientRef": "client", "origin": "https://example.test", "requestTimeoutMs": 1000}) +
		command("c:call", "client.call", map[string]any{"clientRef": "client", "operation": "probe.echo", "input": map[string]any{}})
	results, err = execute(t, control, "", func(ctx context.Context, _ *chik.HTTP, _ string, _ json.RawMessage) (any, error) {
		return nil, errors.New("timeout contains sensitive details")
	})
	if err != nil || len(results) != 3 || results[2].Error.OutcomeUnknown != nil {
		t.Fatalf("unobservable SDK outcome was fabricated: %+v %v", results, err)
	}
}

func TestReferencesAndSecretOutput(t *testing.T) {
	secret, rotated := strings.Repeat("A", 43), strings.Repeat("B", 43)
	protected := fmt.Sprintf("{\"ref\":\"access\",\"value\":%q}\n", secret)
	control := hello + command("c:create", "client.create", map[string]any{"clientRef": "client", "origin": "https://example.test", "requestTimeoutMs": 1000}) +
		command("c:invalid", "client.copy", map[string]any{"sourceClientRef": "client", "clientRef": "signed", "bearerRef": "missing"}) +
		command("c:call", "client.call", map[string]any{"clientRef": "client", "operation": "auth.refresh", "input": map[string]any{}, "inputRefs": map[string]string{"refresh_token": "access"}, "outputRefs": map[string]string{"access_token": "next"}})
	results, err := execute(t, control, protected, func(_ context.Context, _ *chik.HTTP, _ string, raw json.RawMessage) (any, error) {
		if !bytes.Contains(raw, []byte(secret)) {
			t.Error("credential input reference not resolved")
		}
		return map[string]any{"access_token": rotated, "refresh_token": secret, "nested": []any{map[string]any{"wire_value": "prefix " + secret}}, "observed_at": "2026-01-02T03:04:05.123456Z"}, nil
	})
	if err != nil || len(results) != 4 || *results[2].Error.Code != "invalid_reference" {
		t.Fatalf("invalid reference lost: %+v %v", results, err)
	}
	data, _ := json.Marshal(results)
	if bytes.Contains(data, []byte(secret)) || bytes.Contains(data, []byte(rotated)) {
		t.Fatal("secret in control output")
	}
	refs := results[3].Result.(map[string]any)["credentialRefs"].(map[string]any)
	if refs["access_token"] != "next" || refs["refresh_token"] != "access" {
		t.Fatalf("bad output refs: %v", refs)
	}
	c, _ := loadCredentials(strings.NewReader(protected))
	_, _, e := c.output(map[string]any{"access_token": rotated}, map[string]string{"access_token": "access"})
	if e == nil || c.values["access"] != secret {
		t.Fatal("reference overwritten")
	}
	if _, e := loadCredentials(strings.NewReader(protected + protected)); e == nil {
		t.Fatal("duplicate protected reference accepted")
	}
	if _, e := loadCredentials(strings.NewReader(strings.TrimSuffix(protected, "\n"))); e == nil {
		t.Fatal("truncated protected line accepted")
	}
}

func TestStoreCommandsRequireTaggedObservations(t *testing.T) {
	kind := "unimplemented"
	if supportsSession() {
		kind = "driver"
	}
	for _, cmd := range []string{"session.store.create", "session.store.write", "session.store.read"} {
		results, err := execute(t, hello+command("c:store", cmd, map[string]any{"storeRef": "store"}), "", nil)
		if err != nil || results[1].Error == nil || results[1].Error.Kind != kind {
			t.Fatal("store command accepted missing runtime references or instrumentation")
		}
	}
}
