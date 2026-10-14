//go:build chik_conformance

package driver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestObserveSnapshotsPendingAndCompletedRuntimeCall(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(entered)
		select {
		case <-release:
			io.WriteString(w, `{}`)
		case <-r.Context().Done():
		}
	}))
	defer peer.Close()
	input, control := io.Pipe()
	output, writer := io.Pipe()
	t.Cleanup(func() { input.Close(); control.Close(); output.Close(); writer.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, input, writer, strings.NewReader(""), runtimeCall)
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
			t.Fatalf("unexpected response: %+v, %v", result, err)
		}
		return result
	}
	send(hello)
	read("c:hello")
	send(command("c:create", "client.create", map[string]any{"clientRef": "client", "origin": peer.URL, "fixture": "plain", "requestTimeoutMs": 1000}))
	if read("c:create").Result.(map[string]any)["constructorNetworkRequests"] != float64(0) {
		t.Fatal("constructor network observation missing")
	}
	send(command("c:call", "client.call", map[string]any{"clientRef": "client", "operation": "probe.echo", "input": map[string]any{}}))
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("SDK call never reached the peer")
	}
	send(command("c:pending", "client.observe", map[string]any{"callId": "c:call", "afterSequence": 0}))
	pending := read("c:pending").Result.(map[string]any)
	if len(pending) != 4 || pending["callId"] != "c:call" || pending["complete"] != true {
		t.Fatal("pending snapshot violated its protocol shape")
	}
	close(release)
	if read("c:call").Result.(map[string]any)["httpStatus"] != float64(200) {
		t.Fatal("successful SDK response status was not observed")
	}
	send(command("c:final", "client.observe", map[string]any{"callId": "c:call", "afterSequence": 0}))
	final := read("c:final").Result.(map[string]any)
	if final["complete"] != false || final["throughSequence"].(float64) < pending["throughSequence"].(float64) {
		t.Fatal("complete snapshot lost its watermark")
	}
	events := final["events"].([]any)
	var completed bool
	for _, raw := range events {
		event := raw.(map[string]any)
		if len(event) != 8 || event["callId"] != "c:call" || event["httpStatus"] != float64(200) {
			t.Fatal("runtime event field was dropped, changed or extended")
		}
		completed = completed || event["phase"] == "completed"
		if event["phase"] == "completed" && (event["retainedBytes"] != nil || event["peakRetainedBytes"] != nil) {
			t.Fatal("unmeasured decoder retention was fabricated")
		}
	}
	if !completed {
		t.Fatal("SDK completion observation lost")
	}
	send(command("c:empty", "client.observe", map[string]any{"callId": "c:call", "afterSequence": final["throughSequence"]}))
	empty := read("c:empty").Result.(map[string]any)
	if len(empty["events"].([]any)) != 0 || empty["complete"] != false {
		t.Fatal("watermark filtering replayed an event")
	}
	send(command("c:ahead", "client.observe", map[string]any{"callId": "c:call", "afterSequence": final["throughSequence"].(float64) + 1}))
	var ahead response
	if d.Decode(&ahead) != nil || ahead.Error == nil || *ahead.Error.Code != "invalid_args" {
		t.Fatal("future watermark was accepted")
	}
	control.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
