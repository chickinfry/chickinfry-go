//go:build chik_conformance

package driver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	chik "github.com/chickinfry/chickinfry-go"
)

func TestActualSDKBarriersReleaseOnlyTheirCall(t *testing.T) {
	for _, tc := range []struct {
		point  string
		expire bool
	}{
		{point: "sdk-entered"},
		{point: "both-originals-rejected"},
		{point: "refresh-joined"},
		{point: "both-originals-rejected", expire: true},
	} {
		name := tc.point
		if tc.expire {
			name += "/deadline"
		}
		t.Run(name, func(t *testing.T) {
			point := tc.point
			ctx := &controlledDeadline{Context: t.Context(), expired: make(chan struct{})}
			var originals, refreshes atomic.Int64
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/auth.refresh" {
					refreshes.Add(1)
				} else {
					originals.Add(1)
				}
				w.WriteHeader(401)
				io.WriteString(w, `{"error":"invalid_token"}`)
			}))
			defer peer.Close()
			input, control := io.Pipe()
			output, writer := io.Pipe()
			t.Cleanup(func() { control.Close(); input.Close(); output.Close(); writer.Close() })
			done := make(chan error, 1)
			go func() {
				transport, err := chik.NewHTTP(peer.URL)
				if err != nil {
					done <- err
					return
				}
				transport, err = transport.WithSession(&testOnlyStore{current: chik.SessionCredentials{AccessToken: strings.Repeat("A", 43), RefreshToken: strings.Repeat("B", 43)}})
				if err != nil {
					done <- err
					return
				}
				done <- Run(ctx, input, writer, strings.NewReader(protectedTokens()), func(ctx context.Context, _ *chik.HTTP, op string, raw json.RawMessage) (any, error) {
					return runtimeCall(ctx, transport, op, raw)
				})
				writer.Close()
			}()
			decoder := json.NewDecoder(output)
			send := func(text string) {
				t.Helper()
				if _, err := io.WriteString(control, text); err != nil {
					t.Fatal(err)
				}
			}
			read := func() map[string]json.RawMessage {
				t.Helper()
				var value map[string]json.RawMessage
				if decoder.Decode(&value) != nil {
					t.Fatal("bad frame")
				}
				return value
			}
			send(hello)
			read()
			send(command("c:client", "client.create", map[string]any{"clientRef": "client", "origin": peer.URL, "requestTimeoutMs": 1000}))
			read()
			send(command("c:arm", "barrier.arm", map[string]any{"barrierRef": "barrier", "point": point, "participants": []string{"c:call"}}))
			read()
			send(command("c:call", "client.call", map[string]any{"clientRef": "client", "operation": "probe.echo", "input": map[string]any{}}))
			arrival := read()
			var id, cmd string
			json.Unmarshal(arrival["id"], &id)
			json.Unmarshal(arrival["command"], &cmd)
			var args struct {
				CallID string         `json:"callId"`
				Point  string         `json:"point"`
				Facts  map[string]any `json:"facts"`
			}
			json.Unmarshal(arrival["args"], &args)
			if !strings.HasPrefix(id, "d:") || cmd != "barrier.arrive" || args.CallID != "c:call" || args.Point != point {
				t.Fatal("arrival was not tied to actual SDK call")
			}
			if point == "sdk-entered" && args.Facts["entered"] != true || point == "both-originals-rejected" && args.Facts["httpStatus"] != float64(401) {
				t.Fatal("wrong runtime facts")
			}
			if point == "refresh-joined" {
				if ref, ok := args.Facts["refreshRef"].(string); !ok || ref == "" {
					t.Fatal("missing runtime refresh identity")
				}
			}
			send(command("c:read", "client.copy", map[string]any{"sourceClientRef": "client", "clientRef": "copy", "bearerRef": "access"}))
			if string(read()["id"]) != `"c:read"` {
				t.Fatal("barrier blocked command reader")
			}
			if tc.expire {
				close(ctx.expired)
				result := read()
				var e map[string]json.RawMessage
				if string(result["id"]) != `"c:call"` || json.Unmarshal(result["error"], &e) != nil ||
					string(e["kind"]) != `"driver"` || string(e["code"]) != `"deadline_exceeded"` || string(e["outcomeUnknown"]) != "null" {
					t.Fatal("unobservable outcome at the rejection barrier was not null on deadline")
				}
			} else {
				release, _ := json.Marshal(map[string]any{"id": id, "result": map[string]any{"barrierRef": "barrier", "state": "released", "sequence": 1}, "error": nil})
				send(string(release) + "\n")
				if string(read()["id"]) != `"c:call"` {
					t.Fatal("call did not complete after release")
				}
			}
			control.Close()
			err := <-done
			if tc.expire {
				e, ok := errors.AsType[*Error](err)
				if !ok || e.Code == nil || *e.Code != "deadline_exceeded" || originals.Load() != 1 || refreshes.Load() != 0 {
					t.Fatal("deadline did not stop the rejected call before refresh")
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBarrierTimeoutAndUnknownRelease(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var output bytes.Buffer
	s := &server{ctx: ctx, cancel: cancel, writer: &output, credentials: &credentials{values: map[string]string{}}, barriers: map[string]*barrier{}, pending: map[string]*barrierPending{}}
	a := args{commonArgs: commonArgs{CaseID: "case", TimeoutMS: 1000}, BarrierRef: "b", Point: "sdk-entered", Participants: []string{"c:call"}}
	if e := s.armBarrier(a); e != nil {
		t.Fatal(e)
	}
	deadline, end := context.WithTimeout(ctx, 5*time.Millisecond)
	defer end()
	err := s.arrive(deadline, "c:call", "case", "sdk-entered", map[string]any{"entered": true})
	e, ok := errors.AsType[*Error](err)
	if !ok || *e.Code != "deadline_exceeded" {
		t.Fatal("barrier ignored context timeout")
	}
	if e := s.releaseBarrier([]byte(`{"id":"d:unknown","result":{"barrierRef":"b","state":"released","sequence":1},"error":null}`)); e == nil {
		t.Fatal("unknown response ID accepted")
	}
}

func TestClearTraceIsFromRuntimeHook(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "deleted", true: "new-login-retained"}[replace], func(t *testing.T) {
			testClearTrace(t, replace)
		})
	}
}

func testClearTrace(t *testing.T, replace bool) {
	t.Helper()
	initial := chik.SessionCredentials{AccessToken: strings.Repeat("A", 43), RefreshToken: strings.Repeat("B", 43), ExpiresAt: "2099-01-01T00:00:00Z", RefreshExpiresAt: "2099-02-01T00:00:00Z", UserID: "user", SessionID: "session"}
	newer := initial
	newer.AccessToken, newer.RefreshToken = strings.Repeat("C", 43), strings.Repeat("D", 43)
	store := &storeBinding{memory: new(chik.MemoryStore), clearAttempts: []observedClear{}}
	if err := store.memory.Set(initial); err != nil {
		t.Fatal(err)
	}
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if replace && r.URL.Path == "/auth.refresh" {
			if err := store.memory.Set(newer); err != nil {
				t.Error(err)
			}
		}
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"invalid_token"}`)
	}))
	defer peer.Close()
	refs, err := loadCredentials(strings.NewReader(protectedTokens()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s := &server{ctx: ctx, cancel: cancel, credentials: refs, barriers: map[string]*barrier{}, pending: map[string]*barrierPending{}}
	transport, err := chik.NewHTTP(peer.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport, err = transport.WithSession(store.memory)
	if err != nil {
		t.Fatal(err)
	}
	hooked := attachHooks(s, context.WithValue(ctx, storeKey{}, store), ctx, "c:call", "case")
	runtimeCall(hooked, transport, "probe.echo", json.RawMessage(`{}`))
	trace := store.clearAttempts
	if len(trace) != 1 || trace[0].ExpectedAccessRef != "access" || trace[0].ExpectedRefreshRef != "refresh" || trace[0].Removed == nil || *trace[0].Removed != !replace {
		t.Fatal("actual runtime clear trace was not recorded")
	}
	expected := chik.SessionCredentials{}
	if replace {
		expected = newer
	}
	if store.memory.Credentials() != expected || store.traceUnavailable {
		t.Fatal("trace does not reflect the actual memory store")
	}
	if store.revision() != 2 {
		t.Fatal("revision did not observe the actual store mutation")
	}
}

func TestCancelledArrivalDoesNotWriteAfterFinalResponse(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	var output bytes.Buffer
	s := &server{ctx: t.Context(), cancel: func() {}, writer: &output, credentials: &credentials{values: map[string]string{}}}
	cancel()
	s.reply("c:call", nil, failure("driver", "deadline_exceeded"))
	s.write(map[string]any{"id": "d:1", "command": "barrier.arrive"}, "d:1", ctx)
	if lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte("\n")); len(lines) != 1 || !bytes.Contains(lines[0], []byte(`"id":"c:call"`)) {
		t.Fatal("cancelled arrival was written after final response")
	}
}
