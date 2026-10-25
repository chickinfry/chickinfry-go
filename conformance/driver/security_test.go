package driver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chickinfry/chickinfry-go"
)

func runtimeCall(ctx context.Context, transport *chickinfry.HTTPTransport, operation string, input json.RawMessage) (any, error) {
	var output map[string]any
	err := transport.Invoke(ctx, operation, input, &output)
	return output, err
}

func seededControl(origin string) string {
	return hello + command("c:client", "client.create", map[string]any{"clientRef": "client", "origin": origin, "fixture": "plain", "requestTimeoutMs": 1000})
}

func protectedTokens() string {
	return fmt.Sprintf("{\"ref\":\"access\",\"value\":%q}\n{\"ref\":\"refresh\",\"value\":%q}\n", strings.Repeat("A", 43), strings.Repeat("B", 43))
}

func TestExactProtocolFieldNames(t *testing.T) {
	for _, field := range []string{"id", "command", "args", "protocolVersions", "runId", "requiredCapabilities"} {
		for _, duplicate := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/duplicate=%v", field, duplicate), func(t *testing.T) {
				key := `"` + field + `":`
				replacement := `"` + strings.ToUpper(field) + `":`
				if duplicate {
					replacement = key + `null,` + replacement
				}
				control := strings.Replace(hello, key, replacement, 1)
				_, err := execute(t, control, "", nil)
				e, ok := errors.AsType[*Error](err)
				if !ok || e.Code == nil || *e.Code != "protocol_violation" {
					t.Fatal("case-variant protocol key accepted")
				}
			})
		}
	}
	for _, field := range []string{"ref", "value"} {
		for _, duplicate := range []bool{false, true} {
			t.Run(fmt.Sprintf("credential-%s/duplicate=%v", field, duplicate), func(t *testing.T) {
				key := `"` + field + `":`
				replacement := `"` + strings.ToUpper(field) + `":`
				if duplicate {
					replacement = key + `null,` + replacement
				}
				_, err := loadCredentials(strings.NewReader(strings.Replace(protectedTokens(), key, replacement, 1)))
				e, ok := errors.AsType[*Error](err)
				if !ok || *e.Code != "protocol_violation" {
					t.Fatal("case-variant credential key accepted")
				}
			})
		}
	}
}

func TestDuplicateIDAcrossOrdinaryCommands(t *testing.T) {
	create := command("c:reused", "session.store.create", map[string]any{"storeRef": "store"})
	read := command("c:reused", "session.store.read", map[string]any{"storeRef": "store", "includeTrace": true})
	_, err := execute(t, hello+create+read, "", nil)
	e, ok := errors.AsType[*Error](err)
	if !ok || *e.Code != "protocol_violation" {
		t.Fatal("ordinary command reused a request ID")
	}
}

type observedWriter struct {
	mu        sync.Mutex
	data      bytes.Buffer
	responses chan response
}

func (w *observedWriter) Write(line []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	var response response
	if err := json.Unmarshal(line, &response); err != nil {
		return 0, err
	}
	w.responses <- response
	return w.data.Write(line)
}

type controlledDeadline struct {
	context.Context
	expired chan struct{}
}

func (c *controlledDeadline) Done() <-chan struct{} { return c.expired }
func (c *controlledDeadline) Err() error {
	select {
	case <-c.expired:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func TestShutdownJoinsRefreshAfterDeadline(t *testing.T) {
	for _, cancelRun := range []bool{false, true} {
		t.Run(fmt.Sprintf("run-cancel=%v", cancelRun), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			expired := &controlledDeadline{Context: t.Context(), expired: make(chan struct{})}
			if !cancelRun {
				ctx = expired
			}
			release, entered := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/auth.refresh" {
					close(entered)
					select {
					case <-release:
					case <-t.Context().Done():
					}
				}
				w.WriteHeader(401)
				io.WriteString(w, `{"error":"invalid_token"}`)
			}))
			t.Cleanup(func() { unblock(); peer.Close() })
			input, control := io.Pipe()
			t.Cleanup(func() { control.Close(); input.Close() })
			output := &observedWriter{responses: make(chan response, 16)}
			done := make(chan error, 1)
			session := &testOnlyStore{current: chickinfry.SessionCredentials{AccessToken: strings.Repeat("A", 43), RefreshToken: strings.Repeat("B", 43)}}
			transport, err := chickinfry.NewHTTPTransport(peer.URL, chickinfry.WithTimeout(30*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			transport, err = transport.WithSession(session)
			if err != nil {
				t.Fatal(err)
			}
			finished := make(chan struct{})
			go func() {
				done <- Run(ctx, input, output, strings.NewReader(protectedTokens()), func(ctx context.Context, _ *chickinfry.HTTPTransport, operation string, raw json.RawMessage) (any, error) {
					defer close(finished)
					return runtimeCall(ctx, transport, operation, raw)
				})
			}()
			prefix := seededControl(peer.URL)
			if _, err := io.WriteString(control, prefix); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				<-output.responses
			}
			call := command("c:call", "client.call", map[string]any{"clientRef": "client", "operation": "probe.echo", "input": map[string]any{}})
			call = strings.Replace(call, `"timeoutMs":2000`, `"timeoutMs":60000`, 1)
			if _, err := io.WriteString(control, call); err != nil {
				t.Fatal(err)
			}
			<-entered
			if cancelRun {
				cancel()
			} else {
				close(expired.expired)
			}
			reply := <-output.responses
			if reply.ID != "c:call" || reply.Error == nil || *reply.Error.Code != "deadline_exceeded" {
				t.Fatal("missing deadline response before refresh release")
			}
			control.Close()
			select {
			case <-done:
				t.Fatal("driver exited before refresh completion")
			default:
			}
			select {
			case <-finished:
				t.Fatal("SDK returned with refresh still pending")
			default:
			}
			unblock()
			err = <-done
			e, ok := errors.AsType[*Error](err)
			if !ok || *e.Code != "deadline_exceeded" {
				t.Fatal("run deadline or cancellation lost")
			}
			select {
			case <-finished:
			default:
				t.Fatal("SDK work not finished at exit")
			}
			select {
			case <-output.responses:
				t.Fatal("late response after deadline")
			default:
			}
			if session.Credentials() != (chickinfry.SessionCredentials{}) {
				t.Fatal("actual Clear did not precede exit")
			}

		})
	}
}

// Fragment writes as a pipe may; serialize chunks, not whole response lines.
type fragmentedWriter struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (w *fragmentedWriter) Write(line []byte) (int, error) {
	for offset := 0; offset < len(line); offset += 31 {
		w.mu.Lock()
		w.data.Write(line[offset:min(offset+31, len(line))])
		w.mu.Unlock()
		runtime.Gosched()
	}
	return len(line), nil
}

func TestConcurrentCompletionsKeepWholeStdoutLines(t *testing.T) {
	const calls = 16
	entered, release := make(chan struct{}, calls), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	control := hello + command("c:create", "client.create", map[string]any{"clientRef": "client", "origin": "https://example.test", "fixture": "plain", "requestTimeoutMs": 1000})
	for i := range calls {
		control += command(fmt.Sprintf("c:call:%d", i), "client.call", map[string]any{"clientRef": "client", "operation": "probe.echo", "input": map[string]any{}})
	}
	output := &fragmentedWriter{}
	done := make(chan error, 1)
	go func() {
		done <- Run(t.Context(), strings.NewReader(control), output, strings.NewReader(""), func(context.Context, *chickinfry.HTTPTransport, string, json.RawMessage) (any, error) {
			entered <- struct{}{}
			<-release
			return map[string]any{"value": strings.Repeat("x", 1024)}, nil
		})
	}()
	for range calls {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("parallel call never entered")
		}
	}
	unblock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(output.data.Bytes()), []byte{'\n'})
	if len(lines) != calls+2 {
		t.Fatal("stdout response count changed")
	}
	ids := map[string]bool{}
	for _, line := range lines {
		var result response
		if json.Unmarshal(line, &result) != nil || result.ID == "" || ids[result.ID] || result.Error != nil {
			t.Fatal("stdout lines overlapped or lost a response")
		}
		ids[result.ID] = true
	}
}

// This test double has no conditional Clear or shared-refresh policy.
type testOnlyStore struct {
	mu      sync.Mutex
	current chickinfry.SessionCredentials
}

func (s *testOnlyStore) Credentials() chickinfry.SessionCredentials {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current
}
func (s *testOnlyStore) Refresh(ctx context.Context, operation func(context.Context, chickinfry.SessionCredentials) (chickinfry.SessionCredentials, error)) (chickinfry.SessionCredentials, error) {
	value, err := operation(ctx, s.Credentials())
	if err == nil {
		s.mu.Lock()
		s.current = value
		s.mu.Unlock()
	}
	return value, err
}
func (s *testOnlyStore) Clear(context.Context, chickinfry.SessionCredentials) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = chickinfry.SessionCredentials{}
	return nil
}
