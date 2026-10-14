//go:build chik_conformance

package chik

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConstructorCounterMeasuresConstructionWindow(t *testing.T) {
	var requests atomic.Int64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		io.WriteString(w, `{}`)
	}))
	defer peer.Close()
	for _, duringConstruction := range []bool{false, true} {
		name := "normal"
		if duringConstruction {
			name = "real_network_entry"
		}
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() { conformanceConstructorTransportHook = nil })
			var counted int64
			if duringConstruction {
				conformanceConstructorTransportHook = func(transport http.RoundTripper) {
					request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, peer.URL, nil)
					if err != nil {
						t.Fatal(err)
					}
					response, err := transport.RoundTrip(request)
					if err != nil {
						t.Fatal(err)
					}
					response.Body.Close()
					counted = transport.(*conformanceNetworkTransport).counter.entries.Load()
				}
			}
			transport, observation, err := ConformanceNewHTTPWithTimeout(peer.URL, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(transport.client.CloseIdleConnections)
			wantEntries, wantRequests := int64(0), int64(0)
			if duringConstruction {
				wantEntries, wantRequests = 2, 1 // One RoundTrip and one real DialContext entry.
			}
			if observation.NetworkRequests != wantEntries || counted != wantEntries || requests.Load() != wantRequests {
				t.Fatalf("constructorNetworkRequests=%d counted=%d peerRequests=%d; want %d entries and %d request", observation.NetworkRequests, counted, requests.Load(), wantEntries, wantRequests)
			}
		})
	}
}

func TestConstructorCounterCoversSDKNetworkPath(t *testing.T) {
	var requests atomic.Int64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		io.WriteString(w, `{}`)
	}))
	defer peer.Close()
	for _, origin := range []string{peer.URL, "http://localhost", "https://example.test"} {
		transport, observation, err := ConformanceNewHTTPWithTimeout(origin, time.Second)
		if observation.NetworkRequests != 0 || requests.Load() != 0 {
			t.Fatal("constructor made network requests")
		}
		if err != nil && (observation.RawTransportDetails == nil || *observation.RawTransportDetails || observation.OutcomeUnknown == nil || *observation.OutcomeUnknown) {
			t.Fatal("constructor rejection lost measured metadata")
		}
		if origin != peer.URL {
			continue
		}
		var observed ConformanceResultEvent
		ctx := WithConformanceHooks(t.Context(), "c:network", ConformanceHooks{Result: func(event ConformanceResultEvent) { observed = event }})
		if err := transport.Invoke(ctx, "probe.echo", map[string]any{}, &map[string]any{}); err != nil {
			t.Fatal(err)
		}
		counter := transport.client.Transport.(*conformanceNetworkTransport).counter
		if observed.NetworkRequests < 2 || observed.NetworkRequests != counter.entries.Load() || requests.Load() != 1 {
			t.Fatal("real RoundTrip/DialContext entries did not reach the counter")
		}
		requests.Store(0)
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if ok && ((pkg.Name == "http" && slices.Contains([]string{"DefaultClient", "Get", "Head", "Post", "PostForm"}, selector.Sel.Name)) || (pkg.Name == "net" && slices.Contains([]string{"Dial", "DialTimeout", "DefaultResolver", "LookupHost", "LookupIP", "LookupAddr", "LookupCNAME", "LookupPort", "LookupSRV"}, selector.Sel.Name))) {
				t.Errorf("network entry bypasses the SDK transport counter: %s.%s", pkg.Name, selector.Sel.Name)
			}
			return true
		})
	}
}

func TestJoinedRefreshFailureDoesNotReuseOriginalStatusOrOutcome(t *testing.T) {
	originals, joined, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var originalCount, joinCount, refreshCount atomic.Int64
	var unblock sync.Once
	defer unblock.Do(func() { close(release) })
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth.refresh" {
			refreshCount.Add(1)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			w.WriteHeader(500)
			io.WriteString(w, `{"error":"unavailable"}`)
			return
		}
		if originalCount.Add(1) == 2 {
			close(originals)
		}
		select {
		case <-originals:
		case <-r.Context().Done():
			return
		}
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"invalid_token"}`)
	}))
	defer peer.Close()
	credentials := newRefreshStore().Credentials()
	credentials.AccessToken = "metadata_observation_original_access_token_"
	credentials.RefreshToken = "metadata_observation_original_refresh_token"
	store := new(MemoryStore)
	if err := store.Set(credentials); err != nil {
		t.Fatal(err)
	}
	results := make(chan ConformanceResultEvent, 2)
	var workers sync.WaitGroup
	for _, callID := range []string{"c:first", "c:second"} {
		transport, _, err := ConformanceNewHTTPWithTimeout(peer.URL, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		transport, err = transport.WithSession(store)
		if err != nil {
			t.Fatal(err)
		}
		ctx := WithConformanceHooks(t.Context(), callID, ConformanceHooks{
			Result: func(event ConformanceResultEvent) { results <- event },
			Barrier: func(_ context.Context, event ConformanceBarrierEvent) error {
				if event.Point == "refresh-joined" && joinCount.Add(1) == 2 {
					close(joined)
				}
				return nil
			},
		})
		workers.Go(func() {
			if err := transport.Invoke(ctx, "probe.echo", map[string]any{}, &map[string]any{}); err == nil {
				t.Error("expected refresh rejection")
			}
		})
	}
	select {
	case <-joined:
	case <-time.After(3 * time.Second):
		t.Fatal("calls did not join the same real refresh")
	}
	unblock.Do(func() { close(release) })
	workers.Wait()
	var unavailable, unknown int
	for range 2 {
		event := <-results
		if event.HTTPStatus == nil || *event.HTTPStatus != 500 {
			t.Fatal("earlier original 401 replaced the refresh failure status")
		}
		if event.OutcomeUnknown == nil {
			unavailable++
		} else if *event.OutcomeUnknown {
			unknown++
		} else {
			t.Fatal("refresh consumption was fabricated as resolved")
		}
	}
	if unavailable != 1 || unknown != 1 || refreshCount.Load() != 1 {
		t.Fatal("joined-call outcome was inferred or the refresh was duplicated")
	}
}

func TestRuntimeErrorMetadataPreservesUnavailableOutcome(t *testing.T) {
	for _, exposed := range []bool{false, true} {
		class := "network error"
		if exposed {
			class = "RAW_DETAIL"
		}
		observed := conformanceRawDetails(&transportError{cause: errors.New("RAW_DETAIL"), class: class})
		if observed == nil || *observed != exposed {
			t.Fatal("raw underlying error exposure was not measured")
		}
	}
	if conformanceRawDetails(errors.New("external error with no runtime provenance")) != nil {
		t.Fatal("unavailable raw-error observation fabricated")
	}
	for _, test := range []struct {
		name, operation, body string
		status                int
		unknown               bool
	}{
		{"business rejection", "probe.echo", `{"error":"unavailable"}`, 503, false},
		{"refresh 503", "auth.refresh", `{"error":"unavailable"}`, 503, true},
		{"refresh malformed 401", "auth.refresh", `{}`, 401, true},
		{"refresh redirect", "auth.refresh", `{}`, 307, true},
		{"business malformed 503", "probe.echo", `{}`, 503, true},
		{"refresh validated 401", "auth.refresh", `{"error":"invalid_token"}`, 401, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				io.WriteString(w, test.body)
			}))
			defer peer.Close()
			transport, _, err := ConformanceNewHTTPWithTimeout(peer.URL, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			var observed ConformanceResultEvent
			ctx := WithConformanceHooks(t.Context(), "c:result", ConformanceHooks{Result: func(event ConformanceResultEvent) { observed = event }})
			if err := transport.Invoke(ctx, test.operation, map[string]any{}, &map[string]any{}); err == nil {
				t.Fatal("expected SDK rejection")
			}
			if observed.HTTPStatus == nil || *observed.HTTPStatus != test.status || observed.RawTransportDetails == nil || *observed.RawTransportDetails || observed.OutcomeUnknown == nil || *observed.OutcomeUnknown != test.unknown {
				t.Fatalf("rejection metadata: %+v", observed)
			}
		})
	}
}
