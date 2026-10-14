//go:build chik_conformance

package chik

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestConformanceTransportPhasesAndRealBuffers(t *testing.T) {
	const limit = 1 << 20
	for _, test := range []struct {
		name         string
		status, size int
		chunked      bool
	}{
		{"success content length", 200, limit, false},
		{"overflow content length", 200, limit + 65536, false},
		{"redirect content length", 307, limit + 65536, false},
		{"success chunked", 200, limit, true},
		{"overflow chunked", 200, limit + 65536, true},
		{"redirect chunked", 307, limit + 65536, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if !test.chunked {
					response.Header().Set("Content-Length", strconv.Itoa(test.size))
				}
				response.WriteHeader(test.status)
				if test.chunked {
					response.(http.Flusher).Flush()
				}
				fmt.Fprint(response, "{}"+strings.Repeat(" ", test.size-2))
			}))
			defer server.Close()
			transport, err := NewHTTP(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			var events []ConformanceTransportEvent
			ctx := WithConformanceHooks(t.Context(), "call:transport", ConformanceHooks{Observe: func(event ConformanceTransportEvent) { events = append(events, event) }})
			err = transport.Invoke(ctx, "catalog.create", map[string]string{}, &struct{}{})
			if test.status == 200 && test.size == limit {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("negative response succeeded")
			}
			if len(events) < 3 || events[0].Phase != "headers" || events[len(events)-1].Phase != "completed" {
				t.Fatalf("bad phases: %+v", events)
			}
			var sequence uint64
			var elapsed float64
			var stop, closed, observed, limited bool
			var reads int
			var received, framing int64
			for _, event := range events {
				if event.CallID != "call:transport" || event.Sequence <= sequence || event.ElapsedMs < elapsed {
					t.Fatal("event ordering changed")
				}
				sequence = event.Sequence
				elapsed = event.ElapsedMs
				if !event.Measurable || event.LibraryRetainedBytes == nil || event.TotalHeldBytes == nil || event.FramingBytes == nil {
					t.Fatalf("missing underlying measurements: %+v", event)
				}
				if event.RetainedBytes > limit || event.PeakRetainedBytes > limit || *event.LibraryRetainedBytes > conformanceReadBuffer || *event.TotalHeldBytes != event.RuntimeRetainedBytes+*event.LibraryRetainedBytes {
					t.Fatalf("wrong buffers: %+v", event)
				}
				received = max(received, event.ReadBytes)
				framing = max(framing, *event.FramingBytes)
				switch event.Phase {
				case "read":
					if stop {
						t.Fatal("read after stop")
					}
					reads++
				case "limit":
					if len(events) == 0 || event.ReadBytes <= limit {
						t.Fatal("limit without overflow read")
					}
					limited = true
				case "cancel-requested":
					stop = true
				case "cancel-observed":
					if !stop {
						t.Fatal("cancel observed before requested")
					}
					observed = true
				case "reader-closed":
					closed = true
					if stop && !observed {
						t.Fatal("reader closed before cancellation confirmation")
					}
				}
			}
			if !closed {
				t.Fatal("reader was not closed")
			}
			if test.status == 307 && (reads != 0 || limited || !observed) {
				t.Fatal("redirect accepted body bytes or failed to cancel")
			}
			if test.status == 200 && test.size > limit && (!limited || !observed) {
				t.Fatal("overflow did not stop and cancel")
			}
			if test.status == 200 && test.size == limit && received != limit {
				t.Fatalf("wire body count=%d", received)
			}
			if test.chunked && test.status == 200 && framing == 0 {
				t.Fatal("chunk framing was not counted separately")
			}
		})
	}
}

func TestConformanceCancellationPhases(t *testing.T) {
	started := make(chan struct{})
	headersSeen := make(chan struct{})
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Length", "20")
		response.WriteHeader(200)
		response.(http.Flusher).Flush()
		close(started)
		<-release
	}))
	defer server.Close()
	defer unblock()
	transport, err := NewHTTP(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var mu sync.Mutex
	var phases []string
	ctx = WithConformanceHooks(ctx, "call:cancel", ConformanceHooks{Observe: func(event ConformanceTransportEvent) {
		mu.Lock()
		phases = append(phases, event.Phase)
		mu.Unlock()
		if event.Phase == "headers" {
			close(headersSeen)
		}
	}})
	result := make(chan error, 1)
	go func() { result <- transport.Invoke(ctx, "catalog.create", map[string]string{}, &struct{}{}) }()
	<-started
	<-headersSeen
	cancel()
	if err := <-result; err == nil {
		t.Fatal("cancelled request succeeded")
	}
	mu.Lock()
	defer mu.Unlock()
	joined := strings.Join(phases, ",")
	if !strings.Contains(joined, "cancel-requested,cancel-observed,reader-closed") || !strings.HasSuffix(joined, "completed") {
		t.Fatalf("cancel phases=%s", joined)
	}
}

func TestConformanceUnmeasurableTransportIsExplicit(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) { fmt.Fprint(response, "{}") }))
	defer server.Close()
	transport, err := NewHTTP(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport.client = server.Client()
	var events []ConformanceTransportEvent
	ctx := WithConformanceHooks(t.Context(), "call:tls", ConformanceHooks{Observe: func(event ConformanceTransportEvent) { events = append(events, event) }})
	if err := transport.Invoke(ctx, "catalog.create", map[string]string{}, &struct{}{}); err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Measurable || event.LibraryRetainedBytes != nil || event.TotalHeldBytes != nil {
			t.Fatal("TLS bytes were guessed")
		}
	}
}

func TestConformanceRefreshBarriersAndClearTrace(t *testing.T) {
	store := newRefreshStore()
	original := store.Credentials()
	transport, err := NewHTTP("http://127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := transport.WithSession(store)
	if err != nil {
		t.Fatal(err)
	}
	signed.client.Transport = responseTransport(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 401, Header: make(http.Header), Body: &countingResponseBody{Reader: strings.NewReader(`{"error":"invalid_token"}`)}, Request: request}, nil
	})
	var traces []ConformanceSessionEvent
	var barriers []ConformanceBarrierEvent
	ctx := WithConformanceHooks(t.Context(), "call:rejected", ConformanceHooks{CredentialRefs: map[string]string{original.AccessToken: "access:old", original.RefreshToken: "refresh:old"}, SessionTrace: func(event ConformanceSessionEvent) { traces = append(traces, event) }, Barrier: func(_ context.Context, event ConformanceBarrierEvent) error {
		barriers = append(barriers, event)
		return nil
	}})
	err = signed.Invoke(ctx, "catalog.create", map[string]string{}, &struct{}{})
	failure, ok := errors.AsType[*OperationError](err)
	if !ok || failure.Code != "invalid_token" {
		t.Fatal(err)
	}
	if len(barriers) != 2 || barriers[0].Point != "sdk-entered" || !barriers[0].Entered || barriers[1].Point != "both-originals-rejected" || *barriers[1].HTTPStatus != 401 {
		t.Fatalf("barriers=%+v", barriers)
	}
	if len(traces) != 2 || traces[0].Phase != "refresh" || traces[0].RefreshRef != nil || traces[1].Phase != "clear" || !traces[1].Matched || traces[1].Removed == nil || !*traces[1].Removed || !traces[1].Measurable || traces[1].ExpectedAccessRef != "access:old" || traces[1].ExpectedRefreshRef != "refresh:old" {
		t.Fatalf("trace=%+v", traces)
	}
}

func TestConformanceRefreshJoinUsesTheSameOpaqueReference(t *testing.T) {
	flights := &refreshFlights{flights: make(map[string]*refreshFlight)}
	token := newRefreshStore().Credentials().RefreshToken
	started := make(chan struct{})
	release := make(chan struct{})
	joined := make(chan struct{})
	results := make(chan error, 2)
	var mu sync.Mutex
	var refs []string
	hooks := ConformanceHooks{SessionTrace: func(event ConformanceSessionEvent) {
		mu.Lock()
		if event.RefreshRef != nil {
			refs = append(refs, *event.RefreshRef)
		}
		mu.Unlock()
	}, Barrier: func(_ context.Context, event ConformanceBarrierEvent) error {
		if event.Point == "refresh-joined" {
			if event.RefreshRef == "" {
				t.Error("follower barrier has no refresh reference")
			}
			close(joined)
		}
		return nil
	}}
	leader, finish, err := conformanceBegin(t.Context(), "http://127.0.0.1", false)
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	follower, end, err := conformanceBegin(WithConformanceHooks(t.Context(), "call:follower", hooks), "http://127.0.0.1", false)
	if err != nil {
		t.Fatal(err)
	}
	defer end()
	go func() {
		_, err := flights.Do(leader, token, func() (string, error) { close(started); <-release; return "", nil })
		results <- err
	}()
	<-started
	go func() {
		_, err := flights.Do(follower, token, func() (string, error) { return "", errors.New("unexpected second flight") })
		results <- err
	}()
	<-joined
	close(release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(refs) != 1 || refs[0] == "" || strings.Contains(refs[0], token) {
		t.Fatalf("opaque refs=%v", refs)
	}
}

func TestConformanceIndependentRefreshFlightsHaveDistinctReferences(t *testing.T) {
	token := newRefreshStore().Credentials().RefreshToken
	var refs []string
	for range 2 {
		store := new(MemoryStore)
		ctx, finish, err := conformanceBegin(WithConformanceHooks(t.Context(), "call:independent", ConformanceHooks{
			SessionTrace: func(event ConformanceSessionEvent) {
				if event.RefreshRef != nil {
					refs = append(refs, *event.RefreshRef)
				}
			},
		}), "http://127.0.0.1", false)
		if err != nil {
			t.Fatal(err)
		}
		_, err = store.refreshes.Do(ctx, token, func() (string, error) {
			return "", conformanceRefreshSent(ctx)
		})
		finish()
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(refs) != 2 || refs[0] == "" || refs[1] == "" || refs[0] == refs[1] {
		t.Fatalf("independent refresh flights must have distinct nonempty references: %v", refs)
	}
}

func TestConformanceMemoryStoreClearPreservesLoginAfterMatch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := new(MemoryStore)
		original, replacement := newRefreshStore().Credentials(), newRefreshStore().Credentials()
		if err := store.Set(original); err != nil {
			t.Fatal(err)
		}
		matched, resume := make(chan struct{}), make(chan struct{})
		conformanceClearMatchedHook = func(current *MemoryStore) {
			if current == store {
				close(matched)
				<-resume
			}
		}
		defer func() { conformanceClearMatchedHook = nil }()
		cleared, installed := make(chan error, 1), make(chan error, 1)
		go func() { cleared <- store.Clear(t.Context(), original) }()
		<-matched
		attempted := make(chan struct{})
		go func() {
			// Mutex waits are not durable in synctest; probe before choosing the handshake.
			if store.mu.TryLock() {
				store.mu.Unlock()
				installed <- store.Set(replacement)
				close(attempted)
				return
			}
			close(attempted)
			installed <- store.Set(replacement)
		}()
		<-attempted
		close(resume)
		if err := <-cleared; err != nil {
			t.Fatal(err)
		}
		if err := <-installed; err != nil {
			t.Fatal(err)
		}
		if store.Credentials() != replacement {
			t.Fatal("clear removed credentials installed after match")
		}
	})
}

func TestConformanceClearTracePreservesNewCredentials(t *testing.T) {
	store := new(MemoryStore)
	expected := newRefreshStore().Credentials()
	replacement := newRefreshStore().Credentials()
	if err := store.Set(replacement); err != nil {
		t.Fatal(err)
	}
	var trace ConformanceSessionEvent
	ctx := WithConformanceHooks(t.Context(), "call:clear", ConformanceHooks{CredentialRefs: map[string]string{expected.AccessToken: "access:expected", expected.RefreshToken: "refresh:expected"}, SessionTrace: func(event ConformanceSessionEvent) { trace = event }})
	if err := conformanceClear(ctx, store, expected); err != nil {
		t.Fatal(err)
	}
	if trace.Matched || trace.Removed == nil || *trace.Removed || !trace.Measurable || store.Credentials() != replacement {
		t.Fatalf("new login clear trace=%+v", trace)
	}
}

func TestConformanceMemoryStoreClientsJoinOneRefresh(t *testing.T) {
	store := new(MemoryStore)
	original, rotated := newRefreshStore().Credentials(), newRefreshStore().Credentials()
	rotated.AccessToken = strings.Repeat("c", 43)
	if err := store.Set(original); err != nil {
		t.Fatal(err)
	}
	var refreshes, requests atomic.Int64
	started, releaseRefresh := make(chan struct{}), make(chan struct{})
	rejected, joined := make(chan ConformanceBarrierEvent, 2), make(chan ConformanceBarrierEvent, 2)
	releaseOriginals, releaseJoined := make(chan struct{}), make(chan struct{})
	unblockOriginals := sync.OnceFunc(func() { close(releaseOriginals) })
	unblockJoined := sync.OnceFunc(func() { close(releaseJoined) })
	unblockRefresh := sync.OnceFunc(func() { close(releaseRefresh) })
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/auth.refresh" {
			if refreshes.Add(1) == 1 {
				close(started)
			}
			<-releaseRefresh
			writeSessionCredentials(t, response, rotated)
			return
		}
		requests.Add(1)
		if request.Header.Get("Authorization") == "Bearer "+rotated.AccessToken {
			fmt.Fprint(response, "{}")
		} else {
			if request.Header.Get("Authorization") != "Bearer "+original.AccessToken {
				t.Error("original used unexpected credentials")
			}
			writeRefreshResponse(t, response, 401, map[string]string{"error": "invalid_token"})
		}
	}))
	defer server.Close()
	defer unblockRefresh()
	defer unblockJoined()
	defer unblockOriginals()
	var mu sync.Mutex
	var participation []ConformanceSessionEvent
	hooks := ConformanceHooks{
		SessionTrace: func(event ConformanceSessionEvent) {
			if event.RefreshRef != nil {
				mu.Lock()
				participation = append(participation, event)
				mu.Unlock()
			}
		},
		Barrier: func(ctx context.Context, event ConformanceBarrierEvent) error {
			var release <-chan struct{}
			switch event.Point {
			case "both-originals-rejected":
				rejected <- event
				release = releaseOriginals
			case "refresh-joined":
				joined <- event
				release = releaseJoined
			default:
				return nil
			}
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	}
	results := make(chan error, 2)
	for _, callID := range []string{"call:first", "call:second"} {
		transport, err := NewHTTP(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := transport.WithSession(store)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			results <- signed.Invoke(WithConformanceHooks(t.Context(), callID, hooks), "catalog.create", map[string]string{}, &struct{}{})
		}()
	}
	firstRejected, secondRejected := <-rejected, <-rejected
	if firstRejected.CallID == secondRejected.CallID || requests.Load() != 2 {
		t.Fatal("both independent clients did not process their original rejection")
	}
	unblockOriginals()
	<-started
	firstJoin, secondJoin := <-joined, <-joined
	if firstJoin.CallID == secondJoin.CallID || firstJoin.RefreshRef == "" || firstJoin.RefreshRef != secondJoin.RefreshRef || strings.Contains(firstJoin.RefreshRef, original.RefreshToken) {
		t.Fatalf("refresh participation differs: %+v, %+v", firstJoin, secondJoin)
	}
	if refreshes.Load() != 1 || requests.Load() != 2 {
		t.Fatal("refresh was duplicated or originals retried before release")
	}
	unblockJoined()
	unblockRefresh()
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(participation) != 2 || participation[0].Joined == nil || participation[1].Joined == nil || *participation[0].Joined == *participation[1].Joined || !participation[0].Measurable || !participation[1].Measurable {
		t.Fatalf("actual initiator and waiter were not observed: %+v", participation)
	}
	if requests.Load() != 4 || refreshes.Load() != 1 || store.Credentials() != rotated {
		t.Fatal("shared refresh did not save rotation and retry each original once")
	}
}

func TestConformanceClearTraceDoesNotGuessCachedRemoval(t *testing.T) {
	store := newRefreshStore()
	expected := store.Credentials()
	cached := &cachedClearStore{refreshStore: store}
	var trace ConformanceSessionEvent
	ctx := WithConformanceHooks(t.Context(), "call:cached", ConformanceHooks{CredentialRefs: map[string]string{expected.AccessToken: "access:expected", expected.RefreshToken: "refresh:expected"}, SessionTrace: func(event ConformanceSessionEvent) { trace = event }})
	if err := conformanceClear(ctx, cached, expected); err != nil {
		t.Fatal(err)
	}
	if trace.Removed != nil || trace.Measurable {
		t.Fatal("cached store deletion was guessed")
	}
}

type cachedClearStore struct{ *refreshStore }

func (store *cachedClearStore) Clear(context.Context, SessionCredentials) error { return nil }

func TestConformanceAutoRefreshExchangeProjection(t *testing.T) {
	store := newRefreshStore()
	rotated := newRefreshStore().Credentials()
	rotated.AccessToken = strings.Repeat("c", 43)
	var bodyBytes int64
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/auth.refresh" {
			writeSessionCredentials(t, response, rotated)
			return
		}
		if request.Header.Get("Authorization") == "Bearer "+rotated.AccessToken {
			fmt.Fprint(response, "{}")
			return
		}
		response.WriteHeader(401)
		fmt.Fprint(response, `{"error":"invalid_token"}`)
	}))
	defer server.Close()
	transport, err := NewHTTP(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := transport.WithSession(store)
	if err != nil {
		t.Fatal(err)
	}
	var events []ConformanceTransportEvent
	ctx := WithConformanceHooks(t.Context(), "call:exchange", ConformanceHooks{Observe: func(event ConformanceTransportEvent) { events = append(events, event) }})
	if err := signed.Invoke(ctx, "catalog.create", map[string]string{}, &struct{}{}); err != nil {
		t.Fatal(err)
	}
	phases := make(map[string]int)
	statuses := make(map[int]bool)
	var received, peak int64
	var sequence uint64
	var elapsed float64
	for _, event := range events {
		if !event.Measurable || event.ReadBytes < received || event.PeakRetainedBytes < peak || event.Sequence <= sequence || event.ElapsedMs < elapsed {
			t.Fatalf("exchange observation=%+v", event)
		}
		received = event.ReadBytes
		peak = event.PeakRetainedBytes
		sequence = event.Sequence
		elapsed = event.ElapsedMs
		phases[event.Phase]++
		if event.Phase == "read" {
			statuses[*event.HTTPStatus] = true
			bodyBytes = event.ReadBytes
		}
		if event.Phase == "headers" && *event.HTTPStatus != 200 {
			t.Fatal("projected original rejection headers")
		}
	}
	if phases["headers"] != 1 || phases["reader-closed"] != 1 || phases["completed"] != 1 || !statuses[401] || !statuses[200] || bodyBytes <= 2 {
		t.Fatalf("projection phases=%v statuses=%v bytes=%d", phases, statuses, bodyBytes)
	}
}

func TestConformanceIndependentClientsDoNotInferRefreshSharing(t *testing.T) {
	for _, shared := range []bool{true, false} {
		t.Run(fmt.Sprintf("shared store=%t", shared), func(t *testing.T) {
			firstStore := newRefreshStore()
			secondStore := firstStore
			if !shared {
				secondStore = &refreshStore{credentials: firstStore.Credentials()}
			}
			rotated := newRefreshStore().Credentials()
			rotated.AccessToken = strings.Repeat("c", 43)
			started := make(chan struct{})
			release := make(chan struct{})
			pathEntered := make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/auth.refresh" {
					close(started)
					<-release
					writeSessionCredentials(t, response, rotated)
					return
				}
				if request.Header.Get("Authorization") == "Bearer "+rotated.AccessToken {
					fmt.Fprint(response, "{}")
				} else {
					writeRefreshResponse(t, response, 401, map[string]string{"error": "invalid_token"})
				}
			}))
			defer server.Close()
			defer unblock()
			first, err := NewHTTP(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			first, err = first.WithSession(firstStore)
			if err != nil {
				t.Fatal(err)
			}
			second, err := NewHTTP(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			second, err = second.WithSession(secondStore)
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var secondTrace []ConformanceSessionEvent
			ctx := WithConformanceHooks(t.Context(), "call:independent", ConformanceHooks{SessionTrace: func(event ConformanceSessionEvent) {
				mu.Lock()
				secondTrace = append(secondTrace, event)
				mu.Unlock()
				if event.StorePath {
					close(pathEntered)
				}
			}})
			results := make(chan error, 2)
			go func() {
				results <- first.Invoke(WithConformanceHooks(t.Context(), "call:first", ConformanceHooks{}), "catalog.create", map[string]string{}, &struct{}{})
			}()
			<-started
			go func() { results <- second.Invoke(ctx, "catalog.create", map[string]string{}, &struct{}{}) }()
			<-pathEntered
			mu.Lock()
			firstPath := secondTrace[0]
			mu.Unlock()
			if firstPath.Joined != nil || firstPath.RefreshRef != nil || firstPath.Measurable {
				t.Fatalf("store sharing inferred=%+v", firstPath)
			}
			remaining := 2
			if !shared {
				<-results
				remaining = 1
			}
			unblock()
			for range remaining {
				err := <-results
				if shared && err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestConformanceOverflowReadImmediatelyPublishesLimit(t *testing.T) {
	const limit = 1 << 20
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Length", strconv.Itoa(limit-1+8192))
		response.WriteHeader(200)
		fmt.Fprint(response, "{}"+strings.Repeat(" ", limit-3))
		response.(http.Flusher).Flush()
		<-release
		fmt.Fprint(response, strings.Repeat(" ", 8192))
	}))
	defer server.Close()
	defer unblock()
	transport, err := NewHTTP(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	var events []ConformanceTransportEvent
	ctx := WithConformanceHooks(t.Context(), "call:split", ConformanceHooks{Observe: func(event ConformanceTransportEvent) {
		events = append(events, event)
		if event.Phase == "read" && event.RetainedBytes == limit-1 {
			unblock()
		}
	}})
	if err := transport.Invoke(ctx, "catalog.create", map[string]string{}, &struct{}{}); err == nil || err.Error() != "operation response is too large" {
		t.Fatalf("split overflow error=%v", err)
	}
	overflow := -1
	var peak int64
	for index, event := range events {
		if event.PeakRetainedBytes < peak {
			t.Fatal("peak decreased")
		}
		peak = event.PeakRetainedBytes
		if event.Phase == "read" && event.ReadBytes > limit {
			overflow = index
			break
		}
	}
	if overflow < 0 || overflow+1 >= len(events) || events[overflow+1].Phase != "limit" {
		t.Fatalf("overflow order=%+v", events)
	}
	for _, event := range events[overflow+1:] {
		if event.Phase == "read" {
			t.Fatal("additional read after first overflow")
		}
	}
}

func TestConformanceConcurrentCancellationPublicationOrder(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	closing := make(chan struct{})
	closed := make(chan struct{})
	stop := make(chan struct{})
	var phases []string
	ctx, finish, err := conformanceBegin(WithConformanceHooks(t.Context(), "call:order", ConformanceHooks{Observe: func(event ConformanceTransportEvent) {
		phases = append(phases, event.Phase)
		if event.Phase == "cancel-requested" {
			close(entered)
			<-release
		}
	}}), "http://127.0.0.1", false)
	if err != nil {
		t.Fatal(err)
	}
	exchangeCtx, _, end := conformanceRequest(ctx, &http.Client{}, "catalog.create", 0)
	connection := &conformanceConn{closed: make(chan struct{}), measurable: true, headersDone: true}
	close(connection.closed)
	conformanceEmission.Lock()
	conformanceExchangeFrom(exchangeCtx).conn = connection
	conformanceEmission.Unlock()
	conformanceHeaders(exchangeCtx, &http.Response{StatusCode: 200})
	go func() { conformanceStop(exchangeCtx, false); close(stop) }()
	<-entered
	go func() { close(closing); conformanceReaderClosed(exchangeCtx); close(closed) }()
	<-closing
	select {
	case <-closed:
		t.Fatal("reader published before cancel-requested completed")
	default:
	}
	close(release)
	<-stop
	<-closed
	end(errors.New("read failed"))
	finish()
	joined := strings.Join(phases, ",")
	if !strings.Contains(joined, "cancel-requested,cancel-observed,reader-closed") {
		t.Fatalf("concurrent publication=%s", joined)
	}
}

func TestConformanceOtherUnauthorizedErrorDoesNotRefresh(t *testing.T) {
	store := newRefreshStore()
	var refreshes int
	var barriers []ConformanceBarrierEvent
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/auth.refresh" {
			refreshes++
		}
		writeRefreshResponse(t, response, 401, map[string]string{"error": "not_authorized"})
	}))
	defer server.Close()
	transport, err := NewHTTP(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := transport.WithSession(store)
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithConformanceHooks(t.Context(), "call:other", ConformanceHooks{Barrier: func(_ context.Context, event ConformanceBarrierEvent) error {
		barriers = append(barriers, event)
		return nil
	}})
	err = signed.Invoke(ctx, "catalog.create", map[string]string{}, &struct{}{})
	failure, ok := errors.AsType[*OperationError](err)
	if !ok || failure.Code != "not_authorized" || refreshes != 0 || len(barriers) != 1 || barriers[0].Point != "sdk-entered" {
		t.Fatalf("other 401=%v barriers=%+v refreshes=%d", err, barriers, refreshes)
	}
}

type conformanceTrackedStore struct {
	*refreshStore
	done chan struct{}
}

func (store *conformanceTrackedStore) Refresh(ctx context.Context, operation func(context.Context, SessionCredentials) (SessionCredentials, error)) (SessionCredentials, error) {
	defer close(store.done)
	return store.refreshStore.Refresh(ctx, operation)
}

func TestConformanceInitiatorBarrierDoesNotBlockRequestSend(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(fmt.Sprintf("timeout=%t", timeout), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				store := &conformanceTrackedStore{refreshStore: newRefreshStore(), done: make(chan struct{})}
				original := store.Credentials()
				rotated := original
				rotated.AccessToken = strings.Repeat("c", 43)
				peer := make(chan struct{})
				responseReady := make(chan struct{})
				entered := make(chan struct{})
				release := make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				transport, err := NewHTTP("http://127.0.0.1")
				if err != nil {
					t.Fatal(err)
				}
				defer unblock()
				transport.client.Transport.(*http.Transport).DialContext = func(context.Context, string, string) (net.Conn, error) {
					client, peerConn := net.Pipe()
					go func() {
						defer peerConn.Close()
						request, err := http.ReadRequest(bufio.NewReader(peerConn))
						if err != nil {
							t.Error(err)
							return
						}
						if _, err := io.Copy(io.Discard, request.Body); err != nil {
							t.Error(err)
							return
						}
						request.Body.Close()
						recorder := httptest.NewRecorder()
						if request.URL.Path == "/auth.refresh" {
							close(peer)
							if timeout {
								<-release
								return
							}
							writeSessionCredentials(t, recorder, rotated)
						} else if request.Header.Get("Authorization") == "Bearer "+rotated.AccessToken {
							fmt.Fprint(recorder, "{}")
						} else {
							writeRefreshResponse(t, recorder, 401, map[string]string{"error": "invalid_token"})
						}
						response := recorder.Result()
						defer response.Body.Close()
						response.ContentLength = int64(recorder.Body.Len())
						response.Close = true
						var wire bytes.Buffer
						if err := response.Write(&wire); err != nil {
							t.Error(err)
							return
						}
						if _, err := peerConn.Write(wire.Bytes()); err != nil {
							t.Error(err)
							return
						}
						if request.URL.Path == "/auth.refresh" {
							close(responseReady)
						}
					}()
					return client, nil
				}
				if timeout {
					transport.client.Timeout = 500 * time.Millisecond
				}
				signed, err := transport.WithSession(store)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				ctx = WithConformanceHooks(ctx, "call:initiator", ConformanceHooks{Barrier: func(ctx context.Context, event ConformanceBarrierEvent) error {
					if event.Point != "refresh-joined" {
						return nil
					}
					select {
					case <-peer:
					case <-ctx.Done():
						return ctx.Err()
					}
					if event.RefreshRef == "" {
						t.Error("missing actual refresh reference")
					}
					close(entered)
					select {
					case <-release:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				}})
				result := make(chan error, 1)
				go func() { result <- signed.Invoke(ctx, "catalog.create", map[string]string{}, &struct{}{}) }()
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal("initiator barrier did not observe peer arrival")
				}
				signed.refreshes.mu.Lock()
				flight := signed.refreshes.flights[original.RefreshToken]
				signed.refreshes.mu.Unlock()
				if flight == nil {
					t.Fatal("refresh passed its held barrier")
				}
				if !timeout {
					<-responseReady
					// net.Pipe has handed over the full response; exhaust runnable work
					// before asserting that the refresh runner is still at the barrier.
					synctest.Wait()
					if store.Credentials() != original {
						t.Fatal("refresh result applied before barrier release")
					}
					select {
					case <-store.done:
						t.Fatal("store refresh finished before barrier release")
					default:
					}
					unblock()
				}
				select {
				case err = <-result:
				case <-ctx.Done():
					t.Fatal("HTTP timeout left refresh blocked")
				}
				if timeout && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("timeout error=%v", err)
				}
				if !timeout && err != nil {
					t.Fatal(err)
				}
				<-flight.done
				<-store.done
				if !timeout && store.Credentials() != rotated {
					t.Fatal("released refresh result was not saved")
				}
				if !store.refreshMu.TryLock() {
					t.Fatal("store lock leaked after refresh")
				}
				store.refreshMu.Unlock()
			})
		})
	}
}

func TestConformanceCanceledCallPreservesSharedExchangeObservation(t *testing.T) {
	store := &conformanceTrackedStore{refreshStore: newRefreshStore(), done: make(chan struct{})}
	rotated := store.Credentials()
	rotated.AccessToken = strings.Repeat("c", 43)
	peer := make(chan struct{})
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/auth.refresh" {
			close(peer)
			<-release
			writeSessionCredentials(t, response, rotated)
			return
		}
		writeRefreshResponse(t, response, 401, map[string]string{"error": "invalid_token"})
	}))
	defer server.Close()
	defer unblock()
	transport, err := NewHTTP(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := transport.WithSession(store)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var mu sync.Mutex
	var events []ConformanceTransportEvent
	ctx = WithConformanceHooks(ctx, "call:canceled", ConformanceHooks{Observe: func(event ConformanceTransportEvent) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, event)
	}})
	result := make(chan error, 1)
	go func() { result <- signed.Invoke(ctx, "catalog.create", map[string]string{}, &struct{}{}) }()
	<-peer
	signed.refreshes.mu.Lock()
	flight := signed.refreshes.flights[store.Credentials().RefreshToken]
	signed.refreshes.mu.Unlock()
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("caller cancellation=%v", err)
	}
	mu.Lock()
	completedBeforeRelease := events[len(events)-1].Phase == "completed"
	mu.Unlock()
	if !completedBeforeRelease {
		t.Fatal("caller completion was not published")
	}
	unblock()
	<-flight.done
	<-store.done
	if store.Credentials() != rotated {
		t.Fatal("caller cancellation stopped shared refresh")
	}
	mu.Lock()
	defer mu.Unlock()
	completed, afterRead, afterClosed, headers := 0, false, false, 0
	var received, peak int64
	var sequence uint64
	var elapsed float64
	for _, event := range events {
		if event.ReadBytes < received || event.PeakRetainedBytes < peak || event.Sequence <= sequence || event.ElapsedMs < elapsed {
			t.Fatalf("nonmonotonic observation=%+v", event)
		}
		received, peak, sequence, elapsed = event.ReadBytes, event.PeakRetainedBytes, event.Sequence, event.ElapsedMs
		switch event.Phase {
		case "completed":
			completed++
		case "read":
			if completed > 0 {
				afterRead = true
				if event.HTTPStatus == nil || *event.HTTPStatus != 200 {
					t.Fatal("late refresh read lost its actual status")
				}
			}
		case "headers":
			headers++
		case "reader-closed":
			afterClosed = completed > 0
		}
	}
	if completed != 1 || headers != 1 || !afterRead || !afterClosed {
		t.Fatalf("completion=%d headers=%d late read=%t late close=%t", completed, headers, afterRead, afterClosed)
	}
}
