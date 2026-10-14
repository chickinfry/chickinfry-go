//go:build chik_conformance

package chik

import (
	"context"
	"maps"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ConformanceHooks registers trusted test callbacks; no callback receives token or body values.
// CredentialRefs maps in-memory token values to opaque references and is never emitted.
// Callback sinks must not reenter the SDK. Barrier callbacks must honor context cancellation.
type ConformanceHooks struct {
	Observe        func(ConformanceTransportEvent)
	Result         func(ConformanceResultEvent)
	SessionTrace   func(ConformanceSessionEvent)
	Barrier        func(context.Context, ConformanceBarrierEvent) error
	CredentialRefs map[string]string
}

// ConformanceResultEvent reports measured SDK metadata without user-visible error text.
// Nil fields remain unavailable; NetworkRequests counts actual network entry points.
type ConformanceResultEvent struct {
	HTTPStatus          *int
	RawTransportDetails *bool
	OutcomeUnknown      *bool
	NetworkRequests     int64
}

// ConformanceTransportEvent records actual transport measurements for one SDK call.
// LibraryRetainedBytes is transient: the tagged HTTP/1 transport fixes ReadBufferSize
// at 4096. net/http/transport.go creates its reader with bufio.NewReaderSize using
// that size (Go 1.26.9: lines 322-326, 1991; Go 1.27.2: lines 329-333, 2120).
// RetainedBytes and PeakRetainedBytes count the SDK-owned cumulative body buffer.
// Measurable=false requires an unimplemented result; nullable library counts are not zero estimates.
type ConformanceTransportEvent struct {
	Sequence             uint64  `json:"sequence"`
	CallID               string  `json:"callId"`
	ElapsedMs            float64 `json:"elapsedMs"`
	Phase                string  `json:"phase"`
	HTTPStatus           *int    `json:"httpStatus"`
	ReadBytes            int64   `json:"readBytes"`
	RetainedBytes        int64   `json:"retainedBytes"`
	PeakRetainedBytes    int64   `json:"peakRetainedBytes"`
	RuntimeRetainedBytes int64   `json:"runtimeRetainedBytes"`
	LibraryRetainedBytes *int64  `json:"libraryRetainedBytes"`
	TotalHeldBytes       *int64  `json:"totalHeldBytes"`
	FramingBytes         *int64  `json:"framingBytes"`
	Measurable           bool    `json:"measurable"`
}

// ConformanceSessionEvent reports refresh participation or an actual Clear attempt.
// Removed=nil means that the store's cached Credentials cannot prove removal.
type ConformanceSessionEvent struct {
	Sequence           uint64
	CallID             string
	Phase              string
	RefreshRef         *string
	Joined             *bool
	StorePath          bool
	ExpectedAccessRef  string
	ExpectedRefreshRef string
	Matched            bool
	Removed            *bool
	Measurable         bool
}

// ConformanceBarrierEvent identifies an SDK observation point without secrets.
// The refresh-started point is owned by the HTTP peer, not synthesized by this runtime.
type ConformanceBarrierEvent struct {
	CallID     string
	Point      string
	Entered    bool
	HTTPStatus *int
	RefreshRef string
}

type conformanceKey struct{}
type conformanceExchangeKey struct{}
type conformanceProbeKey struct{}

// Package tests inspect live buffers synchronously, outside the observation lock.
func conformanceProbe(ctx context.Context, response *http.Response, data []byte) {
	probe, _ := ctx.Value(conformanceProbeKey{}).(func(*http.Response, []byte))
	if probe != nil {
		probe(response, data)
	}
}

type conformanceState struct {
	hooks                ConformanceHooks
	callID, origin       string
	started              time.Time
	session              bool
	peak, received       int64
	last, final          *conformanceExchange
	flight               *refreshFlight
	completed            bool
	networkRequests      atomic.Int64
	retentionUnavailable bool
	finalUnobserved      bool
	blockedRefreshSent   bool
}

type conformanceExchange struct {
	call                                                           *conformanceState
	operation                                                      string
	original                                                       bool
	status                                                         *int
	held, delivered                                                int64
	conn                                                           *conformanceConn
	cancel                                                         context.CancelFunc
	ctx                                                            context.Context
	sent                                                           chan struct{}
	stopping, limited, closed, headersPublished, terminalPublished bool
	normalErrorEnvelope, refreshRejected                           bool
}

var conformanceEmission sync.Mutex
var conformanceSequence atomic.Uint64
var conformanceRefreshID atomic.Uint64
var conformanceRefreshes = struct {
	sync.Mutex
	byFlight map[*refreshFlight]string
}{byFlight: make(map[*refreshFlight]string)}

// WithConformanceHooks attaches immutable per-call observers in tagged builds only.
func WithConformanceHooks(ctx context.Context, callID string, hooks ConformanceHooks) context.Context {
	hooks.CredentialRefs = maps.Clone(hooks.CredentialRefs)
	return context.WithValue(ctx, conformanceKey{}, &conformanceState{hooks: hooks, callID: callID})
}

// ConformanceStoreRevision observes a MemoryStore's mutation count in tagged builds only.
// It starts at zero and increments once per successful Set or stored Refresh result,
// and once per Clear that removes credentials. It is an observation, not a lock;
// a separate Credentials call may observe a later mutation.
func ConformanceStoreRevision(store *MemoryStore) uint64 {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.revision
}

func conformanceStateFrom(ctx context.Context) *conformanceState {
	state, _ := ctx.Value(conformanceKey{}).(*conformanceState)
	return state
}
func conformanceExchangeFrom(ctx context.Context) *conformanceExchange {
	exchange, _ := ctx.Value(conformanceExchangeKey{}).(*conformanceExchange)
	return exchange
}

func conformanceBegin(ctx context.Context, origin string, session bool) (context.Context, func(), error) {
	previous := conformanceStateFrom(ctx)
	if previous == nil {
		return ctx, func() {}, nil
	}
	state := &conformanceState{hooks: previous.hooks, callID: previous.callID, origin: origin, session: session, started: time.Now()}
	ctx = context.WithValue(ctx, conformanceKey{}, state)
	err := conformanceBarrier(ctx, "sdk-entered", "")
	return ctx, func() {
		conformanceEmission.Lock()
		defer conformanceEmission.Unlock()
		if state.completed {
			return
		}
		if state.final == nil && state.last != nil && !state.finalUnobserved {
			state.selectFinalLocked(state.last)
		}
		if state.final != nil {
			state.final.terminalLocked()
		}
		state.emitLocked(state.final, "completed", 0)
		state.completed = true
	}, err
}
func conformanceBarrier(ctx context.Context, point, refreshRef string) error {
	state := conformanceStateFrom(ctx)
	if state == nil || state.hooks.Barrier == nil {
		return nil
	}
	event := ConformanceBarrierEvent{CallID: state.callID, Point: point, RefreshRef: refreshRef}
	if point == "sdk-entered" {
		event.Entered = true
	}
	if point == "both-originals-rejected" {
		event.HTTPStatus = new(http.StatusUnauthorized)
	}
	return state.hooks.Barrier(ctx, event)
}

// SDK transport-observation contract revision 3 (2026-10-13) projection:
// real reads are cumulative across exchanges; headers and
// terminal phases belong only to the final deciding exchange. For session calls
// their publication time is the final-exchange selection time, not a backdated header time.
func (state *conformanceState) selectFinalLocked(exchange *conformanceExchange) {
	if state.final != nil && state.final != exchange {
		return
	}
	state.final = exchange
	if exchange.status != nil && !exchange.headersPublished {
		exchange.headersPublished = true
		state.emitLocked(exchange, "headers", exchange.held)
	}
}
func (exchange *conformanceExchange) receivedBodyLocked() int64 {
	if exchange.conn != nil {
		body, _, valid := exchange.conn.snapshot()
		if valid {
			return body
		}
	}
	return exchange.delivered
}
func (state *conformanceState) emitLocked(exchange *conformanceExchange, phase string, held int64) {
	if state.hooks.Observe == nil {
		return
	}
	state.peak = max(state.peak, held)
	event := ConformanceTransportEvent{Sequence: conformanceSequence.Add(1), CallID: state.callID, ElapsedMs: float64(time.Since(state.started)) / float64(time.Millisecond), Phase: phase, RetainedBytes: held, RuntimeRetainedBytes: held, PeakRetainedBytes: state.peak, ReadBytes: state.received}
	if exchange == nil && state.last == nil {
		// No HTTP exchange was opened: the SDK stopped before transport entry.
		event.Measurable = true
		event.LibraryRetainedBytes = new(int64(0))
		event.TotalHeldBytes = new(held)
		event.FramingBytes = new(int64(0))
	}
	if exchange != nil {
		event.HTTPStatus = exchange.status
		if !exchange.closed {
			event.ReadBytes += exchange.delivered
		}
		if exchange.conn != nil {
			body, framing, valid := exchange.conn.snapshot()
			library := body - exchange.delivered
			if valid && library >= 0 && library <= conformanceReadBuffer {
				event.Measurable = true
				event.LibraryRetainedBytes = new(library)
				event.TotalHeldBytes = new(held + library)
				event.FramingBytes = new(framing)
			}
		}
	}
	if state.retentionUnavailable {
		event.Measurable = false
		event.TotalHeldBytes = nil
	}
	state.hooks.Observe(event)
}

func conformanceDecode(ctx context.Context) {
	if state := conformanceStateFrom(ctx); state != nil {
		conformanceEmission.Lock()
		state.retentionUnavailable = true
		conformanceEmission.Unlock()
	}
}

func conformanceRefreshFailure(ctx context.Context) {
	if state := conformanceStateFrom(ctx); state != nil {
		conformanceEmission.Lock()
		state.finalUnobserved = state.final == nil && state.last != nil && state.last.operation != "auth.refresh"
		conformanceEmission.Unlock()
	}
}
func conformanceRefreshBlocked(ctx context.Context) {
	if state := conformanceStateFrom(ctx); state != nil {
		conformanceEmission.Lock()
		state.blockedRefreshSent = true
		conformanceEmission.Unlock()
	}
}
func conformanceRejection(ctx context.Context, refreshRejected bool) {
	if exchange := conformanceExchangeFrom(ctx); exchange != nil {
		conformanceEmission.Lock()
		exchange.normalErrorEnvelope, exchange.refreshRejected = true, refreshRejected
		conformanceEmission.Unlock()
	}
}

func (exchange *conformanceExchange) stopLocked(limit bool) {
	if exchange.stopping {
		return
	}
	exchange.call.selectFinalLocked(exchange)
	exchange.stopping = true
	if limit && !exchange.limited {
		exchange.limited = true
		exchange.call.emitLocked(exchange, "limit", exchange.held)
	}
	exchange.call.emitLocked(exchange, "cancel-requested", exchange.held)
}
func (exchange *conformanceExchange) terminalLocked() {
	if exchange.call.final != exchange || !exchange.closed || exchange.terminalPublished {
		return
	}
	exchange.terminalPublished = true
	if exchange.stopping {
		exchange.call.emitLocked(exchange, "cancel-observed", exchange.held)
	}
	exchange.call.emitLocked(exchange, "reader-closed", exchange.held)
}

func conformanceFlightRegister(ctx context.Context, flight *refreshFlight, _ string) {
	state := conformanceStateFrom(ctx)
	// A later participant may enable hooks even if the initiator did not.
	conformanceRefreshes.Lock()
	conformanceRefreshes.byFlight[flight] = "refresh:" + strconv.FormatUint(conformanceRefreshID.Add(1), 10)
	conformanceRefreshes.Unlock()
	if state == nil {
		return
	}
	conformanceEmission.Lock()
	state.flight = flight
	conformanceEmission.Unlock()
}
func conformanceFlightEnd(flight *refreshFlight) {
	conformanceRefreshes.Lock()
	delete(conformanceRefreshes.byFlight, flight)
	conformanceRefreshes.Unlock()
}
func conformanceJoin(ctx context.Context, flight *refreshFlight, storePath bool) error {
	state := conformanceStateFrom(ctx)
	if state == nil {
		return nil
	}
	event := ConformanceSessionEvent{CallID: state.callID, Phase: "refresh", StorePath: storePath}
	// Entry into a store path is not evidence of a shared store refresh.
	if !storePath {
		conformanceRefreshes.Lock()
		ref, ok := conformanceRefreshes.byFlight[flight]
		conformanceRefreshes.Unlock()
		if ok {
			event.RefreshRef = new(ref)
			event.Joined = new(true)
			event.Measurable = true
		}
	}
	if state.hooks.SessionTrace != nil {
		conformanceEmission.Lock()
		event.Sequence = conformanceSequence.Add(1)
		state.hooks.SessionTrace(event)
		conformanceEmission.Unlock()
	}
	if event.RefreshRef != nil {
		return conformanceBarrier(ctx, "refresh-joined", *event.RefreshRef)
	}
	return nil
}
func conformanceRefreshSent(ctx context.Context) error {
	state := conformanceStateFrom(ctx)
	if state == nil {
		return nil
	}
	conformanceEmission.Lock()
	flight := state.flight
	conformanceEmission.Unlock()
	conformanceRefreshes.Lock()
	ref, ok := conformanceRefreshes.byFlight[flight]
	conformanceRefreshes.Unlock()
	if !ok {
		return nil
	}
	if state.hooks.SessionTrace != nil {
		conformanceEmission.Lock()
		state.hooks.SessionTrace(ConformanceSessionEvent{Sequence: conformanceSequence.Add(1), CallID: state.callID, Phase: "refresh", RefreshRef: new(ref), Joined: new(false), Measurable: true})
		conformanceEmission.Unlock()
	}
	return conformanceBarrier(ctx, "refresh-joined", ref)
}

func conformanceDo(client *http.Client, request *http.Request) (*http.Response, error) {
	exchange := conformanceExchangeFrom(request.Context())
	if exchange == nil || exchange.sent == nil {
		return client.Do(request)
	}
	type result struct {
		response *http.Response
		err      error
	}
	done := make(chan result, 1)
	go func() {
		response, err := client.Do(request)
		done <- result{response, err}
	}()
	var received result
	var returned bool
	select {
	case <-exchange.sent:
	case received = <-done:
		returned = true
		if received.err != nil {
			select {
			case <-exchange.sent:
			default:
				return received.response, received.err
			}
		} else {
			select {
			case <-exchange.sent:
			case <-request.Context().Done():
				received.response.Body.Close()
				return nil, request.Context().Err()
			}
		}
	}
	// Wait in the refresh runner, never net/http's writeLoop, and retain the
	// exchange deadline while the barrier keeps a received response unapplied.
	if err := conformanceRefreshSent(request.Context()); err != nil {
		exchange.cancel()
		if !returned {
			received = <-done
		}
		if received.response != nil {
			received.response.Body.Close()
		}
		return nil, err
	}
	if !returned {
		received = <-done
	}
	return received.response, received.err
}

// conformanceClearMatchedHook lets package tests force a login between a split compare/delete.
var conformanceClearMatchedHook func(*MemoryStore)

func conformanceClearMatched(store *MemoryStore) {
	if conformanceClearMatchedHook != nil {
		conformanceClearMatchedHook(store)
	}
}

func conformanceClear(ctx context.Context, store SessionStore, expected SessionCredentials) (err error) {
	state := conformanceStateFrom(ctx)
	if state == nil || state.hooks.SessionTrace == nil {
		return store.Clear(ctx, expected)
	}
	before := store.Credentials()
	event := ConformanceSessionEvent{CallID: state.callID, Phase: "clear", ExpectedAccessRef: state.hooks.CredentialRefs[expected.AccessToken], ExpectedRefreshRef: state.hooks.CredentialRefs[expected.RefreshToken], Matched: before.AccessToken == expected.AccessToken && before.RefreshToken == expected.RefreshToken}
	returned := false
	defer func() {
		if returned && err == nil && event.Removed == nil {
			after := store.Credentials()
			if after.AccessToken == "" && after.RefreshToken == "" {
				event.Removed = new(before.AccessToken != "" || before.RefreshToken != "")
			} else if !event.Matched && after == before {
				event.Removed = new(false)
			}
		}
		event.Measurable = event.Removed != nil && event.ExpectedAccessRef != "" && event.ExpectedRefreshRef != ""
		conformanceEmission.Lock()
		event.Sequence = conformanceSequence.Add(1)
		state.hooks.SessionTrace(event)
		conformanceEmission.Unlock()
	}()
	if memory, ok := store.(*MemoryStore); ok {
		err = ctx.Err()
		if err == nil {
			matched, removed := memory.clear(expected)
			event.Matched, event.Removed = matched, new(removed)
		}
	} else {
		err = store.Clear(ctx, expected)
	}
	returned = true
	return err
}

const conformanceReadBuffer = 4096

func conformanceRequest(ctx context.Context, client *http.Client, operation string, bodyBytes int) (context.Context, *http.Client, func(error)) {
	state := conformanceStateFrom(ctx)
	if state == nil {
		return ctx, client, func(error) {}
	}
	conformanceEmission.Lock()
	exchange := &conformanceExchange{call: state, operation: operation, original: state.last == nil}
	state.last = exchange
	conformanceEmission.Unlock()
	var requestCtx context.Context
	var cancel context.CancelFunc
	if client.Timeout > 0 {
		requestCtx, cancel = context.WithTimeout(ctx, client.Timeout)
	} else {
		requestCtx, cancel = context.WithCancel(ctx)
	}
	requestCtx = context.WithValue(requestCtx, conformanceExchangeKey{}, exchange)
	exchange.ctx = requestCtx
	exchange.cancel = cancel

	watchDone := make(chan struct{})
	watch := context.AfterFunc(requestCtx, func() { defer close(watchDone); conformanceStop(requestCtx, false) })
	copy := *client
	if state.hooks.Observe != nil || state.hooks.Result != nil || state.hooks.Barrier != nil || state.hooks.SessionTrace != nil {
		transport, ok := client.Transport.(*http.Transport)
		if observed, wrapped := client.Transport.(*conformanceNetworkTransport); wrapped {
			transport, ok = observed.transport, true
		}
		if client.Transport == nil {
			transport, ok = http.DefaultTransport.(*http.Transport)
		}
		if ok && transport != nil && strings.HasPrefix(state.origin, "http://") {
			if operation == "auth.refresh" {
				exchange.sent = make(chan struct{})
			}
			owned := transport.Clone()
			owned.DisableKeepAlives = true
			owned.DisableCompression = true
			owned.ReadBufferSize = conformanceReadBuffer
			owned.Protocols = new(http.Protocols)
			owned.Protocols.SetHTTP1(true)
			dial := owned.DialContext
			if dial == nil {
				dial = (&net.Dialer{}).DialContext
			}
			owned.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				connection, err := dial(ctx, network, address)
				if err != nil {
					return nil, err
				}
				wrapped := &conformanceConn{Conn: connection, measurable: true, remaining: -1, closed: make(chan struct{}), requestRemaining: bodyBytes}
				if operation == "auth.refresh" {
					wrapped.onRequestSent = sync.OnceFunc(func() { close(exchange.sent) })
				}
				conformanceEmission.Lock()
				if exchange.conn != nil {
					wrapped.measurable = false
				}
				exchange.conn = wrapped
				conformanceEmission.Unlock()
				return wrapped, nil
			}
			copy.Transport = owned
			if observed, wrapped := client.Transport.(*conformanceNetworkTransport); wrapped {
				copy.Transport = &conformanceNetworkTransport{transport: owned, counter: observed.counter}
			}
		}
	}
	return requestCtx, &copy, func(result error) {
		if !watch() {
			<-watchDone
		}
		conformanceEmission.Lock()
		needsClose := !exchange.closed && exchange.conn != nil
		conformanceEmission.Unlock()
		if needsClose {
			conformanceStop(requestCtx, false)
			cancel()
			conformanceReaderClosed(requestCtx)
		}
		conformanceEmission.Lock()
		final := !state.session || (!exchange.original && operation != "auth.refresh") || (exchange.original && (operation == "auth.refresh" || !isInvalidToken(result))) || (operation == "auth.refresh" && result != nil)
		if final {
			state.selectFinalLocked(exchange)
			exchange.terminalLocked()
		}
		conformanceEmission.Unlock()
		cancel()
		if closer, ok := copy.Transport.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}
}
func conformanceHeaders(ctx context.Context, response *http.Response) {
	if exchange := conformanceExchangeFrom(ctx); exchange != nil {
		conformanceEmission.Lock()
		defer conformanceEmission.Unlock()
		exchange.status = new(response.StatusCode)
		if exchange.call.final == exchange || !exchange.call.session || (exchange.original && exchange.operation == "auth.refresh") {
			exchange.call.selectFinalLocked(exchange)
		}
	}
}
func conformanceRead(ctx context.Context, n, held int) bool {
	exchange := conformanceExchangeFrom(ctx)
	if exchange == nil || n == 0 {
		return false
	}
	conformanceEmission.Lock()
	exchange.delivered += int64(n)
	exchange.held = int64(held)
	exchange.call.peak = max(exchange.call.peak, exchange.held)
	overflow := exchange.delivered > 1<<20
	if overflow {
		exchange.call.selectFinalLocked(exchange)
	}
	exchange.call.emitLocked(exchange, "read", exchange.held)
	if overflow {
		exchange.stopLocked(true)
	}
	conformanceEmission.Unlock()
	if overflow {
		exchange.cancel()
	}
	return overflow
}
func conformanceStop(ctx context.Context, limit bool) {
	exchange := conformanceExchangeFrom(ctx)
	if exchange == nil {
		return
	}
	conformanceEmission.Lock()
	exchange.stopLocked(limit)
	conformanceEmission.Unlock()
	exchange.cancel()
}
func conformanceReaderClosed(ctx context.Context) {
	exchange := conformanceExchangeFrom(ctx)
	if exchange == nil {
		return
	}
	if ctx.Err() != nil {
		conformanceStop(ctx, false)
	}
	conformanceEmission.Lock()
	connection := exchange.conn
	stopping := exchange.stopping
	already := exchange.closed
	conformanceEmission.Unlock()
	if already {
		return
	}
	if stopping && connection != nil {
		<-connection.closed
	}
	conformanceEmission.Lock()
	defer conformanceEmission.Unlock()
	if exchange.closed {
		return
	}
	exchange.call.received += exchange.delivered
	exchange.closed = true
	exchange.terminalLocked()
}
