package chickinfry

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"golang.org/x/net/websocket"
)

const (
	realtimeBudget    = 30 * time.Second
	realtimeOpenLimit = 10 * time.Second
	realtimeQueueSize = 256
	realtimeFrameSize = 66_560
)

var realtimeUUID = regexp.MustCompile(`^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)
var realtimeWireError = regexp.MustCompile(`^[a-z_]{1,64}$`)

type realtimeTransport interface {
	Invoke(context.Context, string, any, any) error
}

// RealtimeClient opens subscriptions using the generated client's operation transport.
type RealtimeClient struct{ transport realtimeTransport }

// NewRealtimeClient binds realtime to the existing operation transport.
func NewRealtimeClient(transport realtimeTransport) *RealtimeClient {
	return &RealtimeClient{transport: transport}
}

// SubscribeOptions configures the application reload callback after a delivery gap.
type SubscribeOptions struct {
	OnGap func(context.Context, RealtimeGap) error
}

// RealtimeGap identifies the channel whose application state must be reloaded.
type RealtimeGap struct{ Type, Channel string }

// RealtimeEvent holds the next payload delivered on the channel.
type RealtimeEvent struct {
	Type, Channel string
	Payload       json.RawMessage
}

type realtimeConnection struct {
	socket       *websocket.Conn
	confirmation string
	checkpoint   *string
	prepared     bool
}

type realtimeRecovery struct {
	cursor     string
	complete   bool
	connection *realtimeConnection
}

type realtimeEvent struct {
	cursor  string
	payload json.RawMessage
}

type realtimeProbe struct {
	endpoint func(string) (string, error)
	point    func(string)
	dispatch func(string, func())
	inspect  func(func() map[string]int)
}
type realtimeProbeKey struct{}

// RealtimeSubscription owns one sequential event stream and its connection lifecycle.
type RealtimeSubscription struct {
	ctx         context.Context
	cancel      context.CancelFunc
	transport   realtimeTransport
	channel, id string
	onGap       func(context.Context, RealtimeGap) error
	probe       *realtimeProbe
	ready, done chan struct{}
	wake        chan struct{}
	consumed    atomic.Bool

	mu                                           sync.Mutex
	socket                                       *realtimeConnection
	recovery                                     *realtimeRecovery
	queue                                        []realtimeEvent
	last                                         string
	firstReady, active, demand, callbackRunning  bool
	failure                                      error
	deadline                                     *time.Timer
	budgetID, lossBudgets, connections, watchers int
}

// Subscribe waits for the first connection to be ready. Cancel ctx or unsubscribe to release it.
func (client *RealtimeClient) Subscribe(ctx context.Context, channel string, options SubscribeOptions) (*RealtimeSubscription, error) {
	if client == nil || client.transport == nil || !validRealtimeChannel(channel) {
		return nil, &ClientError{Code: CodeInvalidArgument}
	}
	ctx, cancel := context.WithCancel(ctx)
	probe, _ := ctx.Value(realtimeProbeKey{}).(*realtimeProbe)
	s := &RealtimeSubscription{
		ctx: ctx, cancel: cancel, transport: client.transport, channel: channel, id: newRealtimeID(),
		onGap: options.OnGap, probe: probe, active: true, ready: make(chan struct{}), done: make(chan struct{}), wake: make(chan struct{}, 1),
	}
	if probe != nil {
		probe.inspect(s.snapshot)
	}
	s.mu.Lock()
	s.startBudget()
	s.mu.Unlock()
	stop := context.AfterFunc(ctx, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.stop(sessionError(ctx.Err(), false))
	})
	go func() {
		defer close(s.done)
		defer stop()
		s.run()
		s.mu.Lock()
		s.stop(sessionError(ctx.Err(), false))
		s.mu.Unlock()
	}()
	if transport, ok := client.transport.(*HTTPTransport); ok && transport.session != nil {
		go s.renew(transport)
	}
	<-s.ready
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.firstReady {
		return nil, s.failure
	}
	return s, nil
}

// Events returns an iterator that may be consumed once. Each yield completes before the next delivery.
func (s *RealtimeSubscription) Events() iter.Seq2[RealtimeEvent, error] {
	return func(yield func(RealtimeEvent, error) bool) {
		if !s.consumed.CompareAndSwap(false, true) {
			yield(RealtimeEvent{}, &ClientError{Code: CodeFailedPrecondition})
			return
		}
		defer s.Unsubscribe()
		for {
			event, err, ok := s.next()
			if !ok {
				if err != nil {
					yield(RealtimeEvent{}, err)
				}
				return
			}
			if !yield(event, nil) {
				return
			}
		}
	}
}

// Unsubscribe ends the subscription. Repeated calls wait on the same cleanup.
func (s *RealtimeSubscription) Unsubscribe() {
	s.mu.Lock()
	s.stop(nil)
	s.mu.Unlock()
	<-s.done
}

func (s *RealtimeSubscription) next() (RealtimeEvent, error, bool) {
	for {
		s.mu.Lock()
		if !s.active {
			s.demand = false
			err := s.failure
			s.mu.Unlock()
			return RealtimeEvent{}, err, false
		}
		if !s.demand {
			s.demand = true
			s.point("demand")
		}
		s.recover()
		if s.recovery == nil && s.socket != nil && s.socket.prepared && len(s.queue) != 0 {
			head := s.queue[0]
			s.queue[0] = realtimeEvent{}
			s.queue = s.queue[1:]
			s.last = head.cursor
			s.demand = false
			s.acknowledge()
			s.mu.Unlock()
			return RealtimeEvent{Type: "event", Channel: s.channel, Payload: head.payload}, nil, true
		}
		s.mu.Unlock()
		<-s.wake
	}
}

func newRealtimeID() string {
	var id [16]byte
	rand.Read(id[:])
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
}

func validRealtimeChannel(value string) bool {
	return value != "" && len(value) <= 128 && utf8.ValidString(value) &&
		!strings.ContainsFunc(value, func(r rune) bool { return r < 32 || r == 127 })
}

func realtimeEndpoint(value string) (string, error) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "wss" || !strings.HasSuffix(u.Host, ".chickinfry.app") ||
		!realtimeUUID.MatchString(strings.TrimSuffix(u.Host, ".chickinfry.app")) ||
		value != "wss://"+u.Host+"/realtime" {
		return "", &ClientError{Code: CodeInternal}
	}
	return value, nil
}

func (s *RealtimeSubscription) notify() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *RealtimeSubscription) point(name string) {
	if s.probe != nil {
		s.probe.point(name)
	}
}

func (s *RealtimeSubscription) snapshot() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending, budget := 0, 0
	if s.demand {
		pending = 1
	}
	if s.lossBudgets > 0 {
		budget = int(realtimeBudget.Milliseconds())
	}
	return map[string]int{"pendingReads": pending, "activeRenewalWatchers": s.watchers,
		"reprepareBudgetMs": budget, "budgetResets": max(0, s.lossBudgets-1), "connectionsStarted": s.connections}
}

func (s *RealtimeSubscription) startBudget() {
	if s.deadline != nil {
		return
	}
	s.budgetID++
	id := s.budgetID
	if s.firstReady {
		s.lossBudgets++
	}
	s.deadline = time.AfterFunc(realtimeBudget, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.active && s.budgetID == id {
			s.stop(&ClientError{Code: CodeDeadlineExceeded})
		}
	})
}

func (s *RealtimeSubscription) clearBudget() {
	s.budgetID++
	if s.deadline != nil {
		s.deadline.Stop()
		s.deadline = nil
	}
}

func (s *RealtimeSubscription) stop(err error) {
	if !s.active {
		return
	}
	s.active, s.failure = false, err
	s.clearBudget()
	s.recovery = nil
	s.watchers = 0
	s.closeSocket()
	s.cancel()
	if !s.firstReady {
		close(s.ready)
	}
	s.notify()
}

func (s *RealtimeSubscription) closeSocket() {
	current := s.socket
	s.socket = nil
	s.queue = nil
	if current != nil {
		_ = current.socket.SetWriteDeadline(time.Now())
		_ = current.socket.Close()
	}
}

func (s *RealtimeSubscription) send(frame map[string]string) bool {
	frame["channel"] = s.channel
	_ = s.socket.socket.SetWriteDeadline(time.Now().Add(time.Second))
	if websocket.JSON.Send(s.socket.socket, frame) == nil {
		return true
	}
	s.closeSocket()
	s.startBudget()
	s.notify()
	return false
}

func (s *RealtimeSubscription) acknowledge() {
	c := s.socket
	if c != nil && c.prepared && c.checkpoint != nil && s.recovery == nil && len(s.queue) == 0 {
		if s.send(map[string]string{"type": "ack", "cursor": *c.checkpoint}) {
			c.checkpoint = nil
		}
	}
}

func (s *RealtimeSubscription) recover() {
	r := s.recovery
	if !s.active || r == nil || r.complete || s.callbackRunning || s.firstReady && !s.demand {
		return
	}
	s.callbackRunning = true
	go func() {
		err := s.onGap(s.ctx, RealtimeGap{Type: "gap", Channel: s.channel})
		s.mu.Lock()
		defer s.mu.Unlock()
		s.callbackRunning = false
		if s.active && s.recovery == r {
			if err != nil {
				s.stop(&ClientError{Code: CodeUnknown, cause: err})
				return
			}
			r.complete = true
			s.last = r.cursor
			s.closeSocket()
		}
		s.recover()
		s.notify()
	}()
}

func (s *RealtimeSubscription) gap(cursor string) {
	if s.onGap == nil {
		s.stop(&ClientError{Code: CodeDataLoss})
		return
	}
	s.recovery = &realtimeRecovery{cursor: cursor}
	s.socket.prepared = false
	s.queue = nil
	s.startBudget()
	s.point("gap")
	s.recover()
	s.notify()
}

type realtimeFrame struct {
	Type         string          `json:"type"`
	Channel      *string         `json:"channel"`
	Cursor       *string         `json:"cursor"`
	Previous     *string         `json:"previous"`
	Confirmation *string         `json:"confirmation"`
	Acknowledge  *bool           `json:"acknowledge"`
	Payload      json.RawMessage `json:"payload"`
	Error        string          `json:"error"`
}

func validRealtimeCursor(cursor *string) bool {
	return cursor != nil && (*cursor == "" || realtimeUUID.MatchString(*cursor))
}

func (s *RealtimeSubscription) receive(c *realtimeConnection, raw string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active || s.socket != c {
		s.point("discarded")
		return
	}
	fail := func() { s.stop(&ClientError{Code: CodeInternal}) }
	var frame realtimeFrame
	var fields map[string]json.RawMessage
	if !utf8.ValidString(raw) || json.Unmarshal([]byte(raw), &frame) != nil || json.Unmarshal([]byte(raw), &fields) != nil {
		fail()
		return
	}
	_, channelPresent := fields["channel"]
	if channelPresent && (frame.Channel == nil || *frame.Channel != s.channel) || !channelPresent && frame.Type != "error" {
		fail()
		return
	}
	switch frame.Type {
	case "ready":
		if !validRealtimeCursor(frame.Cursor) || fields["acknowledge"] != nil && frame.Acknowledge == nil ||
			fields["confirmation"] != nil && (frame.Confirmation == nil || !realtimeUUID.MatchString(*frame.Confirmation)) {
			fail()
			return
		}
		c.checkpoint = nil
		if frame.Acknowledge != nil && *frame.Acknowledge {
			c.checkpoint = frame.Cursor
		}
		if frame.Confirmation == nil {
			if c.confirmation == "" {
				c.confirmation = newRealtimeID()
				s.send(map[string]string{"type": "confirm", "confirmation": c.confirmation})
			}
			return
		}
		if *frame.Confirmation != c.confirmation {
			return
		}
		if r := s.recovery; r != nil {
			if !r.complete || r.connection != c {
				return
			}
			s.recovery = nil
			s.point("recovered")
		}
		c.prepared = true
		s.clearBudget()
		if !s.firstReady {
			s.firstReady = true
			close(s.ready)
		}
		s.acknowledge()
		s.notify()
	case "gap":
		if !validRealtimeCursor(frame.Cursor) {
			fail()
			return
		}
		s.gap(*frame.Cursor)
	case "event":
		if frame.Cursor == nil || !realtimeUUID.MatchString(*frame.Cursor) || !validRealtimeCursor(frame.Previous) || frame.Payload == nil {
			fail()
			return
		}
		cursor := *frame.Cursor
		if cursor == s.last || slices.ContainsFunc(s.queue, func(e realtimeEvent) bool { return e.cursor == cursor }) {
			return
		}
		previous := s.last
		if s.recovery != nil {
			previous = s.recovery.cursor
		}
		if len(s.queue) > 0 {
			previous = s.queue[len(s.queue)-1].cursor
		}
		limit := realtimeQueueSize
		if s.probe != nil {
			limit = 512
		}
		if len(s.queue) >= limit || *frame.Previous != previous {
			if len(s.queue) >= limit {
				s.point("overflow")
			}
			s.gap(cursor)
			return
		}
		s.queue = append(s.queue, realtimeEvent{cursor: cursor, payload: frame.Payload})
		s.notify()
	case "error":
		if !realtimeWireError.MatchString(frame.Error) {
			fail()
			return
		}
		code := CodeUnknown
		switch frame.Error {
		case "unauthorized_channel":
			code = CodePermissionDenied
		case "already_subscribed":
			code = CodeInternal
		case "too_many_channels":
			code = CodeResourceExhausted
		case "replay_failed", "realtime_unavailable":
			code = CodeUnavailable
		}
		s.stop(&ClientError{Code: code})
	default:
		fail()
	}
}

func (s *RealtimeSubscription) connect() (*websocket.Conn, bool) {
	var ticket struct {
		Ticket   string `json:"ticket"`
		Endpoint string `json:"endpoint"`
	}
	if err := s.transport.Invoke(s.ctx, "realtime.ticket", struct{}{}, &ticket); err != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		if remote, ok := errors.AsType[*OperationError](err); ok {
			if remote.Status == 429 || remote.Status >= 500 || remote.Status == 409 && !s.firstReady {
				return nil, true
			}
		} else if local, ok := errors.AsType[*ClientError](err); ok && (local.Code == CodeUnavailable || local.Code == CodeDeadlineExceeded) {
			return nil, true
		}
		s.stop(sessionError(err, false))
		return nil, false
	}
	validate := realtimeEndpoint
	if s.probe != nil {
		validate = s.probe.endpoint
	}
	endpoint, err := validate(ticket.Endpoint)
	if err != nil || !realtimeUUID.MatchString(ticket.Ticket) {
		s.mu.Lock()
		s.stop(&ClientError{Code: CodeInternal})
		s.mu.Unlock()
		return nil, false
	}
	origin := "https://" + strings.TrimSuffix(strings.TrimPrefix(endpoint, "wss://"), "/realtime")
	if httpTransport, ok := s.transport.(*HTTPTransport); ok {
		origin = httpTransport.origin
	}
	config, err := websocket.NewConfig(endpoint+"?ticket="+ticket.Ticket, origin)
	if err != nil {
		s.mu.Lock()
		s.stop(&ClientError{Code: CodeInternal})
		s.mu.Unlock()
		return nil, false
	}
	openCtx, cancel := context.WithTimeout(s.ctx, realtimeOpenLimit)
	defer cancel()
	socket, err := config.DialContext(openCtx)
	if err != nil {
		return nil, true
	}
	socket.MaxPayloadBytes = realtimeFrameSize
	return socket, true
}

func (s *RealtimeSubscription) run() {
	backoff := 500 * time.Millisecond
	for s.ctx.Err() == nil {
		ws, retry := s.connect()
		if !retry {
			return
		}
		if ws != nil {
			s.readSocket(ws)
			backoff = 500 * time.Millisecond
		}
		if !realtimeDelay(s.ctx, backoff) {
			return
		}
		backoff = min(backoff*2, 5*time.Second)
	}
}

var realtimeText = websocket.Codec{Unmarshal: func(data []byte, typ byte, into any) error {
	if typ != websocket.TextFrame {
		return errRealtimeFrame
	}
	*into.(*string) = string(data)
	return nil
}}
var errRealtimeFrame = errors.New("invalid realtime frame")

func (s *RealtimeSubscription) readSocket(ws *websocket.Conn) {
	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		_ = ws.Close()
		return
	}
	s.connections++
	c := &realtimeConnection{socket: ws}
	s.socket = c
	cursor := s.last
	if r := s.recovery; r != nil {
		cursor = r.cursor
		if r.complete {
			r.connection = c
		}
	}
	ok := s.send(map[string]string{"type": "subscribe", "cursor": cursor, "subscription": s.id})
	s.mu.Unlock()
	if !ok {
		return
	}
	for {
		var raw string
		err := realtimeText.Receive(ws, &raw)
		if err != nil {
			s.mu.Lock()
			if s.socket == c {
				if errors.Is(err, errRealtimeFrame) || errors.Is(err, websocket.ErrFrameTooLarge) {
					s.stop(&ClientError{Code: CodeInternal})
				} else {
					s.closeSocket()
					s.startBudget()
					s.notify()
				}
			}
			s.mu.Unlock()
			return
		}
		if s.probe == nil {
			s.receive(c, raw)
		} else {
			s.probe.dispatch(raw, func() { s.receive(c, raw) })
		}
	}
}

func realtimeDelay(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *RealtimeSubscription) renew(transport *HTTPTransport) {
	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		return
	}
	s.watchers = 1
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.watchers = 0; s.mu.Unlock() }()
	for s.ctx.Err() == nil {
		credentials := transport.session.Credentials()
		expires, err := time.Parse(time.RFC3339Nano, credentials.ExpiresAt)
		if err != nil {
			s.mu.Lock()
			s.stop(&ClientError{Code: CodeUnauthenticated})
			s.mu.Unlock()
			return
		}
		if !realtimeDelay(s.ctx, time.Until(expires.Add(-time.Minute))) {
			return
		}
		refreshed, err := transport.refreshSession(s.ctx, credentials)
		if err == nil && refreshed == credentials {
			err = &ClientError{Code: CodeInternal}
		}
		if err != nil {
			s.mu.Lock()
			s.stop(sessionError(err, false))
			s.mu.Unlock()
			return
		}
	}
}
