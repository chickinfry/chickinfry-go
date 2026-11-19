package driver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/chickinfry/chickinfry-go"
)

// RealtimeFactory opens the realtime and query surfaces of one generated client.
type RealtimeFactory func(*chickinfry.HTTPTransport) (*chickinfry.RealtimeClient, func(context.Context) (any, error))

type realtimeHooks struct {
	endpoint func(string) (string, error)
	point    func(string)
	dispatch func(string, func())
	inspect  func(func() map[string]int)
}

type decodeFailure struct{}

func (*decodeFailure) Error() string { return "customer decode failed" }

type recoveryFailure struct{ cause error }

func (*recoveryFailure) Error() string   { return "customer recovery failed" }
func (e *recoveryFailure) Unwrap() error { return e.cause }

type realtimeTrial struct {
	mu              sync.Mutex
	ctx             context.Context
	cancel          context.CancelFunc
	changed         chan struct{}
	done            chan struct{}
	origin          string
	client          *chickinfry.RealtimeClient
	list            func(context.Context) (any, error)
	sub             *chickinfry.RealtimeSubscription
	inspect         func() map[string]int
	holding         bool
	held            map[string]chan struct{}
	frames          map[string]func()
	points          map[string]bool
	facts           map[string]any
	events          []string
	callbacks, gaps int
	customerFailure *recoveryFailure
}

func newRealtimeTrial(ctx context.Context, origin string, client *chickinfry.RealtimeClient, list func(context.Context) (any, error)) *realtimeTrial {
	ctx, cancel := context.WithCancel(ctx)
	return &realtimeTrial{ctx: ctx, cancel: cancel, origin: origin, client: client, list: list,
		changed: make(chan struct{}), held: map[string]chan struct{}{}, frames: map[string]func(){}, points: map[string]bool{},
		events: []string{}, facts: map[string]any{"state": "ready", "callbackStarts": 0, "callbackCompletions": 0, "callbackOverlapAtMost": 0,
			"dbReads": 0, "pendingReads": 0, "activeRenewalWatchers": 0, "deliveredAfterEnd": 0, "publicWireOperations": 0,
			"terminalErrors": 0, "staleFramesHeld": 0, "staleFramesDiscarded": 0}}
}

func (t *realtimeTrial) mark(point string) {
	t.points[point] = true
	close(t.changed)
	t.changed = make(chan struct{})
}

func (t *realtimeTrial) increase(key string) { t.facts[key] = t.facts[key].(int) + 1 }

func (t *realtimeTrial) hold(ctx context.Context, name, point string) error {
	t.mu.Lock()
	wait := make(chan struct{})
	t.held[name] = wait
	t.mark(point)
	t.mu.Unlock()
	select {
	case <-wait:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *realtimeTrial) hooks() realtimeHooks {
	return realtimeHooks{
		endpoint: func(value string) (string, error) {
			if !strings.HasPrefix(t.origin, "http://127.0.0.1:") || value != "ws://"+strings.TrimPrefix(t.origin, "http://")+"/realtime" {
				return "", &chickinfry.ClientError{Code: chickinfry.CodeInternal}
			}
			return value, nil
		},
		point: func(point string) {
			t.mu.Lock()
			defer t.mu.Unlock()
			switch point {
			case "gap":
				t.gaps++
				if t.gaps == 1 {
					t.mark("gap-received")
				} else {
					t.mark("gap-received-again")
				}
			case "demand":
				t.mark("subscribed")
			case "overflow":
				t.mark("overflow-received")
			case "recovered":
				t.mark("recovered")
			case "discarded":
				t.increase("staleFramesDiscarded")
			}
		},
		dispatch: func(raw string, receive func()) {
			var header struct {
				Type string `json:"type"`
			}
			_ = json.Unmarshal([]byte(raw), &header)
			t.mu.Lock()
			hold := t.holding && (header.Type == "ready" || header.Type == "event") && t.frames[header.Type] == nil
			if hold {
				t.frames[header.Type] = receive
				t.increase("staleFramesHeld")
				if len(t.frames) == 2 {
					t.mark("stale-frames-held")
				}
			}
			t.mu.Unlock()
			if !hold {
				receive()
			}
		},
		inspect: func(f func() map[string]int) { t.mu.Lock(); t.inspect = f; t.mu.Unlock() },
	}
}

func (t *realtimeTrial) start(mode, handler, channel string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.done != nil {
		return false
	}
	t.done = make(chan struct{})
	go func() {
		defer func() { t.mu.Lock(); t.mark("ended"); close(t.done); t.mu.Unlock() }()
		ctx := attachRealtimeHooks(t.ctx, t.hooks())
		options := chickinfry.SubscribeOptions{}
		if mode != "absent" {
			options.OnGap = func(ctx context.Context, _ chickinfry.RealtimeGap) error {
				t.mu.Lock()
				t.increase("callbackStarts")
				count := t.facts["callbackStarts"].(int)
				t.callbacks++
				t.facts["callbackOverlapAtMost"] = max(t.callbacks, t.facts["callbackOverlapAtMost"].(int))
				t.mu.Unlock()
				defer func() { t.mu.Lock(); t.callbacks--; t.mu.Unlock() }()
				if _, err := t.list(ctx); err != nil {
					return err
				}
				t.mu.Lock()
				t.increase("dbReads")
				if mode == "fail" || mode == "cause" {
					failure := &recoveryFailure{cause: &decodeFailure{}}
					t.customerFailure = failure
					t.mu.Unlock()
					return failure
				}
				t.mu.Unlock()
				point := "gap-entered"
				if count > 1 {
					point = "gap-entered-again"
				}
				if err := t.hold(ctx, "gap", point); err != nil {
					return err
				}
				t.mu.Lock()
				t.increase("callbackCompletions")
				t.mu.Unlock()
				return nil
			}
		}
		sub, err := t.client.Subscribe(ctx, channel, options)
		if err != nil {
			t.finish(err, "subscribe")
			return
		}
		t.mu.Lock()
		t.sub = sub
		t.mu.Unlock()
		for event, failure := range sub.Events() {
			if failure != nil {
				err = failure
				break
			}
			var value struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(event.Payload, &value) != nil || (value.ID != "A" && value.ID != "B" && value.ID != "C" && value.ID != "overflow") {
				err = &chickinfry.ClientError{Code: chickinfry.CodeInternal}
				break
			}
			t.mu.Lock()
			if t.facts["state"] != "ready" {
				t.increase("deliveredAfterEnd")
			}
			t.events = append(t.events, value.ID)
			t.mu.Unlock()
			if value.ID == "A" && handler == "hold-a" {
				if err = t.hold(ctx, "event-a", "event-a-entered"); err != nil {
					break
				}
			}
			t.mu.Lock()
			t.mark("event-" + strings.ToLower(value.ID) + "-complete")
			t.mu.Unlock()
		}
		t.finish(err, "events")
	}()
	return true
}

func (t *realtimeTrial) finish(err error, phase string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ctx.Err() != nil {
		t.facts["state"] = "canceled"
		return
	}
	if err == nil {
		t.facts["state"] = "ended"
		return
	}
	code := "unknown"
	var status *int
	if local, ok := errors.AsType[*chickinfry.ClientError](err); ok {
		code = string(local.Code)
	}
	if remote, ok := errors.AsType[*chickinfry.OperationError](err); ok {
		code, status = remote.Code, new(remote.Status)
	}
	t.facts["state"], t.facts["errorCode"], t.facts["httpStatus"], t.facts["errorPhase"] = "error", code, status, phase
	t.increase("terminalErrors")
	if cause, ok := errors.AsType[*recoveryFailure](err); ok {
		t.facts["errorType"] = "RecoveryFailure"
		decoded, ok := errors.AsType[*decodeFailure](cause)
		if ok {
			t.facts["causeType"] = "DecodeFailure"
		}
		t.facts["causePreserved"] = cause == t.customerFailure && ok && decoded == cause.cause
	}
}

func (t *realtimeTrial) await(ctx context.Context, point string) bool {
	for {
		t.mu.Lock()
		ready, ch := point == "snapshot" || t.points[point], t.changed
		t.mu.Unlock()
		if ready {
			return true
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return false
		}
	}
}

func (t *realtimeTrial) snapshot() map[string]any {
	t.mu.Lock()
	inspect := t.inspect
	t.mu.Unlock()
	var metrics map[string]int
	if inspect != nil {
		metrics = inspect()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	result := make(map[string]any, len(t.facts)+len(metrics)+1)
	for name, value := range t.facts {
		result[name] = value
	}
	for name, value := range metrics {
		if name != "connectionsStarted" {
			result[name] = value
		}
	}
	result["eventIds"] = append([]string{}, t.events...)
	return result
}

func (t *realtimeTrial) close() {
	t.cancel()
	t.mu.Lock()
	done := t.done
	t.mu.Unlock()
	if done != nil {
		<-done
	}
}

func (s *server) realtimeCommand(req request, a args) *Error {
	t := s.realtime
	if s.protocol != 2 || t == nil {
		return failure("unimplemented", "unimplemented")
	}
	if req.Command == "realtime.start" {
		if s.clients[a.ClientRef] == nil || a.Transport != "plain" || a.Channel != "orders" ||
			(a.OnGap != "hold" && a.OnGap != "absent" && a.OnGap != "fail" && a.OnGap != "cause") ||
			(a.EventHandler != "normal" && a.EventHandler != "hold-a") || !t.start(a.OnGap, a.EventHandler, a.Channel) {
			return failure("driver", "invalid_args")
		}
		s.reply(req.ID, map[string]bool{"accepted": true}, nil)
		return nil
	}
	s.workers.Go(func() {
		ctx, cancel := context.WithTimeout(s.ctx, time.Duration(a.TimeoutMS)*time.Millisecond)
		defer cancel()
		result := any(map[string]bool{"accepted": true})
		var problem *Error
		switch req.Command {
		case "realtime.observe":
			if !t.await(ctx, a.Point) {
				problem = failure("driver", "deadline_exceeded")
			} else {
				result = map[string]any{"facts": t.snapshot()}
			}
		case "realtime.release":
			t.mu.Lock()
			gate := t.held[a.Point]
			if gate != nil {
				delete(t.held, a.Point)
				close(gate)
			} else {
				problem = failure("driver", "invalid_args")
			}
			t.mu.Unlock()
		case "realtime.cancel":
			t.close()
		case "realtime.unsubscribe":
			t.mu.Lock()
			sub, done := t.sub, t.done
			t.mu.Unlock()
			if sub == nil {
				problem = failure("driver", "invalid_args")
			} else {
				sub.Unsubscribe()
				sub.Unsubscribe()
				<-done
			}
		case "realtime.second-consumer":
			t.mu.Lock()
			sub, inspect := t.sub, t.inspect
			t.mu.Unlock()
			if sub == nil || inspect == nil {
				problem = failure("driver", "invalid_args")
				break
			}
			before := inspect()["connectionsStarted"]
			denied := false
			for _, err := range sub.Events() {
				if local, ok := errors.AsType[*chickinfry.ClientError](err); ok {
					denied = local.Code == chickinfry.CodeFailedPrecondition
				}
				break
			}
			connections := inspect()["connectionsStarted"] - before
			t.mu.Lock()
			t.facts["exclusiveConsumption"], t.facts["consumptionRejection"], t.facts["newConnections"] = denied, "runtime", connections
			t.mu.Unlock()
		case "realtime.hold-dispatch":
			t.mu.Lock()
			t.holding = true
			t.mu.Unlock()
		case "realtime.release-dispatch":
			t.mu.Lock()
			frames := t.frames
			t.frames = map[string]func(){}
			t.holding = false
			t.mu.Unlock()
			for _, dispatch := range frames {
				dispatch()
			}
		}
		s.reply(req.ID, result, problem)
	})
	return nil
}
