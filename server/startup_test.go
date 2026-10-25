package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStartupConcurrentAndCancelledWaiter(t *testing.T) {
	resetRuntime(t)
	gate := make(chan struct{})
	entered := make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	defer release()
	var setups, completed, business atomic.Int32
	RegisterStartup(func() (Handler, error) {
		setups.Add(1)
		close(entered)
		<-gate
		return func(Request) (any, error) {
			business.Add(1)
			return nil, nil
		}, nil
	})
	if setups.Load() != 0 {
		t.Fatal("registration ran startup")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	var workers sync.WaitGroup
	defer func() { release(); workers.Wait() }()
	workers.Go(func() { result <- Initialize() })
	cancelled := make(chan bool, 1)
	workers.Go(func() {
		select {
		case <-ctx.Done():
			cancelled <- true
		case <-result:
			cancelled <- false
		}
	})
	for range 8 {
		workers.Go(func() {
			if Initialize() == nil {
				completed.Add(1)
			}
		})
	}
	<-entered
	cancel()
	if !<-cancelled || setups.Load() != 1 || completed.Load() != 0 || handler != nil || business.Load() != 0 {
		t.Fatal("startup completed or published before the barrier")
	}
	ready := make(chan error, 1)
	workers.Go(func() { ready <- Initialize() })
	select {
	case <-ready:
		t.Fatal("initialization returned before startup completed")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	workers.Wait()
	if <-ready != nil {
		t.Fatal("waiting initializer did not succeed")
	}
	if err := <-result; err != nil || Initialize() != nil || InitializeStatus() != 0 || setups.Load() != 1 || completed.Load() != 8 {
		t.Fatal("startup result was not shared after caller cancellation")
	}
	for range 2 {
		if status := handleFrame([]byte(`{"rid":1}`)); status != 200 {
			t.Fatalf("initialized dispatch status=%d", status)
		}
	}
	if setups.Load() != 1 || business.Load() != 2 {
		t.Fatal("dispatch did not retain the initialized handler")
	}
}

func TestStartupFailures(t *testing.T) {
	for _, mode := range []string{"error", "sentinel", "public error", "panic", "sentinel panic", "nil handler", "unregistered"} {
		t.Run(mode, func(t *testing.T) {
			resetRuntime(t)
			setups, business := 0, 0
			if mode != "unregistered" {
				RegisterStartup(func() (Handler, error) {
					setups++
					value := func(Request) (any, error) { business++; return nil, nil }
					switch mode {
					case "error":
						return value, errors.New("private startup failure")
					case "sentinel":
						return value, ErrNotImplemented
					case "public error":
						return value, &OperationError{Status: 401, Code: "unauthenticated"}
					case "panic":
						panic("private startup failure")
					case "sentinel panic":
						panic(ErrNotImplemented)
					default:
						return nil, nil
					}
				})
			}
			first := Initialize()
			failure, ok := errors.AsType[*OperationError](first)
			if !ok || failure.Status != 500 || failure.Code != "operation_failed" {
				t.Fatal("startup failure was not sanitized")
			}
			for range 2 {
				if Initialize() != first || InitializeStatus() != 500 {
					t.Fatal("startup failure was not retained")
				}
				requireFailure(t, handleFrame([]byte(`{"rid":1}`)), 500, "operation_failed")
			}
			want := 1
			if mode == "unregistered" {
				want = 0
			}
			if setups != want || business != 0 || handler != nil {
				t.Fatalf("failed startup counts: setup=%d business=%d", setups, business)
			}
		})
	}
}

func TestStartupDirectHandle(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[fail], func(t *testing.T) {
			resetRuntime(t)
			setups, business := 0, 0
			RegisterStartup(func() (Handler, error) {
				setups++
				value := func(Request) (any, error) { business++; return nil, ErrNotImplemented }
				if fail {
					return value, ErrNotImplemented
				}
				return value, nil
			})
			requireFailure(t, handleFrame([]byte(`{"rid":0}`)), 400, "invalid_input")
			if setups != 0 {
				t.Fatal("invalid frame ran startup")
			}
			for range 2 {
				status := handleFrame([]byte(`{"rid":1}`))
				if fail {
					requireFailure(t, status, 500, "operation_failed")
				} else {
					requireFailure(t, status, 501, "not_implemented")
				}
			}
			wantBusiness := 2
			if fail {
				wantBusiness = 0
			}
			if setups != 1 || business != wantBusiness {
				t.Fatalf("direct dispatch counts: setup=%d business=%d", setups, business)
			}
		})
	}
}

func BenchmarkStartup(b *testing.B) {
	for _, mode := range []string{"no-setup", "no-op", "sha256-1024"} {
		b.Run(mode, func(b *testing.B) {
			resetRuntime(b)
			b.ReportAllocs()
			value := Handler(func(Request) (any, error) { return nil, nil })
			for b.Loop() {
				handler, startup = nil, nil
				initialized = sync.OnceValue(initialize)
				calls := 0
				if mode == "no-setup" {
					Register(value)
				} else {
					RegisterStartup(func() (Handler, error) {
						calls++
						if mode == "sha256-1024" {
							var sum [32]byte
							for range 1024 {
								sum = sha256.Sum256(sum[:])
							}
							return func(Request) (any, error) { return sum, nil }, nil
						}
						return value, nil
					})
				}
				if Initialize() != nil || Initialize() != nil || handler == nil || mode != "no-setup" && calls != 1 || mode == "no-setup" && calls != 0 {
					b.Fatal("startup benchmark did not initialize exactly once")
				}
			}
		})
	}
}
