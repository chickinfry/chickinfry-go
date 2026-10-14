//go:build chik_conformance

package driver

import (
	"context"
	"slices"

	chik "github.com/chickinfry/chickinfry-go"
)

func supportedCapabilities() []string {
	return append(append([]string{}, capabilities...), "barrier", "session.store", "session.trace")
}
func supportsSession() bool                  { return true }
func (store *storeBinding) revision() uint64 { return chik.ConformanceStoreRevision(store.memory) }
func supportsBarrierPoint(point string) bool {
	return slices.Contains([]string{"sdk-entered", "both-originals-rejected", "refresh-joined"}, point)
}

func attachHooks(s *server, ctx, control context.Context, callID, caseID string) context.Context {
	s.credentials.mu.Lock()
	refs := map[string]string{}
	for ref, value := range s.credentials.values {
		if existing, ok := refs[value]; !ok || ref < existing {
			refs[value] = ref
		}
	}
	s.credentials.mu.Unlock()
	return chik.WithConformanceHooks(ctx, callID, chik.ConformanceHooks{
		CredentialRefs: refs,
		SessionTrace: func(event chik.ConformanceSessionEvent) {
			if event.Phase != "clear" {
				return
			}
			s.sessionMu.Lock()
			defer s.sessionMu.Unlock()
			store, _ := ctx.Value(storeKey{}).(*storeBinding)
			if store == nil {
				return
			}
			if !event.Measurable {
				store.traceUnavailable = true
				return
			}
			store.clearAttempts = append(store.clearAttempts, observedClear{CallID: event.CallID, ExpectedAccessRef: event.ExpectedAccessRef, ExpectedRefreshRef: event.ExpectedRefreshRef, Removed: event.Removed})
		},
		Barrier: func(runtime context.Context, event chik.ConformanceBarrierEvent) error {
			if !supportsBarrierPoint(event.Point) {
				return nil
			}
			wait, cancel := context.WithCancel(control)
			defer cancel()
			stopped := make(chan struct{})
			stop := context.AfterFunc(runtime, func() { defer close(stopped); cancel() })
			defer func() {
				if !stop() {
					<-stopped
				}
			}()
			if deadline, ok := runtime.Deadline(); ok {
				var end context.CancelFunc
				wait, end = context.WithDeadline(wait, deadline)
				defer end()
			}
			var facts any
			switch event.Point {
			case "sdk-entered":
				facts = map[string]any{"entered": event.Entered}
			case "both-originals-rejected":
				facts = map[string]any{"httpStatus": event.HTTPStatus}
			case "refresh-joined":
				if event.RefreshRef == "" {
					return Unimplemented()
				}
				facts = map[string]any{"refreshRef": event.RefreshRef}
			default:
				return Unimplemented()
			}
			return s.arrive(wait, event.CallID, caseID, event.Point, facts)
		},
	})
}
