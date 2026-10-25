//go:build chik_conformance

package driver

import (
	"context"
	"slices"
	"time"

	"github.com/chickinfry/chickinfry-go"
)

func supportedCapabilities() []string {
	return append(append([]string{}, capabilities...), "barrier", "session.store", "session.trace", "client.transport")
}
func supportsTransport() bool { return true }
func newHTTP(origin string, timeout time.Duration) (*chickinfry.HTTPTransport, *int64, *Error) {
	transport, observed, err := chickinfry.ConformanceNewHTTPTransport(origin, chickinfry.WithTimeout(timeout))
	if err != nil {
		e := normalize(err)
		e.RawTransportDetails, e.OutcomeUnknown = observed.RawTransportDetails, observed.OutcomeUnknown
		e.ConstructorNetworkRequests = new(observed.NetworkRequests)
		return nil, nil, e
	}
	return transport, new(observed.NetworkRequests), nil
}
func supportsSession() bool { return true }
func (store *storeBinding) revision() uint64 {
	return chickinfry.ConformanceStoreRevision(store.memory)
}
func supportsBarrierPoint(point string) bool {
	return slices.Contains([]string{"sdk-entered", "both-originals-rejected", "refresh-joined"}, point)
}

func attachHooks(s *server, ctx, control context.Context, callID, caseID string) context.Context {
	s.observeMu.Lock()
	if s.observations == nil {
		s.observations = map[string]*callObservations{}
	}
	observations := &callObservations{events: []transportEvent{}, complete: true}
	s.observations[callID] = observations
	s.observeMu.Unlock()
	s.credentials.mu.Lock()
	refs := map[string]string{}
	for ref, value := range s.credentials.values {
		if existing, ok := refs[value]; !ok || ref < existing {
			refs[value] = ref
		}
	}
	s.credentials.mu.Unlock()
	return chickinfry.WithConformanceHooks(ctx, callID, chickinfry.ConformanceHooks{
		Observe: func(event chickinfry.ConformanceTransportEvent) {
			s.observeMu.Lock()
			defer s.observeMu.Unlock()
			observations.complete = observations.complete && event.Measurable
			projected := transportEvent{
				Sequence: event.Sequence, CallID: event.CallID, ElapsedMS: event.ElapsedMs,
				Phase: event.Phase, HTTPStatus: event.HTTPStatus, ReadBytes: event.ReadBytes,
			}
			if event.Measurable {
				projected.RetainedBytes, projected.PeakRetainedBytes = new(event.RetainedBytes), new(event.PeakRetainedBytes)
			}
			observations.events = append(observations.events, projected)
			s.throughSequence = event.Sequence
		},
		Result: func(event chickinfry.ConformanceResultEvent) {
			s.observeMu.Lock()
			defer s.observeMu.Unlock()
			observations.status, observations.raw, observations.unknown = event.HTTPStatus, event.RawTransportDetails, event.OutcomeUnknown
		},
		CredentialRefs: refs,
		SessionTrace: func(event chickinfry.ConformanceSessionEvent) {
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
		Barrier: func(runtime context.Context, event chickinfry.ConformanceBarrierEvent) error {
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
