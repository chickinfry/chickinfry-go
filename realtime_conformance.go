//go:build chik_conformance

package chickinfry

import "context"

// ConformanceRealtime attaches loopback route validation and receive observations to a driver trial.
func ConformanceRealtime(ctx context.Context, endpoint func(string) (string, error), point func(string), dispatch func(string, func()), inspect func(func() map[string]int)) context.Context {
	return context.WithValue(ctx, realtimeProbeKey{}, &realtimeProbe{endpoint, point, dispatch, inspect})
}
