//go:build !chik_conformance

package driver

import (
	"context"
	"time"

	chik "github.com/chickinfry/chickinfry-go"
)

func supportsTransport() bool { return false }
func newHTTP(origin string, timeout time.Duration) (*chik.HTTP, *int64, *Error) {
	transport, err := chik.NewHTTPWithTimeout(origin, timeout)
	if err != nil {
		return nil, nil, normalize(err)
	}
	return transport, nil, nil
}

func supportedCapabilities() []string  { return capabilities }
func supportsSession() bool            { return false }
func (*storeBinding) revision() uint64 { return 0 }
func supportsBarrierPoint(string) bool { return false }
func attachHooks(_ *server, ctx, _ context.Context, _, _ string) context.Context {
	return ctx
}
