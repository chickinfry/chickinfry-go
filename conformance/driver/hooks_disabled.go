//go:build !chik_conformance

package driver

import (
	"context"
	"time"

	"github.com/chickinfry/chickinfry-go"
)

func supportsTransport() bool { return false }
func newHTTP(origin string, timeout time.Duration) (*chickinfry.HTTPTransport, *int64, *Error) {
	transport, err := chickinfry.NewHTTPTransport(origin, chickinfry.WithTimeout(timeout))
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
