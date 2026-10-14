//go:build !chik_conformance

package driver

import "context"

func supportedCapabilities() []string  { return capabilities }
func supportsSession() bool            { return false }
func (*storeBinding) revision() uint64 { return 0 }
func supportsBarrierPoint(string) bool { return false }
func attachHooks(_ *server, ctx, _ context.Context, _, _ string) context.Context {
	return ctx
}
