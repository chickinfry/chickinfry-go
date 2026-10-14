//go:build !chik_conformance

package chik

import (
	"context"
	"net/http"
)

func conformanceBegin(ctx context.Context, _ string, _ bool) (context.Context, func(), error) {
	return ctx, func() {}, nil
}
func conformanceBarrier(context.Context, string, string) error          { return nil }
func conformanceFlightRegister(context.Context, *refreshFlight, string) {}
func conformanceFlightEnd(*refreshFlight)                               {}
func conformanceClearMatched(*MemoryStore)                              {}
func conformanceJoin(context.Context, *refreshFlight, bool) error       { return nil }
func conformanceClear(ctx context.Context, store SessionStore, expected SessionCredentials) error {
	return store.Clear(ctx, expected)
}
func conformanceRequest(ctx context.Context, client *http.Client, _ string, _ int) (context.Context, *http.Client, func(error)) {
	return ctx, client, func(error) {}
}
func conformanceHeaders(context.Context, *http.Response) {}
func conformanceResult(context.Context, error)           {}
func conformanceDecode(context.Context)                  {}
func conformanceRefreshFailure(context.Context)          {}
func conformanceRejection(context.Context, bool)         {}
func conformanceDo(client *http.Client, request *http.Request) (*http.Response, error) {
	return client.Do(request)
}
func conformanceRead(context.Context, int, int) bool { return false }
func conformanceStop(context.Context, bool)          {}
func conformanceReaderClosed(context.Context)        {}
