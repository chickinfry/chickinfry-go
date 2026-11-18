//go:build chik_conformance

package main

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	empty "chickinfry-client-empty-session"
	"github.com/chickinfry/chickinfry-go"
	"github.com/chickinfry/chickinfry-go/conformance/driver"
)

var emptySessionClients sync.Map

func callEmptySession(ctx context.Context, transport *chickinfry.HTTPTransport, operation string, input json.RawMessage) (any, error) {
	value, ok := emptySessionClients.Load(transport)
	if !ok {
		value, _ = emptySessionClients.LoadOrStore(transport, empty.CreateClient(transport))
	}
	client := value.(*empty.Client)
	switch operation {
	case "auth.signin":
		return callTyped(ctx, client.Auth.Signin, input)
	case "auth.logout":
		return callTyped(ctx, client.Auth.Logout, input)
	case "probe.echo":
		return callTyped(ctx, client.Probe.Echo, input)
	case "probe.list":
		return callTyped(ctx, client.Probe.List, input)
	default:
		return nil, driver.Unimplemented()
	}
}

func callTyped[I, O any](ctx context.Context, invoke func(context.Context, I) (O, error), input json.RawMessage) (O, error) {
	var value I
	if json.Unmarshal(input, &value) != nil {
		var output O
		return output, errors.New("invalid SDK input")
	}
	return invoke(ctx, value)
}
