//go:build chik_conformance

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	auth "chickinfry-client-auth"
	plain "chickinfry-client-plain"
	"github.com/chickinfry/chickinfry-go"
	"github.com/chickinfry/chickinfry-go/conformance/driver"
)

func main() {
	protected := os.NewFile(3, "credentials")
	if protected == nil {
		os.Exit(2)
	}
	defer protected.Close()
	info, err := protected.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		fmt.Fprintln(os.Stderr, "driver requires a protected credential pipe on descriptor 3")
		os.Exit(2)
	}
	if err := driver.Run(context.Background(), os.Stdin, os.Stdout, protected, call); err != nil {
		fmt.Fprintln(os.Stderr, "driver failed")
		os.Exit(2)
	}
}

// inputTransport preserves JSON presence that generated string input structs cannot represent.
// Valid declared fields still serialize through the generated SDK's input model.
type inputTransport struct {
	http  *chickinfry.HTTPTransport
	input json.RawMessage
}

func (t inputTransport) Invoke(ctx context.Context, operation string, input any, output any) error {
	var original map[string]json.RawMessage
	if json.Unmarshal(t.input, &original) != nil || original == nil {
		return t.http.Invoke(ctx, operation, t.input, output)
	}
	data, err := json.Marshal(input)
	if err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for field := range fields {
		if value, present := original[field]; !present {
			delete(fields, field)
		} else if string(value) == "null" {
			fields[field] = value
		}
	}
	return t.http.Invoke(ctx, operation, fields, output)
}

func call(ctx context.Context, transport *chickinfry.HTTPTransport, operation string, input json.RawMessage) (any, error) {
	switch driver.Fixture(ctx) {
	case "plain":
		return callPlain(ctx, transport, operation, input)
	case "auth":
		return callAuth(ctx, transport, operation, input)
	default:
		return nil, driver.Unimplemented()
	}
}

func callPlain(ctx context.Context, transport *chickinfry.HTTPTransport, operation string, input json.RawMessage) (any, error) {
	client := plain.New(inputTransport{http: transport, input: input})
	switch operation {
	case "probe.echo":
		var typed plain.ProbeEchoInput
		if json.Unmarshal(input, &typed) != nil {
			return nil, errors.New("invalid SDK input")
		}
		return client.Probe.Echo(ctx, typed)
	case "probe.list":
		var typed plain.ProbeListInput
		if json.Unmarshal(input, &typed) != nil {
			return nil, errors.New("invalid SDK input")
		}
		return client.Probe.List(ctx, typed)
	default:
		return nil, driver.Unimplemented()
	}
}

func callAuth(ctx context.Context, transport *chickinfry.HTTPTransport, operation string, input json.RawMessage) (any, error) {
	client := auth.New(inputTransport{http: transport, input: input})
	switch operation {
	case "probe.echo":
		var typed auth.ProbeEchoInput
		if json.Unmarshal(input, &typed) != nil {
			return nil, errors.New("invalid SDK input")
		}
		return client.Probe.Echo(ctx, typed)
	case "probe.list":
		var typed auth.ProbeListInput
		if json.Unmarshal(input, &typed) != nil {
			return nil, errors.New("invalid SDK input")
		}
		return client.Probe.List(ctx, typed)
	case "auth.refresh":
		var typed auth.AuthRefreshInput
		if json.Unmarshal(input, &typed) != nil {
			return nil, errors.New("invalid SDK input")
		}
		return client.Auth.Refresh(ctx, typed)
	default:
		return nil, driver.Unimplemented()
	}
}
