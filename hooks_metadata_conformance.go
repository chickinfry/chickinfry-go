//go:build chik_conformance

package chik

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"
	"time"
)

type conformanceNetworkCounter struct{ entries atomic.Int64 }

type conformanceNetworkTransport struct {
	transport *http.Transport
	counter   *conformanceNetworkCounter
}

func (counter *conformanceNetworkCounter) enter(ctx context.Context) {
	counter.entries.Add(1)
	if state := conformanceStateFrom(ctx); state != nil {
		state.networkRequests.Add(1)
	}
}

func (counter *conformanceNetworkCounter) wrap(transport *http.Transport) http.RoundTripper {
	dial := transport.DialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		counter.enter(ctx)
		return dial(ctx, network, address)
	}
	if dialTLS := transport.DialTLSContext; dialTLS != nil {
		transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			counter.enter(ctx)
			return dialTLS(ctx, network, address)
		}
	}
	return &conformanceNetworkTransport{transport: transport, counter: counter}
}

func (transport *conformanceNetworkTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.counter.enter(request.Context())
	ctx := httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { transport.counter.enter(request.Context()) },
	})
	return transport.transport.RoundTrip(request.WithContext(ctx))
}

func (transport *conformanceNetworkTransport) CloseIdleConnections() {
	transport.transport.CloseIdleConnections()
}

// conformanceConstructorTransportHook lets package tests enter the counted path during construction.
var conformanceConstructorTransportHook func(http.RoundTripper)

// ConformanceNewHTTPWithTimeout counts network entries from constructor start to return.
// RoundTrip, DialContext, optional DialTLSContext, and DNS trace callbacks cover the
// cloned transport used by the SDK's sole client.Do path; construction uses no
// separate client, resolver or socket. Later calls retain this counter.
func ConformanceNewHTTPWithTimeout(origin string, timeout time.Duration) (*HTTP, ConformanceResultEvent, error) {
	counter := new(conformanceNetworkCounter)
	before := counter.entries.Load()
	transport, err := newHTTPWithTimeout(origin, timeout, func(transport *http.Transport) http.RoundTripper {
		observed := counter.wrap(transport)
		if conformanceConstructorTransportHook != nil {
			conformanceConstructorTransportHook(observed)
		}
		return observed
	})
	event := ConformanceResultEvent{NetworkRequests: counter.entries.Load() - before}
	if err != nil {
		event.RawTransportDetails = conformanceRawDetails(err)
		if event.NetworkRequests == 0 {
			event.OutcomeUnknown = new(false)
		}
	}
	return transport, event, err
}

func conformanceResult(ctx context.Context, result error) {
	state := conformanceStateFrom(ctx)
	if state == nil || state.hooks.Result == nil {
		return
	}
	conformanceEmission.Lock()
	defer conformanceEmission.Unlock()
	event := ConformanceResultEvent{NetworkRequests: state.networkRequests.Load()}
	exchange := state.final
	if exchange == nil && !state.finalUnobserved {
		exchange = state.last
	}
	if exchange != nil {
		event.HTTPStatus = exchange.status
	}
	if result == nil {
		event.OutcomeUnknown = new(false)
	} else {
		event.RawTransportDetails = conformanceRawDetails(result)
		if failure, ok := errors.AsType[*OperationError](result); ok {
			event.HTTPStatus = new(failure.Status)
		}
		if exchange == nil {
			if state.last == nil {
				event.OutcomeUnknown = new(false)
			}
			// Joined-flight exchanges belong to another call; the earlier 401
			// does not establish that exchange's credential-consumption outcome.
		} else if exchange.normalErrorEnvelope {
			// The response parser establishes the envelope before recording a
			// normal rejection; only its validated refresh 401 resolves consumption.
			event.OutcomeUnknown = new(exchange.operation == "auth.refresh" && !exchange.refreshRejected)
		} else if exchange.conn != nil {
			event.OutcomeUnknown = new(exchange.conn.requestBytes.Load() > 0)
		}
	}
	state.hooks.Result(event)
}

func conformanceRawDetails(result error) *bool {
	visible := result.Error()
	if transport, ok := errors.AsType[*transportError](result); ok {
		switch transport.class {
		case "context canceled", "deadline exceeded", "timeout", "connection refused", "tls handshake failed", "malformed HTTP response", "network error":
			return new(visible != "operation request failed: "+transport.class)
		}
		return new(true)
	}
	if operation, ok := errors.AsType[*OperationError](result); ok {
		return new(!errorCode.MatchString(operation.Code) || visible != fmt.Sprintf("operation failed (%s, HTTP %d)", operation.Code, operation.Status))
	}
	// These runtime-owned messages discard the underlying decoder/body error.
	switch visible {
	case "invalid operation name", "invalid operation request", "operation request is too large", "operation response is too large", "could not read operation response", "invalid operation response", "invalid refresh response", "operation timeout must be positive", "invalid operation endpoint", "operation endpoint must be an HTTPS or loopback HTTP origin", "default transport is not a standard *http.Transport; required to bound response buffering":
		return new(false)
	}
	return nil
}
