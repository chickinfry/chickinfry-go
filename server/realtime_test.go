package server

import (
	"errors"
	"testing"

	"github.com/chickinfry/chickinfry-go/server/host"
)

func TestRealtimePublishMapsHostErrors(t *testing.T) {
	for _, item := range []struct {
		name     string
		response []byte
		status   int
		code     string
	}{
		{name: "confirmed", response: []byte(`{}`)},
		{name: "unbound", response: []byte(`{"error":"binding_unavailable"}`), status: 503, code: "service_unavailable"},
		{name: "unknown-outcome", response: []byte(`{"error":"realtime_publish_outcome_unknown"}`), status: 503, code: "realtime_publish_outcome_unknown"},
		{name: "engine-rejection", response: []byte(`{"error":"unauthorized_project","status":403}`), status: 403, code: "unauthorized_project"},
	} {
		request := Request{RID: 2, call: func(name string, input any) ([]byte, error) {
			if name != "realtime" {
				return nil, errors.New("unexpected host port")
			}
			return item.response, nil
		}}
		err := NewRealtime(request).Publish("news", map[string]bool{"published": true})
		if item.code == "" {
			if err != nil {
				t.Fatalf("%s: %v", item.name, err)
			}
			continue
		}
		failure, ok := errors.AsType[*OperationError](err)
		if !ok || failure.Status != item.status || failure.Code != item.code {
			t.Fatalf("%s: got %v", item.name, err)
		}
	}
}

func TestRealtimeTicketReturnsEngineValue(t *testing.T) {
	request := Request{RID: 2, call: func(string, any) ([]byte, error) {
		return []byte(`{"value":{"ticket":"opaque","expiresIn":30}}`), nil
	}}
	value, err := NewRealtime(request).Ticket(RealtimeTicketInput{Transport: "anonymous"})
	if err != nil || string(value) != `{"ticket":"opaque","expiresIn":30}` {
		t.Fatalf("ticket round trip failed: %s %v", value, err)
	}
	unbound := Request{RID: 2, call: func(string, any) ([]byte, error) {
		return []byte(`{"error":"binding_unavailable"}`), nil
	}}
	_, err = NewRealtime(unbound).Ticket(RealtimeTicketInput{Transport: "anonymous"})
	failure, ok := errors.AsType[*OperationError](err)
	if !ok || failure.Status != 503 || failure.Code != "service_unavailable" {
		t.Fatalf("unbound realtime accepted: %v", err)
	}
	if _, ok := errors.AsType[*host.Error](err); ok {
		t.Fatal("host error leaked through the public surface")
	}
}
