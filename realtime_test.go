package chickinfry

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestRealtimeTicketUsesExistingTransport(t *testing.T) {
	var requests atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/realtime.ticket" {
			t.Error("subscription did not use the ticket operation")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthenticated"}`))
	}))
	t.Cleanup(peer.Close)
	transport, err := NewHTTPTransport(peer.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := NewRealtimeClient(transport)
	_, err = client.Subscribe(t.Context(), "invalid\nchannel", SubscribeOptions{})
	if local, ok := errors.AsType[*ClientError](err); !ok || local.Code != CodeInvalidArgument || requests.Load() != 0 {
		t.Fatalf("invalid channel reached transport: %v", err)
	}
	_, err = client.Subscribe(t.Context(), "orders", SubscribeOptions{})
	if remote, ok := errors.AsType[*OperationError](err); !ok || remote.Code != "unauthenticated" ||
		remote.Status != http.StatusUnauthorized || requests.Load() != 1 {
		t.Fatalf("ticket failure lost its HTTP identity: %v", err)
	}
}
