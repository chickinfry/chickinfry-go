package server

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/chickinfry/chickinfry-go/server/host"
)

func storageRequest(response []byte, failure error) Request {
	return Request{RID: 3, call: func(name string, input any) ([]byte, error) {
		if name != "storage" {
			return nil, errors.New("unexpected host port")
		}
		return response, failure
	}}
}

func TestStorageGetMapsHostResults(t *testing.T) {
	body := []byte{0, 255, 1}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name      string
		response  []byte
		want      []byte
		wantError string
		wantCode  string
	}{
		{name: "object", response: append([]byte(`{"value":`), append(encoded, '}')...), want: body},
		{name: "absent", response: []byte(`{"value":null}`)},
		{name: "unbound", response: []byte(`{"error":"binding_unavailable"}`), wantCode: "service_unavailable"},
		{name: "failed", response: []byte(`{"error":"storage_failed"}`), wantError: "storage_failed"},
	} {
		value, err := NewStorage(storageRequest(item.response, nil), "photos").Get("a/b")
		if item.wantError != "" {
			if failure, ok := errors.AsType[*host.Error](err); !ok || failure.Code != item.wantError {
				t.Fatalf("%s: got %v", item.name, err)
			}
			continue
		}
		if item.wantCode != "" {
			failure, ok := errors.AsType[*OperationError](err)
			if !ok || failure.Status != 503 || failure.Code != item.wantCode {
				t.Fatalf("%s: got %v", item.name, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", item.name, err)
		}
		if string(value) != string(item.want) {
			t.Fatalf("%s: got %v", item.name, value)
		}
	}
}

func TestStoragePutRejectsOversizedObject(t *testing.T) {
	err := NewStorage(storageRequest([]byte(`{}`), nil), "photos").Put("k", make([]byte, storageObjectLimit+1), "text/plain")
	if err == nil || !strings.Contains(err.Error(), "4 MiB") {
		t.Fatalf("oversized object accepted: %v", err)
	}
	if err := NewStorage(storageRequest([]byte(`{}`), nil), "photos").Put("k", []byte("x"), "text/plain"); err != nil {
		t.Fatalf("confirmed write failed: %v", err)
	}
	if err := NewStorage(storageRequest([]byte(`{"error":"binding_unavailable"}`), nil), "photos").Put("k", []byte("x"), "text/plain"); err == nil {
		t.Fatal("unbound storage accepted")
	}
}

func TestStorageKeysRejectTraversalAndControls(t *testing.T) {
	for _, key := range []string{"", "a/../b", "..", "ab", strings.Repeat("k", 1025)} {
		if err := validStorageKey(key); err == nil {
			t.Fatalf("accepted key %q", key)
		}
	}
	for _, key := range []string{"photos/1", "a-b_c"} {
		if err := validStorageKey(key); err != nil {
			t.Fatalf("rejected key %q", key)
		}
	}
}

func TestStorageFrameAcceptsObjectHeadroom(t *testing.T) {
	var value *[]byte
	frame := []byte(`{"value":"` + strings.Repeat("A", host.MaxFrame) + `"}`)
	if err := host.EnvelopeLimit(frame, "value", &value, host.StorageFrame); err != nil {
		t.Fatalf("object response rejected within the storage budget: %v", err)
	}
	var ignored *[]byte
	if err := host.EnvelopeLimit(frame, "value", &ignored, host.MaxFrame); err == nil {
		t.Fatal("oversized frame accepted at the shared limit")
	}
}
