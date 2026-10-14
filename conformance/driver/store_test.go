//go:build chik_conformance

package driver

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func sessionRecord(access, refresh string) map[string]string {
	return map[string]string{"origin": "https://example.test", "access_token": access, "refresh_token": refresh, "expires_at": "2099-01-01T00:00:00Z", "refresh_expires_at": "2099-02-01T00:00:00Z", "user_id": "user", "session_id": "session"}
}

func protectedRecord(record map[string]string) string {
	data, _ := json.Marshal(record)
	frame, _ := json.Marshal(map[string]string{"ref": "record", "value": string(data)})
	return protectedTokens() + string(frame) + "\n"
}

func storeArgs() map[string]any {
	return map[string]any{"storeRef": "store", "origin": "https://example.test", "recordRef": "record", "accessRef": "access", "refreshRef": "refresh"}
}

func TestSessionStoreRoundTripAndCopy(t *testing.T) {
	control := hello + command("c:store", "session.store.create", storeArgs()) +
		command("c:client", "client.create", map[string]any{"clientRef": "client", "origin": "https://example.test", "requestTimeoutMs": 1000, "storeRef": "store"}) +
		command("c:copy", "client.copy", map[string]any{"sourceClientRef": "client", "clientRef": "copy", "bearerRef": "access"}) +
		command("c:read", "session.store.read", map[string]any{"storeRef": "store", "includeTrace": true}) +
		command("c:write", "session.store.write", map[string]any{"storeRef": "store", "recordRef": "record", "accessRef": "access", "refreshRef": "refresh"}) +
		command("c:after", "session.store.read", map[string]any{"storeRef": "store"})
	results, err := execute(t, control, protectedRecord(sessionRecord(strings.Repeat("A", 43), strings.Repeat("B", 43))), nil)
	if err != nil || len(results) != 7 {
		t.Fatalf("incomplete store commands: %v", err)
	}
	for _, result := range results {
		if result.Error != nil {
			t.Fatalf("store command failed: %v", result.Error)
		}
	}
	for _, capability := range []string{"session.store", "session.trace", "barrier"} {
		if !slices.Contains(supportedCapabilities(), capability) {
			t.Fatal("tagged observations are not advertised")
		}
	}
	before := results[4].Result.(map[string]any)
	after := results[6].Result.(map[string]any)
	if len(results[1].Result.(map[string]any)) != 2 || len(results[5].Result.(map[string]any)) != 3 {
		t.Fatal("store write responses violate the strict wire shape")
	}
	if before["present"] != true || before["accessRef"] != "access" || before["refreshRef"] != "refresh" || before["revision"] != float64(1) || len(before["clearAttempts"].([]any)) != 0 || after["revision"] != float64(2) || after["accessRef"] != "access" {
		t.Fatal("session read did not report runtime credentials and mutation revision")
	}
}

func TestSessionRecordValidation(t *testing.T) {
	for _, variant := range []string{"missing", "unknown", "case", "empty", "wrong-origin", "wrong-token", "malformed-token"} {
		t.Run(variant, func(t *testing.T) {
			record := sessionRecord(strings.Repeat("A", 43), strings.Repeat("B", 43))
			switch variant {
			case "missing":
				delete(record, "session_id")
			case "unknown":
				record["extra"] = "ignored"
			case "case":
				record["Session_id"] = record["session_id"]
				delete(record, "session_id")
			case "empty":
				record["session_id"] = ""
			case "wrong-origin":
				record["origin"] = "https://other.test"
			case "wrong-token":
				record["access_token"] = strings.Repeat("C", 43)
			case "malformed-token":
				record["refresh_token"] = "invalid"
			}
			results, err := execute(t, hello+command("c:store", "session.store.create", storeArgs()), protectedRecord(record), nil)
			if err != nil || len(results) != 2 || results[1].Error == nil || *results[1].Error.Code != "invalid_args" {
				t.Fatal("untrusted session record accepted")
			}
		})
	}
}

func TestSessionBindingRejectsAnotherOrigin(t *testing.T) {
	control := hello + command("c:store", "session.store.create", storeArgs()) + command("c:client", "client.create", map[string]any{"clientRef": "client", "origin": "https://other.test", "requestTimeoutMs": 1000, "storeRef": "store"})
	results, err := execute(t, control, protectedRecord(sessionRecord(strings.Repeat("A", 43), strings.Repeat("B", 43))), nil)
	if err != nil || results[2].Error == nil || *results[2].Error.Code != "invalid_args" {
		t.Fatal("session credentials bound to another origin")
	}
}
