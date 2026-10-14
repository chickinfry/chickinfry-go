package host

import (
	"errors"
	"testing"
)

func TestStrictResponses(t *testing.T) {
	for _, frame := range []string{`{"rows":[],"rows":[]}`, `{"rows":[],"extra":1}`, `{"error":"23505","detail":"secret"}`, `{"error":"secret"}`, `{"rows":[]} {}`} {
		var rows []int
		err := Envelope([]byte(frame), "rows", &rows)
		if err == nil {
			t.Errorf("accepted %s", frame)
		}
	}
	for _, code := range []string{"23505", "commit_unknown", "database_failed"} {
		err := Envelope([]byte(`{"error":"`+code+`"}`), "rows", nil)
		failure, ok := errors.AsType[*Error](err)
		if !ok || failure.Code != code {
			t.Fatalf("lost host error %s: %v", code, err)
		}
	}
}
