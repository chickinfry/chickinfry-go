package server

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestLogSubmitsStructuredRecordAndDropsInvalidOnes(t *testing.T) {
	var frames []string
	request := Request{RID: 7, call: func(name string, input any) ([]byte, error) {
		if name != "log" {
			return nil, errors.New("unexpected host port")
		}
		raw, err := json.Marshal(input)
		if err != nil {
			return nil, err
		}
		frames = append(frames, string(raw))
		return []byte(`{}`), nil
	}}
	Log(Request{}, "info", "no active request", nil)
	Log(request, "info", "transfer recorded", map[string]any{"count": 2})
	Log(request, "verbose", "dropped level", nil)
	Log(request, "info", "dropped fields", map[string]any{"callback": func() {}})
	if len(frames) != 1 {
		t.Fatalf("expected one accepted record, got %d", len(frames))
	}
	for _, want := range []string{`"rid":7`, `"level":"info"`, `"message":"transfer recorded"`, `"fields":{"count":2}`} {
		if !strings.Contains(frames[0], want) {
			t.Fatalf("log frame %s is missing %s", frames[0], want)
		}
	}
}
