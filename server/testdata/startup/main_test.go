package main

import (
	"os"
	"os/exec"
	"testing"

	"github.com/chickinfry/chickinfry-go/server"
)

func TestInitializeExport(t *testing.T) {
	mode := os.Getenv("CHIK_STARTUP_EXPORT_TEST")
	if mode == "" {
		for _, mode := range []string{"success", "failure"} {
			command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestInitializeExport$")
			command.Env = append(os.Environ(), "CHIK_STARTUP_EXPORT_TEST="+mode)
			if err := command.Run(); err != nil {
				t.Fatalf("initialization export case=%s failed", mode)
			}
		}
		return
	}
	want := int32(0)
	if mode == "failure" {
		startupFailure = server.ErrNotImplemented
		want = 500
	}
	for range 2 {
		if initialize() != want || setups != 1 {
			t.Fatalf("initialization export counts: setup=%d", setups)
		}
	}
}
