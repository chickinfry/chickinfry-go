package chik

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestConformanceExportedSymbolsRequireBuildTag(t *testing.T) {
	root := t.TempDir()
	for _, tagged := range []bool{false, true} {
		name := "default"
		registration := "ctx := context.Background()"
		if tagged {
			name = "tagged"
			registration = `ctx := chik.WithConformanceHooks(context.Background(), "call:symbol", chik.ConformanceHooks{})`
		}
		source := `package main
import ("context"; "fmt"; chik "github.com/chickinfry/chickinfry-go")
func main(){` + registration + `;transport,err:=chik.NewHTTP("http://127.0.0.1:1");if err==nil{err=transport.Invoke(ctx,"catalog.create",map[string]string{},&struct{}{})};fmt.Println(err)}`
		file := filepath.Join(root, name+".go")
		binary := filepath.Join(root, name)
		if err := os.WriteFile(file, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		if !tagged {
			// nm alone misses exported APIs eliminated as unused by the linker.
			probe := filepath.Join(root, "unavailable.go")
			probeSource := strings.Replace(source, registration, `ctx := chik.WithConformanceHooks(context.Background(), "call:symbol", chik.ConformanceHooks{})`, 1)
			if err := os.WriteFile(probe, []byte(probeSource), 0600); err != nil {
				t.Fatal(err)
			}
			output, err := exec.CommandContext(t.Context(), "go", "build", "-o", filepath.Join(root, "unavailable"), probe).CombinedOutput()
			if err == nil {
				t.Fatal("default build declares the conformance API")
			}
			if !strings.Contains(string(output), "undefined: chik.WithConformanceHooks") {
				t.Fatalf("default API probe failed for another reason: %s", output)
			}
		}
		args := []string{"build", "-gcflags=all=-l", "-o", binary}
		if tagged {
			args = append(args, "-tags", "chik_conformance")
		}
		args = append(args, file)
		if output, err := exec.CommandContext(t.Context(), "go", args...).CombinedOutput(); err != nil {
			t.Fatalf("%s build: %v\n%s", name, err, output)
		}
		output, err := exec.CommandContext(t.Context(), "go", "tool", "nm", binary).CombinedOutput()
		if err != nil {
			t.Fatalf("%s symbols: %v", name, err)
		}
		symbols := string(output)
		present := strings.Contains(symbols, "github.com/chickinfry/chickinfry-go.WithConformanceHooks")
		if present != tagged {
			t.Fatalf("%s registration symbol=%t", name, present)
		}
		if !tagged && strings.Contains(symbols, "github.com/chickinfry/chickinfry-go.Conformance") {
			t.Fatal("default binary exposes conformance types")
		}
	}
}
