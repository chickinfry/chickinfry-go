//go:build chik_conformance

package auth

import "testing"

func TestActualKDFInvocations(t *testing.T) {
	ConformanceKDFInvocations()
	for _, stored := range []*string{new(passwordVector), nil, new("corrupt")} {
		if _, err := verifyPassword("public test vector", stored); err != nil {
			t.Fatal(err)
		}
		calls := ConformanceKDFInvocations()
		if len(calls) != 1 || calls[0] != (KDFInvocation{32768, 8, 3, 16, 32, true, false}) {
			t.Fatalf("actual KDF observations=%v", calls)
		}
	}
}
