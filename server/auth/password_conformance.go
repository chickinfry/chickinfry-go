//go:build chik_conformance

package auth

import "sync"

// KDFInvocation records the parameters of an actual scrypt call without its inputs.
type KDFInvocation struct {
	N            int  `json:"N"`
	R            int  `json:"r"`
	P            int  `json:"p"`
	SaltBytes    int  `json:"saltBytes"`
	DerivedBytes int  `json:"derivedBytes"`
	Completed    bool `json:"completed"`
	Failed       bool `json:"failed"`
}

var kdfObservation struct {
	sync.Mutex
	invocations []KDFInvocation
}

func recordKDF(n, r, p, saltBytes, derivedBytes int, completed bool) {
	kdfObservation.Lock()
	defer kdfObservation.Unlock()
	kdfObservation.invocations = append(kdfObservation.invocations, KDFInvocation{n, r, p, saltBytes, derivedBytes, completed, !completed})
}

// ConformanceKDFInvocations drains observations from actual calls in this instance.
func ConformanceKDFInvocations() []KDFInvocation {
	kdfObservation.Lock()
	defer kdfObservation.Unlock()
	calls := kdfObservation.invocations
	kdfObservation.invocations = nil
	return calls
}

// CleanupObservation counts calls made by the actual foreground pass.
type CleanupObservation struct {
	Passes         int
	DeleteAttempts int
	Failed         bool
}

var cleanupObservation struct {
	sync.Mutex
	value CleanupObservation
}

func recordCleanup(event string) {
	cleanupObservation.Lock()
	defer cleanupObservation.Unlock()
	switch event {
	case "pass":
		cleanupObservation.value.Passes++
	case "delete":
		cleanupObservation.value.DeleteAttempts++
	case "failed":
		cleanupObservation.value.Failed = true
	}
}

// ConformanceCleanup drains counts from this instance without stored values.
func ConformanceCleanup() CleanupObservation {
	cleanupObservation.Lock()
	defer cleanupObservation.Unlock()
	value := cleanupObservation.value
	cleanupObservation.value = CleanupObservation{}
	return value
}
