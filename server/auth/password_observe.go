//go:build !chik_conformance

package auth

func recordKDF(n, r, p, saltBytes, derivedBytes int, completed bool) {}

func recordCleanup(string) {}
