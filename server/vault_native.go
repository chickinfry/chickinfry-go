//go:build !wasip1 || !wasm

package server

func readVaultBinding(int64, string) (*string, error) {
	return nil, &OperationError{Status: 503, Code: "service_unavailable"}
}
