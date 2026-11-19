//go:build wasip1 && wasm

package server

import (
	"encoding/json"
	"errors"
	"runtime"

	"github.com/chickinfry/chickinfry-go/server/host"
)

//go:wasmimport chik-go:1 vault
func vaultBinding(input *byte, size int32, output *byte, capacity int32) int32

func readVaultBinding(rid int64, name string) (*string, error) {
	input, err := json.Marshal(struct {
		RID  int64  `json:"rid"`
		Name string `json:"name"`
	}{RID: rid, Name: name})
	if err != nil {
		return nil, err
	}
	output := make([]byte, host.MaxFrame)
	size := vaultBinding(&input[0], int32(len(input)), &output[0], int32(len(output)))
	runtime.KeepAlive(input)
	runtime.KeepAlive(output)
	if size <= 0 || size > int32(len(output)) {
		return nil, errors.New("invalid vault response size")
	}
	var value *string
	err = host.Envelope(output[:size], "value", &value)
	return value, err
}
