//go:build wasip1 && wasm

package host

import (
	"errors"
	"runtime"
)

//go:wasmimport chik-host:1 db
func database(input *byte, size int32, output *byte, capacity int32) int32

//go:wasmimport chik-host:1 env
func environment(input *byte, size int32, output *byte, capacity int32) int32

//go:wasmimport chik-host:1 log
func log(input *byte, size int32, output *byte, capacity int32) int32

func exchange(name string, input []byte) ([]byte, error) {
	output := make([]byte, MaxFrame)
	var size int32
	switch name {
	case "db":
		size = database(&input[0], int32(len(input)), &output[0], int32(len(output)))
	case "env":
		size = environment(&input[0], int32(len(input)), &output[0], int32(len(output)))
	case "log":
		size = log(&input[0], int32(len(input)), &output[0], int32(len(output)))
	default:
		return nil, errors.New("unknown host binding")
	}
	runtime.KeepAlive(input)
	runtime.KeepAlive(output)
	if size <= 0 || size > int32(len(output)) {
		return nil, errors.New("invalid host response size")
	}
	return output[:size], nil
}
