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

//go:wasmimport chik-host:1 storage
func storage(input *byte, size int32, output *byte, capacity int32) int32

//go:wasmimport chik-host:1 realtime
func realtime(input *byte, size int32, output *byte, capacity int32) int32

func exchange(name string, input []byte) ([]byte, error) {
	// Storage responses carry base64-encoded object bytes, so the transport
	// buffer needs headroom beyond the shared frame limit.
	capacity := MaxFrame
	if name == "storage" {
		capacity = StorageFrame
	}
	output := make([]byte, capacity)
	var size int32
	switch name {
	case "db":
		size = database(&input[0], int32(len(input)), &output[0], int32(len(output)))
	case "env":
		size = environment(&input[0], int32(len(input)), &output[0], int32(len(output)))
	case "log":
		size = log(&input[0], int32(len(input)), &output[0], int32(len(output)))
	case "storage":
		size = storage(&input[0], int32(len(input)), &output[0], int32(len(output)))
	case "realtime":
		size = realtime(&input[0], int32(len(input)), &output[0], int32(len(output)))
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
