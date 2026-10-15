package main

import "github.com/chickinfry/chickinfry-go/server"

var setups int32
var startupFailure error

func init() {
	server.RegisterStartup(func() (server.Handler, error) {
		setups++
		return func(server.Request) (any, error) { return setups, nil }, startupFailure
	})
}

func main() {}

//go:wasmexport chik_initialize
func initialize() int32 { return server.InitializeStatus() }

//go:wasmexport chik_alloc
func allocate(size int32) *byte { return server.Allocate(size) }

//go:wasmexport chik_handle
func handle(size int32) int32 { return server.Handle(size) }

//go:wasmexport chik_output
func output() *byte { pointer, _ := server.Output(); return pointer }

//go:wasmexport chik_output_size
func outputSize() int32 { _, size := server.Output(); return size }
