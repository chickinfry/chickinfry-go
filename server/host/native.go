//go:build !wasip1 || !wasm

package host

import "errors"

func exchange(string, []byte) ([]byte, error) {
	return nil, errors.New("server host calls require wasip1/wasm")
}
