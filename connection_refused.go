//go:build !plan9

package chik

import (
	"errors"
	"syscall"
)

// isConnectionRefused matches the errno-backed refusal that networked
// platforms report through the error chain.
func isConnectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
