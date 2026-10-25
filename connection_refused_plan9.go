//go:build plan9

package chickinfry

// plan9 reports dial failures as string errors without a stable errno, so
// refusals fall through to the generic network failure class.
func isConnectionRefused(err error) bool {
	return false
}
