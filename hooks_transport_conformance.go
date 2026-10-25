//go:build chik_conformance

package chickinfry

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// conformanceConn counts response payload separately from HTTP framing without
// copying body data. The parser is test-only and rejects unsupported wire shapes.
type conformanceConn struct {
	net.Conn
	mu                              sync.Mutex
	closeOnce                       sync.Once
	closed                          chan struct{}
	measurable                      bool
	headersDone, firstLine          bool
	line                            []byte
	chunked                         bool
	remaining                       int64
	body, framing                   int64
	chunkState                      int
	chunkRemaining                  int64
	requestRemaining                int
	requestHeaderMatch              int
	requestHeadersDone, requestSent bool
	onRequestSent                   func()
	requestBytes                    atomic.Int64
}

func (connection *conformanceConn) NetConn() net.Conn { return connection.Conn }

func (connection *conformanceConn) Write(buffer []byte) (int, error) {
	n, err := connection.Conn.Write(buffer)
	connection.requestBytes.Add(int64(n))
	if connection.onRequestSent == nil || connection.requestSent {
		return n, err
	}
	terminator := []byte("\r\n\r\n")
	for _, value := range buffer[:n] {
		if !connection.requestHeadersDone {
			if value == terminator[connection.requestHeaderMatch] {
				connection.requestHeaderMatch++
			} else {
				connection.requestHeaderMatch = 0
				if value == '\r' {
					connection.requestHeaderMatch = 1
				}
			}
			if connection.requestHeaderMatch == 4 {
				connection.requestHeadersDone = true
			}
		} else if connection.requestRemaining > 0 {
			connection.requestRemaining--
		}
	}
	if connection.requestHeadersDone && connection.requestRemaining == 0 {
		connection.requestSent = true
		connection.onRequestSent()
	}
	return n, err
}

func (connection *conformanceConn) Read(buffer []byte) (int, error) {
	n, err := connection.Conn.Read(buffer)
	connection.mu.Lock()
	for _, value := range buffer[:n] {
		connection.count(value)
	}
	connection.mu.Unlock()
	return n, err
}
func (connection *conformanceConn) Close() error {
	err := connection.Conn.Close()
	connection.closeOnce.Do(func() { close(connection.closed) })
	return err
}
func (connection *conformanceConn) snapshot() (int64, int64, bool) {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return connection.body, connection.framing, connection.measurable && connection.headersDone && (connection.chunked || connection.remaining >= 0)
}
func (connection *conformanceConn) count(value byte) {
	if !connection.measurable {
		return
	}
	if !connection.headersDone {
		if value != '\n' {
			if len(connection.line) >= 65536 {
				connection.measurable = false
				connection.line = nil
				return
			}
			connection.line = append(connection.line, value)
			return
		}
		line := strings.TrimSuffix(string(connection.line), "\r")
		connection.line = connection.line[:0]
		if !connection.firstLine {
			connection.firstLine = true
			parts := strings.Fields(line)
			if len(parts) < 2 || (parts[0] != "HTTP/1.1" && parts[0] != "HTTP/1.0") {
				connection.measurable = false
				return
			}
			status, err := strconv.Atoi(parts[1])
			if err != nil || status < 200 || status == 101 {
				connection.measurable = false
			}
			return
		}
		if line == "" {
			connection.headersDone = true
			connection.line = nil
			return
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			connection.measurable = false
			return
		}
		switch strings.ToLower(name) {
		case "content-length":
			length, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			if err != nil || length < 0 {
				connection.measurable = false
				return
			}
			connection.remaining = length
		case "transfer-encoding":
			if strings.TrimSpace(strings.ToLower(value)) != "chunked" {
				connection.measurable = false
				return
			}
			connection.chunked = true
		case "content-encoding":
			if strings.TrimSpace(strings.ToLower(value)) != "identity" {
				connection.measurable = false
			}
		}
		return
	}
	if !connection.chunked {
		// remaining is zero only at a framed body's end. Close-delimited bodies
		// are conservatively unmeasurable rather than guessed from socket EOF.
		if connection.remaining > 0 {
			connection.body++
			connection.remaining--
		}
		return
	}
	if connection.chunkState == 1 {
		connection.body++
		connection.chunkRemaining--
		if connection.chunkRemaining == 0 {
			connection.chunkState = 2
		}
		return
	}
	connection.framing++
	switch connection.chunkState {
	case 0:
		if value != '\n' {
			if len(connection.line) >= 4096 {
				connection.measurable = false
				return
			}
			connection.line = append(connection.line, value)
			return
		}
		line := strings.TrimSuffix(string(connection.line), "\r")
		connection.line = nil
		size, _, _ := strings.Cut(line, ";")
		length, err := strconv.ParseInt(size, 16, 64)
		if err != nil || length < 0 {
			connection.measurable = false
			return
		}
		connection.chunkRemaining = length
		if length == 0 {
			connection.chunkState = 4
		} else {
			connection.chunkState = 1
		}
	case 2:
		if value != '\r' {
			connection.measurable = false
			return
		}
		connection.chunkState = 3
	case 3:
		if value != '\n' {
			connection.measurable = false
			return
		}
		connection.chunkState = 0
	case 4:
		// Trailers contain framing, never response body bytes.
	}
}
