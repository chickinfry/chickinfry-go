// Package chickinfry provides the shared Go runtime behind Chickinfry generated clients.
package chickinfry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// OperationError carries an operation error code and its HTTP status.
type OperationError struct {
	Code   string
	Status int
}

// Error formats the operation failure for reading.
func (err *OperationError) Error() string {
	return fmt.Sprintf("operation failed (%s, HTTP %d)", err.Code, err.Status)
}

// HTTPTransport is a transport that invokes operations against a fixed origin.
type HTTPTransport struct {
	origin    string
	client    *http.Client
	bearer    string
	session   SessionStore
	refreshes *refreshFlights
}

// SessionCredentials is the rotating token bundle the SDK exchanges with a session store.
type SessionCredentials struct {
	AccessToken      string
	RefreshToken     string
	ExpiresAt        string
	RefreshExpiresAt string
	UserID           string
	SessionID        string
}

// SessionStore defines reading, saving, and ending session credentials owned by the caller.
// Refresh must serialize on the shared session unit, read its latest credentials,
// and persist successful results before returning. Clear must match expected credentials.
// MemoryStore provides these storage guarantees in memory.
// The SDK shares in-flight refreshes across clients bound to the same comparable
// store value in one process. Non-comparable or non-reflexive values use per-binding
// flights. Custom stores remain responsible for their own shared storage semantics.
// Use a store only with clients for the same origin.
type SessionStore interface {
	Credentials() SessionCredentials
	Refresh(ctx context.Context, operation func(context.Context, SessionCredentials) (SessionCredentials, error)) (SessionCredentials, error)
	Clear(ctx context.Context, expected SessionCredentials) error
}

type refreshFlight struct {
	done        chan struct{}
	credentials SessionCredentials
	err         error
}

type refreshFlights struct {
	mu      sync.Mutex
	flights map[refreshKey]*refreshFlight
}

type refreshKey struct {
	store SessionStore
	token string
}

type refreshResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresAt        string `json:"expires_at"`
	RefreshExpiresAt string `json:"refresh_expires_at"`
	UserID           string `json:"user_id"`
	SessionID        string `json:"session_id"`
}

var customRefreshes refreshFlights

// ponytail: retain one fingerprint per unknown refresh token for the process
// lifetime (O(unknown tokens)); use durable store state if restart recovery is needed.
var unknownRefreshes sync.Map

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func (flights *refreshFlights) Do(ctx context.Context, key refreshKey, run func() (SessionCredentials, error)) (SessionCredentials, error) {
	if err := ctx.Err(); err != nil {
		return SessionCredentials{}, err
	}
	flights.mu.Lock()
	if flights.flights == nil {
		flights.flights = make(map[refreshKey]*refreshFlight)
	}
	if flight, ok := flights.flights[key]; ok {
		flights.mu.Unlock()
		if err := conformanceJoin(ctx, flight, false); err != nil {
			return SessionCredentials{}, err
		}
		select {
		case <-flight.done:
			return flight.credentials, flight.err
		case <-ctx.Done():
			failure := newTransportError(ctx.Err())
			failure.OutcomeUnknown = true
			return SessionCredentials{}, failure
		}
	}
	flight := &refreshFlight{done: make(chan struct{})}
	flights.flights[key] = flight
	conformanceFlightRegister(ctx, flight, key.token)
	flights.mu.Unlock()
	go func() {
		defer func() {
			if recover() != nil {
				unknownRefreshes.Store(sha256.Sum256([]byte(key.token)), struct{}{})
				flight.err = &ClientError{Code: CodeUnauthenticated, Message: "session refresh failed; sign in again", OutcomeUnknown: true}
			}
			flights.mu.Lock()
			delete(flights.flights, key)
			conformanceFlightEnd(flight)
			close(flight.done)
			flights.mu.Unlock()
		}()
		if err := conformanceJoin(ctx, flight, true); err != nil {
			flight.err = err
			return
		}
		flight.credentials, flight.err = run()
	}()
	select {
	case <-flight.done:
		return flight.credentials, flight.err
	case <-ctx.Done():
		failure := newTransportError(ctx.Err())
		failure.OutcomeUnknown = true
		return SessionCredentials{}, failure
	}
}

// WithBearer returns a copy that uses the given bearer token without mutating the original transport.
func (transport *HTTPTransport) WithBearer(token string) (*HTTPTransport, error) {
	if !tokenPattern.MatchString(token) {
		return nil, &ClientError{Code: CodeInvalidArgument, Message: "invalid access token"}
	}
	copy := *transport
	copy.bearer = token
	copy.session = nil
	return &copy, nil
}

// WithSession returns a copy that uses the given session store.
// Clients bound to the same comparable store value share one in-flight refresh
// in this process. Pointer stores share by pointer identity; equal value stores
// share by value equality. Non-comparable or non-reflexive values (such as values
// containing NaN) use per-binding flights. The shared flight registry retains stores
// only until their flights complete. Use a store only with clients for the same origin.
func (transport *HTTPTransport) WithSession(store SessionStore) (*HTTPTransport, error) {
	if store == nil {
		return nil, &ClientError{Code: CodeInvalidArgument, Message: "session store is required"}
	}
	if transport.refreshes == nil {
		return nil, &ClientError{Code: CodeFailedPrecondition, Message: "session transport is not initialized"}
	}
	credentials := store.Credentials()
	if !tokenPattern.MatchString(credentials.AccessToken) || !tokenPattern.MatchString(credentials.RefreshToken) {
		return nil, &ClientError{Code: CodeUnauthenticated, Message: "session is unavailable; sign in again"}
	}
	signed, err := transport.WithBearer(credentials.AccessToken)
	if err != nil {
		return nil, err
	}
	signed.session = store
	signed.refreshes = new(refreshFlights)
	if memory, ok := store.(*MemoryStore); ok {
		signed.refreshes = &memory.refreshes
	} else if reflect.ValueOf(store).Comparable() && store == store {
		signed.refreshes = &customRefreshes
	}
	return signed, nil
}

// HTTPTransportOption configures an HTTP transport during construction.
type HTTPTransportOption func(*httpTransportOptions)

type httpTransportOptions struct{ timeout time.Duration }

// WithTimeout sets a positive per-request timeout, validated by NewHTTPTransport.
func WithTimeout(timeout time.Duration) HTTPTransportOption {
	return func(options *httpTransportOptions) { options.timeout = timeout }
}

// NewHTTPTransport accepts only HTTPS or loopback HTTP origins and refuses redirects.
// The per-request timeout defaults to 30 seconds.
func NewHTTPTransport(origin string, options ...HTTPTransportOption) (*HTTPTransport, error) {
	return newHTTP(origin, options, nil)
}

func newHTTP(origin string, options []HTTPTransportOption, observe func(*http.Transport) http.RoundTripper) (*HTTPTransport, error) {
	config := httpTransportOptions{timeout: 30 * time.Second}
	for _, option := range options {
		if option == nil {
			return nil, &ClientError{Code: CodeInvalidArgument, Message: "transport option is required"}
		}
		option(&config)
	}
	timeout := config.timeout
	if timeout <= 0 {
		return nil, &ClientError{Code: CodeInvalidArgument, Message: "operation timeout must be positive"}
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Hostname() == "" {
		return nil, &ClientError{Code: CodeInvalidArgument, Message: "invalid operation endpoint"}
	}
	host := parsed.Hostname()
	ip, ipErr := netip.ParseAddr(host)
	loopback := (host == "::1" && (parsed.Host == "[::1]" || strings.HasPrefix(parsed.Host, "[::1]:"))) ||
		(ipErr == nil && ip.Is4() && ip.IsLoopback() && host == ip.String())
	secure := parsed.Scheme == "https" || (parsed.Scheme == "http" && loopback)
	invalidPath := parsed.Path != "" && parsed.Path != "/"
	if !secure || invalidPath || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || strings.Contains(origin, "#") {
		return nil, &ClientError{Code: CodeInvalidArgument, Message: "operation endpoint must be an HTTPS or loopback HTTP origin"}
	}
	// Go 1.27 HTTP/2 retains a 4 MiB stream window, exceeding our response budget
	// (net/http/internal/http2/transport.go:45,50; config.go:57,62).
	standardTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok || standardTransport == nil {
		return nil, &ClientError{Code: CodeFailedPrecondition, Message: "default transport is not a standard *http.Transport; required to bound response buffering"}
	}
	clientTransport := standardTransport.Clone()
	clientTransport.Protocols = new(http.Protocols)
	clientTransport.Protocols.SetHTTP1(true)
	dial := clientTransport.DialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	clientTransport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		connection, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &requestConn{Conn: connection}, nil
	}
	var roundTripper http.RoundTripper = clientTransport
	if observe != nil {
		roundTripper = observe(clientTransport)
	}
	return &HTTPTransport{
		// Serialize through url.URL so IPv6 zone identifiers keep their
		// canonical percent encoding and the origin still round-trips.
		origin:    (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host}).String(),
		refreshes: new(refreshFlights),
		client: &http.Client{
			Transport:     roundTripper,
			Timeout:       timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

var operationName = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)
var errorCode = regexp.MustCompile(`^[a-z_]+$`)

// Invoke calls a single operation with POST and fills output from the response.
func (transport *HTTPTransport) Invoke(ctx context.Context, operation string, input any, output any) (result error) {
	ctx, finish, hookErr := conformanceBegin(ctx, transport.origin, transport.session != nil)
	defer finish()
	defer func() {
		result = sessionError(result, false)
		conformanceResult(ctx, result)
	}()
	if hookErr != nil {
		return hookErr
	}
	if transport.session == nil {
		return transport.invokeOnce(ctx, operation, input, output, transport.bearer, nil)
	}
	credentials := transport.session.Credentials()
	if !tokenPattern.MatchString(credentials.AccessToken) || !tokenPattern.MatchString(credentials.RefreshToken) {
		return &ClientError{Code: CodeUnauthenticated, Message: "session is unavailable; sign in again"}
	}
	bearer := credentials.AccessToken
	if operation == "auth.refresh" {
		bearer = ""
	}
	err := transport.invokeOnce(ctx, operation, input, output, bearer, nil)
	if operation == "auth.refresh" || !isInvalidToken(err) {
		return err
	}
	if hookErr := conformanceBarrier(ctx, "both-originals-rejected", ""); hookErr != nil {
		return hookErr
	}
	credentials, err = transport.refreshSession(ctx, credentials)
	if err != nil {
		conformanceRefreshFailure(ctx)
		return err
	}
	return transport.invokeOnce(ctx, operation, input, output, credentials.AccessToken, nil)
}

func (transport *HTTPTransport) refreshSession(ctx context.Context, failed SessionCredentials) (SessionCredentials, error) {
	current := transport.session.Credentials()
	if !tokenPattern.MatchString(current.AccessToken) || !tokenPattern.MatchString(current.RefreshToken) {
		return SessionCredentials{}, &ClientError{Code: CodeUnauthenticated, Message: "session is unavailable; sign in again"}
	}
	if current != failed {
		if !sameSession(current, failed) {
			return SessionCredentials{}, &ClientError{Code: CodeUnauthenticated, Message: "session changed; sign in again"}
		}
		return current, nil
	}
	key := refreshKey{token: current.RefreshToken}
	if transport.refreshes == &customRefreshes {
		key.store = transport.session
	}
	refreshed, err := transport.refreshes.Do(ctx, key, func() (SessionCredentials, error) {
		var rejected SessionCredentials
		fingerprint := sha256.Sum256([]byte(current.RefreshToken))
		attempted := false
		unknownOutcome := false
		refreshed, err := transport.session.Refresh(context.WithoutCancel(ctx), func(refreshCtx context.Context, latest SessionCredentials) (SessionCredentials, error) {
			rejected = latest
			if latest != failed {
				if !sameSession(latest, failed) {
					return SessionCredentials{}, &ClientError{Code: CodeUnauthenticated, Message: "session changed; sign in again"}
				}
				return latest, nil
			}
			written := new(atomic.Bool)
			if previous, blocked := unknownRefreshes.LoadOrStore(fingerprint, written); blocked {
				unknownOutcome = true
				if observed, ok := previous.(*atomic.Bool); ok && observed.Load() {
					conformanceRefreshBlocked(refreshCtx)
				}
				return SessionCredentials{}, &ClientError{Code: CodeUnauthenticated, Message: "refresh outcome is unknown; sign in again", OutcomeUnknown: true}
			}
			refreshCtx = httptrace.WithClientTrace(refreshCtx, &httptrace.ClientTrace{
				WroteRequest: func(info httptrace.WroteRequestInfo) {
					if info.Err == nil {
						written.Store(true)
					}
				},
			})
			var response refreshResponse
			// A lost or invalid response cannot prove that the server did not consume the token.
			attempted = true
			unknownOutcome = true
			classified := false
			err := transport.invokeOnce(refreshCtx, "auth.refresh", map[string]string{"refresh_token": latest.RefreshToken}, &response, "", &classified)
			if err != nil {
				failure, local := errors.AsType[*ClientError](err)
				if classified || (local && !failure.OutcomeUnknown) {
					unknownOutcome = false
				}
				return SessionCredentials{}, err
			}
			return SessionCredentials(response), nil
		})
		if err != nil {
			if !unknownOutcome && isUnauthorized(err) {
				if clearErr := conformanceClear(context.WithoutCancel(ctx), transport.session, rejected); clearErr != nil {
					return SessionCredentials{}, errors.Join(err, sessionError(clearErr, unknownOutcome))
				}
			}
			if attempted && !unknownOutcome {
				unknownRefreshes.Delete(fingerprint)
			}
			return SessionCredentials{}, sessionError(err, unknownOutcome)
		}
		// The callback succeeding does not prove that rotated credentials were saved.
		if attempted {
			unknownRefreshes.Delete(fingerprint)
		}
		return refreshed, nil
	})
	if err != nil {
		return SessionCredentials{}, err
	}
	latest := transport.session.Credentials()
	if (latest.AccessToken != refreshed.AccessToken || latest.RefreshToken != refreshed.RefreshToken) && !sameSession(latest, refreshed) {
		return SessionCredentials{}, &ClientError{Code: CodeUnauthenticated, Message: "session changed; sign in again"}
	}
	if !tokenPattern.MatchString(latest.AccessToken) || !tokenPattern.MatchString(latest.RefreshToken) {
		return SessionCredentials{}, &ClientError{Code: CodeUnauthenticated, Message: "session is unavailable; sign in again", OutcomeUnknown: true}
	}
	return latest, nil
}

func sameSession(first, second SessionCredentials) bool {
	// Two tokens alone cannot establish that a concurrent replacement is a rotation.
	return first.UserID != "" && first.SessionID != "" && first.UserID == second.UserID && first.SessionID == second.SessionID
}

type requestWrite struct {
	written atomic.Bool
	pending atomic.Int64
}

type requestConn struct {
	net.Conn
	write atomic.Pointer[requestWrite]
}

func (connection *requestConn) Write(buffer []byte) (int, error) {
	state := connection.write.Load()
	if state == nil {
		return connection.Conn.Write(buffer)
	}
	state.pending.Add(1)
	n, err := connection.Conn.Write(buffer)
	if n > 0 {
		state.written.Store(true)
	}
	state.pending.Add(-1)
	return n, err
}

func isInvalidToken(err error) bool {
	failure, ok := errors.AsType[*OperationError](err)
	return ok && failure.Status == http.StatusUnauthorized && failure.Code == "invalid_token"
}

func isUnauthorized(err error) bool {
	failure, ok := errors.AsType[*OperationError](err)
	return ok && failure.Status == http.StatusUnauthorized
}

// transportError reports the failure class without the raw transport message,
// which echoes server-controlled response bytes, the request URL, and proxy or
// TLS details that callers must not log or display.
type transportError struct {
	cause error
	class string
}

func (err *transportError) Error() string {
	return "operation request failed: " + err.class
}

func (err *transportError) Unwrap() error { return err.cause }

func newTransportError(cause error) *ClientError {
	class := classifyTransportFailure(cause)
	code := CodeUnavailable
	switch class {
	case "context canceled":
		code = CodeCanceled
	case "deadline exceeded", "timeout":
		code = CodeDeadlineExceeded
	case "malformed HTTP response":
		code = CodeInternal
	}
	redacted := &transportError{cause: cause, class: class}
	return &ClientError{Code: code, Message: redacted.Error(), cause: redacted}
}

func classifyTransportFailure(err error) string {
	var netFailure net.Error
	var verification *tls.CertificateVerificationError
	var record tls.RecordHeaderError
	switch {
	case errors.Is(err, context.Canceled):
		return "context canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline exceeded"
	case errors.As(err, &netFailure) && netFailure.Timeout():
		return "timeout"
	case isConnectionRefused(err):
		return "connection refused"
	case errors.As(err, &verification) || errors.As(err, &record):
		return "tls handshake failed"
	case isMalformedResponse(err):
		return "malformed HTTP response"
	default:
		return "network error"
	}
}

// isMalformedResponse matches genuine response parse failures only: the
// transport decorates those with the fixed connection-broken wrapper, and the
// leaf carries the parser's own message shape. A bare leaf alone proves
// nothing, because proxy CONNECT failures return the proxy's status text as
// an unadorned error.
func isMalformedResponse(err error) bool {
	transportBroken := false
	for {
		if strings.HasPrefix(err.Error(), "net/http: HTTP/1.x transport connection broken: ") {
			transportBroken = true
		}
		next := errors.Unwrap(err)
		if next == nil {
			break
		}
		err = next
	}
	if !transportBroken {
		return false
	}
	message := err.Error()
	return strings.HasPrefix(message, `malformed HTTP response "`) ||
		strings.HasPrefix(message, `malformed HTTP status code "`) ||
		strings.HasPrefix(message, `malformed HTTP version "`) ||
		strings.HasPrefix(message, "malformed MIME header")
}

func (transport *HTTPTransport) invokeOnce(ctx context.Context, operation string, input any, output any, bearer string, classified *bool) (result error) {
	if !operationName.MatchString(operation) {
		return &ClientError{Code: CodeInvalidArgument, Message: "invalid operation name"}
	}
	value := reflect.ValueOf(output)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return &ClientError{Code: CodeInvalidArgument, Message: "operation output must be a non-nil pointer"}
	}
	body, err := json.Marshal(input)
	if err != nil {
		return &ClientError{Code: CodeInvalidArgument, Message: "invalid operation request"}
	}
	if len(body) > 4<<20 {
		return &ClientError{Code: CodeResourceExhausted, Message: "operation request is too large"}
	}
	if err := ctx.Err(); err != nil {
		return newTransportError(err)
	}
	written := new(requestWrite)
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			// Start counting after TLS and proxy handshakes, including on reused connections.
			connection := info.Conn
			for {
				if tracked, ok := connection.(*requestConn); ok {
					tracked.write.Store(written)
					return
				}
				wrapped, ok := connection.(interface{ NetConn() net.Conn })
				if !ok {
					// A custom TLS dialer may hide its writes; their outcome remains unknown.
					written.written.Store(true)
					return
				}
				connection = wrapped.NetConn()
			}
		},
	})
	requestCtx, client, finishRequest := conformanceRequest(ctx, transport.client, operation, len(body))
	defer func() { finishRequest(result) }()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, transport.origin+"/"+operation, bytes.NewReader(body))
	if err != nil {
		return newTransportError(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := conformanceDo(client, request)
	if err != nil {
		failure := newTransportError(err)
		failure.OutcomeUnknown = written.written.Load() || written.pending.Load() > 0
		if response != nil {
			failure.Status = new(response.StatusCode)
		}
		return failure
	}
	conformanceProbe(requestCtx, response, nil)
	conformanceHeaders(requestCtx, response)
	defer func() { response.Body.Close(); conformanceReaderClosed(requestCtx) }()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		conformanceStop(requestCtx, false)
		return &ClientError{Code: CodeInternal, Message: "redirect not allowed", Status: new(response.StatusCode), OutcomeUnknown: true}
	}
	data := make([]byte, 1<<20)
	size := 0
	for {
		if size == len(data) {
			var overflow [1]byte
			n, err := io.ReadFull(response.Body, overflow[:])
			conformanceProbe(requestCtx, response, data)
			if conformanceRead(requestCtx, n, size) {
				return &ClientError{Code: CodeResourceExhausted, Message: "operation response is too large", Status: new(response.StatusCode), OutcomeUnknown: true}
			}
			if n != 0 {
				conformanceStop(requestCtx, true)
				return &ClientError{Code: CodeResourceExhausted, Message: "operation response is too large", Status: new(response.StatusCode), OutcomeUnknown: true}
			}
			if err != io.EOF {
				failure := newTransportError(err)
				failure.Message = "could not read operation response"
				failure.Status = new(response.StatusCode)
				failure.OutcomeUnknown = true
				return failure
			}
			break
		}
		n, err := response.Body.Read(data[size:])
		size += n
		conformanceProbe(requestCtx, response, data)
		if conformanceRead(requestCtx, n, size) {
			return &ClientError{Code: CodeResourceExhausted, Message: "operation response is too large", Status: new(response.StatusCode), OutcomeUnknown: true}
		}
		if err != nil {
			if err != io.EOF {
				failure := newTransportError(err)
				failure.Message = "could not read operation response"
				failure.Status = new(response.StatusCode)
				failure.OutcomeUnknown = true
				return failure
			}
			break
		}
	}
	data = data[:size]
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		failure := struct {
			Error string `json:"error"`
		}{}
		conformanceDecode(requestCtx)
		if json.Unmarshal(data, &failure) == nil && errorCode.MatchString(failure.Error) {
			// Other statuses do not guarantee that a refresh token was left unconsumed.
			if classified != nil && response.StatusCode == http.StatusUnauthorized {
				*classified = true
			}
			conformanceRejection(requestCtx, response.StatusCode == http.StatusUnauthorized)
			return &OperationError{Code: failure.Error, Status: response.StatusCode}
		}
		return &ClientError{Code: CodeInternal, Message: "invalid operation response", Status: new(response.StatusCode), OutcomeUnknown: true}
	}
	conformanceDecode(requestCtx)
	decoded := reflect.New(value.Elem().Type())
	if err := json.Unmarshal(data, decoded.Interface()); err != nil {
		return &ClientError{Code: CodeInternal, Message: "invalid operation response", Status: new(response.StatusCode), OutcomeUnknown: true}
	}
	if refreshed, ok := decoded.Interface().(*refreshResponse); ok && !validCredentials(SessionCredentials(*refreshed)) {
		return &ClientError{Code: CodeInternal, Message: "invalid operation response", Status: new(response.StatusCode), OutcomeUnknown: true}
	}
	value.Elem().Set(decoded.Elem())
	return nil
}
