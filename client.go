// Package chik provides the shared Go runtime behind Chickinfry generated clients.
package chik

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
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
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

// HTTP is a transport that invokes operations against a fixed origin.
type HTTP struct {
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
type SessionStore interface {
	Credentials() SessionCredentials
	Refresh(ctx context.Context, operation func(context.Context, SessionCredentials) (SessionCredentials, error)) (SessionCredentials, error)
	Clear(ctx context.Context, expected SessionCredentials) error
}

type refreshFlight struct {
	done  chan struct{}
	token string
	err   error
}

type refreshFlights struct {
	mu      sync.Mutex
	flights map[string]*refreshFlight
}

// ponytail: retain one fingerprint per unknown refresh token for the process
// lifetime (O(unknown tokens)); use durable store state if restart recovery is needed.
var unknownRefreshes sync.Map

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func (flights *refreshFlights) Do(ctx context.Context, refreshToken string, run func() (string, error)) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	flights.mu.Lock()
	if flight, ok := flights.flights[refreshToken]; ok {
		flights.mu.Unlock()
		select {
		case <-flight.done:
			return flight.token, flight.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	flight := &refreshFlight{done: make(chan struct{})}
	flights.flights[refreshToken] = flight
	flights.mu.Unlock()
	go func() {
		defer func() {
			if recover() != nil {
				unknownRefreshes.Store(sha256.Sum256([]byte(refreshToken)), struct{}{})
				flight.err = errors.New("session refresh failed; sign in again")
			}
			flights.mu.Lock()
			delete(flights.flights, refreshToken)
			close(flight.done)
			flights.mu.Unlock()
		}()
		flight.token, flight.err = run()
	}()
	select {
	case <-flight.done:
		return flight.token, flight.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// WithBearer returns a copy that uses the given bearer token without mutating the original transport.
func (transport *HTTP) WithBearer(token string) (*HTTP, error) {
	if !tokenPattern.MatchString(token) {
		return nil, errors.New("invalid access token")
	}
	copy := *transport
	copy.bearer = token
	copy.session = nil
	return &copy, nil
}

// WithSession returns a copy that uses the given session store.
func (transport *HTTP) WithSession(store SessionStore) (*HTTP, error) {
	if store == nil {
		return nil, errors.New("session store is required")
	}
	if transport.refreshes == nil {
		return nil, errors.New("session transport is not initialized")
	}
	credentials := store.Credentials()
	if !tokenPattern.MatchString(credentials.AccessToken) || !tokenPattern.MatchString(credentials.RefreshToken) {
		return nil, errors.New("invalid session credential")
	}
	signed, err := transport.WithBearer(credentials.AccessToken)
	if err != nil {
		return nil, err
	}
	signed.session = store
	// Each store binding must enter its own Refresh path to synchronize cached credentials.
	signed.refreshes = &refreshFlights{flights: map[string]*refreshFlight{}}
	return signed, nil
}

// NewHTTP accepts only HTTPS or loopback HTTP origins and refuses redirects.
func NewHTTP(origin string) (*HTTP, error) {
	return NewHTTPWithTimeout(origin, 30*time.Second)
}

// NewHTTPWithTimeout builds a transport applying a per-request timeout.
func NewHTTPWithTimeout(origin string, timeout time.Duration) (*HTTP, error) {
	if timeout <= 0 {
		return nil, errors.New("operation timeout must be positive")
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Hostname() == "" {
		return nil, errors.New("invalid operation endpoint")
	}
	host := parsed.Hostname()
	ip, ipErr := netip.ParseAddr(host)
	loopback := (host == "::1" && (parsed.Host == "[::1]" || strings.HasPrefix(parsed.Host, "[::1]:"))) ||
		(ipErr == nil && ip.Is4() && ip.IsLoopback() && host == ip.String())
	secure := parsed.Scheme == "https" || (parsed.Scheme == "http" && loopback)
	invalidPath := parsed.Path != "" && parsed.Path != "/"
	if !secure || invalidPath || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || strings.Contains(origin, "#") {
		return nil, errors.New("operation endpoint must be an HTTPS or loopback HTTP origin")
	}
	// Go 1.27 HTTP/2 retains a 4 MiB stream window, exceeding our response budget
	// (net/http/internal/http2/transport.go:45,50; config.go:57,62).
	standardTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok || standardTransport == nil {
		return nil, errors.New("default transport is not a standard *http.Transport; required to bound response buffering")
	}
	clientTransport := standardTransport.Clone()
	clientTransport.Protocols = new(http.Protocols)
	clientTransport.Protocols.SetHTTP1(true)
	return &HTTP{
		// Serialize through url.URL so IPv6 zone identifiers keep their
		// canonical percent encoding and the origin still round-trips.
		origin:    (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host}).String(),
		refreshes: &refreshFlights{flights: map[string]*refreshFlight{}},
		client: &http.Client{
			Transport:     clientTransport,
			Timeout:       timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

var operationName = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)
var errorCode = regexp.MustCompile(`^[a-z_]+$`)

// Invoke calls a single operation with POST and fills output from the response.
func (transport *HTTP) Invoke(ctx context.Context, operation string, input any, output any) error {
	if transport.session == nil {
		return transport.invokeOnce(ctx, operation, input, output, transport.bearer, nil)
	}
	credentials := transport.session.Credentials()
	bearer := credentials.AccessToken
	if operation == "auth.refresh" {
		bearer = ""
	}
	err := transport.invokeOnce(ctx, operation, input, output, bearer, nil)
	if operation == "auth.refresh" || !isInvalidToken(err) {
		return err
	}
	credentials, err = transport.refreshSession(ctx, credentials)
	if err != nil {
		return err
	}
	return transport.invokeOnce(ctx, operation, input, output, credentials.AccessToken, nil)
}

func (transport *HTTP) refreshSession(ctx context.Context, failed SessionCredentials) (SessionCredentials, error) {
	current := transport.session.Credentials()
	if current != failed {
		return current, nil
	}
	_, err := transport.refreshes.Do(ctx, current.RefreshToken, func() (string, error) {
		var rejected SessionCredentials
		fingerprint := sha256.Sum256([]byte(current.RefreshToken))
		attempted := false
		unknownOutcome := false
		refreshed, err := transport.session.Refresh(context.WithoutCancel(ctx), func(refreshCtx context.Context, latest SessionCredentials) (SessionCredentials, error) {
			rejected = latest
			if latest != failed {
				return latest, nil
			}
			if _, blocked := unknownRefreshes.LoadOrStore(fingerprint, struct{}{}); blocked {
				unknownOutcome = true
				return SessionCredentials{}, &OperationError{Code: "invalid_token", Status: http.StatusUnauthorized}
			}
			response := struct {
				AccessToken      string `json:"access_token"`
				RefreshToken     string `json:"refresh_token"`
				ExpiresAt        string `json:"expires_at"`
				RefreshExpiresAt string `json:"refresh_expires_at"`
				UserID           string `json:"user_id"`
				SessionID        string `json:"session_id"`
			}{}
			// A lost or invalid response cannot prove that the server did not consume the token.
			attempted = true
			unknownOutcome = true
			classified := false
			err := transport.invokeOnce(refreshCtx, "auth.refresh", map[string]string{"refresh_token": latest.RefreshToken}, &response, "", &classified)
			if err != nil {
				if classified {
					unknownOutcome = false
				}
				return SessionCredentials{}, err
			}
			refreshed := SessionCredentials(response)
			if !tokenPattern.MatchString(refreshed.AccessToken) || !tokenPattern.MatchString(refreshed.RefreshToken) ||
				refreshed.ExpiresAt == "" || refreshed.RefreshExpiresAt == "" || refreshed.UserID == "" || refreshed.SessionID == "" {
				return SessionCredentials{}, errors.New("invalid refresh response")
			}
			return refreshed, nil
		})
		if err != nil {
			if !unknownOutcome && isUnauthorized(err) {
				if clearErr := transport.session.Clear(context.WithoutCancel(ctx), rejected); clearErr != nil {
					return "", errors.Join(err, clearErr)
				}
			}
			if attempted && !unknownOutcome {
				unknownRefreshes.Delete(fingerprint)
			}
			return "", err
		}
		// The callback succeeding does not prove that rotated credentials were saved.
		if attempted {
			unknownRefreshes.Delete(fingerprint)
		}
		return refreshed.AccessToken, nil
	})
	if err != nil {
		return SessionCredentials{}, err
	}
	return transport.session.Credentials(), nil
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

func newTransportError(cause error) error {
	return &transportError{cause: cause, class: classifyTransportFailure(cause)}
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

func (transport *HTTP) invokeOnce(ctx context.Context, operation string, input any, output any, bearer string, classified *bool) error {
	if !operationName.MatchString(operation) {
		return errors.New("invalid operation name")
	}
	body, err := json.Marshal(input)
	if err != nil {
		return errors.New("invalid operation request")
	}
	if len(body) > 4<<20 {
		return errors.New("operation request is too large")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, transport.origin+"/"+operation, bytes.NewReader(body))
	if err != nil {
		return newTransportError(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := transport.client.Do(request)
	if err != nil {
		return newTransportError(err)
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return &OperationError{Code: "redirect_not_allowed", Status: response.StatusCode}
	}
	data := make([]byte, 1<<20)
	size := 0
	for {
		if size == len(data) {
			var overflow [1]byte
			n, err := io.ReadFull(response.Body, overflow[:])
			if n != 0 {
				return errors.New("operation response is too large")
			}
			if err != io.EOF {
				return errors.New("could not read operation response")
			}
			break
		}
		n, err := response.Body.Read(data[size:])
		size += n
		if err != nil {
			if err != io.EOF {
				return errors.New("could not read operation response")
			}
			break
		}
	}
	data = data[:size]
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		failure := struct {
			Error string `json:"error"`
		}{}
		code := "invalid_response"
		if json.Unmarshal(data, &failure) == nil && errorCode.MatchString(failure.Error) {
			code = failure.Error
			// Other statuses do not guarantee that a refresh token was left unconsumed.
			if classified != nil && response.StatusCode == http.StatusUnauthorized {
				*classified = true
			}
		}
		return &OperationError{Code: code, Status: response.StatusCode}
	}
	if err := json.Unmarshal(data, output); err != nil {
		return errors.New("invalid operation response")
	}
	return nil
}
