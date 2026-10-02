// Package chik provides the shared Go runtime behind Chickinfry generated clients.
package chik

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
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
		flight.token, flight.err = run()
		close(flight.done)
		flights.mu.Lock()
		delete(flights.flights, refreshToken)
		flights.mu.Unlock()
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
	ip := net.ParseIP(parsed.Hostname())
	secure := parsed.Scheme == "https" || (parsed.Scheme == "http" && ip != nil && ip.IsLoopback())
	invalidPath := parsed.Path != "" && parsed.Path != "/"
	if !secure || invalidPath || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("operation endpoint must be an HTTPS or loopback HTTP origin")
	}
	return &HTTP{
		origin:    parsed.Scheme + "://" + parsed.Host,
		refreshes: &refreshFlights{flights: map[string]*refreshFlight{}},
		client: &http.Client{
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
		return transport.invokeOnce(ctx, operation, input, output, transport.bearer)
	}
	credentials := transport.session.Credentials()
	bearer := credentials.AccessToken
	if operation == "auth.refresh" {
		bearer = ""
	}
	err := transport.invokeOnce(ctx, operation, input, output, bearer)
	if operation == "auth.refresh" || !isInvalidToken(err) {
		return err
	}
	credentials, err = transport.refreshSession(ctx, credentials)
	if err != nil {
		return err
	}
	return transport.invokeOnce(ctx, operation, input, output, credentials.AccessToken)
}

func (transport *HTTP) refreshSession(ctx context.Context, failed SessionCredentials) (SessionCredentials, error) {
	current := transport.session.Credentials()
	if current.AccessToken != failed.AccessToken {
		return current, nil
	}
	_, err := transport.refreshes.Do(ctx, current.RefreshToken, func() (string, error) {
		var rejected SessionCredentials
		refreshed, err := transport.session.Refresh(context.WithoutCancel(ctx), func(refreshCtx context.Context, latest SessionCredentials) (SessionCredentials, error) {
			rejected = latest
			if latest.AccessToken != failed.AccessToken {
				return latest, nil
			}
			response := struct {
				AccessToken      string `json:"access_token"`
				RefreshToken     string `json:"refresh_token"`
				ExpiresAt        string `json:"expires_at"`
				RefreshExpiresAt string `json:"refresh_expires_at"`
				UserID           string `json:"user_id"`
				SessionID        string `json:"session_id"`
			}{}
			err := transport.invokeOnce(refreshCtx, "auth.refresh", map[string]string{"refresh_token": latest.RefreshToken}, &response, "")
			if err != nil {
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
			if isUnauthorized(err) {
				if clearErr := transport.session.Clear(context.WithoutCancel(ctx), rejected); clearErr != nil {
					return "", errors.Join(err, clearErr)
				}
			}
			return "", err
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

func (transport *HTTP) invokeOnce(ctx context.Context, operation string, input any, output any, bearer string) error {
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
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := transport.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return &OperationError{Code: "redirect_not_allowed", Status: response.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil {
		return errors.New("could not read operation response")
	}
	if len(data) > 1<<20 {
		return errors.New("operation response is too large")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		failure := struct {
			Error string `json:"error"`
		}{}
		code := "operation_failed"
		if json.Unmarshal(data, &failure) == nil && errorCode.MatchString(failure.Error) {
			code = failure.Error
		}
		return &OperationError{Code: code, Status: response.StatusCode}
	}
	if err := json.Unmarshal(data, output); err != nil {
		return errors.New("invalid operation response")
	}
	return nil
}
