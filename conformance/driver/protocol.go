// Package driver connects a JSON Lines controller to generated SDK calls.
package driver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/chickinfry/chickinfry-go"
)

const MaxLineBytes = 16 << 20

// Call invokes a generated typed method, without interpreting suite expectations.
type Call func(context.Context, *chickinfry.HTTPTransport, string, json.RawMessage) (any, error)

// Error is the sanitized protocol error; unavailable SDK metadata remains null.
type Error struct {
	Kind                       string  `json:"kind"`
	Code                       *string `json:"code"`
	HTTPStatus                 *int    `json:"httpStatus"`
	OutcomeUnknown             *bool   `json:"outcomeUnknown"`
	RawTransportDetails        *bool   `json:"rawTransportDetails,omitempty"`
	ConstructorNetworkRequests *int64  `json:"constructorNetworkRequests,omitempty"`
}

func (e *Error) Error() string { return "conformance driver error" }

// Unimplemented reports an operation or observation with no connection.
func Unimplemented() error { return failure("unimplemented", "unimplemented") }

func failure(kind, code string) *Error { return &Error{Kind: kind, Code: new(code)} }

var referenceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._/-]{0,255}$`)

func validReference(value string) bool { return referenceName.MatchString(value) }

var safeCode = regexp.MustCompile(`^[a-z_]+$`)

func normalize(err error) *Error {
	if own, ok := errors.AsType[*Error](err); ok {
		return own
	}
	e := &Error{Kind: "sdk"}
	if local, ok := errors.AsType[*chickinfry.ClientError](err); ok {
		code := string(local.Code)
		if safeCode.MatchString(code) {
			e.Code = new(code)
		}
		e.HTTPStatus = local.Status
		e.OutcomeUnknown = new(local.OutcomeUnknown)
		return e
	}
	if sdk, ok := errors.AsType[*chickinfry.OperationError](err); ok {
		if safeCode.MatchString(sdk.Code) {
			e.Code = new(sdk.Code)
		}
		if sdk.Status >= 100 && sdk.Status <= 599 {
			e.HTTPStatus = new(sdk.Status)
		}
	}
	return e
}

type request struct {
	ID      string          `json:"id"`
	Command string          `json:"command"`
	Args    json.RawMessage `json:"args"`
}

type response struct {
	ID     string `json:"id"`
	Result any    `json:"result"`
	Error  *Error `json:"error"`
}

func readLine(r *bufio.Reader) ([]byte, error) {
	return readLineLimit(r, MaxLineBytes)
}

func readLineLimit(r *bufio.Reader, maxBytes int) ([]byte, error) {
	var line []byte
	for {
		part, err := r.ReadSlice('\n')
		if len(line)+len(part) > maxBytes {
			return nil, failure("driver", "protocol_violation")
		}
		line = append(line, part...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) && len(line) == 0 {
			return nil, io.EOF
		}
		if err != nil || len(line) == 0 || line[len(line)-1] != '\n' || !utf8.Valid(line) {
			return nil, failure("driver", "protocol_violation")
		}
		return line[:len(line)-1], nil
	}
}

// Reject duplicate keys even inside operation inputs and credential maps.
func validateJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 1000 {
			return errors.New("JSON nesting limit")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, container := token.(json.Delim)
		if !container {
			return nil
		}
		if delim != '{' && delim != '[' {
			return errors.New("invalid JSON container")
		}
		keys := map[string]bool{}
		for d.More() {
			if delim == '{' {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || keys[name] {
					return errors.New("duplicate or invalid JSON key")
				}
				keys[name] = true
			}
			if err := value(depth + 1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
			return errors.New("invalid JSON container")
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

func decode(data []byte, dst any, allowed ...string) error {
	if len(data) == 0 || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return failure("driver", "invalid_args")
	}
	if len(allowed) != 0 {
		var fields map[string]json.RawMessage
		if json.Unmarshal(data, &fields) != nil || fields == nil {
			return failure("driver", "protocol_violation")
		}
		for field := range fields {
			if !slices.Contains(allowed, field) {
				return failure("driver", "protocol_violation")
			}
		}
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		if _, ok := errors.AsType[*json.UnmarshalTypeError](err); ok {
			return failure("driver", "invalid_args")
		}
		return failure("driver", "protocol_violation")
	}
	return nil
}

var capabilities = []string{"client.create", "client.copy", "client.call"}

type fixtureKey struct{}

// Fixture returns the SDK fixture selected for this client's call.
func Fixture(ctx context.Context) string {
	value, _ := ctx.Value(fixtureKey{}).(string)
	return value
}

type clientBinding struct {
	http    *chickinfry.HTTPTransport
	fixture string
	store   *storeBinding
}

type server struct {
	writer          io.Writer
	writeMu         sync.Mutex
	writeErr        error
	ctx             context.Context
	cancel          context.CancelFunc
	workers         sync.WaitGroup
	call            Call
	credentials     *credentials
	clients         map[string]*clientBinding
	stores          map[string]*storeBinding
	caseID          string
	sessionMu       sync.Mutex
	barrierMu       sync.Mutex
	barriers        map[string]*barrier
	pending         map[string]*barrierPending
	nextID          atomic.Uint64
	observeMu       sync.Mutex
	observations    map[string]*callObservations
	throughSequence uint64
}

func (s *server) reply(id string, result any, e *Error) {
	s.write(response{ID: id, Result: result, Error: e}, id, nil)
}

func (s *server) write(message any, id string, arrival context.Context) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeErr != nil || arrival != nil && arrival.Err() != nil {
		return
	}
	line, err := json.Marshal(message)
	if arrival != nil && (err != nil || len(line)+1 > MaxLineBytes || s.credentials.containsSecret(line)) {
		s.writeErr = failure("driver", "driver_failed")
		s.cancel()
		return
	}
	if err != nil || len(line)+1 > MaxLineBytes {
		line, _ = json.Marshal(response{ID: id, Error: failure("driver", "driver_failed")})
	}
	if s.credentials.containsSecret(line) {
		line, _ = json.Marshal(response{ID: id, Error: failure("driver", "driver_failed")})
		if s.credentials.containsSecret(line) {
			s.writeErr = failure("driver", "driver_failed")
			s.cancel()
			return
		}
	}
	if len(line)+1 > MaxLineBytes {
		// An ID that cannot fit in an error response cannot be replaced or truncated.
		s.writeErr = failure("driver", "protocol_violation")
		s.cancel()
		return
	}
	line = append(line, '\n')
	n, err := s.writer.Write(line)
	if err == nil && n != len(line) {
		err = io.ErrShortWrite
	}
	if err != nil {
		s.writeErr = failure("driver", "driver_failed")
		s.cancel()
	}
}

// Run reads protected credentials to EOF before negotiating or accepting calls.
// Closing control input joins SDK work; the controller owns process-level deadlines.
func Run(ctx context.Context, input io.Reader, output io.Writer, protected io.Reader, call Call) error {
	refs, err := loadCredentials(protected)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if closer, ok := input.(io.Closer); ok {
		closed := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { defer close(closed); closer.Close() })
		defer func() {
			if !stop() {
				<-closed
			}
		}()
	}
	s := &server{writer: output, ctx: ctx, cancel: cancel, call: call, credentials: refs,
		clients: map[string]*clientBinding{}, stores: map[string]*storeBinding{}, barriers: map[string]*barrier{}, pending: map[string]*barrierPending{}}
	defer func() { clear(s.clients); clear(s.stores); refs.erase() }()
	r := bufio.NewReader(input)
	seen := map[string]bool{}
	negotiated := false
	for {
		line, readErr := readLine(r)
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			if ctx.Err() != nil {
				err = failure("driver", "deadline_exceeded")
			} else {
				err = readErr
			}
			break
		}
		var direction struct {
			ID string `json:"id"`
		}
		if validateJSON(line) == nil && json.Unmarshal(line, &direction) == nil && strings.HasPrefix(direction.ID, "d:") {
			if e := s.releaseBarrier(line); e != nil {
				err = e
				break
			}
			continue
		}
		var req request
		if validateJSON(line) != nil || decode(line, &req, "id", "command", "args") != nil ||
			!validReference(req.ID) || !strings.HasPrefix(req.ID, "c:") || len(req.ID) <= 2 || req.Command == "" || seen[req.ID] {
			err = failure("driver", "protocol_violation")
			break
		}
		seen[req.ID] = true
		if !negotiated {
			if req.Command != "handshake" {
				err = failure("driver", "protocol_violation")
			} else {
				err = s.handshake(req)
			}
			if err != nil {
				s.reply(req.ID, nil, normalize(err))
				break
			}
			negotiated = true
			continue
		}
		if req.Command == "handshake" {
			err = failure("driver", "protocol_violation")
			s.reply(req.ID, nil, normalize(err))
			break
		}
		if e := s.dispatch(req); e != nil {
			s.reply(req.ID, nil, e)
			if e.Code != nil && *e.Code == "protocol_violation" {
				err = e
				break
			}
		}
	}
	if err != nil {
		cancel()
	}
	s.workers.Wait()
	if ctx.Err() != nil && err == nil {
		err = failure("driver", "deadline_exceeded")
	}
	if err == nil && !negotiated {
		err = failure("driver", "protocol_violation")
	}
	return errors.Join(s.writeErr, err)
}

func (s *server) handshake(req request) error {
	var args struct {
		ProtocolVersions     []int           `json:"protocolVersions"`
		RunID                string          `json:"runId"`
		RequiredCapabilities []string        `json:"requiredCapabilities"`
		Target               json.RawMessage `json:"target"`
	}
	if err := decode(req.Args, &args, "protocolVersions", "runId", "requiredCapabilities", "target"); err != nil {
		return err
	}
	if len(args.Target) != 0 {
		var target struct {
			Language    string `json:"language"`
			Role        string `json:"role"`
			Environment string `json:"environment"`
		}
		if err := decode(args.Target, &target, "language", "role", "environment"); err != nil {
			return err
		}
		if target.Language != "go" || target.Role != "sdk" || target.Environment != "native" {
			return Unimplemented()
		}
	}
	if !validReference(args.RunID) || args.ProtocolVersions == nil || args.RequiredCapabilities == nil {
		return failure("driver", "invalid_args")
	}
	if !slices.Contains(args.ProtocolVersions, 1) {
		return failure("driver", "protocol_mismatch")
	}
	for _, capability := range args.RequiredCapabilities {
		if !slices.Contains(supportedCapabilities(), capability) {
			return Unimplemented()
		}
	}
	s.reply(req.ID, map[string]any{"protocolVersion": 1, "driverVersion": "1", "capabilities": supportedCapabilities()}, nil)
	return nil
}

type commonArgs struct {
	CaseID    string `json:"caseId"`
	TimeoutMS int64  `json:"timeoutMs"`
}

func (s *server) scope(args commonArgs) *Error {
	if !validReference(args.CaseID) || args.TimeoutMS <= 0 || args.TimeoutMS > int64((1<<63-1)/time.Millisecond) {
		return failure("driver", "invalid_args")
	}
	if s.caseID != "" && s.caseID != args.CaseID {
		return failure("driver", "invalid_reference")
	}
	s.caseID = args.CaseID
	return nil
}
