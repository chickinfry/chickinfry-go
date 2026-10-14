package driver

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"time"

	chik "github.com/chickinfry/chickinfry-go"
)

type args struct {
	commonArgs
	ClientRef        string            `json:"clientRef"`
	Fixture          string            `json:"fixture"`
	SourceClientRef  string            `json:"sourceClientRef"`
	Origin           string            `json:"origin"`
	StoreRef         string            `json:"storeRef"`
	BearerRef        string            `json:"bearerRef"`
	RequestTimeoutMS int64             `json:"requestTimeoutMs"`
	Operation        string            `json:"operation"`
	Input            json.RawMessage   `json:"input"`
	InputRefs        map[string]string `json:"inputRefs"`
	OutputRefs       map[string]string `json:"outputRefs"`
	AccessRef        string            `json:"accessRef"`
	RefreshRef       string            `json:"refreshRef"`
	RecordRef        string            `json:"recordRef"`
	BarrierRef       string            `json:"barrierRef"`
	Point            string            `json:"point"`
	Participants     []string          `json:"participants"`
	IncludeTrace     *bool             `json:"includeTrace"`
}

var fields = map[string][]string{
	"client.create":        {"clientRef", "origin", "storeRef", "bearerRef", "requestTimeoutMs", "fixture"},
	"client.copy":          {"sourceClientRef", "clientRef", "bearerRef"},
	"client.call":          {"clientRef", "operation", "input", "inputRefs", "outputRefs"},
	"session.store.create": {"storeRef", "accessRef", "refreshRef", "recordRef", "origin"},
	"session.store.write":  {"storeRef", "accessRef", "refreshRef", "recordRef"},
	"session.store.read":   {"storeRef", "includeTrace"},
	"barrier.arm":          {"barrierRef", "point", "participants"},
}

func (s *server) dispatch(req request) *Error {
	if s.ctx.Err() != nil {
		return failure("driver", "deadline_exceeded")
	}
	allowed, supported := fields[req.Command]
	if !supported {
		return failure("unimplemented", "unimplemented")
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(req.Args, &keys) != nil || keys == nil {
		return failure("driver", "invalid_args")
	}
	for key, value := range keys {
		valid := key == "caseId" || key == "timeoutMs"
		for _, field := range allowed {
			valid = valid || key == field
		}
		if !valid {
			return failure("driver", "protocol_violation")
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) && key != "input" {
			return failure("driver", "invalid_args")
		}
		if strings.HasSuffix(key, "Ref") {
			var ref string
			if json.Unmarshal(value, &ref) != nil || !validReference(ref) {
				return failure("driver", "invalid_args")
			}
		}
	}
	var a args
	if err := decode(req.Args, &a); err != nil {
		return normalize(err)
	}
	for _, refs := range []map[string]string{a.InputRefs, a.OutputRefs} {
		for _, ref := range refs {
			if !validReference(ref) {
				return failure("driver", "invalid_args")
			}
		}
	}
	for _, id := range a.Participants {
		if !validReference(id) || !strings.HasPrefix(id, "c:") || len(id) <= 2 {
			return failure("driver", "invalid_args")
		}
	}
	if e := s.scope(a.commonArgs); e != nil {
		return e
	}
	switch req.Command {
	case "client.create", "client.copy":
		if a.ClientRef == "" {
			return failure("driver", "invalid_args")
		}
		if s.clients[a.ClientRef] != nil {
			return failure("driver", "invalid_reference")
		}
		var transport *chik.HTTP
		var store *storeBinding
		var err error
		fixture := "plain"
		if req.Command == "client.copy" {
			source := s.clients[a.SourceClientRef]
			if source == nil {
				return failure("driver", "invalid_reference")
			}
			transport, fixture = source.http, source.fixture
			if a.BearerRef == "" {
				return failure("driver", "invalid_args")
			}
		} else {
			if _, supplied := keys["fixture"]; supplied {
				if a.Fixture != "plain" {
					return failure("driver", "invalid_args")
				}
				fixture = a.Fixture
			}
			_, hasOrigin := keys["origin"]
			_, hasStore := keys["storeRef"]
			_, hasBearer := keys["bearerRef"]
			if !hasOrigin || a.RequestTimeoutMS <= 0 || a.RequestTimeoutMS > int64((1<<63-1)/time.Millisecond) || (hasStore && hasBearer) {
				return failure("driver", "invalid_args")
			}
			transport, err = chik.NewHTTPWithTimeout(a.Origin, time.Duration(a.RequestTimeoutMS)*time.Millisecond)
			if err != nil {
				return normalize(err)
			}
		}
		if a.BearerRef != "" {
			token, e := s.credentials.resolve(a.BearerRef)
			if e != nil {
				return e
			}
			transport, err = transport.WithBearer(token)
		} else if a.StoreRef != "" {
			if !supportsSession() {
				return failure("unimplemented", "unimplemented")
			}
			store = s.stores[a.StoreRef]
			if store == nil {
				return failure("driver", "invalid_reference")
			}
			if a.Origin != store.origin {
				return failure("driver", "invalid_args")
			}
			transport, err = transport.WithSession(store.memory)
		}
		if err != nil {
			return normalize(err)
		}
		s.clients[a.ClientRef] = &clientBinding{http: transport, fixture: fixture, store: store}
		s.reply(req.ID, map[string]any{"clientRef": a.ClientRef}, nil)
	case "session.store.create", "session.store.write", "session.store.read":
		return s.sessionStore(req, a)
	case "barrier.arm":
		if e := s.armBarrier(a); e != nil {
			return e
		}
		s.reply(req.ID, map[string]any{"barrierRef": a.BarrierRef, "state": "armed"}, nil)
	case "client.call":
		binding := s.clients[a.ClientRef]
		if binding == nil {
			return failure("driver", "invalid_reference")
		}
		if a.Operation == "" || len(a.Input) == 0 {
			return failure("driver", "invalid_args")
		}
		if len(a.InputRefs) != 0 {
			var input map[string]json.RawMessage
			if json.Unmarshal(a.Input, &input) != nil || input == nil {
				return failure("driver", "invalid_args")
			}
			for field, ref := range a.InputRefs {
				if field == "" {
					return failure("driver", "invalid_args")
				}
				if _, exists := input[field]; exists {
					return failure("driver", "invalid_args")
				}
				token, e := s.credentials.resolve(ref)
				if e != nil {
					return e
				}
				input[field], _ = json.Marshal(token)
			}
			a.Input, _ = json.Marshal(input)
		}
		if s.call == nil {
			return failure("unimplemented", "unimplemented")
		}
		ctx, cancel := context.WithTimeout(s.ctx, time.Duration(a.TimeoutMS)*time.Millisecond)
		ctx = context.WithValue(ctx, callKey{}, req.ID)
		ctx = context.WithValue(ctx, fixtureKey{}, binding.fixture)
		if binding.store != nil {
			ctx = context.WithValue(ctx, storeKey{}, binding.store)
		}
		sdkCtx := attachHooks(s, context.WithoutCancel(ctx), ctx, req.ID, a.CaseID)
		type callResult struct {
			output any
			err    error
		}
		completed := make(chan callResult, 1)
		s.workers.Go(func() {
			var result callResult
			defer func() {
				if recover() != nil {
					result = callResult{err: failure("driver", "driver_failed")}
				}
				completed <- result
			}()
			if ctx.Err() != nil {
				result.err = failure("driver", "deadline_exceeded")
				return
			}
			// The SDK joins its refresh flight only while this context remains live.
			result.output, result.err = s.call(sdkCtx, binding.http, a.Operation, a.Input)
			if result.err == nil {
				clean, refs, e := s.credentials.output(result.output, a.OutputRefs)
				if e != nil {
					result.err = e
				} else {
					// Register credential outputs even when the command deadline has expired.
					result.output = map[string]any{"output": clean, "credentialRefs": refs, "httpStatus": nil}
				}
			}
		})
		s.workers.Go(func() {
			defer cancel()
			defer func() {
				if recover() != nil {
					s.reply(req.ID, nil, failure("driver", "driver_failed"))
				}
			}()
			var result callResult
			select {
			case result = <-completed:
			case <-ctx.Done():
			}
			if ctx.Err() != nil {
				s.reply(req.ID, nil, failure("driver", "deadline_exceeded"))
				return
			}
			if result.err != nil {
				s.reply(req.ID, nil, normalize(result.err))
				return
			}
			// The public SDK does not expose successful response status codes.
			s.reply(req.ID, result.output, nil)
		})
	}
	return nil
}
