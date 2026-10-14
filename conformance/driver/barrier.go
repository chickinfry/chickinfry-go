package driver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type barrier struct {
	ref, point, caseID string
	participants       map[string]bool
}

type barrierPending struct {
	ref  string
	done chan *Error
	ctx  context.Context
}

func (s *server) armBarrier(a args) *Error {
	if !supportsBarrierPoint(a.Point) {
		return failure("unimplemented", "unimplemented")
	}
	if !validReference(a.BarrierRef) || len(a.Participants) == 0 {
		return failure("driver", "invalid_args")
	}
	s.barrierMu.Lock()
	defer s.barrierMu.Unlock()
	if s.barriers[a.BarrierRef] != nil {
		return failure("driver", "protocol_violation")
	}
	b := &barrier{ref: a.BarrierRef, point: a.Point, caseID: a.CaseID, participants: map[string]bool{}}
	for _, id := range a.Participants {
		if !validReference(id) || !strings.HasPrefix(id, "c:") || len(id) <= 2 {
			return failure("driver", "invalid_args")
		}
		if _, exists := b.participants[id]; exists {
			return failure("driver", "protocol_violation")
		}
		b.participants[id] = false
	}
	s.barriers[a.BarrierRef] = b
	return nil
}

func (s *server) arrive(ctx context.Context, callID, caseID, point string, facts any) error {
	if ctx.Err() != nil {
		return failure("driver", "deadline_exceeded")
	}
	s.barrierMu.Lock()
	var selected *barrier
	for _, b := range s.barriers {
		if b.point != point || b.caseID != caseID {
			continue
		}
		arrived, participant := b.participants[callID]
		if !participant {
			continue
		}
		if arrived || selected != nil {
			s.barrierMu.Unlock()
			return failure("driver", "protocol_violation")
		}
		selected = b
	}
	if selected == nil {
		s.barrierMu.Unlock()
		return nil
	}
	selected.participants[callID] = true
	id := fmt.Sprintf("d:%d", s.nextID.Add(1))
	pending := &barrierPending{ref: selected.ref, done: make(chan *Error, 1), ctx: ctx}
	s.pending[id] = pending
	s.barrierMu.Unlock()
	timeout := int64(1)
	if deadline, ok := ctx.Deadline(); ok {
		timeout = max(1, time.Until(deadline).Milliseconds())
	}
	s.write(map[string]any{"id": id, "command": "barrier.arrive", "args": map[string]any{"caseId": caseID, "timeoutMs": timeout, "barrierRef": selected.ref, "callId": callID, "point": point, "facts": facts}}, id, ctx)
	select {
	case e := <-pending.done:
		if e != nil {
			return e
		}
		return nil
	case <-ctx.Done():
		return failure("driver", "deadline_exceeded")
	case <-s.ctx.Done():
		return failure("driver", "deadline_exceeded")
	}
}

func (s *server) releaseBarrier(line []byte) *Error {
	var reply struct {
		ID     string          `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if decode(line, &reply, "id", "result", "error") != nil || !validReference(reply.ID) || !strings.HasPrefix(reply.ID, "d:") || len(reply.ID) <= 2 || string(reply.Error) != "null" {
		return failure("driver", "protocol_violation")
	}
	var released struct {
		BarrierRef string `json:"barrierRef"`
		State      string `json:"state"`
		Sequence   uint64 `json:"sequence"`
	}
	if decode(reply.Result, &released, "barrierRef", "state", "sequence") != nil || !validReference(released.BarrierRef) || released.State != "released" || released.Sequence == 0 {
		return failure("driver", "protocol_violation")
	}
	s.barrierMu.Lock()
	defer s.barrierMu.Unlock()
	pending := s.pending[reply.ID]
	if pending == nil || pending.ref != released.BarrierRef || pending.ctx.Err() != nil {
		return failure("driver", "protocol_violation")
	}
	delete(s.pending, reply.ID)
	pending.done <- nil
	return nil
}
