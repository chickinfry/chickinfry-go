package driver

// transportEvent is the exact protocol projection of a runtime observation.
type transportEvent struct {
	Sequence          uint64  `json:"sequence"`
	CallID            string  `json:"callId"`
	ElapsedMS         float64 `json:"elapsedMs"`
	Phase             string  `json:"phase"`
	HTTPStatus        *int    `json:"httpStatus"`
	ReadBytes         int64   `json:"readBytes"`
	RetainedBytes     *int64  `json:"retainedBytes"`
	PeakRetainedBytes *int64  `json:"peakRetainedBytes"`
}

type callObservations struct {
	events   []transportEvent
	complete bool
	status   *int
	raw      *bool
	unknown  *bool
}

func (s *server) observe(req request, a args) *Error {
	if !supportsTransport() {
		return failure("unimplemented", "unimplemented")
	}
	s.observeMu.Lock()
	defer s.observeMu.Unlock()
	observations := s.observations[a.CallID]
	if observations == nil {
		return failure("driver", "invalid_reference")
	}
	if *a.AfterSequence > s.throughSequence {
		return failure("driver", "invalid_args")
	}
	events := []transportEvent{}
	for _, event := range observations.events {
		if event.Sequence > *a.AfterSequence {
			events = append(events, event)
		}
	}
	s.reply(req.ID, map[string]any{"callId": a.CallID, "throughSequence": s.throughSequence, "complete": observations.complete, "events": events}, nil)
	return nil
}

func (s *server) observedStatus(callID string) *int {
	s.observeMu.Lock()
	defer s.observeMu.Unlock()
	if observations := s.observations[callID]; observations != nil {
		return observations.status
	}
	return nil
}

func (s *server) observedError(callID string, err error) *Error {
	e := normalize(err)
	if e.Kind != "sdk" {
		return e
	}
	s.observeMu.Lock()
	defer s.observeMu.Unlock()
	if observations := s.observations[callID]; observations != nil {
		e.HTTPStatus, e.RawTransportDetails, e.OutcomeUnknown = observations.status, observations.raw, observations.unknown
	}
	return e
}
