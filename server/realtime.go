package server

import (
	"encoding/json"
	"errors"

	"github.com/chickinfry/chickinfry-go/server/host"
)

// Realtime issues tickets and publishes events through the host realtime port.
type Realtime struct {
	request Request
}

// NewRealtime binds the realtime port to one request.
func NewRealtime(request Request) Realtime {
	return Realtime{request: request}
}

// RealtimeTicketInput carries the verified session and transport of a ticket request.
type RealtimeTicketInput struct {
	Session   *Session `json:"session"`
	Origin    *string  `json:"origin"`
	Native    bool     `json:"native"`
	Transport string   `json:"transport"`
}

type realtimePublishInput struct {
	Channel string `json:"channel"`
	Payload any    `json:"payload"`
}

type realtimeQuery struct {
	RID   int64  `json:"rid"`
	Op    string `json:"op"`
	Input any    `json:"input"`
}

// Publish delivers one event on a channel.
func (realtime Realtime) Publish(channel string, payload any) error {
	response, err := realtime.request.call("realtime", realtimeQuery{RID: realtime.request.RID, Op: "publish", Input: realtimePublishInput{Channel: channel, Payload: payload}})
	if err != nil {
		return err
	}
	if err := host.Envelope(response, "", nil); err != nil {
		return realtimeFailure(err)
	}
	return nil
}

// Ticket issues a connection ticket from the realtime engine.
func (realtime Realtime) Ticket(input RealtimeTicketInput) (json.RawMessage, error) {
	response, err := realtime.request.call("realtime", realtimeQuery{RID: realtime.request.RID, Op: "ticket", Input: input})
	if err != nil {
		return nil, err
	}
	var value json.RawMessage
	if err := host.Envelope(response, "value", &value); err != nil {
		return nil, realtimeFailure(err)
	}
	return value, nil
}

func realtimeFailure(err error) error {
	if failure, ok := errors.AsType[*host.Error](err); ok {
		if failure.Code == "binding_unavailable" {
			return &OperationError{Status: 503, Code: "service_unavailable"}
		}
		if failure.Status >= 400 && failure.Status <= 599 {
			return &OperationError{Status: failure.Status, Code: failure.Code}
		}
		return &OperationError{Status: 503, Code: failure.Code}
	}
	return err
}
