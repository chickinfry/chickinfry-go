package chickinfry

import (
	"context"
	"errors"
)

// ClientErrorCode classifies a local SDK failure independently of server codes.
type ClientErrorCode string

// CodeInvalidArgument and the remaining codes classify local SDK failures.
const (
	CodeUnauthenticated    ClientErrorCode = "unauthenticated"
	CodeInvalidArgument    ClientErrorCode = "invalid_argument"
	CodeFailedPrecondition ClientErrorCode = "failed_precondition"
	CodeResourceExhausted  ClientErrorCode = "resource_exhausted"
	CodeDeadlineExceeded   ClientErrorCode = "deadline_exceeded"
	CodeCanceled           ClientErrorCode = "canceled"
	CodeUnavailable        ClientErrorCode = "unavailable"
	CodeDataLoss           ClientErrorCode = "data_loss"
	CodeUnimplemented      ClientErrorCode = "unimplemented"
	CodeInternal           ClientErrorCode = "internal"
	CodeUnknown            ClientErrorCode = "unknown"
)

// ClientError reports a local failure, not a validated server rejection.
// Status is nil unless an HTTP response was received. OutcomeUnknown means the
// operation may have executed; callers must not automatically replay it.
// Message is safe to display; the wrapped cause may contain transport details.
type ClientError struct {
	Code           ClientErrorCode
	Status         *int
	OutcomeUnknown bool
	Message        string
	cause          error
}

// Error returns the safe local failure message without formatting its cause.
func (err *ClientError) Error() string {
	if err.Message != "" {
		return err.Message
	}
	return "client failed (" + string(err.Code) + ")"
}

// Unwrap preserves errors.Is and errors.As inspection of the underlying cause.
func (err *ClientError) Unwrap() error { return err.cause }

func sessionError(err error, outcomeUnknown bool) error {
	if err == nil {
		return nil
	}
	if _, ok := errors.AsType[*ClientError](err); ok {
		return err
	}
	if _, ok := errors.AsType[*OperationError](err); ok {
		return err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		failure := newTransportError(err)
		failure.OutcomeUnknown = outcomeUnknown
		return failure
	}
	return &ClientError{Code: CodeFailedPrecondition, Message: "session storage failed; sign in again", OutcomeUnknown: outcomeUnknown, cause: err}
}
