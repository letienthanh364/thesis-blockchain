package common

import (
	"errors"
)

var (
	ErrMissingAuthContext = errors.New("authentication context unavailable")
	ErrMethodNotAllowed   = errors.New("method not allowed")
)

// StatusError conveys an HTTP response code alongside the error message.
type StatusError struct {
	Code int
	Msg  string
}

func (e *StatusError) Error() string {
	return e.Msg
}

// NewStatusError builds an error tied to a specific HTTP status code.
func NewStatusError(code int, msg string) error {
	return &StatusError{Code: code, Msg: msg}
}

// AsStatusError reports the embedded status error for centralized handling.
func AsStatusError(err error) (*StatusError, bool) {
	var se *StatusError
	if errors.As(err, &se) {
		return se, true
	}
	return nil, false
}
