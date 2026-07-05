//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/bassosimone/nop/blob/ae41909903156c3fc9c0d80a56ce884c1ca4eb4a/config.go
// Adapted from: https://github.com/bassosimone/nop/blob/ae41909903156c3fc9c0d80a56ce884c1ca4eb4a/errclassifier.go
// Adapted from: https://github.com/ooni/probe-cli/blob/v3.20.1/internal/netxlite/dialer.go
// Adapted from: https://github.com/rbmk-project/rbmk/blob/v0.17.0/pkg/x/netcore/dialer.go
// Adapted from: https://github.com/bassosimone/nop/blob/ae41909903156c3fc9c0d80a56ce884c1ca4eb4a/slogger.go
//

package ptnop

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/bassosimone/errclass"
	"github.com/bassosimone/runtimex"
)

// Dialer abstracts the [*net.Dialer] behavior.
//
// By making [*ConnectFunc] depend on an abstract implementation we
// allow for unit testing and for using alternative dialers.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// ErrClassifier classifies errors into categorical strings for analysis.
//
// Implementations map errors to short, descriptive labels (e.g., "ETIMEDOUT",
// "ECONNRESET") that facilitate systematic analysis of network measurement results.
type ErrClassifier interface {
	Classify(err error) string
}

// ErrClassifierFunc adapts a function to the [ErrClassifier] interface.
//
// This allows using simple functions as classifiers:
//
//	cfg.ErrClassifier = ptnop.ErrClassifierFunc(myClassifier)
type ErrClassifierFunc func(error) string

var _ ErrClassifier = ErrClassifierFunc(nil)

// Classify implements [ErrClassifier].
func (f ErrClassifierFunc) Classify(err error) string {
	return f(err)
}

// ErrSkip is a wrapper error indicating that a pipeline stage was skipped
// because a previous stage failed. Stages that receive an error-carrying
// input emit their start/done events with this error rather than executing.
type ErrSkip struct {
	Err error
}

// Error returns a string representation of the error.
func (err ErrSkip) Error() string {
	return err.Err.Error()
}

// Unwrap returns the underlying error.
func (err ErrSkip) Unwrap() error {
	return err.Err
}

// ESKIP is the error class string for [ErrSkip].
const ESKIP = "ESKIP"

// NewErrSkip creates a new [ErrSkip] instance wrapping the given error
// unless the error is already an [ErrSkip], in which case we return the
// unmodified [ErrSkip] instance to the caller.
//
// Note that this function panics if passed a nil err.
func NewErrSkip(err error) error {
	runtimex.Assert(err != nil)
	if _, ok := errors.AsType[ErrSkip](err); ok {
		return err
	}
	return ErrSkip{err}
}

// DefaultErrClassifier classifies errors into Unix-like error names.
//
// It recognizes [ErrSkip] as [ESKIP] and delegates all other errors to
// [errclass.New] (e.g., "ETIMEDOUT", "ECONNRESET").
var DefaultErrClassifier = ErrClassifierFunc(func(err error) string {
	if _, ok := errors.AsType[ErrSkip](err); ok {
		return ESKIP
	}
	return errclass.New(err)
})

// Config holds common configuration for ptnop operations.
//
// Pass this to constructor functions to pre-wire dependencies.
//
// All fields have sensible defaults set by [NewConfig].
type Config struct {
	// Dialer is used by [*ConnectFunc].
	//
	// Set by [NewConfig] to [*net.Dialer].
	Dialer Dialer

	// ErrClassifier classifies errors for structured logging.
	//
	// Set by [NewConfig] to [DefaultErrClassifier], which uses the
	// [errclass] package to map errors to Unix-like names.
	ErrClassifier ErrClassifier

	// TimeNow returns the current time.
	//
	// Set by [NewConfig] to [time.Now].
	TimeNow func() time.Time
}

// NewConfig creates a [*Config] with sensible defaults.
func NewConfig() *Config {
	return &Config{
		Dialer:        &net.Dialer{},
		ErrClassifier: DefaultErrClassifier,
		TimeNow:       time.Now,
	}
}

// SLogger abstracts the [*slog.Logger] behavior.
//
// By using an abstraction we allow for unit testing and alternative implementations.
//
// This package uses two log levels:
//
//   - Info for lifecycle and protocol events (connect, close, TLS handshake,
//     HTTP round trip, DNS exchange, DNS query/response)
//
//   - Debug for per-I/O events (read, write, set deadline)
//
// The [*slog.Logger] type satisfies this interface.
type SLogger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
}

// DefaultSLogger returns the default [SLogger] to use.
//
// The default is a no-op logger that discards all output. This follows the
// library convention of not writing to stdout/stderr unless explicitly configured.
//
// Use a custom [*slog.Logger] for emitting logs.
func DefaultSLogger() SLogger {
	return discardSLogger{}
}

// discardSLogger is a no-op [SLogger] that discards all log messages.
type discardSLogger struct{}

var _ SLogger = discardSLogger{}

// Debug implements [SLogger].
func (discardSLogger) Debug(msg string, args ...any) {
	// nothing
}

// Info implements [SLogger].
func (discardSLogger) Info(msg string, args ...any) {
	// nothing
}
