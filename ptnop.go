//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/bassosimone/nop/blob/ae41909903156c3fc9c0d80a56ce884c1ca4eb4a/config.go
// Adapted from: https://github.com/bassosimone/nop/blob/ae41909903156c3fc9c0d80a56ce884c1ca4eb4a/errclassifier.go
// Adapted from: https://github.com/bassosimone/nop/blob/ae41909903156c3fc9c0d80a56ce884c1ca4eb4a/slogger.go
// Adapted from: https://github.com/bassosimone/nop/blob/ae41909903156c3fc9c0d80a56ce884c1ca4eb4a/func.go
// Adapted from: https://github.com/ooni/probe-cli/blob/v3.20.0/internal/x/dslx/fxasync.go
// Adapted from: https://github.com/ooni/probe-cli/blob/v3.20.0/internal/x/dslx/fxcore.go
// Adapted from: https://github.com/ooni/probe-cli/blob/v3.20.0/internal/x/dslx/fxstream.go
// Adapted from: https://github.com/bassosimone/nop/blob/ae41909903156c3fc9c0d80a56ce884c1ca4eb4a/compose.go
// Adapted from: https://github.com/bassosimone/nop/blob/ae41909903156c3fc9c0d80a56ce884c1ca4eb4a/unit.go
//

package ptnop

import (
	"context"
	"errors"
	"time"

	"github.com/bassosimone/errclass"
	"github.com/bassosimone/runtimex"
)

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

// Result represents a T instance or an error.
//
// We use this type as a convenience to avoid adding an explicit `Err` field to
// every returned type and to avoid creating additional types when standard library
// types could be wrapped in this fashion (e.g. `Result[net.Conn]` instead of
// introducing our own `Conn` type including an explicit `Err` field).
//
// The type system does not allow to enforce that just one of `Err` and `Value`
// is not a zero value and the other type is a zero value. However, in general, the
// convention in this library is either-or, as documented by each [Func].
type Result[T any] struct {
	Err   error
	Value T
}

// Unpack returns the Err and Value fields as a tuple. This bridges the
// single [Result] convention used in this library with expectations
// of Go code, which typically return a tuple containing a result or an error.
func (r Result[T]) Unpack() (T, error) {
	return r.Value, r.Err
}

// Func is a generic operation that accepts an input and returns an output. Both
// the input and the output are [Result] wrapped. The input may already contain
// an error if the previous pipeline stage has failed.
//
// The expectation is that the input contains either a valid [Result] value (as
// documented by each [Func]) and a nil [Result] error or a zero [Result] value
// and a non-nil [Result] error.
//
// The expectation is that the output contains either a valid [Result] value (as
// documented by each [Func]) and a nil [Result] error or a zero [Result] value
// and a non-nil [Result] error.
//
// Whenever a function receives a valid [Result] value and returns a non-nil
// [Result] error, it must close the [Result] value resource where applicable
// along with any additional resources it constructed.
//
// Together these rules mean that a [Func] receiving an error [Result] input
// may ignore the [Result] value and that composed pipelines never leak resources
// when a failure occurs inside a specific stage.
type Func[A, B any] interface {
	Call(ctx context.Context, input Result[A]) Result[B]
}

// FuncAdapter wraps a function as a [Func] implementation.
//
// Use this to create ad-hoc [Func] instances from closures when you need
// custom behavior that doesn't fit the existing primitives.
type FuncAdapter[A, B any] func(ctx context.Context, input Result[A]) Result[B]

// Call implements [Func].
func (f FuncAdapter[A, B]) Call(ctx context.Context, input Result[A]) Result[B] {
	return f(ctx, input)
}

// Compose2 chains two [Func] instances together into a pipeline.
//
// The output of op1 becomes the input to op2. If op1 returns an error,
// op2 is called and should return an [ErrSkip] instance. The type system
// cannot express this constraint and each operation implementation is
// required to comply with this rule and enforce it with testing.
//
// This function composition design ensures that later pipeline stages
// run even when previous stages failed, which causes the structured logs
// to contain explicit information on each pipeline stage. Conversely,
// short circuiting after a failure, hides the subsequent pipeline stages
// and thus the overall intent of a given measurement pipeline.
func Compose2[A, B, C any](op1 Func[A, B], op2 Func[B, C]) Func[A, C] {
	return compose2[A, B, C]{op1, op2}
}

type compose2[A, B, C any] struct {
	op1 Func[A, B]
	op2 Func[B, C]
}

// Call implements [Func].
func (c compose2[A, B, C]) Call(ctx context.Context, input Result[A]) Result[C] {
	return c.op2.Call(ctx, c.op1.Call(ctx, input))
}

// Unit is a type not containing any value (analogous to an
// explicit `void` type in C and C++).
//
// Use this type to construct [Func] that take no argument
// or return no value to the caller.
type Unit struct{}

// NewResultUnit constructs a [Result] containing a [Unit] with nil error.
func NewResultUnit() Result[Unit] {
	return Result[Unit]{Value: Unit{}}
}
