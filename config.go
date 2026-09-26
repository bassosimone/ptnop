//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/ooni/probe-cli/blob/v3.20.1/internal/netxlite/dialer.go
// Adapted from: https://github.com/rbmk-project/rbmk/blob/v0.17.0/pkg/x/netcore/dialer.go
// Adapted from: https://github.com/bassosimone/nop/blob/89b21810488/errclassifier.go
// Adapted from: https://github.com/bassosimone/nop/blob/89b21810488/slogger.go
//

package ptnop

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/bassosimone/errclass"
)

// ErrSkip indicates that a stage has been skipped due to previous failures.
type ErrSkip struct {
	PrevErr error
}

// Error implements the error interface.
func (e ErrSkip) Error() string {
	return e.PrevErr.Error()
}

// Unwrap returns the underlying error.
func (e ErrSkip) Unwrap() error {
	return e.PrevErr
}

// Dialer abstracts the [*net.Dialer] behavior for testing.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DefaultDialer returns the default [*net.Dialer] we use.
//
// We disable multipath TCP explicitly. Since Go 1.24 the default (`multipathtcp=2`)
// enables it only for listeners, so this is a guard against a future change of the
// default rather than a fix: see https://go.dev/doc/godebug#go-124.
func DefaultDialer() *net.Dialer {
	d := &net.Dialer{}
	d.SetMultipathTCP(false)
	return d
}

// ErrClassifier classifies errors into categorical strings.
type ErrClassifier interface {
	Classify(err error) string
}

// DefaultErrClassifier returns the default [ErrClassifier] to use.
//
// We map [ErrSkip] to "ESKIP" and defer to the [errclass.New] function otherwise.
func DefaultErrClassifier() ErrClassifier {
	return &skipAwareErrClassifier{}
}

type skipAwareErrClassifier struct{}

var _ ErrClassifier = &skipAwareErrClassifier{}

func (*skipAwareErrClassifier) Classify(err error) string {
	if _, good := errors.AsType[ErrSkip](err); good {
		return "ESKIP"
	}
	return errclass.New(err)
}

// SLogger abstracts the [*slog.Logger] behavior for testing.
type SLogger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
}

// DefaultSLogger returns the default [SLogger] to use: a discard
// logger that drops any message passed to it.
func DefaultSLogger() SLogger {
	return &discardSLogger{}
}

type discardSLogger struct{}

var _ SLogger = &discardSLogger{}

func (*discardSLogger) Debug(msg string, args ...any) {
	// nothing
}

func (*discardSLogger) Info(msg string, args ...any) {
	// nothing
}

// TimeNowProvider abstracts over [time.Now] for testing.
type TimeNowProvider interface {
	Get() time.Time
}

// DefaultTimeNowProvider returns a [TimeNowProvider] using [time.Now].
func DefaultTimeNowProvider() TimeNowProvider {
	return &stdlibTimeNowProvider{}
}

type stdlibTimeNowProvider struct{}

var _ TimeNowProvider = &stdlibTimeNowProvider{}

func (*stdlibTimeNowProvider) Get() time.Time {
	return time.Now()
}

// Config holds common configuration for network operations.
//
// Use [NewConfig] to create a new instance.
type Config struct {
	Dialer        Dialer
	ErrClassifier ErrClassifier
	SLogger       SLogger
	TimeNow       TimeNowProvider
}

// Defaults used by [NewConfig]. Defined once to test using `testify.Same`.
var (
	defaultDialer          = DefaultDialer()
	defaultErrClassifier   = DefaultErrClassifier()
	defaultSLogger         = DefaultSLogger()
	defaultTimeNowProvider = DefaultTimeNowProvider()
)

// NewConfig creates a [*Config] using:
//
//  1. [DefaultDialer]
//  2. [DefaultErrClassifier]
//  3. [DefaultSLogger]
//  4. [DefaultTimeNowProvider]
//
// Modify the fields as needed before usage.
func NewConfig() *Config {
	return &Config{
		Dialer:        defaultDialer,
		ErrClassifier: defaultErrClassifier,
		SLogger:       defaultSLogger,
		TimeNow:       defaultTimeNowProvider,
	}
}
