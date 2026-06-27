// SPDX-License-Identifier: GPL-3.0-or-later

package ptnop

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/bassosimone/errclass"
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

// ErrSkip is a sentinel error indicating that a pipeline stage was skipped
// because a previous stage failed. Stages that receive an error-carrying
// input emit their start/done events with this error rather than executing.
var ErrSkip = errors.New("ptnop: previous stage failed")

// ESKIP is the error class string for [ErrSkip].
const ESKIP = "ESKIP"

// DefaultErrClassifier classifies errors into Unix-like error names.
// It recognizes [ErrSkip] as [ESKIP] and delegates all other errors
// to [errclass.New] (e.g., "ETIMEDOUT", "ECONNRESET", "EDNS_NONAME").
var DefaultErrClassifier = ErrClassifierFunc(func(err error) string {
	if errors.Is(err, ErrSkip) {
		return ESKIP
	}
	return errclass.New(err)
})

// Config holds common configuration for ptnop operations.
//
// Pass this to constructor functions to pre-wire dependencies.
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
