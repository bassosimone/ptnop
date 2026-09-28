// SPDX-License-Identifier: GPL-3.0-or-later

package ptnop

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
)

// Make sure that [ErrSkip.Error] returns the unmodified error.
func TestErrSkip_Error(t *testing.T) {
	mocked := errors.New("mocked")
	err := ErrSkip{mocked}
	assert.Equal(t, mocked.Error(), err.Error())
}

// Make sure [ErrSkip.Unwrap] allows to unwrap errors.
func TestErrSkip_Unwrap(t *testing.T) {
	mocked := errors.New("mocked")
	err := ErrSkip{mocked}
	ok := errors.Is(err, mocked)
	assert.True(t, ok)
}

// Make sure that [DefaultDialer] creates a [*net.Dialer] with the required properties.
func TestDefaultDialer(t *testing.T) {
	dialer := DefaultDialer()
	ok := dialer.MultipathTCP()
	assert.False(t, ok)
}

// Make sure [DefaultErrClassifier] uses [errclass.New] and handles [ErrSkip].
func TestDefaultErrClassifier(t *testing.T) {
	ec := DefaultErrClassifier()

	// [ErrSkip]
	got := ec.Classify(ErrSkip{errors.New("mocked")})
	assert.Equal(t, "ESKIP", got)

	// [ErrSkip] wrapped by a foreign layer
	got = ec.Classify(fmt.Errorf("wrapped: %w", ErrSkip{errors.New("mocked")}))
	assert.Equal(t, "ESKIP", got)

	// [errclass.New]
	got = ec.Classify(context.DeadlineExceeded)
	assert.Equal(t, "ETIMEDOUT", got)
}

// Make sure there is coverage for [DefaultSLogger].
func TestDefaultSLogger(t *testing.T) {
	logger := DefaultSLogger()
	logger.Info("foo")
	logger.Debug("bar")
}

// Make sure there is coverage for [DefaultTimeNowProvider].
func TestDefaultTimeNowProvider(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		expect := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
		provider := DefaultTimeNowProvider()
		now := provider.Get().UTC()
		assert.Equal(t, expect, now)
	})
}

// Make sure [NewConfig] initializes all [*Config] fields.
func TestNewConfig(t *testing.T) {
	cfg := NewConfig()
	assert.Same(t, defaultDialer, cfg.Dialer)
	assert.Same(t, defaultErrClassifier, cfg.ErrClassifier)
	assert.Same(t, defaultSLogger, cfg.SLogger)
	assert.Same(t, defaultTimeNowProvider, cfg.TimeNow)
}
