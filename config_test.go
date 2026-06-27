// SPDX-License-Identifier: GPL-3.0-or-later

package ptnop

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/bassosimone/errclass"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultErrClassifier(t *testing.T) {
	// Should return empty string for nil error
	result := DefaultErrClassifier.Classify(nil)
	assert.Equal(t, "", result)

	// Should classify ErrSkip as ESKIP
	result = DefaultErrClassifier.Classify(ErrSkip)
	assert.Equal(t, ESKIP, result)

	// Should classify a wrapped ErrSkip as ESKIP
	wrapped := fmt.Errorf("stage failed: %w", ErrSkip)
	result = DefaultErrClassifier.Classify(wrapped)
	assert.Equal(t, ESKIP, result)

	// Should classify known errors using errclass
	result = DefaultErrClassifier.Classify(context.DeadlineExceeded)
	assert.Equal(t, errclass.ETIMEDOUT, result)

	// Should return EGENERIC for unknown errors
	result = DefaultErrClassifier.Classify(errors.New("unknown error"))
	assert.Equal(t, errclass.EGENERIC, result)
}

func TestNewConfig(t *testing.T) {
	cfg := NewConfig()

	require.NotNil(t, cfg)

	// Dialer should be set to *net.Dialer
	_, ok := cfg.Dialer.(*net.Dialer)
	assert.True(t, ok, "Dialer should be *net.Dialer")

	// ErrClassifier should use errclass by default
	assert.Equal(t, "", cfg.ErrClassifier.Classify(nil))
	assert.Equal(t, "ETIMEDOUT", cfg.ErrClassifier.Classify(context.DeadlineExceeded))

	// TimeNow should be set and return a valid time
	now := cfg.TimeNow()
	assert.False(t, now.IsZero())
}
