//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/bassosimone/nop/blob/ae41909903156c3fc9c0d80a56ce884c1ca4eb4a/config_test.go
// Adapted from: https://github.com/bassosimone/nop/blob/ae41909903156c3fc9c0d80a56ce884c1ca4eb4a/errclassifier_test.go
// Adapted from: https://github.com/bassosimone/nop/blob/ae41909903156c3fc9c0d80a56ce884c1ca4eb4a/slogger_test.go
// Adapted from: https://github.com/bassosimone/nop/blob/ae41909903156c3fc9c0d80a56ce884c1ca4eb4a/compose_test.go
//

package ptnop

import (
	"context"
	"errors"
	"fmt"
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
	result = DefaultErrClassifier.Classify(NewErrSkip(errors.New("mocked")))
	assert.Equal(t, ESKIP, result)

	// Should classify a wrapped ErrSkip as ESKIP
	wrapped := fmt.Errorf("stage failed: %w", NewErrSkip(errors.New("mocked")))
	result = DefaultErrClassifier.Classify(wrapped)
	assert.Equal(t, ESKIP, result)

	// Should classify known errors using errclass
	result = DefaultErrClassifier.Classify(context.DeadlineExceeded)
	assert.Equal(t, errclass.ETIMEDOUT, result)

	// Should return EGENERIC for unknown errors
	result = DefaultErrClassifier.Classify(errors.New("unknown error"))
	assert.Equal(t, errclass.EGENERIC, result)
}

func TestNewErrSkip(t *testing.T) {
	// Wrapping a wrapped error should return the same error.
	expectedErr := NewErrSkip(errors.New("mocked"))
	gotErr := NewErrSkip(expectedErr)
	assert.NotEqual(t, ErrSkip{Err: expectedErr}, gotErr)
	assert.Equal(t, expectedErr, gotErr)

	// Constructing with a nil error panics.
	assert.Panics(t, func() { NewErrSkip(nil) })
}

func TestErrSkip(t *testing.T) {
	underlying := errors.New("mocked")
	err := NewErrSkip(underlying)
	assert.Equal(t, "mocked", err.Error())
	assert.Same(t, underlying, errors.Unwrap(err))
}

func TestNewConfig(t *testing.T) {
	cfg := NewConfig()
	require.NotNil(t, cfg)

	// ErrClassifier should use errclass by default
	assert.Equal(t, "", cfg.ErrClassifier.Classify(nil))
	assert.Equal(t, "ETIMEDOUT", cfg.ErrClassifier.Classify(context.DeadlineExceeded))

	// TimeNow should be set and return a valid time
	now := cfg.TimeNow()
	assert.False(t, now.IsZero())
}

func TestDefaultSLogger(t *testing.T) {
	logger := DefaultSLogger()

	// Should return a non-nil logger
	assert.NotNil(t, logger)

	// Should be able to call Debug and Info without panic (discards output)
	logger.Debug("debug message", "key", "value")
	logger.Info("info message", "key", "value")
}

func TestDiscardSLogger(t *testing.T) {
	logger := discardSLogger{}

	// Verify it implements SLogger
	var _ SLogger = logger

	// Should be able to call Debug and Info without panic (discards output)
	logger.Debug("debug message", "key1", "value1", "key2", 42)
	logger.Info("info message", "key1", "value1", "key2", 42)
}

func TestResult_Unpack(t *testing.T) {
	expectValue := 10
	expectErr := errors.New("mocked")
	result := Result[int]{Value: expectValue, Err: expectErr}
	gotValue, gotErr := result.Unpack()
	assert.Equal(t, expectValue, gotValue)
	assert.Same(t, expectErr, gotErr)
}

func TestCompose2(t *testing.T) {
	op1 := FuncAdapter[int, string](func(ctx context.Context, n Result[int]) Result[string] {
		return Result[string]{Value: fmt.Sprintf("hello %d", n.Value)}
	})
	op2 := FuncAdapter[string, int](func(ctx context.Context, s Result[string]) Result[int] {
		return Result[int]{Value: len(s.Value)}
	})
	composed := Compose2(op1, op2)
	value, err := composed.Call(context.Background(), Result[int]{Value: 42}).Unpack()
	assert.NoError(t, err)
	assert.Equal(t, 8, value) // len("hello 42") = 8
}
