// SPDX-License-Identifier: GPL-3.0-or-later

package ptnop

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/bassosimone/netstub"
	"github.com/stretchr/testify/assert"
)

// slogSimpleRecord is a simplified [*slog.Record].
type slogSimpleRecord struct {
	Level string
	Msg   string
	Attrs []string
}

// slogValidationHelper helps to validate the structured logs.
//
// It implements [SLogger] and should be configured as the [SLogger] to use.
//
// [slogValidationHelper.Get] should also be used inside [*Config] so that the
// time collected by events is always a consistent fixture.
//
// After the [Func] has finished running, [slogValidationHelper.Got] should
// be compared to the expected list of structured logs.
type slogValidationHelper struct {
	Got []slogSimpleRecord
}

// Get implements [TimeNowProvider].
func (lvh *slogValidationHelper) Get() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}

var (
	_ SLogger         = &slogValidationHelper{}
	_ TimeNowProvider = &slogValidationHelper{}
)

// Debug implements [SLogger].
func (lvh *slogValidationHelper) Debug(msg string, args ...any) {
	lvh.collect("debug", msg, args...)
}

// Info implements [SLogger].
func (lvh *slogValidationHelper) Info(msg string, args ...any) {
	lvh.collect("info", msg, args...)
}

// collect saves a structured log record.
func (lvh *slogValidationHelper) collect(level, msg string, args ...any) {
	var attrs []string
	for _, arg := range args {
		attr := arg.(slog.Attr) // panic on type-cast failure is okay when running tests
		attrs = append(attrs, fmt.Sprintf("%s=%s", attr.Key, attr.Value))
	}
	lvh.Got = append(lvh.Got, slogSimpleRecord{
		Level: level,
		Msg:   msg,
		Attrs: attrs,
	})
}

// Make sure [NewConnectFunc] initializes all [*ConnectFunc] fields.
func TestNewConnectFunc(t *testing.T) {
	cfg := NewConfig()
	fx := NewConnectFunc(cfg, "tcp")
	assert.Same(t, cfg.Dialer, fx.Dialer)
	assert.Same(t, cfg.ErrClassifier, fx.ErrClassifier)
	assert.Equal(t, "tcp", fx.Network)
	assert.Same(t, cfg.SLogger, fx.SLogger)
	assert.Same(t, cfg.TimeNow, fx.TimeNow)
}

// Make sure [ConnectFunc.Call] returns the correct value on failure.
func TestConnectFunc_Call(t *testing.T) {
	// mockedErr is the error mock we use in this test.
	mockedErr := errors.New("mocked")

	// mockedConn is the conn mock we use in this test.
	mockedConn := &netstub.FuncConn{
		LocalAddrFunc: func() net.Addr {
			return &net.TCPAddr{
				IP:   net.IPv4(10, 0, 0, 1),
				Port: 19774,
				Zone: "",
			}
		},
	}

	// We use testcases to test for dial success and failure.
	type testcase struct {
		// name is the test case name.
		name string

		// dialFunc is the function that should implement dialing.
		dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

		// checkResult checks the result of dialing.
		checkResult func(t *testing.T, conn net.Conn, err error)

		// expected `connectDone` event fields.
		expectErr       string
		expectErrClass  string
		expectLocalAddr string
	}

	cases := []testcase{
		{
			name: "failure",
			dialFunc: func(ctx context.Context, network string, address string) (net.Conn, error) {
				return nil, mockedErr
			},
			checkResult: func(t *testing.T, conn net.Conn, err error) {
				t.Helper()
				assert.NotNil(t, err)
				assert.Equal(t, mockedErr, err)
				assert.Nil(t, conn)
			},
			expectErr:       "mocked",
			expectErrClass:  "EGENERIC",
			expectLocalAddr: "",
		},

		{
			name: "success",
			dialFunc: func(ctx context.Context, network string, address string) (net.Conn, error) {
				return mockedConn, nil
			},
			checkResult: func(t *testing.T, conn net.Conn, err error) {
				t.Helper()
				assert.Nil(t, err)
				assert.NotNil(t, conn)
				assert.Same(t, mockedConn, conn)
			},
			expectErr:       "<nil>",
			expectErrClass:  "",
			expectLocalAddr: "10.0.0.1:19774",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 1. prepare
			logHelper := &slogValidationHelper{}
			cfg := NewConfig()
			cfg.Dialer = &netstub.FuncDialer{
				DialContextFunc: tc.dialFunc,
			}
			cfg.TimeNow = logHelper
			cfg.SLogger = logHelper
			deadline := cfg.TimeNow.Get().Add(10 * time.Second)
			ctx, cancel := context.WithDeadline(context.Background(), deadline)
			defer cancel()
			remoteAddr := netip.MustParseAddrPort("8.8.8.8:443")
			fx := NewConnectFunc(cfg, "tcp")

			// 2. invoke
			result := fx.Call(ctx, remoteAddr)

			// 3. check
			tc.checkResult(t, result.V, result.Err)

			expect := []slogSimpleRecord{{
				Level: "info",
				Msg:   "connectStart",
				Attrs: []string{
					"deadline=2026-01-01 00:00:10 +0000 UTC",
					"protocol=tcp",
					"remoteAddr=8.8.8.8:443",
					"t=2026-01-01 00:00:00 +0000 UTC",
				},
			}, {
				Level: "info",
				Msg:   "connectDone",
				Attrs: []string{
					"deadline=2026-01-01 00:00:10 +0000 UTC",
					"err=" + tc.expectErr,
					"errClass=" + tc.expectErrClass,
					"localAddr=" + tc.expectLocalAddr,
					"protocol=tcp",
					"remoteAddr=8.8.8.8:443",
					"t=2026-01-01 00:00:00 +0000 UTC",
					"t0=2026-01-01 00:00:00 +0000 UTC",
				},
			}}

			assert.Equal(t, expect, logHelper.Got)
		})
	}
}
