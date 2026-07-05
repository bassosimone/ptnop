//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/bassosimone/nop/blob/ae41909903156c3fc9c0d80a56ce884c1ca4eb4a/connect_test.go
// Adapted from: https://github.com/bassosimone/nop/blob/ae41909903156c3fc9c0d80a56ce884c1ca4eb4a/helpers_test.go
//

package ptnop

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/bassosimone/netstub"
	"github.com/bassosimone/slogstub"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newCapturingLogger returns a logger that captures all log records into the
// returned slice. The caller can inspect the slice after exercising the code
// under test to verify which events were emitted.
func newCapturingLogger() (*slog.Logger, *[]slog.Record) {
	var records []slog.Record
	handler := &slogstub.FuncHandler{
		EnabledFunc: func(ctx context.Context, level slog.Level) bool {
			return true
		},
		HandleFunc: func(ctx context.Context, record slog.Record) error {
			records = append(records, record)
			return nil
		},
	}
	return slog.New(handler), &records
}

// newMinimalConn returns a [*netstub.FuncConn] with only LocalAddrFunc and
// RemoteAddrFunc set. This is the minimum needed for code that calls
// [safeconn.LocalAddr], [safeconn.RemoteAddr], and [safeconn.Network]
// during construction.
func newMinimalConn() *netstub.FuncConn {
	return &netstub.FuncConn{
		LocalAddrFunc:  func() net.Addr { return &net.TCPAddr{} },
		RemoteAddrFunc: func() net.Addr { return &net.TCPAddr{} },
	}
}

// NewDefaultDialer disables multipath TCP.
func TestNewDefaultDialer(t *testing.T) {
	dd := NewDefaultDialer()
	assert.False(t, dd.MultipathTCP())
}

// NewConnectFunc populates all fields from Config and the provided logger.
func TestNewConnectFunc(t *testing.T) {
	cfg := NewConfig()
	logger := DefaultSLogger()

	fn := NewConnectFunc(cfg, "tcp", logger)

	require.NotNil(t, fn)
	assert.Equal(t, "tcp", fn.Network)
	assert.NotNil(t, fn.Dialer)
	assert.NotNil(t, fn.Logger)
	assert.NotNil(t, fn.TimeNow)
	assert.NotNil(t, fn.ErrClassifier)
}

// Call dials the address and returns a net.Conn or an error.
func TestConnectFunc(t *testing.T) {
	// errMocked is the canonical mocked error used by this test.
	errMocked := errors.New("mocked error")

	tests := []struct {
		// name describes what this test case verifies.
		name string

		// dialer is the mock dialer to use.
		dialer *netstub.FuncDialer

		// network is the network type.
		network string

		// address is the target address.
		address Result[netip.AddrPort]

		// wantErr indicates whether we expect an error.
		wantErr bool

		// errCheck is the optional function for checking the error.
		errCheck func(t *testing.T, err error)
	}{
		{
			name:    "pre-existing error",
			network: "tcp",
			address: Result[netip.AddrPort]{Err: errMocked},
			wantErr: true,
			errCheck: func(t *testing.T, err error) {
				underlying, ok := errors.AsType[ErrSkip](err)
				assert.True(t, ok)
				assert.Same(t, errMocked, underlying.Err)
			},
		},

		{
			name: "successful TCP connect",
			dialer: &netstub.FuncDialer{
				DialContextFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
					conn := newMinimalConn()
					conn.CloseFunc = func() error { return nil }
					conn.LocalAddrFunc = func() net.Addr {
						return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 54321}
					}
					conn.RemoteAddrFunc = func() net.Addr {
						return &net.TCPAddr{IP: net.IPv4(93, 184, 216, 34), Port: 443}
					}
					return conn, nil
				},
			},
			network:  "tcp",
			address:  Result[netip.AddrPort]{Value: netip.MustParseAddrPort("93.184.216.34:443")},
			wantErr:  false,
			errCheck: nil,
		},

		{
			name: "dial error",
			dialer: &netstub.FuncDialer{
				DialContextFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
					return nil, errors.New("connection refused")
				},
			},
			network:  "tcp",
			address:  Result[netip.AddrPort]{Value: netip.MustParseAddrPort("93.184.216.34:443")},
			wantErr:  true,
			errCheck: nil,
		},

		{
			name: "successful UDP connect",
			dialer: &netstub.FuncDialer{
				DialContextFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
					conn := newMinimalConn()
					conn.CloseFunc = func() error { return nil }
					conn.LocalAddrFunc = func() net.Addr {
						return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 54321}
					}
					conn.RemoteAddrFunc = func() net.Addr {
						return &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}
					}
					return conn, nil
				},
			},
			network:  "udp",
			address:  Result[netip.AddrPort]{Value: netip.MustParseAddrPort("8.8.8.8:53")},
			wantErr:  false,
			errCheck: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()

			fn := NewConnectFunc(cfg, tt.network, DefaultSLogger())
			fn.Dialer = tt.dialer

			conn, err := fn.Call(context.Background(), tt.address).Unpack()

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, conn)
				if tt.errCheck != nil {
					tt.errCheck(t, err)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, conn)
			conn.Close()
		})
	}
}

// Call transparently passes the caller's context to the dialer.
func TestConnectFuncContextTransparency(t *testing.T) {
	tests := []struct {
		// name describes the scenario.
		name string

		// dialer is the mock dialer to use.
		dialer *netstub.FuncDialer

		// makeCtx builds the context for the call.
		makeCtx func() (context.Context, context.CancelFunc)
	}{
		{
			name: "pre-expired context",
			dialer: &netstub.FuncDialer{
				DialContextFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
					if ctx.Err() != nil {
						return nil, ctx.Err()
					}
					return nil, errors.New("should not reach here")
				},
			},
			makeCtx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
				time.Sleep(10 * time.Millisecond)
				return ctx, cancel
			},
		},

		{
			name: "context expires during dial",
			dialer: &netstub.FuncDialer{
				DialContextFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
					time.Sleep(10 * time.Millisecond)
					if ctx.Err() != nil {
						return nil, ctx.Err()
					}
					return nil, errors.New("should not reach here")
				},
			},
			makeCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 1*time.Nanosecond)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()

			fn := NewConnectFunc(cfg, "tcp", DefaultSLogger())
			fn.Dialer = tt.dialer

			ctx, cancel := tt.makeCtx()
			defer cancel()

			_, err := fn.Call(ctx, Result[netip.AddrPort]{Value: netip.MustParseAddrPort("93.184.216.34:443")}).Unpack()
			require.Error(t, err)
		})
	}
}

// Call propagates the caller's context deadline to the dialer.
func TestConnectFuncCallerContextDeadline(t *testing.T) {
	cfg := NewConfig()
	dialCalled := false
	expectedTimeout := 5 * time.Second

	fn := NewConnectFunc(cfg, "tcp", DefaultSLogger())
	fn.Dialer = &netstub.FuncDialer{
		DialContextFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialCalled = true
			deadline, ok := ctx.Deadline()
			assert.True(t, ok, "context should have deadline from caller")
			assert.True(t, time.Until(deadline) <= expectedTimeout)
			return nil, errors.New("expected error")
		},
	}

	// Caller controls timeout via context.WithTimeout
	ctx, cancel := context.WithTimeout(context.Background(), expectedTimeout)
	defer cancel()

	_, _ = fn.Call(ctx, Result[netip.AddrPort]{Value: netip.MustParseAddrPort("93.184.216.34:443")}).Unpack()

	assert.True(t, dialCalled)
}

// Call emits connectStart/connectDone log events.
func TestConnectFuncLogging(t *testing.T) {
	logger, records := newCapturingLogger()

	cfg := NewConfig()

	fn := NewConnectFunc(cfg, "tcp", logger)
	fn.Dialer = &netstub.FuncDialer{
		DialContextFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn := newMinimalConn()
			conn.CloseFunc = func() error { return nil }
			return conn, nil
		},
	}

	conn, err := fn.Call(context.Background(), Result[netip.AddrPort]{Value: netip.MustParseAddrPort("93.184.216.34:443")}).Unpack()
	require.NoError(t, err)
	conn.Close()

	require.Len(t, *records, 2)
	assert.Equal(t, "connectStart", (*records)[0].Message)
	assert.Equal(t, "connectDone", (*records)[1].Message)
}
