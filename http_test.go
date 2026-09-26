// SPDX-License-Identifier: GPL-3.0-or-later

package ptnop

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bassosimone/netstub"
	"github.com/bassosimone/tlsstub"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO(bassosimone): consider moving funcHTTPClientConn to bassosimone/httptestx
// since it is basically a standard library mock after go1.26.

type funcHTTPEngine struct {
	NewClientConnFunc func(ctx context.Context, dialer, tlsDialer Dialer,
		scheme, raddr string) (HTTPEngineConn, error)
}

func (e *funcHTTPEngine) NewClientConn(ctx context.Context, dialer, tlsDialer Dialer,
	scheme, raddr string) (HTTPEngineConn, error) {
	return e.NewClientConnFunc(ctx, dialer, tlsDialer, scheme, raddr)
}

type funcHTTPClientConn struct {
	RoundTripFunc func(req *http.Request) (*http.Response, error)
	CloseFunc     func() error
}

func (cc *funcHTTPClientConn) RoundTrip(req *http.Request) (*http.Response, error) {
	return cc.RoundTripFunc(req)
}

func (cc *funcHTTPClientConn) Close() error {
	return cc.CloseFunc()
}

// Make sure [NewHTTPConnFunc] initializes all [*HTTPConnFunc] fields.
func TestNewHTTPConnFunc(t *testing.T) {
	cfg := NewConfig()
	fx := NewHTTPConnFunc(cfg)
	assert.Same(t, defaultHTTPEngine, fx.Engine)
	assert.Same(t, cfg.ErrClassifier, fx.ErrClassifier)
	assert.Same(t, cfg.SLogger, fx.SLogger)
	assert.Same(t, cfg.TimeNow, fx.TimeNow)
}

// Make sure [*HTTPConnFunc.Call] works as intended.
func TestHTTPConnFunc_Call(t *testing.T) {
	// mockErr is the err mock that we use
	mockErr := errors.New("mocked")

	// mockConnFactory returns the conn mock that we use
	mockConnFactory := func(closefn func() error) *netstub.FuncConn {
		return &netstub.FuncConn{
			CloseFunc: closefn,
			LocalAddrFunc: func() net.Addr {
				return &net.TCPAddr{
					IP:   net.IPv4(10, 0, 0, 1),
					Port: 19774,
					Zone: "",
				}
			},
			RemoteAddrFunc: func() net.Addr {
				return &net.TCPAddr{
					IP:   net.IPv4(10, 0, 0, 2),
					Port: 443,
					Zone: "",
				}
			},
		}
	}

	// mockTLSConnFactory is like mockConnFactory but uses TLS.
	mockTLSConnFactory := func(closefn func() error) *tlsstub.FuncTLSConn {
		return &tlsstub.FuncTLSConn{
			FuncConn: mockConnFactory(closefn),
		}
	}

	// mockEngineConn is the conn returned on success
	mockEngineConn := &funcHTTPClientConn{}

	// We use test cases to test for all input combinations as well as for
	// the result returned by NewClientConn.
	type testcase struct {
		// name is the test case name.
		name string

		// input is the input passed to `Call`.
		inputfn func(closefn func() error) Result[net.Conn]

		// configuration for the NewClientConn invocation.
		engineMockConn HTTPEngineConn
		engineMockErr  error

		// expectations after invoking `Call`.
		expectHTTPEngineConn HTTPEngineConn
		expectErr            error
		expectLocalAddr      string
		expectProto          string
		expectRemoteAddr     string
		expectScheme         string

		// assertions about side effects
		closeCount int
	}

	cases := []testcase{
		{
			name: "previous stage failed",
			inputfn: func(closefn func() error) Result[net.Conn] {
				return Result[net.Conn]{Err: mockErr}
			},
			engineMockConn:       nil,
			engineMockErr:        nil,
			expectHTTPEngineConn: nil, // not set
			expectErr:            ErrSkip{mockErr},
			expectLocalAddr:      "",
			expectProto:          "",
			expectRemoteAddr:     "",
			expectScheme:         "",
			closeCount:           0,
		},
		{
			name: "cannot build the HTTPEngineConn",
			inputfn: func(closefn func() error) Result[net.Conn] {
				return Result[net.Conn]{V: mockConnFactory(closefn)}
			},
			engineMockConn:       nil,
			engineMockErr:        mockErr,
			expectHTTPEngineConn: nil,
			expectErr:            mockErr,
			expectLocalAddr:      "10.0.0.1:19774",
			expectProto:          "tcp",
			expectRemoteAddr:     "10.0.0.2:443",
			expectScheme:         "http",
			closeCount:           1,
		},
		{
			name: "can build the HTTPEngineConn for http",
			inputfn: func(closefn func() error) Result[net.Conn] {
				return Result[net.Conn]{V: mockConnFactory(closefn)}
			},
			engineMockConn:       mockEngineConn,
			engineMockErr:        nil,
			expectHTTPEngineConn: mockEngineConn,
			expectErr:            nil,
			expectLocalAddr:      "10.0.0.1:19774",
			expectProto:          "tcp",
			expectRemoteAddr:     "10.0.0.2:443",
			expectScheme:         "http",
			closeCount:           0,
		},
		{
			name: "can build the HTTPEngineConn for https",
			inputfn: func(closefn func() error) Result[net.Conn] {
				return Result[net.Conn]{V: mockTLSConnFactory(closefn)}
			},
			engineMockConn:       mockEngineConn,
			engineMockErr:        nil,
			expectHTTPEngineConn: mockEngineConn,
			expectErr:            nil,
			expectLocalAddr:      "10.0.0.1:19774",
			expectProto:          "tcp",
			expectRemoteAddr:     "10.0.0.2:443",
			expectScheme:         "https",
			closeCount:           0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 1. setup
			cfg := NewConfig()
			fx := NewHTTPConnFunc(cfg)
			var gotScheme string
			fx.Engine = &funcHTTPEngine{
				NewClientConnFunc: func(ctx context.Context, dialer Dialer,
					tlsDialer Dialer, scheme string, raddr string) (HTTPEngineConn, error) {
					gotScheme = scheme
					return tc.engineMockConn, tc.engineMockErr
				},
			}
			var closeCount int
			closefn := func() error {
				closeCount++
				return nil
			}

			// 2. invoke
			hc := fx.Call(context.Background(), tc.inputfn(closefn))

			// 3. check
			assert.NotNil(t, hc)
			assert.Same(t, cfg.ErrClassifier, hc.ErrClassifier)

			assert.Equal(t, tc.expectErr, hc.HTTPCc.Err)
			assert.Equal(t, tc.expectHTTPEngineConn, hc.HTTPCc.V)

			assert.Equal(t, tc.expectLocalAddr, hc.LocalAddr)
			assert.Equal(t, tc.expectProto, hc.Proto)
			assert.Equal(t, tc.expectRemoteAddr, hc.RemoteAddr)

			assert.Same(t, cfg.SLogger, hc.SLogger)
			assert.Same(t, cfg.TimeNow, hc.TimeNow)

			assert.Equal(t, tc.expectScheme, gotScheme)

			assert.Equal(t, tc.closeCount, closeCount)
		})
	}
}

// Make sure [HTTPConn.RoundTrip] works as intended.
func TestHTTPConn_RoundTrip(t *testing.T) {
	// mockErr is the err mock that we use
	mockErr := errors.New("mocked")

	// mockResp is the response mock that we use
	mockResp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Server": []string{"ptnop/0.1.1"}},
	}

	// We use test cases to test all possible cases together.
	type testcase struct {
		// name is the test case name
		name string

		// httpCc is the field to initialize HTTPConn with.
		httpCc Result[HTTPEngineConn]

		// expectations for the operation result.
		expectErr  error
		expectResp *http.Response

		// expectations for the structured logs.
		expectLogErr      string
		expectLogClass    string
		expectLogRespHdrs string
		expectLogRespCode string
	}

	cases := []testcase{
		{
			name:              "previous stage failed",
			httpCc:            Result[HTTPEngineConn]{Err: mockErr},
			expectErr:         ErrSkip{mockErr},
			expectResp:        nil,
			expectLogErr:      "mocked",
			expectLogClass:    "ESKIP",
			expectLogRespHdrs: "map[]",
			expectLogRespCode: "0",
		},
		{
			name: "round trip fails",
			httpCc: Result[HTTPEngineConn]{V: &funcHTTPClientConn{
				RoundTripFunc: func(req *http.Request) (*http.Response, error) {
					return nil, mockErr
				},
				CloseFunc: func() error {
					panic("should not be called")
				},
			}},
			expectErr:         mockErr,
			expectResp:        nil,
			expectLogErr:      "mocked",
			expectLogClass:    "EGENERIC",
			expectLogRespHdrs: "map[]",
			expectLogRespCode: "0",
		},
		{
			name: "round trip succeeds",
			httpCc: Result[HTTPEngineConn]{V: &funcHTTPClientConn{
				RoundTripFunc: func(req *http.Request) (*http.Response, error) {
					return mockResp, nil
				},
				CloseFunc: func() error {
					panic("should not be called")
				},
			}},
			expectErr:         nil,
			expectResp:        mockResp,
			expectLogErr:      "<nil>",
			expectLogClass:    "",
			expectLogRespHdrs: "map[Server:[ptnop/0.1.1]]",
			expectLogRespCode: "200",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 1. setup
			logHelper := &slogValidationHelper{}
			cfg := NewConfig()
			cfg.TimeNow = logHelper
			cfg.SLogger = logHelper
			deadline := cfg.TimeNow.Get().Add(10 * time.Second)
			ctx, cancel := context.WithDeadline(context.Background(), deadline)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet,
				"https://www.example.com/", http.NoBody)
			require.Nil(t, err)
			require.NotNil(t, req)
			req.Header.Set("User-Agent", "ptnop/0.1.0")

			hc := &HTTPConn{
				ErrClassifier: DefaultErrClassifier(),
				HTTPCc:        tc.httpCc,
				LocalAddr:     "10.0.0.1:19774",
				Proto:         "tcp",
				RemoteAddr:    "10.0.0.2:443",
				SLogger:       logHelper,
				TimeNow:       logHelper,
			}

			// 2. invoke
			resp, err := hc.RoundTrip(req)

			// 3. check
			require.Equal(t, tc.expectErr, err)
			require.Equal(t, tc.expectResp, resp)

			expect := []slogSimpleRecord{{
				Level: "info",
				Msg:   "httpRoundTripStart",
				Attrs: []string{
					"deadline=2026-01-01 00:00:10 +0000 UTC",
					"httpMethod=GET",
					"httpUrl=https://www.example.com/",
					"httpRequestHeaders=map[User-Agent:[ptnop/0.1.0]]",
					"localAddr=10.0.0.1:19774",
					"protocol=tcp",
					"remoteAddr=10.0.0.2:443",
					"t=2026-01-01 00:00:00 +0000 UTC",
				},
			}, {
				Level: "info",
				Msg:   "httpRoundTripDone",
				Attrs: []string{
					"deadline=2026-01-01 00:00:10 +0000 UTC",
					"err=" + tc.expectLogErr,
					"errClass=" + tc.expectLogClass,
					"httpMethod=GET",
					"httpUrl=https://www.example.com/",
					"httpRequestHeaders=map[User-Agent:[ptnop/0.1.0]]",
					"httpResponseHeaders=" + tc.expectLogRespHdrs,
					"httpResponseStatusCode=" + tc.expectLogRespCode,
					"localAddr=10.0.0.1:19774",
					"protocol=tcp",
					"remoteAddr=10.0.0.2:443",
					"t=2026-01-01 00:00:00 +0000 UTC",
					"t0=2026-01-01 00:00:00 +0000 UTC",
				},
			}}

			assert.Equal(t, expect, logHelper.Got)
		})
	}
}

// Make sure that [*HTTPConn.Close] works as intended.
func TestHTTPConn_close(t *testing.T) {
	// mockErr is the err mock that we use
	mockErr := errors.New("mocked")

	// We use test cases to test all possible cases together.
	type testcase struct {
		// name is the test case name
		name string

		// httpCc is the field to initialize HTTPConn with.
		httpCc Result[HTTPEngineConn]

		// expectations for the operation result.
		expectErr error
	}

	cases := []testcase{
		{
			name:      "without a conn",
			httpCc:    Result[HTTPEngineConn]{Err: mockErr},
			expectErr: nil,
		},
		{
			name: "with a conn",
			httpCc: Result[HTTPEngineConn]{V: &funcHTTPClientConn{
				RoundTripFunc: func(req *http.Request) (*http.Response, error) {
					panic("should not be called")
				},
				CloseFunc: func() error {
					return mockErr
				},
			}},
			expectErr: mockErr,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 1. setup
			hc := &HTTPConn{
				ErrClassifier: DefaultErrClassifier(),
				HTTPCc:        tc.httpCc,
				LocalAddr:     "10.0.0.1:19774",
				Proto:         "tcp",
				RemoteAddr:    "10.0.0.2:443",
				SLogger:       DefaultSLogger(),
				TimeNow:       DefaultTimeNowProvider(),
			}

			// 2. invoke
			err := hc.Close()

			// 3. check
			assert.Equal(t, tc.expectErr, err)
		})
	}
}

func TestHTTPBodyWrapper(t *testing.T) {
	// mockErr is the err mock that we use
	mockErr := errors.New("mocked")

	// expected events to be assembled depending on needs
	bodyStreamStart := slogSimpleRecord{
		Level: "info",
		Msg:   "httpBodyStreamStart",
		Attrs: []string{
			"localAddr=10.0.0.1:19774",
			"protocol=tcp",
			"remoteAddr=10.0.0.2:80",
			"t=2026-01-01 00:00:00 +0000 UTC",
		},
	}

	bodyStreamReadError := slogSimpleRecord{
		Level: "info",
		Msg:   "httpBodyStreamReadError",
		Attrs: []string{
			"err=mocked",
			"errClass=EGENERIC",
			"localAddr=10.0.0.1:19774",
			"protocol=tcp",
			"remoteAddr=10.0.0.2:80",
			"t=2026-01-01 00:00:00 +0000 UTC",
		},
	}

	bodyStreamCloseError := slogSimpleRecord{
		Level: "info",
		Msg:   "httpBodyStreamCloseError",
		Attrs: []string{
			"err=mocked",
			"errClass=EGENERIC",
			"localAddr=10.0.0.1:19774",
			"protocol=tcp",
			"remoteAddr=10.0.0.2:80",
			"t=2026-01-01 00:00:00 +0000 UTC",
		},
	}

	bodyStreamDone := slogSimpleRecord{
		Level: "info",
		Msg:   "httpBodyStreamDone",
		Attrs: []string{
			"localAddr=10.0.0.1:19774",
			"protocol=tcp",
			"remoteAddr=10.0.0.2:80",
			"t=2026-01-01 00:00:00 +0000 UTC",
			"t0=2026-01-01 00:00:00 +0000 UTC",
		},
	}

	// We use test cases to test all the code paths.
	type testcase struct {
		// name is the test case name
		name string

		// reader simulates the body
		reader io.ReadCloser

		// output expectations
		expectData     []byte
		expectReadErr  error
		expectCloseErr error
		expectEvs      []slogSimpleRecord
	}

	cases := []testcase{
		{
			name:           "no read or close error",
			reader:         io.NopCloser(strings.NewReader("Kampai!")),
			expectData:     []byte("Kampai!"),
			expectReadErr:  nil,
			expectCloseErr: nil,
			expectEvs: []slogSimpleRecord{
				bodyStreamStart,
				bodyStreamDone,
			},
		},
		{
			name: "read error",
			reader: &netstub.FuncConn{
				CloseFunc: func() error {
					return nil
				},
				ReadFunc: func(data []byte) (int, error) {
					return 0, mockErr
				},
			},
			expectData:     []byte{},
			expectReadErr:  mockErr,
			expectCloseErr: nil,
			expectEvs: []slogSimpleRecord{
				bodyStreamStart,
				bodyStreamReadError,
				bodyStreamDone,
			},
		},
		{
			name: "close error",
			reader: &netstub.FuncConn{
				CloseFunc: func() error {
					return mockErr
				},
				ReadFunc: func(data []byte) (int, error) {
					return 0, io.EOF
				},
			},
			expectData:     []byte{},
			expectReadErr:  nil,
			expectCloseErr: mockErr,
			expectEvs: []slogSimpleRecord{
				bodyStreamStart,
				bodyStreamCloseError,
				bodyStreamDone,
			},
		},
		{
			name: "read and close error",
			reader: &netstub.FuncConn{
				CloseFunc: func() error {
					return mockErr
				},
				ReadFunc: func(data []byte) (int, error) {
					return 0, mockErr
				},
			},
			expectData:     []byte{},
			expectReadErr:  mockErr,
			expectCloseErr: mockErr,
			expectEvs: []slogSimpleRecord{
				bodyStreamStart,
				bodyStreamReadError,
				bodyStreamCloseError,
				bodyStreamDone,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 1. setup
			logHelper := &slogValidationHelper{}
			hc := &HTTPConn{
				ErrClassifier: DefaultErrClassifier(),
				HTTPCc:        Result[HTTPEngineConn]{}, // zero is OK for this test
				LocalAddr:     "10.0.0.1:19774",
				Proto:         "tcp",
				RemoteAddr:    "10.0.0.2:80",
				SLogger:       logHelper,
				TimeNow:       logHelper,
			}
			bw := NewHTTPBodyWrapper(hc, tc.reader)

			// 2. invoke
			data, readErr := io.ReadAll(bw)
			closeErr := bw.Close()

			// 3. check
			assert.Equal(t, tc.expectData, data)
			assert.Equal(t, tc.expectCloseErr, closeErr)
			assert.Equal(t, tc.expectReadErr, readErr)

			assert.Equal(t, tc.expectEvs, logHelper.Got)
		})
	}
}
