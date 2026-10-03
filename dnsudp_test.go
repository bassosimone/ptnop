// SPDX-License-Identifier: GPL-3.0-or-later

package ptnop

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/bassosimone/dnscodec"
	"github.com/bassosimone/netstub"
	"github.com/bassosimone/runtimex"
	"github.com/bassosimone/safeconn"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

// Make sure [NewDNSOverUDPConnFunc] initializes all [*DNSOverUDPConnFunc] fields.
func TestNewDNSOverUDPConnFunc(t *testing.T) {
	cfg := NewConfig()

	fx := NewDNSOverUDPConnFunc(cfg)

	assert.Same(t, cfg.ErrClassifier, fx.ErrClassifier)
	assert.Same(t, cfg.SLogger, fx.SLogger)
	assert.Same(t, cfg.TimeNow, fx.TimeNow)
}

// Make sure [DNSOverUDPConnFunc.Call] forwards its input and config correctly.
func TestDNSOverUDPCallFunc(t *testing.T) {
	mocked := errors.New("mocked")
	input := Result[net.Conn]{Err: mocked}
	cfg := NewConfig()
	fx := NewDNSOverUDPConnFunc(cfg)

	output := fx.Call(context.Background(), input).(*DNSOverUDPConn)

	assert.NotNil(t, output)
	assert.Equal(t, input, output.Conn)
	assert.Same(t, cfg.ErrClassifier, output.ErrClassifier)
	assert.Same(t, cfg.SLogger, output.SLogger)
	assert.Same(t, cfg.TimeNow, output.TimeNow)
}

// Make sure [DNSOverUDPConn.Close] works as intended.
func TestDNSOverUDPConn_Close(t *testing.T) {
	mocked := errors.New("mocked")

	// We use test cases to check for all valid cases here.
	type testcase struct {
		name   string
		conn   Result[net.Conn]
		expect error
	}

	cases := []testcase{
		{
			name:   "no connection wrapped",
			conn:   Result[net.Conn]{Err: mocked},
			expect: nil,
		},
		{
			name: "connection wrapped",
			conn: Result[net.Conn]{V: &netstub.FuncConn{
				CloseFunc: func() error {
					return mocked
				},
			}},
			expect: mocked,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := &DNSOverUDPConn{
				Conn:          tc.conn,
				ErrClassifier: DefaultErrClassifier(),
				SLogger:       DefaultSLogger(),
				TimeNow:       DefaultTimeNowProvider(),
			}

			err := conn.Close()

			assert.Equal(t, tc.expect, err)
		})
	}
}

// Make sure [DNSOverUDPConn.Exchange] works as intended.
func TestDNSOverUDPConn_Exchange(t *testing.T) {
	// mockErr is the error mock we use
	mockErr := errors.New("mocked")

	// query is the query we'll send when possible to send queries
	query := dnscodec.NewQuery("www.example.com", dns.TypeA)
	query.ID = 171

	// connMockFactory creates a mocked conn with the given read function.
	connMockFactory := func(read func([]byte) (int, error)) *netstub.FuncConn {
		return &netstub.FuncConn{
			LocalAddrFunc: func() net.Addr {
				return &net.UDPAddr{
					IP:   net.IPv4(10, 0, 0, 1),
					Port: 19774,
					Zone: "",
				}
			},
			ReadFunc: read,
			RemoteAddrFunc: func() net.Addr {
				return &net.UDPAddr{
					IP:   net.IPv4(10, 0, 0, 2),
					Port: 53,
					Zone: "",
				}
			},
			SetDeadlineFunc: func(t time.Time) error {
				return nil
			},
			WriteFunc: func(data []byte) (int, error) {
				return len(data), nil
			},
		}
	}

	// We use test cases to test all possible cases
	type testcase struct {
		// name is the test case name
		name string

		// conn is used to initialize [DNSOverUDPConn.Conn]
		conn Result[net.Conn]

		// expectation for the structured logs
		expectLogErr   string
		expectLogClass string

		// additional records we expect to see in the logs
		expectExtraRecords []slogSimpleRecord
	}

	cases := []testcase{
		{
			name:               "previous stage failed",
			conn:               Result[net.Conn]{Err: mockErr},
			expectLogErr:       "mocked",
			expectLogClass:     "ESKIP",
			expectExtraRecords: nil,
		},
		{
			name: "read failure",
			conn: Result[net.Conn]{V: connMockFactory(func(data []byte) (int, error) {
				return 0, mockErr
			})},
			expectLogErr:   "mocked",
			expectLogClass: "EGENERIC",
			expectExtraRecords: []slogSimpleRecord{{
				Level: "info",
				Msg:   "dnsQuery",
				Attrs: []string{
					"dnsRawQuery=[0 171 1 0 0 1 0 0 0 0 0 1 3 119 119 119 7 101 120 97 109 112 108 101 3 99 111 109 0 0 1 0 1 0 0 41 4 208 0 0 0 0 0 0]",
					"dnsServerProtocol=udp",
					"localAddr=10.0.0.1:19774",
					"protocol=udp",
					"remoteAddr=10.0.0.2:53",
					"t=2026-01-01 00:00:00 +0000 UTC",
				},
			}},
		},
		{
			name: "read success w/ invalid response",
			conn: Result[net.Conn]{V: connMockFactory(func(data []byte) (int, error) {
				runtimex.Assert(len(data) > 512)
				data[0] = 15
				data[1] = 4
				data[2] = 12
				return 3, nil
			})},
			expectLogErr:   "bad header bits: dns: overflow unpacking uint16",
			expectLogClass: "EGENERIC",
			expectExtraRecords: []slogSimpleRecord{{
				Level: "info",
				Msg:   "dnsQuery",
				Attrs: []string{
					"dnsRawQuery=[0 171 1 0 0 1 0 0 0 0 0 1 3 119 119 119 7 101 120 97 109 112 108 101 3 99 111 109 0 0 1 0 1 0 0 41 4 208 0 0 0 0 0 0]",
					"dnsServerProtocol=udp",
					"localAddr=10.0.0.1:19774",
					"protocol=udp",
					"remoteAddr=10.0.0.2:53",
					"t=2026-01-01 00:00:00 +0000 UTC",
				},
			}, {
				Level: "info",
				Msg:   "dnsResponse",
				Attrs: []string{
					"dnsRawQuery=[0 171 1 0 0 1 0 0 0 0 0 1 3 119 119 119 7 101 120 97 109 112 108 101 3 99 111 109 0 0 1 0 1 0 0 41 4 208 0 0 0 0 0 0]",
					"dnsRawResponse=[15 4 12]",
					"dnsServerProtocol=udp",
					"localAddr=10.0.0.1:19774",
					"protocol=udp",
					"remoteAddr=10.0.0.2:53",
					"t=2026-01-01 00:00:00 +0000 UTC",
					"t0=2026-01-01 00:00:00 +0000 UTC",
				},
			}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 1. setup
			logHelper := &slogValidationHelper{}
			deadline := logHelper.Get().Add(10 * time.Second)
			ctx, cancel := context.WithDeadline(context.Background(), deadline)
			defer cancel()
			conn := &DNSOverUDPConn{
				Conn:          tc.conn,
				ErrClassifier: DefaultErrClassifier(),
				SLogger:       logHelper,
				TimeNow:       logHelper,
			}

			// 2. execute
			resp, err := conn.Exchange(ctx, query)

			// 3. check
			assert.Nil(t, resp)
			assert.NotNil(t, err)

			dnsExchangeStart := slogSimpleRecord{
				Level: "info",
				Msg:   "dnsExchangeStart",
				Attrs: []string{
					"deadline=2026-01-01 00:00:10 +0000 UTC",
					"dnsQueryName=www.example.com",
					"dnsQueryType=A",
					"dnsServerProtocol=udp",
					"localAddr=" + safeconn.LocalAddr(conn.Conn.V),   // nil safe
					"protocol=" + safeconn.Network(conn.Conn.V),      // nil safe
					"remoteAddr=" + safeconn.RemoteAddr(conn.Conn.V), // nil safe
					"t=2026-01-01 00:00:00 +0000 UTC",
				},
			}
			expect := []slogSimpleRecord{dnsExchangeStart}
			expect = append(expect, tc.expectExtraRecords...)

			dnsExchangeDone := slogSimpleRecord{
				Level: "info",
				Msg:   "dnsExchangeDone",
				Attrs: []string{
					"deadline=2026-01-01 00:00:10 +0000 UTC",
					"dnsQueryName=www.example.com",
					"dnsQueryType=A",
					"dnsServerProtocol=udp",
					"err=" + tc.expectLogErr,
					"errClass=" + tc.expectLogClass,
					"localAddr=" + safeconn.LocalAddr(conn.Conn.V),   // nil safe
					"protocol=" + safeconn.Network(conn.Conn.V),      // nil safe
					"remoteAddr=" + safeconn.RemoteAddr(conn.Conn.V), // nil safe
					"t=2026-01-01 00:00:00 +0000 UTC",
					"t0=2026-01-01 00:00:00 +0000 UTC",
				},
			}
			expect = append(expect, dnsExchangeDone)

			assert.Equal(t, expect, logHelper.Got)
		})
	}
}
