// SPDX-License-Identifier: GPL-3.0-or-later

package ptnop

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/bassosimone/dnscodec"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

// Make sure [NewDNSOverHTTPSConnFunc] correctly initializes all fields.
func TestNewDNSOverHTTPSConnFunc(t *testing.T) {
	// 1. setup
	cfg := NewConfig()
	targetURL := "https://dns.google/dns-query"

	// 2. invoke
	fx := NewDNSOverHTTPSConnFunc(cfg, targetURL)

	// 3. verify
	assert.Same(t, cfg.ErrClassifier, fx.ErrClassifier)
	assert.Same(t, cfg.SLogger, fx.SLogger)
	assert.Same(t, cfg.TimeNow, fx.TimeNow)
	assert.Equal(t, targetURL, fx.URL)
}

// Make sure [DNSOverHTTPSConnFunc.Call] correctly forwards all fields.
func TestDNSOverHTTPSConnFunc_Call(t *testing.T) {
	// 1. setup
	cfg := NewConfig()
	targetURL := "https://dns.google/dns-query"
	fx := NewDNSOverHTTPSConnFunc(cfg, targetURL)
	httpCc := &HTTPConn{}

	// 2. invoke
	dnsCc := fx.Call(context.Background(), httpCc).(*DNSOverHTTPSConn)

	// 3. verify
	assert.Same(t, fx.ErrClassifier, dnsCc.ErrClassifier)
	assert.Same(t, httpCc, dnsCc.HTTPConn)
	assert.Same(t, fx.SLogger, dnsCc.SLogger)
	assert.Same(t, fx.TimeNow, dnsCc.TimeNow)
	assert.Equal(t, fx.URL, dnsCc.URL)
}

// Make sure [DNSOverHTTPSConn.Close] works as intended.
func TestDNSOverHTTPSConn_Close(t *testing.T) {
	// 1. setup
	mockErr := errors.New("mocked")
	httpCc := &funcHTTPClientConn{
		CloseFunc: func() error {
			return mockErr
		},
	}
	dnsCc := &DNSOverHTTPSConn{
		ErrClassifier: DefaultErrClassifier(),
		HTTPConn:      httpCc,
		SLogger:       DefaultSLogger(),
		TimeNow:       DefaultTimeNowProvider(),
		URL:           "https://dns.google/dns-query",
	}

	// 2. invoke
	err := dnsCc.Close()

	// 3. check
	assert.Equal(t, mockErr, err)
}

// Make sure [DNSOverHTTPSConn.Exchange] works as intended.
func TestDNSOverHTTPSConn_Exchange(t *testing.T) {
	// mockErr is the error mock we use
	mockErr := errors.New("mocked")

	// defaultQuery is the default query we try to send to the server
	defaultQuery := dnscodec.NewQuery("www.example.com", dns.TypeA)
	defaultQuery.ID = 171 // note: DoH wants query ID zero so you'll see zero in the raw query

	// We use test cases to test all possible cases
	type testcase struct {
		// name is the test case name
		name string

		// query is the query to use
		query *dnscodec.Query

		// conn is used to initialize [DNSOverHTTPSConn.HTTPConn]
		conn HTTPEngineConn

		// expectation for the structured logs
		expectLogErr   string
		expectLogClass string

		// additional records we expect to see in the logs
		expectExtraRecords []slogSimpleRecord
	}

	cases := []testcase{
		{
			// When the previous stage has failed DoH still serializes the query though
			// the semantic is not "query on the wire" (because, in general, we can't
			// be sure: sending is just copying into a socket buffer) but rather "this
			// raw query is what we'd like to send"; so, semantic wise, this is OK.
			name:  "previous stage failed",
			query: defaultQuery,
			conn: &funcHTTPClientConn{
				RoundTripFunc: func(req *http.Request) (*http.Response, error) {
					return nil, ErrSkip{mockErr}
				},
			},
			expectLogErr:   "mocked",
			expectLogClass: "ESKIP",
			expectExtraRecords: []slogSimpleRecord{{
				Level: "info",
				Msg:   "dnsQuery",
				Attrs: []string{
					"serverProtocol=doh",
					"dnsRawQuery=[0 0 1 0 0 1 0 0 0 0 0 1 3 119 119 119 7 101 120 97 109 112 108 101 3 99 111 109 0 0 1 0 1 0 0 41 16 0 0 0 128 0 0 84 0 12 0 80 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
					"localAddr=10.0.0.1:19774",
					"protocol=tcp",
					"remoteAddr=10.0.0.2:53",
					"t=2026-01-01 00:00:00 +0000 UTC",
				},
			}},
		},
		{
			name:               "query serialization failure",
			query:              dnscodec.NewQuery("bad name.example", dns.TypeA),
			conn:               nil,
			expectLogErr:       "idna: disallowed rune U+0020",
			expectLogClass:     "EGENERIC",
			expectExtraRecords: []slogSimpleRecord{},
		},
		{
			name:  "round trip failure",
			query: defaultQuery,
			conn: &funcHTTPClientConn{
				RoundTripFunc: func(req *http.Request) (*http.Response, error) {
					return nil, mockErr
				},
			},
			expectLogErr:   "mocked",
			expectLogClass: "EGENERIC",
			expectExtraRecords: []slogSimpleRecord{{
				Level: "info",
				Msg:   "dnsQuery",
				Attrs: []string{
					"serverProtocol=doh",
					"dnsRawQuery=[0 0 1 0 0 1 0 0 0 0 0 1 3 119 119 119 7 101 120 97 109 112 108 101 3 99 111 109 0 0 1 0 1 0 0 41 16 0 0 0 128 0 0 84 0 12 0 80 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
					"localAddr=10.0.0.1:19774",
					"protocol=tcp",
					"remoteAddr=10.0.0.2:53",
					"t=2026-01-01 00:00:00 +0000 UTC",
				},
			}},
		},
		{
			name:  "read success w/ invalid response",
			query: defaultQuery,
			conn: &funcHTTPClientConn{
				RoundTripFunc: func(req *http.Request) (*http.Response, error) {
					resp := &http.Response{
						Request:    req,
						StatusCode: 200,
						Header: http.Header{
							"Content-Type": []string{"application/dns-message"},
						},
						Body: io.NopCloser(bytes.NewReader([]byte{15, 4, 12})),
					}
					return resp, nil
				},
			},
			expectLogErr:   "server misbehaving",
			expectLogClass: "EGENERIC",
			expectExtraRecords: []slogSimpleRecord{{
				Level: "info",
				Msg:   "dnsQuery",
				Attrs: []string{
					"serverProtocol=doh",
					"dnsRawQuery=[0 0 1 0 0 1 0 0 0 0 0 1 3 119 119 119 7 101 120 97 109 112 108 101 3 99 111 109 0 0 1 0 1 0 0 41 16 0 0 0 128 0 0 84 0 12 0 80 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
					"localAddr=10.0.0.1:19774",
					"protocol=tcp",
					"remoteAddr=10.0.0.2:53",
					"t=2026-01-01 00:00:00 +0000 UTC",
				},
			}, {
				Level: "info",
				Msg:   "dnsResponse",
				Attrs: []string{
					"serverProtocol=doh",
					"dnsRawQuery=[0 0 1 0 0 1 0 0 0 0 0 1 3 119 119 119 7 101 120 97 109 112 108 101 3 99 111 109 0 0 1 0 1 0 0 41 16 0 0 0 128 0 0 84 0 12 0 80 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
					"localAddr=10.0.0.1:19774",
					"protocol=tcp",
					"remoteAddr=10.0.0.2:53",
					"t=2026-01-01 00:00:00 +0000 UTC",
					"t0=2026-01-01 00:00:00 +0000 UTC",
					"dnsRawResponse=[15 4 12]",
				},
			}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 1. setup
			//
			// Note: cannot test with deadline here because the underlying
			// code uses github.com/bassosimone/iox, which binds reading the
			// response to the context being not canceled; however, due to
			// the fact that we're using a time fixture and that such a fixture
			// is in the past, the deadline is always expired.
			logHelper := &slogValidationHelper{}
			conn := &DNSOverHTTPSConn{
				ErrClassifier: DefaultErrClassifier(),
				HTTPConn:      tc.conn,
				LocalAddr:     "10.0.0.1:19774",
				Proto:         "tcp",
				RemoteAddr:    "10.0.0.2:53",
				SLogger:       logHelper,
				TimeNow:       logHelper,
				URL:           "",
			}

			// 2. execute
			resp, err := conn.Exchange(context.Background(), tc.query)

			// 3. check
			assert.Nil(t, resp)
			assert.NotNil(t, err)

			dnsExchangeStart := slogSimpleRecord{
				Level: "info",
				Msg:   "dnsExchangeStart",
				Attrs: []string{
					"deadline=0001-01-01 00:00:00 +0000 UTC",
					"localAddr=10.0.0.1:19774",
					"protocol=tcp",
					"queryName=" + tc.query.Name,
					"queryType=A",
					"remoteAddr=10.0.0.2:53",
					"serverProtocol=doh",
					"t=2026-01-01 00:00:00 +0000 UTC",
				},
			}
			expect := []slogSimpleRecord{dnsExchangeStart}
			expect = append(expect, tc.expectExtraRecords...)

			dnsExchangeDone := slogSimpleRecord{
				Level: "info",
				Msg:   "dnsExchangeDone",
				Attrs: []string{
					"deadline=0001-01-01 00:00:00 +0000 UTC",
					"err=" + tc.expectLogErr,
					"errClass=" + tc.expectLogClass,
					"localAddr=10.0.0.1:19774",
					"protocol=tcp",
					"queryName=" + tc.query.Name,
					"queryType=A",
					"remoteAddr=10.0.0.2:53",
					"serverProtocol=doh",
					"t=2026-01-01 00:00:00 +0000 UTC",
					"t0=2026-01-01 00:00:00 +0000 UTC",
				},
			}
			expect = append(expect, dnsExchangeDone)

			assert.Equal(t, expect, logHelper.Got)
		})
	}
}
