// SPDX-License-Identifier: GPL-3.0-or-later

package ptnop_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"

	"github.com/bassosimone/ptnop"
	"github.com/stretchr/testify/require"
)

func TestLocalhost_httpServer(t *testing.T) {
	// 1. create server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, world!\n"))
	}))
	defer server.Close()
	parsedURL, err := url.Parse(server.URL)
	require.NotNil(t, parsedURL)
	require.Nil(t, err)
	endpoint, err := netip.ParseAddrPort(parsedURL.Host)
	require.Nil(t, err)

	// 2. create request
	req, err := http.NewRequest(http.MethodGet, server.URL, http.NoBody)
	require.Nil(t, err)

	// 3. create pipeline
	cfg := ptnop.NewConfig()
	pipeline := ptnop.Compose2(
		ptnop.NewConnectFunc(cfg, "tcp"),
		ptnop.NewHTTPConnFunc(cfg),
	)

	// 4. execute pipeline
	httpcc := pipeline.Call(context.Background(), endpoint)
	defer httpcc.Close()

	// 5. use the returned conn
	resp, err := httpcc.RoundTrip(req)
	require.Nil(t, err)
	require.Equal(t, 200, resp.StatusCode)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	require.Nil(t, err)
	require.Equal(t, []byte("Hello, world!\n"), respBody)
}

func TestLocalhost_httpsServer(t *testing.T) {
	// We use test cases to test both HTTP/1.1 and H2
	type testcase struct {
		alpn   []string // offered
		expect string   // negotiated must be this
		major  int      // major must be this
	}

	cases := []testcase{
		{
			alpn:   nil,
			expect: "",
			major:  1,
		},
		{
			alpn:   []string{"http/1.1"},
			expect: "http/1.1",
			major:  1,
		},
		{
			alpn:   []string{"h2", "http/1.1"},
			expect: "h2",
			major:  2,
		},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("alpn=%v", tc.alpn), func(t *testing.T) {
			// 1. create server
			server := httptest.NewUnstartedServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Write([]byte("Hello, world!\n"))
				}))
			defer server.Close()
			server.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
			server.EnableHTTP2 = true // make sure that http/2 is supported
			server.StartTLS()
			parsedURL, err := url.Parse(server.URL)
			require.NotNil(t, parsedURL)
			require.Nil(t, err)
			endpoint, err := netip.ParseAddrPort(parsedURL.Host)
			require.Nil(t, err)

			certpool := x509.NewCertPool()
			certpool.AddCert(server.Certificate())
			tlsConfig := &tls.Config{
				RootCAs:    certpool,
				ServerName: "www.example.com",
				NextProtos: tc.alpn,
			}

			// 2. create request
			req, err := http.NewRequest(http.MethodGet, server.URL, http.NoBody)
			require.Nil(t, err)

			// 3. create pipeline
			cfg := ptnop.NewConfig()
			pipeline := ptnop.Compose3(
				ptnop.NewConnectFunc(cfg, "tcp"),
				ptnop.NewTLSHandshakeFunc(cfg, tlsConfig),
				ptnop.NewHTTPConnFunc(cfg),
			)

			// 4. execute pipeline
			httpcc := pipeline.Call(context.Background(), endpoint)
			defer httpcc.Close()

			// 5. use the returned conn
			resp, err := httpcc.RoundTrip(req)
			require.Nil(t, err)
			require.Equal(t, 200, resp.StatusCode)
			defer resp.Body.Close()

			require.Equal(t, tc.expect, resp.TLS.NegotiatedProtocol)
			require.Equal(t, tc.major, resp.ProtoMajor)

			respBody, err := io.ReadAll(resp.Body)
			require.Nil(t, err)
			require.Equal(t, []byte("Hello, world!\n"), respBody)
		})
	}
}
