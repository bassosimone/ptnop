// SPDX-License-Identifier: GPL-3.0-or-later

package ptnop_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/bassosimone/dnscodec"
	"github.com/bassosimone/dnstest"
	"github.com/bassosimone/pkitest"
	"github.com/bassosimone/ptnop"
	"github.com/miekg/dns"
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

func TestLocalhost_dnsOverUDP(t *testing.T) {
	// 1. create server
	hconfig := dnstest.NewHandlerConfig()
	hconfig.AddNetipAddr("dns.google", netip.MustParseAddr("8.8.8.8"))
	hconfig.AddNetipAddr("dns.google", netip.MustParseAddr("8.8.4.4"))
	server := dnstest.MustNewUDPServer(&net.ListenConfig{}, "127.0.0.1:0", dnstest.NewHandler(hconfig))
	defer server.Close()
	endpoint, err := netip.ParseAddrPort(server.Address())
	require.Nil(t, err)

	// 2. create pipeline
	cfg := ptnop.NewConfig()
	pipeline := ptnop.Compose2(
		ptnop.NewConnectFunc(cfg, "udp"),
		ptnop.NewDNSOverUDPConnFunc(cfg),
	)

	// 3. execute pipeline
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dnsConn := pipeline.Call(ctx, endpoint)
	defer dnsConn.Close()

	// 4. use the returned conn
	resp, err := dnsConn.Exchange(ctx, dnscodec.NewQuery("dns.google", dns.TypeA))
	require.Nil(t, err)
	addrs, err := resp.RecordsA()
	require.Nil(t, err)
	slices.Sort(addrs)
	require.Equal(t, []string{"8.8.4.4", "8.8.8.8"}, addrs)
}

func TestLocalhost_dnsOverTCP(t *testing.T) {
	// 1. create server
	hconfig := dnstest.NewHandlerConfig()
	hconfig.AddNetipAddr("dns.google", netip.MustParseAddr("8.8.8.8"))
	hconfig.AddNetipAddr("dns.google", netip.MustParseAddr("8.8.4.4"))
	server := dnstest.MustNewTCPServer(&net.ListenConfig{}, "127.0.0.1:0", dnstest.NewHandler(hconfig))
	defer server.Close()
	endpoint, err := netip.ParseAddrPort(server.Address())
	require.Nil(t, err)

	// 2. create pipeline
	cfg := ptnop.NewConfig()
	pipeline := ptnop.Compose2(
		ptnop.NewConnectFunc(cfg, "tcp"),
		ptnop.NewDNSOverTCPConnFunc(cfg),
	)

	// 3. execute pipeline
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dnsConn := pipeline.Call(ctx, endpoint)
	defer dnsConn.Close()

	// 4. use the returned conn
	resp, err := dnsConn.Exchange(ctx, dnscodec.NewQuery("dns.google", dns.TypeA))
	require.Nil(t, err)
	addrs, err := resp.RecordsA()
	require.Nil(t, err)
	slices.Sort(addrs)
	require.Equal(t, []string{"8.8.4.4", "8.8.8.8"}, addrs)
}

func TestLocalhost_dnsOverTLS(t *testing.T) {
	// 1. create server
	hconfig := dnstest.NewHandlerConfig()
	hconfig.AddNetipAddr("dns.google", netip.MustParseAddr("8.8.8.8"))
	hconfig.AddNetipAddr("dns.google", netip.MustParseAddr("8.8.4.4"))
	pki := pkitest.MustNewPKI("testdata")
	cert := pki.MustNewCert(&pkitest.SelfSignedCertConfig{
		CommonName:   "dns.example.com",
		DNSNames:     []string{"dns.example.com"},
		Organization: []string{"Example"},
	})
	server := dnstest.MustNewTLSServer(&net.ListenConfig{}, "127.0.0.1:0", cert, dnstest.NewHandler(hconfig))
	defer server.Close()
	endpoint, err := netip.ParseAddrPort(server.Address())
	require.Nil(t, err)

	tlsConfig := &tls.Config{
		NextProtos: []string{"dot"},
		RootCAs:    pki.CertPool(),
		ServerName: "dns.example.com",
	}

	// 2. create pipeline
	cfg := ptnop.NewConfig()
	pipeline := ptnop.Compose3(
		ptnop.NewConnectFunc(cfg, "tcp"),
		ptnop.NewTLSHandshakeFunc(cfg, tlsConfig),
		ptnop.NewDNSOverTLSConnFunc(cfg),
	)

	// 3. execute pipeline
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dnsConn := pipeline.Call(ctx, endpoint)
	defer dnsConn.Close()

	// 4. use the returned conn
	resp, err := dnsConn.Exchange(ctx, dnscodec.NewQuery("dns.google", dns.TypeA))
	require.Nil(t, err)
	addrs, err := resp.RecordsA()
	require.Nil(t, err)
	slices.Sort(addrs)
	require.Equal(t, []string{"8.8.4.4", "8.8.8.8"}, addrs)
}

func TestLocalhost_dnsOverHTTPS(t *testing.T) {
	// 1. create server
	hconfig := dnstest.NewHandlerConfig()
	hconfig.AddNetipAddr("dns.google", netip.MustParseAddr("8.8.8.8"))
	hconfig.AddNetipAddr("dns.google", netip.MustParseAddr("8.8.4.4"))
	pki := pkitest.MustNewPKI("testdata")
	cert := pki.MustNewCert(&pkitest.SelfSignedCertConfig{
		CommonName:   "dns.example.com",
		DNSNames:     []string{"dns.example.com"},
		Organization: []string{"Example"},
	})
	server := dnstest.MustNewHTTPSServer(&net.ListenConfig{}, "127.0.0.1:0", cert, dnstest.NewHandler(hconfig))
	defer server.Close()
	parsedURL, err := url.Parse(server.URL())
	require.NotNil(t, parsedURL)
	require.Nil(t, err)
	endpoint, err := netip.ParseAddrPort(parsedURL.Host)
	require.Nil(t, err)

	tlsConfig := &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
		RootCAs:    pki.CertPool(),
		ServerName: "dns.example.com",
	}

	// 2. create pipeline
	cfg := ptnop.NewConfig()
	pipeline := ptnop.Compose4(
		ptnop.NewConnectFunc(cfg, "tcp"),
		ptnop.NewTLSHandshakeFunc(cfg, tlsConfig),
		ptnop.NewHTTPConnFunc(cfg),
		ptnop.NewDNSOverHTTPSConnFunc(cfg, server.URL()+"/dns-query"),
	)

	// 3. execute pipeline
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dnsConn := pipeline.Call(ctx, endpoint)
	defer dnsConn.Close()

	// 4. use the returned conn
	resp, err := dnsConn.Exchange(ctx, dnscodec.NewQuery("dns.google", dns.TypeA))
	require.Nil(t, err)
	addrs, err := resp.RecordsA()
	require.Nil(t, err)
	slices.Sort(addrs)
	require.Equal(t, []string{"8.8.4.4", "8.8.8.8"}, addrs)
}
