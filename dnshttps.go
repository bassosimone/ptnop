//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/bassosimone/nop/blob/89b21810488/dnsoverhttps.go
//

package ptnop

import (
	"context"
	"github.com/bassosimone/dnscodec"
	"github.com/bassosimone/dnsoverhttps"
	"github.com/bassosimone/runtimex"
	"github.com/miekg/dns"
)

// DNSOverHTTPSConnFunc is the [Func] that creates [*DNSOverHTTPSConn].
//
// Use [NewDNSOverHTTPSConnFunc] to create a new instance.
type DNSOverHTTPSConnFunc struct {
	ErrClassifier ErrClassifier
	SLogger       SLogger
	TimeNow       TimeNowProvider
	URL           string
}

// NewDNSOverHTTPSConnFunc creates a [*DNSOverHTTPSConnFunc] using the [*Config]
// to properly initialize all the [*DNSOverHTTPSConnFunc] fields. The `targetURL` is
// also necessary to set the `Host` header and the URL path. However, note that
// [*DNSOverHTTPSConnFunc] takes as input an [*HTTPConn], so the URL host will not
// be used for dialing. The scheme is not used for dialing either, but HTTP/2 sends
// it as the `:scheme` pseudo-header, so use `https`.
func NewDNSOverHTTPSConnFunc(cfg *Config, targetURL string) *DNSOverHTTPSConnFunc {
	return &DNSOverHTTPSConnFunc{
		ErrClassifier: cfg.ErrClassifier,
		SLogger:       cfg.SLogger,
		TimeNow:       cfg.TimeNow,
		URL:           targetURL,
	}
}

var _ Func[*HTTPConn, *DNSOverHTTPSConn] = &DNSOverHTTPSConnFunc{}

// Call wraps the HTTPConn into a DNSOverHTTPSConn.
func (op *DNSOverHTTPSConnFunc) Call(ctx context.Context, httpConn *HTTPConn) *DNSOverHTTPSConn {
	return &DNSOverHTTPSConn{
		ErrClassifier: op.ErrClassifier,
		HTTPConn:      httpConn,
		LocalAddr:     httpConn.LocalAddr,
		Proto:         httpConn.Proto,
		RemoteAddr:    httpConn.RemoteAddr,
		SLogger:       op.SLogger,
		TimeNow:       op.TimeNow,
		URL:           op.URL,
	}
}

// DNSOverHTTPSConn wraps a HTTPS conn and allows executing DNS exchanges.
//
// Typically constructed by [*DNSOverHTTPSConnFunc].
type DNSOverHTTPSConn struct {
	ErrClassifier ErrClassifier
	HTTPConn      HTTPEngineConn
	LocalAddr     string
	Proto         string
	RemoteAddr    string
	SLogger       SLogger
	TimeNow       TimeNowProvider
	URL           string
}

// Close closes the underlying [*HTTPConn].
func (c *DNSOverHTTPSConn) Close() (err error) {
	return c.HTTPConn.Close()
}

// Exchange performs a DNS exchange over HTTPS.
func (c *DNSOverHTTPSConn) Exchange(
	ctx context.Context, query *dnscodec.Query) (*dnscodec.Response, error) {
	// 1. Create the log context
	t0 := c.TimeNow.Get()
	deadline, _ := ctx.Deadline()
	var rqr []byte
	lc := &dnsExchangeLogContext{
		ErrClassifier:  c.ErrClassifier,
		LocalAddr:      c.LocalAddr,
		QueryName:      query.Name,
		QueryType:      dns.TypeToString[query.Type],
		SLogger:        c.SLogger,
		Protocol:       c.Proto,
		RemoteAddr:     c.RemoteAddr,
		ServerProtocol: "doh",
		TimeNow:        c.TimeNow,
	}

	// 2. Create the HTTP request and the query message
	lc.LogStart(t0, deadline)
	httpReq, queryMsg, err := dnsoverhttps.NewRequestWithHook(
		ctx, query, c.URL, lc.MakeQueryObserver(t0, &rqr))
	if err != nil {
		lc.LogDone(t0, deadline, err)
		return nil, err
	}

	// 3. Perform the HTTP round trip
	httpResp, err := c.HTTPConn.RoundTrip(httpReq)
	if err != nil {
		lc.LogDone(t0, deadline, err)
		return nil, err
	}

	// 4. Read the response and validate it
	resp, err := dnsoverhttps.ReadResponseWithHook(
		ctx, httpResp, queryMsg, lc.MakeResponseObserver(t0, &rqr))
	lc.LogDone(t0, deadline, err)

	// 5. enforce output invariant and return
	runtimex.Assert((resp != nil && err == nil) || (resp == nil && err != nil))
	return resp, err
}
