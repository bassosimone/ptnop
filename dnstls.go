//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/bassosimone/nop/blob/89b21810488/dnsovertls.go
//

package ptnop

import (
	"context"
	"net"
	"net/netip"

	"github.com/bassosimone/dnscodec"
	"github.com/bassosimone/dnsoverstream"
	"github.com/bassosimone/runtimex"
	"github.com/bassosimone/safeconn"
	"github.com/miekg/dns"
)

// DNSOverTLSConnFunc is the [Func] that creates [*DNSOverTLSConn].
//
// Use [NewDNSOverTLSConnFunc] to create a new instance.
type DNSOverTLSConnFunc struct {
	ErrClassifier ErrClassifier
	SLogger       SLogger
	TimeNow       TimeNowProvider
}

// NewDNSOverTLSConnFunc creates a [*DNSOverTLSConnFunc] using the [*Config]
// to properly initialize all the [*DNSOverTLSConnFunc] fields.
func NewDNSOverTLSConnFunc(cfg *Config) *DNSOverTLSConnFunc {
	return &DNSOverTLSConnFunc{
		ErrClassifier: cfg.ErrClassifier,
		SLogger:       cfg.SLogger,
		TimeNow:       cfg.TimeNow,
	}
}

var _ Func[Result[net.Conn], *DNSOverTLSConn] = &DNSOverTLSConnFunc{}

// Call wraps the TLSConn into a DNSOverTLSConn.
func (op *DNSOverTLSConnFunc) Call(ctx context.Context, conn Result[net.Conn]) *DNSOverTLSConn {
	return &DNSOverTLSConn{
		Conn:          conn,
		ErrClassifier: op.ErrClassifier,
		SLogger:       op.SLogger,
		TimeNow:       op.TimeNow,
	}
}

// DNSOverTLSConn wraps a TLS conn and allows executing DNS exchanges.
//
// Typically constructed by [*DNSOverTLSConnFunc].
type DNSOverTLSConn struct {
	Conn          Result[net.Conn]
	ErrClassifier ErrClassifier
	SLogger       SLogger
	TimeNow       TimeNowProvider
}

// Close closes the underlying TLS connection.
func (c *DNSOverTLSConn) Close() error {
	if conn, err := c.Conn.V, c.Conn.Err; err == nil {
		return conn.Close()
	}
	return nil
}

// Exchange performs a DNS exchange over TLS.
func (c *DNSOverTLSConn) Exchange(
	ctx context.Context, query *dnscodec.Query) (*dnscodec.Response, error) {
	// 1. unpack the input and verify invariant
	conn, err := c.Conn.V, c.Conn.Err
	runtimex.Assert((conn != nil && err == nil) || (conn == nil && err != nil))

	// 2. Create the log context
	t0 := c.TimeNow.Get()
	deadline, _ := ctx.Deadline()
	var rqr []byte
	lc := &dnsExchangeLogContext{
		ErrClassifier:  c.ErrClassifier,
		LocalAddr:      safeconn.LocalAddr(conn), // nil safe
		QueryName:      query.Name,
		QueryType:      dns.TypeToString[query.Type],
		SLogger:        c.SLogger,
		Protocol:       safeconn.Network(conn),    // nil safe
		RemoteAddr:     safeconn.RemoteAddr(conn), // nil safe
		ServerProtocol: "dot",
		TimeNow:        c.TimeNow,
	}

	// 3. Create the transport
	//
	// Note: we're not going to dial, so let's use a dialer that panics
	// if we attempt to dial (programmer error).
	streamDialer := dnsoverstream.NewStreamOpenerDialerTCP(dnsUnusedDialer{})
	txp := dnsoverstream.NewTransport(
		streamDialer, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))

	// 4. Set observers for raw messages
	txp.ObserveRawQuery = lc.MakeQueryObserver(t0, &rqr)
	txp.ObserveRawResponse = lc.MakeResponseObserver(t0, &rqr)

	// 5. Execute with events logging
	var resp *dnscodec.Response
	lc.LogStart(t0, deadline)
	if err == nil {
		so := dnsoverstream.NewTLSStreamOpener(conn) // turns on padding and DNSSEC
		resp, err = txp.ExchangeWithStreamOpener(ctx, so, query)
	} else {
		err = ErrSkip{err}
	}
	lc.LogDone(t0, deadline, err)

	// 6. enforce output invariant and return
	runtimex.Assert((resp != nil && err == nil) || (resp == nil && err != nil))
	return resp, err
}
