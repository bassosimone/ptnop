//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/bassosimone/nop/blob/89b21810488/dnsovertcp.go
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

// DNSOverTCPConnFunc is the [Func] that creates [*DNSOverTCPConn].
//
// Use [NewDNSOverTCPConnFunc] to create a new instance.
type DNSOverTCPConnFunc struct {
	ErrClassifier ErrClassifier
	SLogger       SLogger
	TimeNow       TimeNowProvider
}

// NewDNSOverTCPConnFunc creates a [*DNSOverTCPConnFunc] using the [*Config]
// to properly initialize all the [*DNSOverTCPConnFunc] fields.
func NewDNSOverTCPConnFunc(cfg *Config) *DNSOverTCPConnFunc {
	return &DNSOverTCPConnFunc{
		ErrClassifier: cfg.ErrClassifier,
		SLogger:       cfg.SLogger,
		TimeNow:       cfg.TimeNow,
	}
}

var _ Func[Result[net.Conn], DNSConn] = &DNSOverTCPConnFunc{}

// Call transforms a [net.Conn] into an [DNSConn] thus allowing for DNS exchanges.
//
// The returned value is a [*DNSOverTCPConn].
func (op *DNSOverTCPConnFunc) Call(ctx context.Context, conn Result[net.Conn]) DNSConn {
	return &DNSOverTCPConn{
		Conn:          conn,
		ErrClassifier: op.ErrClassifier,
		SLogger:       op.SLogger,
		TimeNow:       op.TimeNow,
	}
}

// DNSOverTCPConn wraps a TCP conn and allows executing DNS exchanges.
//
// Typically constructed by [*DNSOverTCPConnFunc].
type DNSOverTCPConn struct {
	Conn          Result[net.Conn]
	ErrClassifier ErrClassifier
	SLogger       SLogger
	TimeNow       TimeNowProvider
}

// Close closes the underlying TCP connection.
func (c *DNSOverTCPConn) Close() error {
	if conn, err := c.Conn.V, c.Conn.Err; err == nil {
		return conn.Close()
	}
	return nil
}

// Exchange performs a DNS exchange over TCP.
func (c *DNSOverTCPConn) Exchange(
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
		ServerProtocol: "tcp",
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
		so := dnsoverstream.NewTCPStreamOpener(conn)
		resp, err = txp.ExchangeWithStreamOpener(ctx, so, query)
	} else {
		err = ErrSkip{err}
	}
	lc.LogDone(t0, deadline, err)

	// 6. enforce output invariant and return
	runtimex.Assert((resp != nil && err == nil) || (resp == nil && err != nil))
	return resp, err
}
