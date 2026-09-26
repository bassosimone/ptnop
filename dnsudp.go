//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/bassosimone/nop/blob/89b21810488/dnsoverudp.go
//

package ptnop

import (
	"context"
	"net"
	"net/netip"

	"github.com/bassosimone/dnscodec"
	"github.com/bassosimone/minest"
	"github.com/bassosimone/runtimex"
	"github.com/bassosimone/safeconn"
	"github.com/miekg/dns"
)

// DNSOverUDPConnFunc is the [Func] that creates [*DNSOverUDPConn].
//
// Use [NewDNSOverUDPConnFunc] to create a new instance.
type DNSOverUDPConnFunc struct {
	ErrClassifier ErrClassifier
	SLogger       SLogger
	TimeNow       TimeNowProvider
}

// NewDNSOverUDPConnFunc creates a [*DNSOverUDPConnFunc] using the [*Config]
// to properly initialize all the [*DNSOverUDPConnFunc] fields.
func NewDNSOverUDPConnFunc(cfg *Config) *DNSOverUDPConnFunc {
	return &DNSOverUDPConnFunc{
		ErrClassifier: cfg.ErrClassifier,
		SLogger:       cfg.SLogger,
		TimeNow:       cfg.TimeNow,
	}
}

var _ Func[Result[net.Conn], *DNSOverUDPConn] = &DNSOverUDPConnFunc{}

// Call transforms a [net.Conn] into an [*DNSOverUDPConn] thus allowing for DNS exchanges.
func (op *DNSOverUDPConnFunc) Call(ctx context.Context, conn Result[net.Conn]) *DNSOverUDPConn {
	return &DNSOverUDPConn{
		Conn:          conn,
		ErrClassifier: op.ErrClassifier,
		SLogger:       op.SLogger,
		TimeNow:       op.TimeNow,
	}
}

// DNSOverUDPConn wraps a UDP conn and allows executing DNS exchanges.
//
// Typically constructed by [*DNSOverUDPConnFunc].
type DNSOverUDPConn struct {
	Conn          Result[net.Conn]
	ErrClassifier ErrClassifier
	SLogger       SLogger
	TimeNow       TimeNowProvider
}

// Close closes the underlying UDP conn.
func (c *DNSOverUDPConn) Close() error {
	if conn, err := c.Conn.V, c.Conn.Err; err == nil {
		return conn.Close()
	}
	return nil
}

// Exchange performs a DNS exchange over UDP.
func (c *DNSOverUDPConn) Exchange(
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
		ServerProtocol: "udp",
		TimeNow:        c.TimeNow,
	}

	// 3. Create the transport
	//
	// Note: we're not going to dial, so let's use a dialer that panics
	// if we attempt to dial (programmer error).
	txp := minest.NewDNSOverUDPTransport(
		dnsUnusedDialer{},
		netip.AddrPortFrom(netip.IPv4Unspecified(), 0),
	)

	// 4. Set observers for raw messages
	txp.ObserveRawQuery = lc.MakeQueryObserver(t0, &rqr)
	txp.ObserveRawResponse = lc.MakeResponseObserver(t0, &rqr)

	// 5. Execute with events logging
	var resp *dnscodec.Response
	lc.LogStart(t0, deadline)
	if err == nil {
		resp, err = txp.ExchangeWithConn(ctx, conn, query)
	} else {
		err = ErrSkip{err}
	}
	lc.LogDone(t0, deadline, err)

	// 6. enforce output invariant and return
	runtimex.Assert((resp != nil && err == nil) || (resp == nil && err != nil))
	return resp, err
}
