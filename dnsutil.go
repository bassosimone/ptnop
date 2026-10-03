//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/bassosimone/nop/blob/89b21810488/dnsdial.go
// Adapted from: https://github.com/bassosimone/nop/blob/89b21810488/dnsexchange.go
//

package ptnop

import (
	"context"
	"log/slog"
	"net"
	"time"

	"github.com/bassosimone/dnscodec"
)

// DNSConn is the conn returned by stages such as [*DNSOverUDPConnFunc].
type DNSConn interface {
	Close() error
	Exchange(ctx context.Context, query *dnscodec.Query) (*dnscodec.Response, error)
}

// dnsUnusedDialer is a [Dialer] that panics if DialContext is called. Dialing should
// not happen because we're using connections directly.
type dnsUnusedDialer struct{}

var _ Dialer = dnsUnusedDialer{}

func (dnsUnusedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	panic("ptnop: DNS transport must not dial; this is a programming error")
}

// dnsExchangeLogContext holds common logging state for DNS exchanges.
type dnsExchangeLogContext struct {
	ErrClassifier  ErrClassifier
	LocalAddr      string
	SLogger        SLogger
	Protocol       string
	QueryName      string
	QueryType      string
	RemoteAddr     string
	ServerProtocol string
	TimeNow        TimeNowProvider
}

// LogStart logs the start of a DNS exchange.
func (lc *dnsExchangeLogContext) LogStart(t0 time.Time, deadline time.Time) {
	lc.SLogger.Info(
		"dnsExchangeStart",
		slog.Time("deadline", deadline),
		slog.String("dnsQueryName", lc.QueryName),
		slog.String("dnsQueryType", lc.QueryType),
		slog.String("dnsServerProtocol", lc.ServerProtocol),
		slog.String("localAddr", lc.LocalAddr),
		slog.String("protocol", lc.Protocol),
		slog.String("remoteAddr", lc.RemoteAddr),
		slog.Time("t", t0),
	)
}

// LogDone logs the completion of a DNS exchange.
func (lc *dnsExchangeLogContext) LogDone(t0 time.Time, deadline time.Time, err error) {
	lc.SLogger.Info(
		"dnsExchangeDone",
		slog.Time("deadline", deadline),
		slog.String("dnsQueryName", lc.QueryName),
		slog.String("dnsQueryType", lc.QueryType),
		slog.String("dnsServerProtocol", lc.ServerProtocol),
		slog.Any("err", err),
		slog.String("errClass", lc.ErrClassifier.Classify(err)),
		slog.String("localAddr", lc.LocalAddr),
		slog.String("protocol", lc.Protocol),
		slog.String("remoteAddr", lc.RemoteAddr),
		slog.Time("t", lc.TimeNow.Get()),
		slog.Time("t0", t0),
	)
}

// MakeQueryObserver returns an observer function for raw DNS queries.
//
// The rqr pointer is used to capture the raw query for correlation
// with the response observer.
func (lc *dnsExchangeLogContext) MakeQueryObserver(t0 time.Time, rqr *[]byte) func([]byte) {
	return func(rawQuery []byte) {
		lc.SLogger.Info(
			"dnsQuery",
			slog.Any("dnsRawQuery", rawQuery),
			slog.String("dnsServerProtocol", lc.ServerProtocol),
			slog.String("localAddr", lc.LocalAddr),
			slog.String("protocol", lc.Protocol),
			slog.String("remoteAddr", lc.RemoteAddr),
			slog.Time("t", t0),
		)
		*rqr = rawQuery
	}
}

// MakeResponseObserver returns an observer function for raw DNS responses.
//
// The rqr pointer should be the same one passed to [dnsExchangeLogContext.MakeQueryObserver],
// allowing the response to be correlated with the original query.
func (lc *dnsExchangeLogContext) MakeResponseObserver(t0 time.Time, rqr *[]byte) func([]byte) {
	return func(rawResp []byte) {
		lc.SLogger.Info(
			"dnsResponse",
			slog.Any("dnsRawQuery", *rqr),
			slog.Any("dnsRawResponse", rawResp),
			slog.String("dnsServerProtocol", lc.ServerProtocol),
			slog.String("localAddr", lc.LocalAddr),
			slog.String("protocol", lc.Protocol),
			slog.String("remoteAddr", lc.RemoteAddr),
			slog.Time("t", lc.TimeNow.Get()),
			slog.Time("t0", t0),
		)
	}
}
