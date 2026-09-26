//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/ooni/probe-cli/blob/v3.20.1/internal/netxlite/dialer.go
// Adapted from: https://github.com/rbmk-project/rbmk/blob/v0.17.0/pkg/x/netcore/dialer.go
// Adapted from: https://github.com/bassosimone/nop/blob/89b21810488/connect.go
//

package ptnop

import (
	"context"
	"log/slog"
	"net"
	"net/netip"

	"github.com/bassosimone/runtimex"
	"github.com/bassosimone/safeconn"
)

// ConnectFunc is the [Func] that performs [net.Conn] dialing.
//
// Use [NewConnectFunc] to create a new instance.
type ConnectFunc struct {
	Dialer        Dialer
	ErrClassifier ErrClassifier
	Network       string
	SLogger       SLogger
	TimeNow       TimeNowProvider
}

// NewConnectFunc creates a [*ConnectFunc] using the [*Config] and `network`
// to properly initialize all the [*ConnectFunc] fields.
func NewConnectFunc(cfg *Config, network string) *ConnectFunc {
	return &ConnectFunc{
		Dialer:        cfg.Dialer,
		ErrClassifier: cfg.ErrClassifier,
		Network:       network,
		SLogger:       cfg.SLogger,
		TimeNow:       cfg.TimeNow,
	}
}

var _ Func[netip.AddrPort, Result[net.Conn]] = &ConnectFunc{}

// Call dials a [net.Conn] and, on success, transfers its ownership to the next stage.
func (op *ConnectFunc) Call(ctx context.Context, address netip.AddrPort) Result[net.Conn] {
	// 1. log before executing the operation
	t0 := op.TimeNow.Get()
	deadline, _ := ctx.Deadline()
	op.SLogger.Info(
		"connectStart",
		slog.Time("deadline", deadline),
		slog.String("protocol", op.Network),
		slog.String("remoteAddr", address.String()),
		slog.Time("t", t0),
	)

	// 2. execute the operation
	conn, err := op.Dialer.DialContext(ctx, op.Network, address.String())

	// 3. log after executing the operation
	op.SLogger.Info(
		"connectDone",
		slog.Time("deadline", deadline),
		slog.Any("err", err),
		slog.String("errClass", op.ErrClassifier.Classify(err)),
		slog.String("localAddr", safeconn.LocalAddr(conn)), // nil safe
		slog.String("protocol", op.Network),
		slog.String("remoteAddr", address.String()),
		slog.Time("t", op.TimeNow.Get()),
		slog.Time("t0", t0),
	)

	// 4. verify output invariant
	runtimex.Assert((conn != nil && err == nil) || (conn == nil && err != nil))

	// 5. return the result
	return Result[net.Conn]{Err: err, V: conn}
}
