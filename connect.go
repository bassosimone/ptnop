//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/ooni/probe-cli/blob/v3.20.1/internal/netxlite/dialer.go
// Adapted from: https://github.com/rbmk-project/rbmk/blob/v0.17.0/pkg/x/netcore/dialer.go
// Adapted from: https://github.com/bassosimone/nop/blob/ae41909903156c3fc9c0d80a56ce884c1ca4eb4a/connect.go
//

package ptnop

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/bassosimone/runtimex"
	"github.com/bassosimone/safeconn"
)

// Dialer abstracts the [*net.Dialer] behavior for [*ConnectFunc]. Like
// the [*net.Dialer], this implementation must always return a valid [net.Conn]
// or an error. It must not return (nil, nil) or a [net.Conn] and an error.
//
// By making [*ConnectFunc] depend on an abstract implementation we
// allow for unit testing and for using alternative dialers.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// NewDefaultDialer returns a [*net.Dialer] configured so that
// multipath TCP is disabled. The reason for this is that we use
// this package for measuring and multipath TCP could become a
// confounding factor by switching to an alternate path.
func NewDefaultDialer() *net.Dialer {
	d := &net.Dialer{}
	d.SetMultipathTCP(false)
	return d
}

// NewConnectFunc returns a new [*ConnectFunc] using the [Dialer]
// returned by [NewDefaultDialer] as the underlying dialer.
//
// The cfg argument contains the common configuration for nop operations.
//
// The network argument should be either "tcp" or "udp".
//
// The logger argument is the [SLogger] to use for structured logging.
func NewConnectFunc(cfg *Config, network string, logger SLogger) *ConnectFunc {
	return &ConnectFunc{
		Dialer:        NewDefaultDialer(),
		ErrClassifier: cfg.ErrClassifier,
		Logger:        logger,
		Network:       network,
		TimeNow:       cfg.TimeNow,
	}
}

// ConnectFunc dials a [netip.AddrPort] using a configured network.
//
// Expects either a valid [netip.AddrPort] or an error. Returns a [Result] containing
// either a valid [net.Conn] or an error, never both. The code panics if the
// input/output expectations are violated.
//
// All fields are safe to modify after construction but before first use.
type ConnectFunc struct {
	// Dialer is the [Dialer] to use.
	//
	// Set by [NewConnectFunc] using [NewDefaultDialer].
	Dialer Dialer

	// ErrClassifier classifies errors for structured logging.
	//
	// Set by [NewConnectFunc] from [Config.ErrClassifier].
	ErrClassifier ErrClassifier

	// Logger is the [SLogger] to use (configurable for testing or custom logging).
	//
	// Set by [NewConnectFunc] to the user-provided logger.
	Logger SLogger

	// Network is the network to use (either "tcp" or "udp").
	//
	// Set by [NewConnectFunc] to the user-provided value.
	Network string

	// TimeNow is the function to get the current time (configurable for testing).
	//
	// Set by [NewConnectFunc] from [Config.TimeNow].
	TimeNow func() time.Time
}

var _ Func[netip.AddrPort, net.Conn] = &ConnectFunc{}

// Call invokes the [*ConnectFunc] to connect to the given [netip.AddrPort].
func (op *ConnectFunc) Call(ctx context.Context, address Result[netip.AddrPort]) Result[net.Conn] {
	// Enforce the input invariant.
	runtimex.Assert((address.Value.IsValid() && address.Err == nil) || (!address.Value.IsValid() && address.Err != nil))

	// Log before dialing the connection.
	t0 := op.TimeNow()
	deadline, _ := ctx.Deadline()
	var addrStr string
	if address.Err == nil {
		addrStr = address.Value.String()
	}
	logEnabled := op.Logger.Enabled(ctx, slog.LevelInfo)
	if logEnabled {
		op.Logger.Info(
			"connectStart",
			slog.Time("deadline", deadline),
			slog.String("protocol", op.Network),
			slog.String("remoteAddr", addrStr),
			slog.Time("t", t0),
		)
	}

	// Attempt to dial the connection if possible.
	var (
		conn net.Conn
		err  error
	)
	if address.Err == nil {
		conn, err = op.Dialer.DialContext(ctx, op.Network, addrStr)
	} else {
		err = NewErrSkip(address.Err)
	}

	// Enforce the output invariant.
	runtimex.Assert((conn != nil && err == nil) || (conn == nil && err != nil))

	// Log after the dial attempt.
	if logEnabled {
		op.Logger.Info(
			"connectDone",
			slog.Time("deadline", deadline),
			slog.Any("err", err),
			slog.String("errClass", op.ErrClassifier.Classify(err)),
			slog.String("localAddr", safeconn.LocalAddr(conn)),
			slog.String("protocol", op.Network),
			slog.String("remoteAddr", addrStr),
			slog.Time("t0", t0),
			slog.Time("t", op.TimeNow()),
		)
	}

	// Return the suitable result type.
	return Result[net.Conn]{Err: err, Value: conn}
}
