//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/bassosimone/nop/blob/89b21810488/cancelwatch.go
//

package ptnop

import (
	"context"
	"net"
)

// CancelWatchFunc is the [Func] that closes a [net.Conn] when the context is canceled.
//
// Use [NewCancelWatchFunc] to construct.
type CancelWatchFunc struct{}

// NewCancelWatchFunc creates a new [*CancelWatchFunc].
func NewCancelWatchFunc() *CancelWatchFunc {
	return &CancelWatchFunc{}
}

var _ Func[Result[net.Conn], Result[net.Conn]] = &CancelWatchFunc{}

// Call wraps `conn` so that it is closed when the context is done. Closing
// the returned conn unregisters the watcher.
func (op *CancelWatchFunc) Call(ctx context.Context, conn Result[net.Conn]) Result[net.Conn] {
	if conn.Err == nil {
		stop := context.AfterFunc(ctx, func() {
			conn.V.Close()
		})
		conn.V = &cancelWatchedConn{Conn: conn.V, stop: stop}
	}
	return conn
}

type cancelWatchedConn struct {
	net.Conn
	stop func() bool
}

func (c *cancelWatchedConn) Close() error {
	c.stop()
	return c.Conn.Close()
}
