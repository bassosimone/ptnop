//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/ooni/probe-cli/blob/v3.20.1/internal/measurexlite/conn.go
// Adapted from: https://github.com/rbmk-project/rbmk/blob/v0.17.0/pkg/x/netcore/conn.go
// Adapted from: https://github.com/bassosimone/nop/blob/89b21810488/observeconn.go
//

package ptnop

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/bassosimone/safeconn"
)

// ObserveConnFunc is the [Func] that observes I/O operations as a side effect.
//
// Use [NewObserveConnFunc] to create a new instance.
type ObserveConnFunc struct {
	ErrClassifier ErrClassifier
	SLogger       SLogger
	TimeNow       TimeNowProvider
}

// NewObserveConnFunc creates an [*ObserveConnFunc] using the [*Config]
// to properly initialize all the [*ObserveConnFunc] fields.
func NewObserveConnFunc(cfg *Config) *ObserveConnFunc {
	return &ObserveConnFunc{
		ErrClassifier: cfg.ErrClassifier,
		SLogger:       cfg.SLogger,
		TimeNow:       cfg.TimeNow,
	}
}

var _ Func[Result[net.Conn], Result[net.Conn]] = &ObserveConnFunc{}

// Call wraps `conn` to observe I/O operations and transfers ownership to the next stage.
func (op *ObserveConnFunc) Call(ctx context.Context, conn Result[net.Conn]) Result[net.Conn] {
	if conn.Err == nil {
		conn.V = &observedConn{
			closeonce: sync.Once{},
			conn:      conn.V,
			laddr:     safeconn.LocalAddr(conn.V),
			op:        op,
			protocol:  safeconn.Network(conn.V),
			raddr:     safeconn.RemoteAddr(conn.V),
		}
	}
	return conn
}

type observedConn struct {
	closeonce sync.Once
	conn      net.Conn
	laddr     string
	op        *ObserveConnFunc
	protocol  string
	raddr     string
}

func (c *observedConn) Close() (err error) {
	err = net.ErrClosed

	c.closeonce.Do(func() {
		// 1. log before the operation
		t0 := c.op.TimeNow.Get()
		c.op.SLogger.Info(
			"closeStart",
			slog.String("localAddr", c.laddr),
			slog.String("protocol", c.protocol),
			slog.String("remoteAddr", c.raddr),
			slog.Time("t", t0),
		)

		// 2. execute the operation
		err = c.conn.Close()

		// 3. log after the operation
		c.op.SLogger.Info(
			"closeDone",
			slog.Any("err", err),
			slog.String("errClass", c.op.ErrClassifier.Classify(err)),
			slog.String("localAddr", c.laddr),
			slog.String("protocol", c.protocol),
			slog.String("remoteAddr", c.raddr),
			slog.Time("t", c.op.TimeNow.Get()),
			slog.Time("t0", t0),
		)
	})

	return
}

func (c *observedConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *observedConn) Read(buf []byte) (int, error) {
	// 1. log before the operation
	t0 := c.op.TimeNow.Get()
	c.op.SLogger.Debug(
		"readStart",
		slog.Int("ioBufferSize", len(buf)),
		slog.String("localAddr", c.laddr),
		slog.String("protocol", c.protocol),
		slog.String("remoteAddr", c.raddr),
		slog.Time("t", t0),
	)

	// 2. execute the operation
	count, err := c.conn.Read(buf)

	// 3. log after the operation
	c.op.SLogger.Debug(
		"readDone",
		slog.Int("ioBytesCount", count),
		slog.Any("err", err),
		slog.String("errClass", c.op.ErrClassifier.Classify(err)),
		slog.String("localAddr", c.laddr),
		slog.String("protocol", c.protocol),
		slog.String("remoteAddr", c.raddr),
		slog.Time("t", c.op.TimeNow.Get()),
		slog.Time("t0", t0),
	)

	return count, err
}

func (c *observedConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *observedConn) SetDeadline(t time.Time) error {
	err := c.conn.SetDeadline(t)
	c.op.SLogger.Debug(
		"setDeadline",
		slog.Time("deadline", t),
		slog.Any("err", err),
		slog.String("errClass", c.op.ErrClassifier.Classify(err)),
		slog.String("localAddr", c.laddr),
		slog.String("protocol", c.protocol),
		slog.String("remoteAddr", c.raddr),
		slog.Time("t", c.op.TimeNow.Get()),
	)
	return err
}

func (c *observedConn) SetReadDeadline(t time.Time) error {
	err := c.conn.SetReadDeadline(t)
	c.op.SLogger.Debug(
		"setReadDeadline",
		slog.Time("deadline", t),
		slog.Any("err", err),
		slog.String("errClass", c.op.ErrClassifier.Classify(err)),
		slog.String("localAddr", c.laddr),
		slog.String("protocol", c.protocol),
		slog.String("remoteAddr", c.raddr),
		slog.Time("t", c.op.TimeNow.Get()),
	)
	return err
}

func (c *observedConn) SetWriteDeadline(t time.Time) error {
	err := c.conn.SetWriteDeadline(t)
	c.op.SLogger.Debug(
		"setWriteDeadline",
		slog.Time("deadline", t),
		slog.Any("err", err),
		slog.String("errClass", c.op.ErrClassifier.Classify(err)),
		slog.String("localAddr", c.laddr),
		slog.String("protocol", c.protocol),
		slog.String("remoteAddr", c.raddr),
		slog.Time("t", c.op.TimeNow.Get()),
	)
	return err
}

func (c *observedConn) Write(data []byte) (int, error) {
	// 1. log before the operation
	t0 := c.op.TimeNow.Get()
	c.op.SLogger.Debug(
		"writeStart",
		slog.Int("ioBufferSize", len(data)),
		slog.String("localAddr", c.laddr),
		slog.String("protocol", c.protocol),
		slog.String("remoteAddr", c.raddr),
		slog.Time("t", t0),
	)

	// 2. execute the operation
	count, err := c.conn.Write(data)

	// 3. log after the operation
	c.op.SLogger.Debug(
		"writeDone",
		slog.Int("ioBytesCount", count),
		slog.Any("err", err),
		slog.String("errClass", c.op.ErrClassifier.Classify(err)),
		slog.String("localAddr", c.laddr),
		slog.String("protocol", c.protocol),
		slog.String("remoteAddr", c.raddr),
		slog.Time("t", c.op.TimeNow.Get()),
		slog.Time("t0", t0),
	)

	return count, err
}
