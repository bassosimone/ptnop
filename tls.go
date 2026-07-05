//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/rbmk-project/rbmk/blob/v0.17.0/pkg/x/netcore/tlsdialer.go
// Adapted from: https://github.com/ooni/probe-cli/blob/v3.20.1/internal/measurexlite/tls.go
// Adapted from: https://github.com/bassosimone/nop/blob/ae41909903156c3fc9c0d80a56ce884c1ca4eb4a/tls.go
//

package ptnop

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/bassosimone/runtimex"
	"github.com/bassosimone/safeconn"
)

// TLSEngine is the engine to create a new [TLSConn].
type TLSEngine interface {
	// Client builds a new client [TLSConn] which must not be nil.
	Client(conn net.Conn, config *tls.Config) TLSConn

	// Name returns the engine name.
	Name() string

	// Parrot returns the configured parrot or an empty string.
	Parrot() string
}

// TLSEngineStdlib implements [TLSEngine] for the standard library.
//
// The zero value is ready to use.
type TLSEngineStdlib struct{}

var _ TLSEngine = TLSEngineStdlib{}

// Client implements [TLSEngine].
//
// This function uses [tls.Client] to build a new [*tls.Conn].
func (TLSEngineStdlib) Client(conn net.Conn, config *tls.Config) TLSConn {
	return tls.Client(conn, config)
}

// Name implements [TLSEngine].
//
// This function returns "stdlib".
func (TLSEngineStdlib) Name() string {
	return "stdlib"
}

// Parrot implements [TLSEngine].
//
// This function returns "".
func (s TLSEngineStdlib) Parrot() string {
	return ""
}

// TLSConn abstracts over [*tls.Conn].
//
// By using an abstraction we allow for alternative TLS implementations.
type TLSConn interface {
	// ConnectionState returns the connection state.
	ConnectionState() tls.ConnectionState

	// HandshakeContext performs the handshake unless interrupted by the context.
	HandshakeContext(ctx context.Context) error

	// Embedding Conn means we can use this type as a [net.Conn].
	net.Conn
}

// NewTLSHandshakeFunc returns a new [*TLSHandshakeFunc] using the given [*tls.Config].
//
// The cfg argument contains the common configuration for nop operations.
//
// The tlsConfig argument is the TLS configuration to use.
//
// The logger argument is the [SLogger] to use for structured logging.
func NewTLSHandshakeFunc(cfg *Config, tlsConfig *tls.Config, logger SLogger) *TLSHandshakeFunc {
	runtimex.Assert(tlsConfig != nil)
	return &TLSHandshakeFunc{
		Config:        tlsConfig,
		Engine:        TLSEngineStdlib{},
		ErrClassifier: cfg.ErrClassifier,
		Logger:        logger,
		TimeNow:       cfg.TimeNow,
	}
}

// TLSHandshakeFunc performs a TLS handshake over an existing [net.Conn].
//
// The input is [Result] wrapping a [net.Conn] or an error. The input is
// expected to be either-or: when it carries an error, [TLSHandshakeFunc.Call]
// ignores the value without closing it, per the [Func] resource cleanup
// contract. The code panics if the either-or input/output invariants are violated.
//
// The [*tls.Config] is configured using [NewTLSHandshakeFunc].
//
// Returns a [Result] containing either a valid [TLSConn] or an error, never both.
//
// All fields are safe to modify after construction but before first use.
type TLSHandshakeFunc struct {
	// Config contains the [*tls.Config] configuration to use.
	//
	// Set by [NewTLSHandshakeFunc] to the user-provided [*tls.Config] pointer.
	Config *tls.Config

	// Engine is the [TLSEngine] to use to handshake.
	//
	// Set by [NewTLSHandshakeFunc] to [TLSEngineStdlib].
	Engine TLSEngine

	// ErrClassifier classifies errors for structured logging.
	//
	// Set by [NewTLSHandshakeFunc] from [Config.ErrClassifier].
	ErrClassifier ErrClassifier

	// Logger is the [SLogger] to use (configurable for testing or custom logging).
	//
	// Set by [NewTLSHandshakeFunc] to the user-provided logger.
	Logger SLogger

	// TimeNow is the function to get the current time (configurable for testing).
	//
	// Set by [NewTLSHandshakeFunc] from [Config.TimeNow].
	TimeNow func() time.Time
}

var _ Func[net.Conn, TLSConn] = &TLSHandshakeFunc{}

// Call invokes the [*TLSHandshakeFunc] to create a [TLSConn] from a [net.Conn].
func (op *TLSHandshakeFunc) Call(ctx context.Context, conn Result[net.Conn]) Result[TLSConn] {
	// Enforce the input invariant.
	runtimex.Assert((conn.Value != nil && conn.Err == nil) || (conn.Value == nil && conn.Err != nil))

	// Log before initiating the handshake.
	config := op.tlsConfig()
	t0 := op.TimeNow()
	deadline, _ := ctx.Deadline()
	logEnabled := op.Logger.Enabled(ctx, slog.LevelInfo)
	if logEnabled {
		op.Logger.Info(
			"tlsHandshakeStart",
			slog.Time("deadline", deadline),
			slog.String("localAddr", safeconn.LocalAddr(conn.Value)),   // nil safe
			slog.String("protocol", safeconn.Network(conn.Value)),      // nil safe
			slog.String("remoteAddr", safeconn.RemoteAddr(conn.Value)), // nil safe
			slog.Time("t", t0),
			slog.String("tlsEngineName", op.Engine.Name()),
			slog.String("tlsParrot", op.Engine.Parrot()),
			slog.Any("tlsOfferedProtocols", config.NextProtos),
			slog.String("tlsServerName", config.ServerName),
			slog.Bool("tlsSkipVerify", config.InsecureSkipVerify),
		)
	}

	// Do the TLS handshake.
	var (
		err   error
		state tls.ConnectionState
		t     time.Time
		tconn TLSConn
	)
	if conn.Err == nil {
		tconn = op.Engine.Client(conn.Value, config)
		runtimex.Assert(tconn != nil)
		err = tconn.HandshakeContext(ctx)
		t = op.TimeNow()
		state = tconn.ConnectionState()
		if err != nil {
			tconn.Close()
			tconn = nil
		}
	} else {
		err = NewErrSkip(conn.Err)
		t = op.TimeNow()
	}

	// Enforce the output invariant.
	runtimex.Assert((tconn != nil && err == nil) || (tconn == nil && err != nil))

	// Log after the handshake.
	if logEnabled {
		op.Logger.Info(
			"tlsHandshakeDone",
			slog.Time("deadline", deadline),
			slog.Any("err", err),
			slog.String("errClass", op.ErrClassifier.Classify(err)),
			slog.String("localAddr", safeconn.LocalAddr(conn.Value)),   // nil safe
			slog.String("protocol", safeconn.Network(conn.Value)),      // nil safe
			slog.String("remoteAddr", safeconn.RemoteAddr(conn.Value)), // nil safe
			slog.Time("t0", t0),
			slog.Time("t", t),
			slog.String("tlsCipherSuite", tls.CipherSuiteName(state.CipherSuite)),
			slog.String("tlsEngineName", op.Engine.Name()),
			slog.String("tlsParrot", op.Engine.Parrot()),
			slog.String("tlsNegotiatedProtocol", state.NegotiatedProtocol),
			slog.Any("tlsOfferedProtocols", config.NextProtos),
			slog.Any("tlsPeerCerts", op.peerCerts(state, err)),
			slog.String("tlsServerName", config.ServerName),
			slog.Bool("tlsSkipVerify", config.InsecureSkipVerify),
			slog.String("tlsVersion", tls.VersionName(state.Version)),
		)
	}

	// Return the suitable result type.
	return Result[TLSConn]{Err: err, Value: tconn}
}

func (op *TLSHandshakeFunc) tlsConfig() *tls.Config {
	runtimex.Assert(op.Config != nil)
	config := op.Config.Clone()
	config.Time = op.TimeNow
	return config
}

func (op *TLSHandshakeFunc) peerCerts(state tls.ConnectionState, err error) (out [][]byte) {
	out = [][]byte{}

	// 1. Check whether the error is a known certificate error and extract
	// the certificate using `errors.AsType` for additional robustness.
	if x509HostnameError, ok := errors.AsType[x509.HostnameError](err); ok {
		// Test case: https://wrong.host.badssl.com/
		out = append(out, x509HostnameError.Certificate.Raw)
		return
	}

	if x509UnknownAuthorityError, ok := errors.AsType[x509.UnknownAuthorityError](err); ok {
		// Test case: https://self-signed.badssl.com/. This error has
		// never been among the ones returned by MK.
		out = append(out, x509UnknownAuthorityError.Cert.Raw)
		return
	}

	if x509CertificateInvalidError, ok := errors.AsType[x509.CertificateInvalidError](err); ok {
		// Test case: https://expired.badssl.com/
		out = append(out, x509CertificateInvalidError.Cert.Raw)
		return
	}

	// 2. Otherwise extract certificates from the connection state.
	for _, cert := range state.PeerCertificates {
		out = append(out, cert.Raw)
	}
	return
}
