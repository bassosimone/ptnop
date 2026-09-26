//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/rbmk-project/rbmk/blob/v0.17.0/pkg/x/netcore/tlsdialer.go
// Adapted from: https://github.com/ooni/probe-cli/blob/v3.20.1/internal/measurexlite/tls.go
// Adapted from: https://github.com/bassosimone/nop/blob/89b21810488/tls.go
//

package ptnop

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"

	"github.com/bassosimone/runtimex"
	"github.com/bassosimone/safeconn"
)

// TLSConn abstracts over [*tls.Conn] for testing.
type TLSConn interface {
	ConnectionState() tls.ConnectionState
	HandshakeContext(ctx context.Context) error
	net.Conn
}

// TLSEngine allows mocking the [crypto/tls] library for testing.
type TLSEngine interface {
	Client(conn net.Conn, config *tls.Config) TLSConn
	Name() string
	Parrot() string
}

// DefaultTLSEngine returns the default [TLSEngine] using [crypto/tls].
func DefaultTLSEngine() TLSEngine {
	return &cryptoTLSEngine{}
}

type cryptoTLSEngine struct{}

var _ TLSEngine = &cryptoTLSEngine{}

func (*cryptoTLSEngine) Client(conn net.Conn, config *tls.Config) TLSConn {
	return tls.Client(conn, config)
}

func (*cryptoTLSEngine) Name() string {
	return "stdlib"
}

func (*cryptoTLSEngine) Parrot() string {
	return ""
}

// TLSHandshakeFunc is the [Func] that performs TLS handshakes.
//
// Use [NewTLSHandshakeFunc] to create a new instance.
type TLSHandshakeFunc struct {
	Config        *tls.Config
	Engine        TLSEngine
	ErrClassifier ErrClassifier
	SLogger       SLogger
	TimeNow       TimeNowProvider
}

// Reify the default [TLSEngine] to use `assert.Same` in testing.
var defaultTLSEngine = DefaultTLSEngine()

// NewTLSHandshakeFunc creates a [*TLSHandshakeFunc] using the [*Config] and `tlsConfig`
// to properly initialize all the [*TLSHandshakeFunc] fields. We also initialize the
// `Engine` field using the [DefaultTLSEngine].
func NewTLSHandshakeFunc(cfg *Config, tlsConfig *tls.Config) *TLSHandshakeFunc {
	return &TLSHandshakeFunc{
		Config:        tlsConfig,
		Engine:        defaultTLSEngine,
		ErrClassifier: cfg.ErrClassifier,
		SLogger:       cfg.SLogger,
		TimeNow:       cfg.TimeNow,
	}
}

var _ Func[Result[net.Conn], Result[net.Conn]] = &TLSHandshakeFunc{}

// Call performs a TLS handshake and, on success, transfers the TLS conn ownership to the next stage.
//
// The return value is type-erased to [net.Conn] to simplify creating pipelines. The type of conn
// returned on success is [*tls.Conn]. Subsequent stages should not depend on the exact type; rather
// use type assertions (e.g., on `ConnectionState`) to manipulate the returned conn.
func (op *TLSHandshakeFunc) Call(ctx context.Context, input Result[net.Conn]) Result[net.Conn] {
	// 1. unpack the input and verify invariant
	conn, err := input.V, input.Err
	runtimex.Assert((conn != nil && err == nil) || (conn == nil && err != nil))

	// 2. clone and patch the TLS config
	config := op.Config.Clone()
	config.Time = op.TimeNow.Get

	// 3. log before performing the operation
	t0 := op.TimeNow.Get()
	deadline, _ := ctx.Deadline()
	op.SLogger.Info(
		"tlsHandshakeStart",
		slog.Time("deadline", deadline),
		slog.String("localAddr", safeconn.LocalAddr(conn)),   // nil safe
		slog.String("protocol", safeconn.Network(conn)),      // nil safe
		slog.String("remoteAddr", safeconn.RemoteAddr(conn)), // nil safe
		slog.Time("t", t0),
		slog.String("tlsEngineName", op.Engine.Name()),
		slog.String("tlsParrot", op.Engine.Parrot()),
		slog.Any("tlsOfferedProtocols", config.NextProtos),
		slog.String("tlsServerName", config.ServerName),
		slog.Bool("tlsSkipVerify", config.InsecureSkipVerify),
	)

	// 4. execute the operation
	var (
		state   tls.ConnectionState
		tlsConn TLSConn
	)
	if err == nil {
		tlsConn = op.Engine.Client(conn, config)
		err = tlsConn.HandshakeContext(ctx)
		state = tlsConn.ConnectionState()
		if err != nil {
			conn.Close()  // we don't return it so close it
			tlsConn = nil // respect output invariant
		}
	} else {
		err = ErrSkip{err}
	}

	// 5. verify output invariant
	runtimex.Assert((tlsConn != nil && err == nil) || (tlsConn == nil && err != nil))

	// 6. log after the operation and return
	op.SLogger.Info(
		"tlsHandshakeDone",
		slog.Time("deadline", deadline),
		slog.Any("err", err),
		slog.String("errClass", op.ErrClassifier.Classify(err)),
		slog.String("localAddr", safeconn.LocalAddr(conn)),   // nil safe
		slog.String("protocol", safeconn.Network(conn)),      // nil safe
		slog.String("remoteAddr", safeconn.RemoteAddr(conn)), // nil safe
		slog.Time("t", op.TimeNow.Get()),
		slog.Time("t0", t0),
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
	return Result[net.Conn]{V: tlsConn, Err: err}
}

func (op *TLSHandshakeFunc) peerCerts(state tls.ConnectionState, err error) (out [][]byte) {
	out = [][]byte{}

	// 1. Check whether the error is a known certificate error and extract
	// the certificate using `errors.As` for additional robustness.
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
