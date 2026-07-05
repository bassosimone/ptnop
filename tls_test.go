//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/bassosimone/nop/blob/ae41909903156c3fc9c0d80a56ce884c1ca4eb4a/tls_test.go
//

package ptnop

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/bassosimone/netstub"
	"github.com/bassosimone/tlsstub"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMockTLSEngine returns a [*tlsstub.FuncTLSEngine] that wraps the given
// [TLSConn]. The engine's ClientFunc returns the conn, NameFunc returns
// "mock", and ParrotFunc returns "".
func newMockTLSEngine(conn TLSConn) *tlsstub.FuncTLSEngine[TLSConn] {
	return &tlsstub.FuncTLSEngine[TLSConn]{
		ClientFunc: func(c net.Conn, config *tls.Config) TLSConn {
			return conn
		},
		NameFunc: func() string {
			return "mock"
		},
		ParrotFunc: func() string {
			return ""
		},
	}
}

// TLSEngineStdlib returns "stdlib" as Name, "" as Parrot, and a *tls.Conn from Client.
func TestTLSEngineStdlib(t *testing.T) {
	engine := TLSEngineStdlib{}

	t.Run("Name", func(t *testing.T) {
		assert.Equal(t, "stdlib", engine.Name())
	})

	t.Run("Parrot", func(t *testing.T) {
		assert.Equal(t, "", engine.Parrot())
	})

	t.Run("Client", func(t *testing.T) {
		mockConn := &netstub.FuncConn{
			// Don't initialize what we don't use
		}

		tlsConn := engine.Client(mockConn, &tls.Config{})

		require.NotNil(t, tlsConn)
		// Verify it returns a *tls.Conn
		_, ok := tlsConn.(*tls.Conn)
		assert.True(t, ok)
	})
}

// NewTLSHandshakeFunc populates all fields from Config and the provided logger.
func TestNewTLSHandshakeFunc(t *testing.T) {
	cfg := NewConfig()
	tlsConfig := &tls.Config{ServerName: "example.com"}
	logger := DefaultSLogger()

	fn := NewTLSHandshakeFunc(cfg, tlsConfig, logger)

	require.NotNil(t, fn)
	assert.Equal(t, tlsConfig, fn.Config)
	assert.NotNil(t, fn.Engine)
	assert.NotNil(t, fn.Logger)
	assert.NotNil(t, fn.TimeNow)
	assert.NotNil(t, fn.ErrClassifier)
}

// Call returns the TLSConn on previous connect error.
func TestTLSHandshakeFuncPreviousError(t *testing.T) {
	cfg := NewConfig()
	tlsConfig := &tls.Config{ServerName: "example.com"}

	wantState := tls.ConnectionState{}

	mockTLSConn := &tlsstub.FuncTLSConn{
		FuncConn: newMinimalConn(),
		ConnectionStateFunc: func() tls.ConnectionState {
			return wantState
		},
		HandshakeContextFunc: func(ctx context.Context) error {
			return nil
		},
	}

	fn := NewTLSHandshakeFunc(cfg, tlsConfig, DefaultSLogger())
	fn.Engine = newMockTLSEngine(mockTLSConn)

	errMocked := errors.New("mocked error")
	mconn := Result[net.Conn]{Err: errMocked}
	result, err := fn.Call(context.Background(), mconn).Unpack()

	require.Error(t, err)
	assert.True(t, errors.Is(err, errMocked))
	underlying, ok := errors.AsType[ErrSkip](err)
	assert.True(t, ok)
	assert.Equal(t, errMocked, underlying.Err)
	require.Nil(t, result)
}

// Call returns the TLSConn on successful handshake.
func TestTLSHandshakeFuncSuccess(t *testing.T) {
	cfg := NewConfig()
	tlsConfig := &tls.Config{ServerName: "example.com"}

	wantState := tls.ConnectionState{
		Version:            tls.VersionTLS13,
		CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
		NegotiatedProtocol: "h2",
	}

	mockTLSConn := &tlsstub.FuncTLSConn{
		FuncConn: newMinimalConn(),
		ConnectionStateFunc: func() tls.ConnectionState {
			return wantState
		},
		HandshakeContextFunc: func(ctx context.Context) error {
			return nil
		},
	}

	fn := NewTLSHandshakeFunc(cfg, tlsConfig, DefaultSLogger())
	fn.Engine = newMockTLSEngine(mockTLSConn)

	mconn := Result[net.Conn]{Value: newMinimalConn()}
	result, err := fn.Call(context.Background(), mconn).Unpack()

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, wantState, result.ConnectionState())
}

// Call closes the TLS connection and returns nil on handshake failure.
func TestTLSHandshakeFuncError(t *testing.T) {
	cfg := NewConfig()
	tlsConfig := &tls.Config{ServerName: "example.com"}
	wantErr := errors.New("handshake failed")

	closeCalled := false
	mockTLSConn := &tlsstub.FuncTLSConn{
		FuncConn: newMinimalConn(),
		ConnectionStateFunc: func() tls.ConnectionState {
			return tls.ConnectionState{}
		},
		HandshakeContextFunc: func(ctx context.Context) error {
			return wantErr
		},
	}
	mockTLSConn.FuncConn.CloseFunc = func() error {
		closeCalled = true
		return nil
	}

	fn := NewTLSHandshakeFunc(cfg, tlsConfig, DefaultSLogger())
	fn.Engine = newMockTLSEngine(mockTLSConn)

	mconn := Result[net.Conn]{Value: newMinimalConn()}
	result, err := fn.Call(context.Background(), mconn).Unpack()

	require.ErrorIs(t, err, wantErr)
	assert.Nil(t, result)
	assert.True(t, closeCalled, "connection should be closed on error")
}

// Call propagates the caller's context deadline to HandshakeContext.
func TestTLSHandshakeFuncCallerTimeout(t *testing.T) {
	cfg := NewConfig()
	tlsConfig := &tls.Config{ServerName: "example.com"}

	// Caller-provided timeout
	callerTimeout := 5 * time.Second

	mockTLSConn := &tlsstub.FuncTLSConn{
		FuncConn: newMinimalConn(),
		ConnectionStateFunc: func() tls.ConnectionState {
			return tls.ConnectionState{}
		},
		HandshakeContextFunc: func(ctx context.Context) error {
			// Verify context has the caller-provided deadline
			deadline, ok := ctx.Deadline()
			assert.True(t, ok, "context should have deadline from caller")
			assert.True(t, time.Until(deadline) <= callerTimeout)
			return nil
		},
	}

	fn := NewTLSHandshakeFunc(cfg, tlsConfig, DefaultSLogger())
	fn.Engine = newMockTLSEngine(mockTLSConn)

	// Caller provides timeout via context
	ctx, cancel := context.WithTimeout(context.Background(), callerTimeout)
	defer cancel()

	mconn := Result[net.Conn]{Value: newMinimalConn()}
	_, err := fn.Call(ctx, mconn).Unpack()
	require.NoError(t, err)
}

// Call emits tlsHandshakeStart/tlsHandshakeDone log events.
func TestTLSHandshakeFuncLogging(t *testing.T) {
	cfg := NewConfig()
	tlsConfig := &tls.Config{ServerName: "example.com"}
	logger, records := newCapturingLogger()

	mockTLSConn := &tlsstub.FuncTLSConn{
		FuncConn: newMinimalConn(),
		ConnectionStateFunc: func() tls.ConnectionState {
			return tls.ConnectionState{}
		},
		HandshakeContextFunc: func(ctx context.Context) error {
			return nil
		},
	}

	fn := NewTLSHandshakeFunc(cfg, tlsConfig, logger)
	fn.Engine = newMockTLSEngine(mockTLSConn)

	mconn := Result[net.Conn]{Value: newMinimalConn()}
	_, _ = fn.Call(context.Background(), mconn).Unpack()

	require.Len(t, *records, 2)
	assert.Equal(t, "tlsHandshakeStart", (*records)[0].Message)
	assert.Equal(t, "tlsHandshakeDone", (*records)[1].Message)
}

// Call logs the peer certificate extracted from x509.HostnameError.
func TestTLSHandshakeFuncPeerCertsFromHostnameError(t *testing.T) {
	cfg := NewConfig()
	tlsConfig := &tls.Config{ServerName: "example.com"}

	// Create a certificate for testing
	cert := &x509.Certificate{
		Raw: []byte("test cert data"),
	}

	hostnameErr := x509.HostnameError{
		Certificate: cert,
		Host:        "wrong.host.com",
	}

	mockTLSConn := &tlsstub.FuncTLSConn{
		FuncConn: newMinimalConn(),
		ConnectionStateFunc: func() tls.ConnectionState {
			return tls.ConnectionState{}
		},
		HandshakeContextFunc: func(ctx context.Context) error {
			return hostnameErr
		},
	}
	mockTLSConn.FuncConn.CloseFunc = func() error { return nil }

	logger, records := newCapturingLogger()

	fn := NewTLSHandshakeFunc(cfg, tlsConfig, logger)
	fn.Engine = newMockTLSEngine(mockTLSConn)

	mconn := Result[net.Conn]{Value: newMinimalConn()}
	_, err := fn.Call(context.Background(), mconn).Unpack()

	// Verify error type
	var hostErr x509.HostnameError
	require.True(t, errors.As(err, &hostErr))

	// Verify certificate was logged
	require.Len(t, *records, 2)
	assert.Equal(t, "tlsHandshakeStart", (*records)[0].Message)
	assert.Equal(t, "tlsHandshakeDone", (*records)[1].Message)

	// Find tlsPeerCerts in the Done record
	var foundCerts [][]byte
	(*records)[1].Attrs(func(attr slog.Attr) bool {
		if attr.Key == "tlsPeerCerts" {
			foundCerts = attr.Value.Any().([][]byte)
			return false
		}
		return true
	})
	require.Len(t, foundCerts, 1)
	assert.Equal(t, cert.Raw, foundCerts[0])
}

// Call logs the peer certificate extracted from x509.UnknownAuthorityError.
func TestTLSHandshakeFuncPeerCertsFromUnknownAuthorityError(t *testing.T) {
	cfg := NewConfig()
	tlsConfig := &tls.Config{ServerName: "example.com"}

	cert := &x509.Certificate{
		Raw: []byte("self-signed cert"),
	}

	unknownAuthErr := x509.UnknownAuthorityError{
		Cert: cert,
	}

	mockTLSConn := &tlsstub.FuncTLSConn{
		FuncConn: newMinimalConn(),
		ConnectionStateFunc: func() tls.ConnectionState {
			return tls.ConnectionState{}
		},
		HandshakeContextFunc: func(ctx context.Context) error {
			return unknownAuthErr
		},
	}
	mockTLSConn.FuncConn.CloseFunc = func() error { return nil }

	logger, records := newCapturingLogger()

	fn := NewTLSHandshakeFunc(cfg, tlsConfig, logger)
	fn.Engine = newMockTLSEngine(mockTLSConn)

	mconn := Result[net.Conn]{Value: newMinimalConn()}
	_, err := fn.Call(context.Background(), mconn).Unpack()

	// Verify error type
	var uaErr x509.UnknownAuthorityError
	require.True(t, errors.As(err, &uaErr))

	// Verify certificate was logged
	require.Len(t, *records, 2)
	assert.Equal(t, "tlsHandshakeStart", (*records)[0].Message)
	assert.Equal(t, "tlsHandshakeDone", (*records)[1].Message)

	// Find tlsPeerCerts in the Done record
	var foundCerts [][]byte
	(*records)[1].Attrs(func(attr slog.Attr) bool {
		if attr.Key == "tlsPeerCerts" {
			foundCerts = attr.Value.Any().([][]byte)
			return false
		}
		return true
	})
	require.Len(t, foundCerts, 1)
	assert.Equal(t, cert.Raw, foundCerts[0])
}

// Call logs the peer certificate extracted from x509.CertificateInvalidError.
func TestTLSHandshakeFuncPeerCertsFromCertificateInvalidError(t *testing.T) {
	cfg := NewConfig()
	tlsConfig := &tls.Config{ServerName: "example.com"}

	cert := &x509.Certificate{
		Raw: []byte("expired cert"),
	}

	invalidErr := x509.CertificateInvalidError{
		Cert:   cert,
		Reason: x509.Expired,
	}

	mockTLSConn := &tlsstub.FuncTLSConn{
		FuncConn: newMinimalConn(),
		ConnectionStateFunc: func() tls.ConnectionState {
			return tls.ConnectionState{}
		},
		HandshakeContextFunc: func(ctx context.Context) error {
			return invalidErr
		},
	}
	mockTLSConn.FuncConn.CloseFunc = func() error { return nil }

	logger, records := newCapturingLogger()

	fn := NewTLSHandshakeFunc(cfg, tlsConfig, logger)
	fn.Engine = newMockTLSEngine(mockTLSConn)

	mconn := Result[net.Conn]{Value: newMinimalConn()}
	_, err := fn.Call(context.Background(), mconn).Unpack()

	// Verify error type
	var ciErr x509.CertificateInvalidError
	require.True(t, errors.As(err, &ciErr))

	// Verify certificate was logged
	require.Len(t, *records, 2)
	assert.Equal(t, "tlsHandshakeStart", (*records)[0].Message)
	assert.Equal(t, "tlsHandshakeDone", (*records)[1].Message)

	// Find tlsPeerCerts in the Done record
	var foundCerts [][]byte
	(*records)[1].Attrs(func(attr slog.Attr) bool {
		if attr.Key == "tlsPeerCerts" {
			foundCerts = attr.Value.Any().([][]byte)
			return false
		}
		return true
	})
	require.Len(t, foundCerts, 1)
	assert.Equal(t, cert.Raw, foundCerts[0])
}

// Call logs the peer certificate chain from ConnectionState on success.
func TestTLSHandshakeFuncPeerCertsFromConnectionState(t *testing.T) {
	cfg := NewConfig()
	tlsConfig := &tls.Config{ServerName: "example.com"}

	// When there's no error, certs come from connection state
	peerCerts := []*x509.Certificate{
		{Raw: []byte("cert1")},
		{Raw: []byte("cert2")},
	}

	mockTLSConn := &tlsstub.FuncTLSConn{
		FuncConn: newMinimalConn(),
		ConnectionStateFunc: func() tls.ConnectionState {
			return tls.ConnectionState{
				PeerCertificates: peerCerts,
			}
		},
		HandshakeContextFunc: func(ctx context.Context) error {
			return nil
		},
	}

	logger, records := newCapturingLogger()

	fn := NewTLSHandshakeFunc(cfg, tlsConfig, logger)
	fn.Engine = newMockTLSEngine(mockTLSConn)

	mconn := Result[net.Conn]{Value: newMinimalConn()}
	result, err := fn.Call(context.Background(), mconn).Unpack()

	require.NoError(t, err)
	require.NotNil(t, result)
	state := result.ConnectionState()
	assert.Len(t, state.PeerCertificates, 2)

	// Verify certificates were logged
	require.Len(t, *records, 2)
	assert.Equal(t, "tlsHandshakeStart", (*records)[0].Message)
	assert.Equal(t, "tlsHandshakeDone", (*records)[1].Message)

	// Find tlsPeerCerts in the Done record
	var foundCerts [][]byte
	(*records)[1].Attrs(func(attr slog.Attr) bool {
		if attr.Key == "tlsPeerCerts" {
			foundCerts = attr.Value.Any().([][]byte)
			return false
		}
		return true
	})
	require.Len(t, foundCerts, 2)
	assert.Equal(t, []byte("cert1"), foundCerts[0])
	assert.Equal(t, []byte("cert2"), foundCerts[1])
}

// Call sets the time function on the cloned *tls.Config.
func TestTLSHandshakeFuncSetsTimeOnConfig(t *testing.T) {
	cfg := NewConfig()
	fixedTime := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	cfg.TimeNow = func() time.Time {
		return fixedTime
	}

	tlsConfig := &tls.Config{ServerName: "example.com"}

	var capturedConfig *tls.Config
	mockTLSConn := &tlsstub.FuncTLSConn{
		FuncConn: newMinimalConn(),
		ConnectionStateFunc: func() tls.ConnectionState {
			return tls.ConnectionState{}
		},
		HandshakeContextFunc: func(ctx context.Context) error {
			return nil
		},
	}

	mockEngine := &tlsstub.FuncTLSEngine[TLSConn]{
		ClientFunc: func(conn net.Conn, config *tls.Config) TLSConn {
			capturedConfig = config
			return mockTLSConn
		},
		NameFunc: func() string {
			return "mock"
		},
		ParrotFunc: func() string {
			return ""
		},
	}

	fn := NewTLSHandshakeFunc(cfg, tlsConfig, DefaultSLogger())
	fn.Engine = mockEngine

	mconn := Result[net.Conn]{Value: newMinimalConn()}
	_, _ = fn.Call(context.Background(), mconn).Unpack()

	require.NotNil(t, capturedConfig)
	require.NotNil(t, capturedConfig.Time)
	assert.Equal(t, fixedTime, capturedConfig.Time())
}
