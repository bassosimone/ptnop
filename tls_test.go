// SPDX-License-Identifier: GPL-3.0-or-later

package ptnop

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bassosimone/netstub"
	"github.com/bassosimone/tlsstub"
	"github.com/stretchr/testify/assert"
)

// Make sure [NewTLSHandshakeFunc] initializes all [*TLSHandshakeFunc] fields.
func TestNewTLSHandshakeFunc(t *testing.T) {
	// 1. setup
	tlsConfig := &tls.Config{}
	cfg := NewConfig()

	// 2. invoke
	fx := NewTLSHandshakeFunc(cfg, tlsConfig)

	// 3. check
	assert.Same(t, tlsConfig, fx.Config)
	assert.Same(t, defaultTLSEngine, fx.Engine)
	assert.Same(t, cfg.ErrClassifier, fx.ErrClassifier)
	assert.Same(t, cfg.SLogger, fx.SLogger)
	assert.Same(t, cfg.TimeNow, fx.TimeNow)
}

// Make sure that [DefaultTLSEngine] uses the stdlib.
func TestDefaultTLSEngine(t *testing.T) {
	// 1. setup
	eng := DefaultTLSEngine()
	conn := &netstub.FuncConn{}

	// 2. invoke
	tconn := eng.Client(conn, &tls.Config{})

	// 3. check
	_, ok := tconn.(*tls.Conn)
	assert.True(t, ok)
	assert.Equal(t, "stdlib", eng.Name())
	assert.Equal(t, "", eng.Parrot())
}

// Make sure [TLSHandshakeFunc.Call] returns the correct value on previous stage failure.
func TestTLSHandshakeFunc_Call_prevStageFailure(t *testing.T) {
	// 1. setup
	logHelper := &slogValidationHelper{}
	mocked := errors.New("mocked")
	cfg := NewConfig()
	cfg.TimeNow = logHelper
	cfg.SLogger = logHelper
	tlsConfig := &tls.Config{
		ServerName: "en.wikipedia.org",
		NextProtos: []string{"h2", "http/1.1"},
	}
	deadline := cfg.TimeNow.Get().Add(10 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	input := Result[net.Conn]{Err: mocked}
	fx := NewTLSHandshakeFunc(cfg, tlsConfig)
	fx.Engine = &tlsstub.FuncTLSEngine[TLSConn]{
		ClientFunc: func(conn net.Conn, config *tls.Config) TLSConn {
			t.Fatal("the engine must not be invoked on skip")
			return nil
		},
		NameFunc: func() string {
			return "custom"
		},
		ParrotFunc: func() string {
			return ""
		},
	}

	// 2. invoke
	result := fx.Call(ctx, input)

	// 3. check
	assert.NotNil(t, result.Err)
	skipErr, ok := errors.AsType[ErrSkip](result.Err)
	assert.True(t, ok)
	assert.Equal(t, mocked, skipErr.PrevErr)
	assert.Nil(t, result.V)

	expect := []slogSimpleRecord{{
		Level: "info",
		Msg:   "tlsHandshakeStart",
		Attrs: []string{
			"deadline=2026-01-01 00:00:10 +0000 UTC",
			"localAddr=",
			"protocol=",
			"remoteAddr=",
			"t=2026-01-01 00:00:00 +0000 UTC",
			"tlsEngineName=custom",
			"tlsOfferedProtocols=[h2 http/1.1]",
			"tlsParrot=",
			"tlsServerName=en.wikipedia.org",
			"tlsSkipVerify=false",
		},
	}, {
		Level: "info",
		Msg:   "tlsHandshakeDone",
		Attrs: []string{
			"deadline=2026-01-01 00:00:10 +0000 UTC",
			"err=mocked",
			"errClass=ESKIP",
			"localAddr=",
			"protocol=",
			"remoteAddr=",
			"t=2026-01-01 00:00:00 +0000 UTC",
			"t0=2026-01-01 00:00:00 +0000 UTC",
			"tlsCipherSuite=0x0000",
			"tlsEngineName=custom",
			"tlsNegotiatedProtocol=",
			"tlsOfferedProtocols=[h2 http/1.1]",
			"tlsParrot=",
			"tlsPeerCerts=[]",
			"tlsServerName=en.wikipedia.org",
			"tlsSkipVerify=false",
			"tlsVersion=0x0000",
		},
	}}

	assert.Equal(t, expect, logHelper.Got)
}

// Make sure [TLSHandshakeFunc.Call] works as intended when given a valid conn.
func TestTLSHandshakeFunc_Call_withValidConn(t *testing.T) {
	// mockedErr is the mocked err used by this func.
	mockedErr := errors.New("mocked")

	// We need multiple cases to test for success/failure cases.
	type testcase struct {
		// name of the testcase
		name string

		// err to return from HandshakeContext
		err error

		// stateMod is optional and modifies the ConnectionState
		stateMod func(state *tls.ConnectionState)

		// expectations for the `tlsHandshakeDone` event
		expectPeer               string
		expectErr                string
		expectClass              string
		expectCipherSuite        string
		expectNegotiatedProtocol string
		expectOfferedProtocols   string
		expectVersion            string
	}

	cases := []testcase{
		{
			name: "err=nil",
			err:  nil,
			stateMod: func(state *tls.ConnectionState) {
				state.Version = tls.VersionTLS13
				state.HandshakeComplete = true
				state.CipherSuite = tls.TLS_AES_256_GCM_SHA384
				state.NegotiatedProtocol = "h2"
				state.ServerName = "en.wikipedia.org"
				state.PeerCertificates = []*x509.Certificate{{
					Raw: []byte("0xdeadbeef"),
				}}
			},
			expectPeer:               "[[48 120 100 101 97 100 98 101 101 102]]",
			expectErr:                "<nil>",
			expectClass:              "",
			expectCipherSuite:        "TLS_AES_256_GCM_SHA384",
			expectNegotiatedProtocol: "h2",
			expectOfferedProtocols:   "[h2 http/1.1]",
			expectVersion:            "TLS 1.3",
		},
		{
			name:                     "err=mocked",
			err:                      mockedErr,
			stateMod:                 nil,
			expectPeer:               "[]",
			expectErr:                "mocked",
			expectClass:              "EGENERIC",
			expectCipherSuite:        "0x0000",
			expectNegotiatedProtocol: "",
			expectOfferedProtocols:   "[h2 http/1.1]",
			expectVersion:            "0x0000",
		},
		{
			name: "err=x509.HostnameError",
			err: x509.HostnameError{
				Certificate: &x509.Certificate{
					Raw: []byte("0xdeadbeef"),
				},
				Host: "www.example.com",
			},
			stateMod:   nil,
			expectPeer: "[[48 120 100 101 97 100 98 101 101 102]]",
			expectErr: "x509: certificate is not valid for any " +
				"names, but wanted to match www.example.com",
			expectClass:              "ETLS_HOSTNAME_MISMATCH",
			expectCipherSuite:        "0x0000",
			expectNegotiatedProtocol: "",
			expectOfferedProtocols:   "[h2 http/1.1]",
			expectVersion:            "0x0000",
		},
		{
			name: "err=x509.UnknownAuthorityError",
			err: x509.UnknownAuthorityError{
				Cert: &x509.Certificate{
					Raw: []byte("0xdeadbeef"),
				},
			},
			stateMod:                 nil,
			expectPeer:               "[[48 120 100 101 97 100 98 101 101 102]]",
			expectErr:                "x509: certificate signed by unknown authority",
			expectClass:              "ETLS_CA_UNKNOWN",
			expectCipherSuite:        "0x0000",
			expectNegotiatedProtocol: "",
			expectOfferedProtocols:   "[h2 http/1.1]",
			expectVersion:            "0x0000",
		},
		{
			name: "err=x509.CertificateInvalidError",
			err: x509.CertificateInvalidError{
				Cert: &x509.Certificate{
					Raw: []byte("0xdeadbeef"),
				},
				Reason: 0,
				Detail: "",
			},
			stateMod:                 nil,
			expectPeer:               "[[48 120 100 101 97 100 98 101 101 102]]",
			expectErr:                "x509: certificate is not authorized to sign other certificates",
			expectClass:              "ETLS_CERT_INVALID",
			expectCipherSuite:        "0x0000",
			expectNegotiatedProtocol: "",
			expectOfferedProtocols:   "[h2 http/1.1]",
			expectVersion:            "0x0000",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 1. setup
			logHelper := &slogValidationHelper{}
			cfg := NewConfig()
			cfg.TimeNow = logHelper
			cfg.SLogger = logHelper
			tlsConfig := &tls.Config{
				ServerName: "en.wikipedia.org",
				NextProtos: []string{"h2", "http/1.1"},
			}
			deadline := cfg.TimeNow.Get().Add(10 * time.Second)
			ctx, cancel := context.WithDeadline(context.Background(), deadline)
			defer cancel()

			closeCalled := &atomic.Bool{}
			input := Result[net.Conn]{V: &netstub.FuncConn{
				CloseFunc: func() error {
					closeCalled.Store(true)
					return nil
				},
				LocalAddrFunc: func() net.Addr {
					if closeCalled.Load() {
						return nil
					}
					return &net.TCPAddr{
						IP:   net.IPv4(10, 0, 0, 1),
						Port: 19774,
						Zone: "",
					}
				},
				RemoteAddrFunc: func() net.Addr {
					if closeCalled.Load() {
						return nil
					}
					return &net.TCPAddr{
						IP:   net.IPv4(10, 0, 0, 2),
						Port: 443,
						Zone: "",
					}
				},
			}}

			state := tls.ConnectionState{}
			if tc.stateMod != nil {
				tc.stateMod(&state)
			}

			fx := NewTLSHandshakeFunc(cfg, tlsConfig)
			fx.Engine = &tlsstub.FuncTLSEngine[TLSConn]{
				ClientFunc: func(conn net.Conn, config *tls.Config) TLSConn {
					return &tlsstub.FuncTLSConn{
						FuncConn: conn.(*netstub.FuncConn), // we don't wrap in TLSHandshakeFunc
						ConnectionStateFunc: func() tls.ConnectionState {
							return state
						},
						HandshakeContextFunc: func(ctx context.Context) error {
							return tc.err
						},
					}
				},
				NameFunc: func() string {
					return "custom"
				},
				ParrotFunc: func() string {
					return "foo"
				},
			}

			// 2. invoke
			result := fx.Call(ctx, input)

			// 3. check
			if tc.err != nil {
				assert.NotNil(t, result.Err)
				assert.Equal(t, tc.err, result.Err)
				assert.Nil(t, result.V)
				assert.True(t, closeCalled.Load())
			} else {
				assert.Nil(t, result.Err)
				assert.NotNil(t, result.V)
				assert.False(t, closeCalled.Load())
			}

			expect := []slogSimpleRecord{{
				Level: "info",
				Msg:   "tlsHandshakeStart",
				Attrs: []string{
					"deadline=2026-01-01 00:00:10 +0000 UTC",
					"localAddr=10.0.0.1:19774",
					"protocol=tcp",
					"remoteAddr=10.0.0.2:443",
					"t=2026-01-01 00:00:00 +0000 UTC",
					"tlsEngineName=custom",
					"tlsOfferedProtocols=[h2 http/1.1]",
					"tlsParrot=foo",
					"tlsServerName=en.wikipedia.org",
					"tlsSkipVerify=false",
				},
			}, {
				Level: "info",
				Msg:   "tlsHandshakeDone",
				Attrs: []string{
					"deadline=2026-01-01 00:00:10 +0000 UTC",
					"err=" + tc.expectErr,
					"errClass=" + tc.expectClass,
					"localAddr=10.0.0.1:19774",
					"protocol=tcp",
					"remoteAddr=10.0.0.2:443",
					"t=2026-01-01 00:00:00 +0000 UTC",
					"t0=2026-01-01 00:00:00 +0000 UTC",
					"tlsCipherSuite=" + tc.expectCipherSuite,
					"tlsEngineName=custom",
					"tlsNegotiatedProtocol=" + tc.expectNegotiatedProtocol,
					"tlsOfferedProtocols=" + tc.expectOfferedProtocols,
					"tlsParrot=foo",
					"tlsPeerCerts=" + tc.expectPeer,
					"tlsServerName=en.wikipedia.org",
					"tlsSkipVerify=false",
					"tlsVersion=" + tc.expectVersion,
				},
			}}

			assert.Equal(t, expect, logHelper.Got)
		})
	}
}
