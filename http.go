//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/rbmk-project/rbmk/blob/v0.17.0/pkg/common/httpslog/httpslog.go
// Adapted from: https://github.com/bassosimone/nop/blob/89b21810488/httpbody.go
// Adapted from: https://github.com/bassosimone/nop/blob/89b21810488/httpconn.go
//

package ptnop

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bassosimone/runtimex"
	"github.com/bassosimone/safeconn"
	"github.com/bassosimone/sud"
)

// HTTPEngineConn abstracts over [*http.ClientConn] for testing.
type HTTPEngineConn interface {
	RoundTrip(req *http.Request) (*http.Response, error)
	Close() error
}

// HTTPEngine abstracts over [*http.ClientConn] creation for testing.
type HTTPEngine interface {
	// NewClientConn creates a new [HTTPClientConn] by using:
	//
	//	1. the context to limit the dialing duration
	//	2. the dialer or tlsDialer to dial depending on the scheme
	//	3. the given scheme ("http" or "https") to choose how to dial
	//	4. the given remote endpoint address
	//
	// The stdlib equivalent of this function calls for setting DialContext and
	// DialTLSContext on a transport using dialer.DialContext and tlsDialer.DialContext and
	// then invoking the NewClientConn method of the transport to get the client conn.
	NewClientConn(ctx context.Context, dialer, tlsDialer Dialer,
		scheme, raddr string) (HTTPEngineConn, error)
}

// DefaultHTTPEngine returns the default [HTTPEngine]. The engine implementation
// is exactly as described by [HTTPEngine.NewClientConn] docs.
func DefaultHTTPEngine() HTTPEngine {
	return &netHTTPEngine{}
}

type netHTTPEngine struct{}

var _ HTTPEngine = &netHTTPEngine{}

func (eng *netHTTPEngine) NewClientConn(ctx context.Context, dialer Dialer,
	tlsDialer Dialer, scheme string, raddr string) (HTTPEngineConn, error) {
	txp := &http.Transport{
		DialContext:       dialer.DialContext,    // scheme picks the dialing func
		DialTLSContext:    tlsDialer.DialContext, // scheme picks the dialing func
		ForceAttemptHTTP2: true,                  // go1.27+: https://go.dev/doc/go1.27#nethttppkgnethttp
	}
	return txp.NewClientConn(ctx, scheme, raddr)
}

// HTTPConnFunc is the func that constructs [*HTTPConn] from [net.Conn]. We pick the
// correct protocol scheme ("https" or "http") depending on whether the [net.Conn]
// implements [TLSConn] or not. Hence, the [TLSConn] must be the outermost [net.Conn]
// reaching this func: a wrapper around it hides both the type assertion and the
// ConnectionState method that HTTP/2 negotiation needs.
//
// Use [NewHTTPConnFunc] to create a new instance.
type HTTPConnFunc struct {
	Engine        HTTPEngine
	ErrClassifier ErrClassifier
	SLogger       SLogger
	TimeNow       TimeNowProvider
}

// Reify the default [HTTPEngine] to use `assert.Same` in testing
var defaultHTTPEngine = DefaultHTTPEngine()

// NewHTTPConnFunc creates a [*HTTPConnFunc] using the [*Config] to
// properly initialize all the [*HTTPConnFunc] fields. We also initialize
// the Engine field by using [DefaultHTTPEngine].
func NewHTTPConnFunc(cfg *Config) *HTTPConnFunc {
	return &HTTPConnFunc{
		Engine:        defaultHTTPEngine,
		ErrClassifier: cfg.ErrClassifier,
		SLogger:       cfg.SLogger,
		TimeNow:       cfg.TimeNow,
	}
}

var _ Func[Result[net.Conn], *HTTPConn] = &HTTPConnFunc{}

// Call transforms a [net.Conn] into an [*HTTPConn] thus allowing for HTTP round trips.
func (op *HTTPConnFunc) Call(ctx context.Context, input Result[net.Conn]) *HTTPConn {
	var (
		httpcc HTTPEngineConn
		laddr  string
		proto  string
		raddr  string
	)

	// 1. unpack the input and verify invariant
	conn, err := input.V, input.Err
	runtimex.Assert((conn != nil && err == nil) || (conn == nil && err != nil))

	// 2. if possible, create the [HTTPClientConn] instance
	if err == nil {
		dialer := sud.NewSingleUseDialer(conn)
		laddr = safeconn.LocalAddr(conn)
		proto = safeconn.Network(conn)
		raddr = safeconn.RemoteAddr(conn)
		scheme := "http"
		if _, ok := conn.(TLSConn); ok {
			scheme += "s"
		}
		// The signature of [sud.Dialer] matches [Dialer] and the connection is cached
		// anyway so the caller will basically always call the same dialer, however, in
		// general, those are two distinct code paths so we implemented both
		httpcc, err = op.Engine.NewClientConn(ctx, dialer, dialer, scheme, raddr)
		if err != nil {
			conn.Close() // we're not returning it so we close it
		}
	} else {
		err = ErrSkip{err}
	}

	// 3. enforce output invariant
	runtimex.Assert((httpcc != nil && err == nil) || (httpcc == nil && err != nil))

	// 4. create the [*HTTPConn] instance.
	hc := &HTTPConn{
		ErrClassifier: op.ErrClassifier,
		HTTPCc:        Result[HTTPEngineConn]{V: httpcc, Err: err},
		LocalAddr:     laddr,
		Proto:         proto,
		RemoteAddr:    raddr,
		SLogger:       op.SLogger,
		TimeNow:       op.TimeNow,
	}
	return hc
}

// HTTPConn is an [HTTPEngineConn] using the [net.Conn] dialed by a previous stage.
//
// Typically constructed using [*HTTPConnFunc.Call].
type HTTPConn struct {
	ErrClassifier ErrClassifier
	HTTPCc        Result[HTTPEngineConn]
	LocalAddr     string
	Proto         string
	RemoteAddr    string
	SLogger       SLogger
	TimeNow       TimeNowProvider
}

// RoundTrip implements [http.RoundTripper] as implemented by [*http.ClientConn.RoundTrip].
//
// On success the [*http.Response] body is an [*HTTPBodyWrapper] emitting logs.
func (hc *HTTPConn) RoundTrip(req *http.Request) (*http.Response, error) {
	// 1. log before the operation
	t0 := hc.TimeNow.Get()
	deadline, _ := req.Context().Deadline()
	hc.SLogger.Info(
		"httpRoundTripStart",
		slog.Time("deadline", deadline),
		slog.String("httpMethod", req.Method),
		slog.String("httpUrl", req.URL.String()),
		slog.Any("httpRequestHeaders", req.Header),
		slog.String("localAddr", hc.LocalAddr),
		slog.String("protocol", hc.Proto),
		slog.String("remoteAddr", hc.RemoteAddr),
		slog.Time("t", t0),
	)

	// 2. execute the operation
	var (
		err        = hc.HTTPCc.Err // unpack
		cc         = hc.HTTPCc.V   // unpack
		headers    http.Header
		resp       *http.Response
		statusCode int
		uncompr    bool
	)
	runtimex.Assert((cc != nil && err == nil) || (cc == nil && err != nil)) // invariant
	if err == nil {
		resp, err = cc.RoundTrip(req)
		if err == nil {
			statusCode = resp.StatusCode
			headers = resp.Header
			resp.Body = NewHTTPBodyWrapper(hc, resp.Body)
			uncompr = resp.Uncompressed
		}
	} else {
		err = ErrSkip{err}
	}
	runtimex.Assert((resp != nil && err == nil) || (resp == nil && err != nil)) // invariant

	// 3. log after the operation
	hc.SLogger.Info(
		"httpRoundTripDone",
		slog.Time("deadline", deadline),
		slog.Any("err", err),
		slog.String("errClass", hc.ErrClassifier.Classify(err)),
		slog.String("httpMethod", req.Method),
		slog.String("httpUrl", req.URL.String()),
		slog.Any("httpRequestHeaders", req.Header),
		slog.Bool("httpResponseBodyUncompressed", uncompr),
		slog.Any("httpResponseHeaders", headers),
		slog.Int("httpResponseStatusCode", statusCode),
		slog.String("localAddr", hc.LocalAddr),
		slog.String("protocol", hc.Proto),
		slog.String("remoteAddr", hc.RemoteAddr),
		slog.Time("t", hc.TimeNow.Get()),
		slog.Time("t0", t0),
	)

	return resp, err
}

// Close cleans up the transport and closes the underlying connection.
func (hc *HTTPConn) Close() error {
	if conn, err := hc.HTTPCc.V, hc.HTTPCc.Err; err == nil {
		return conn.Close()
	}
	return nil
}

// HTTPBodyWrapper wraps a response body and emits structured logs
// when we start and when we finish reading the body.
//
// Use [NewHTTPBodyWrapper] to create a new instance.
//
// Must not use if you use [*HTTPConn]: it automatically wraps the body itself.
type HTTPBodyWrapper struct {
	// Body is the wrapped body.
	//
	// Must be public to allow callers to unwrap and opt-out of
	// logging the body events if so they wish.
	Body io.ReadCloser

	// didRead tracks whether at least one Read happened.
	didRead atomic.Bool

	// errClass is the err classifier in use.
	errClass ErrClassifier

	// laddr is the local address.
	laddr string

	// slogger is the [SLogger] in use.
	slogger SLogger

	// closeOnce ensures that Close has "once" semantics.
	closeOnce sync.Once

	// protocol is the network protocol ("tcp" or "udp").
	protocol string

	// raddr is the remote address.
	raddr string

	// readErr is the saved body-reading error.
	readErr error

	// readErrMu protects readErr.
	readErrMu sync.Mutex

	// readOnce ensures we log httpBodyStreamStart only once.
	readOnce sync.Once

	// t0 is the time when we started reading the body.
	t0 time.Time

	// timeNow allows mocking [time.Now].
	timeNow TimeNowProvider
}

// NewHTTPBodyWrapper creates an [*HTTPBodyWrapper] using the [*HTTPConn] and the
// given [io.ReadCloser] to initialize all [*HTTPBodyWrapper] fields.
//
// Must not use if you use [*HTTPConn]: it automatically wraps the body itself.
func NewHTTPBodyWrapper(hc *HTTPConn, body io.ReadCloser) *HTTPBodyWrapper {
	return &HTTPBodyWrapper{ // arrange for logging body events
		Body:      body,
		didRead:   atomic.Bool{},
		errClass:  hc.ErrClassifier,
		laddr:     hc.LocalAddr,
		slogger:   hc.SLogger,
		closeOnce: sync.Once{},
		protocol:  hc.Proto,
		raddr:     hc.RemoteAddr,
		readOnce:  sync.Once{},
		readErr:   nil,
		readErrMu: sync.Mutex{},
		t0:        time.Time{}, // set later when we start reading the body
		timeNow:   hc.TimeNow,
	}
}

var _ io.ReadCloser = &HTTPBodyWrapper{}

// Close closes the underlying body emitting `httpBodyStreamDone` if we did ever
// attempt reading from the body. In such a case, the event error is the last error
// observed when reading, which might indicate a network filtering issue.
func (b *HTTPBodyWrapper) Close() (err error) {
	b.closeOnce.Do(func() {
		err = b.Body.Close()
		if b.didRead.Load() { // acquire: t0 is visible if this returns true

			b.readErrMu.Lock()
			readErr := b.readErr
			b.readErrMu.Unlock()

			b.slogger.Info(
				"httpBodyStreamDone",
				slog.Any("err", readErr),
				slog.String("errClass", b.errClass.Classify(readErr)),
				slog.String("localAddr", b.laddr),
				slog.String("protocol", b.protocol),
				slog.String("remoteAddr", b.raddr),
				slog.Time("t", b.timeNow.Get()),
				slog.Time("t0", b.t0),
			)
		}
	})
	return
}

// Read reads a chunk of the body and emits `httpBodyStreamStart` on the first read.
func (b *HTTPBodyWrapper) Read(buffer []byte) (int, error) {
	// 1. log once when we do the first read
	b.readOnce.Do(func() {
		b.t0 = b.timeNow.Get() // write t0 BEFORE the atomic store (release)
		b.didRead.Store(true)  // release: makes t0 visible to Close
		b.slogger.Info(
			"httpBodyStreamStart",
			slog.String("localAddr", b.laddr),
			slog.String("protocol", b.protocol),
			slog.String("remoteAddr", b.raddr),
			slog.Time("t", b.t0),
		)
	})

	// 2. execute the actual read operation
	count, err := b.Body.Read(buffer)

	// 3. report protocol errors to the caller but mask `io.EOF` because it's the
	// sentinel used to indicate EOF and emitting it is useless
	if err != nil && !errors.Is(err, io.EOF) {
		b.readErrMu.Lock()
		b.readErr = err
		b.readErrMu.Unlock()
	}

	// 4. return the results
	return count, err
}
