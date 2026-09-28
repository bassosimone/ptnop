//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/bassosimone/nop/blob/89b21810488/example_httpconn_test.go
//

package ptnop_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/bassosimone/ptnop"
	"github.com/bassosimone/runtimex"
	"github.com/google/uuid"
)

// This example shows how to compose an HTTPS pipeline that performs
// an HTTP round trip and reads the response body.
func Example_httpsRoundTrip() {
	// Create context with overall timeout for the entire operation.
	// Caller controls timeout externally and ptnop never modifies the context.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create a logger that emits JSON to stderr. Use LevelDebug to include
	// per-I/O events (read, write, deadline); use LevelInfo to see only
	// lifecycle and protocol events (connect, close, TLS, DNS, HTTP).
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	// Generate a span ID (UUIDv7) and attach it to the logger so that
	// all log entries from this operation can be correlated.
	spanID := uuid.Must(uuid.NewV7()).String()
	logger = logger.With("spanID", spanID)

	// Create the shared configuration for ptnop operations.
	cfg := ptnop.NewConfig()
	cfg.SLogger = logger

	// Create pipeline for establishing an HTTPS connection.
	// CancelWatchFunc binds context lifecycle to connection lifecycle:
	// when context is done (timeout, cancel, signal), connection closes.
	connectOp := ptnop.NewConnectFunc(cfg, "tcp")

	observeOp := ptnop.NewObserveConnFunc(cfg)

	autoCancelOp := ptnop.NewCancelWatchFunc()

	tlsConfig := &tls.Config{ServerName: "dns.google", NextProtos: []string{"h2", "http/1.1"}}
	tlsHandshakeOp := ptnop.NewTLSHandshakeFunc(cfg, tlsConfig)

	httpConnOp := ptnop.NewHTTPConnFunc(cfg)

	dialPipe := ptnop.Compose5(connectOp, observeOp, autoCancelOp, tlsHandshakeOp, httpConnOp)

	// Connect and wrap in HTTPConn
	endpoint := netip.MustParseAddrPort("8.8.8.8:443")
	httpConn := dialPipe.Call(ctx, endpoint)
	defer httpConn.Close()

	// Create the HTTP request and perform the round trip
	httpReq := runtimex.PanicOnError1(
		http.NewRequestWithContext(ctx, "GET", "https://dns.google/", http.NoBody))
	resp := runtimex.PanicOnError1(httpConn.RoundTrip(httpReq))
	defer resp.Body.Close()
	runtimex.Assert(resp.StatusCode < 400)

	// Read the body
	body := runtimex.PanicOnError1(io.ReadAll(resp.Body))

	// Extract and print the title from the HTML
	title := extractTitle(string(body))
	fmt.Printf("%s\n", title)

	// Output:
	// Google Public DNS
}

// extractTitle extracts the content of the <title> tag from HTML.
func extractTitle(html string) string {
	const startTag = "<title>"
	const endTag = "</title>"
	start := strings.Index(html, startTag)
	if start == -1 {
		return ""
	}
	start += len(startTag)
	end := strings.Index(html[start:], endTag)
	if end == -1 {
		return ""
	}
	return html[start : start+end]
}
