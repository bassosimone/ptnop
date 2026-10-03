//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/bassosimone/nop/blob/89b21810488/example_dnsovertcp_test.go
//

package ptnop_test

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"time"

	"github.com/bassosimone/dnscodec"
	"github.com/bassosimone/ptnop"
	"github.com/bassosimone/runtimex"
	"github.com/google/uuid"
	"github.com/miekg/dns"
)

// This example shows how to compose a DNS-over-TCP pipeline that
// resolves a domain name using Google's public DNS server.
func Example_dnsOverTCP() {
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
	logger = logger.With("spanId", spanID)

	// Create the shared configuration for ptnop operations.
	cfg := ptnop.NewConfig()
	cfg.SLogger = logger

	// Create pipeline for establishing a DNS-over-TCP connection.
	// CancelWatchFunc binds context lifecycle to connection lifecycle:
	// when context is done (timeout, cancel, signal), connection closes.
	connectOp := ptnop.NewConnectFunc(cfg, "tcp")

	observeOp := ptnop.NewObserveConnFunc(cfg)

	autoCancelOp := ptnop.NewCancelWatchFunc()

	wrapOp := ptnop.NewDNSOverTCPConnFunc(cfg)

	dialPipe := ptnop.Compose4(connectOp, observeOp, autoCancelOp, wrapOp)

	// Connect and wrap in DNSOverTCPConn (which owns the underlying connection)
	endpoint := netip.MustParseAddrPort("8.8.8.8:53")
	dnsConn := dialPipe.Call(ctx, endpoint)
	defer dnsConn.Close()

	// Perform the DNS exchange
	dnsQuery := dnscodec.NewQuery("dns.google", dns.TypeA)
	dnsResp := runtimex.PanicOnError1(dnsConn.Exchange(ctx, dnsQuery))

	// Print the results
	addrs := runtimex.PanicOnError1(dnsResp.RecordsA())
	slices.Sort(addrs)
	fmt.Printf("%+v\n", addrs)

	// Output:
	// [8.8.4.4 8.8.8.8]
}
