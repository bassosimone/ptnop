# Pass-through Network Observation Pipelines

[![GoDoc](https://pkg.go.dev/badge/github.com/bassosimone/ptnop)](https://pkg.go.dev/github.com/bassosimone/ptnop) [![Build Status](https://github.com/bassosimone/ptnop/actions/workflows/go.yml/badge.svg)](https://github.com/bassosimone/ptnop/actions) [![codecov](https://codecov.io/gh/bassosimone/ptnop/branch/main/graph/badge.svg)](https://codecov.io/gh/bassosimone/ptnop)

The `ptnop` Go package provides composable primitives for building network
measurement pipelines with structured logging. Each primitive is a
`Func[A, B]` that can be chained via type-safe composition (`Compose2`
through `Compose8`).

Basic usage (DNS-over-UDP lookup):

```Go
import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"time"

	"github.com/bassosimone/dnscodec"
	"github.com/bassosimone/ptnop"
	"github.com/miekg/dns"
)

// Use LevelDebug to include per-I/O events (read, write, deadline);
// Use LevelInfo to see only lifecycle and protocol events.
logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
	Level: slog.LevelDebug,
}))

// Create configuration with default settings.
cfg := ptnop.NewConfig()
cfg.SLogger = logger

pipeline := ptnop.Compose4(
	// Dial a UDP socket to the target endpoint.
	ptnop.NewConnectFunc(cfg, "udp"),

	// Wrap the connection to log each read, write, and deadline change.
	ptnop.NewObserveConnFunc(cfg),

	// Close the connection when the context is cancelled (e.g., ^C).
	ptnop.NewCancelWatchFunc(),

	// Wrap the UDP connection as a DNS-over-UDP connection.
	ptnop.NewDNSOverUDPConnFunc(cfg),
)

// The context controls the overall timeout for the pipeline.
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

// Pass the target endpoint directly as input to the pipeline.
conn := pipeline.Call(ctx, netip.MustParseAddrPort("8.8.8.8:53"))
defer conn.Close()

// Use the connection to perform a DNS exchange.
query := dnscodec.NewQuery("dns.google", dns.TypeA)
resp, err := conn.Exchange(ctx, query)
```

See the [package documentation](https://pkg.go.dev/github.com/bassosimone/ptnop)
and testable examples for DNS-over-TCP, DNS-over-TLS, DNS-over-HTTPS, and
HTTPS round trip pipelines.

## Installation

To add this package as a dependency to your module:

```sh
go get github.com/bassosimone/ptnop
```

## Development

To run the tests:

```sh
go test -v .
```

To measure test coverage:

```sh
go test -v -cover .
```

## License

```
SPDX-License-Identifier: GPL-3.0-or-later
```

## History

Adapted from [nop](https://github.com/bassosimone/nop). The main
difference is that `nop` stops logging events mid-pipeline on the
first error. By contrast, `ptnop` does not interrupt the pipeline
and introduces a specific sentinel error `ErrSkip` to note that a
previous pipeline stage has failed. The resulting `ptnop` events are
more suitable for automatic processing, since they also include the
configuration of the skipped stages.

The `pt` in `ptnop` means "pass-through" and refers to the `ErrSkip`
mechanism so that we pass through each stage regardless of
whether the previous stages failed or not.

In turn, `nop` was adapted from [ooni/probe-cli](https://github.com/ooni/probe-cli/tree/v3.20.1)
and [rbmk-project/rbmk](https://github.com/rbmk-project/rbmk/tree/v0.17.0).
