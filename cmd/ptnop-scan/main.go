// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"time"

	"github.com/bassosimone/deferexit"
	"github.com/bassosimone/dnscodec"
	"github.com/bassosimone/ptnop"
	"github.com/bassosimone/runtimex"
	"github.com/bassosimone/vclip"
	"github.com/bassosimone/vflag"
	"github.com/miekg/dns"
)

func main() {
	// 1. route panic-as-exit to proper exit.
	defer deferexit.Recover(os.Exit)

	// 2. initialize the root command.
	ctx := context.Background()
	root := vclip.NewRootCommand(vclip.CommandFunc(realmain))

	// 3. run through the root command to get automatic signal handling.
	root.Main(ctx, os.Args[1:])
}

// slogVerboseLevel maps a verbose boolean flag to [log/slog] levels.
var slogVerboseLevel = map[bool]slog.Level{
	false: slog.LevelInfo,
	true:  slog.LevelDebug,
}

func realmain(ctx context.Context, args []string) error {
	// 1. initialize defaults.
	var (
		alpn       []string
		domain     = "www.example.com"
		endpoint   = ""
		fail       = false
		host       = "dns.google"
		method     = "GET"
		mode       = "tls"
		path       = ""
		proto      = ""
		queryType  = "A"
		skipVerify = false
		sni        = "dns.google"
		source     = false
		timeout    = 30 * time.Second
		verbose    = false
	)

	// 2. parse command line flags.
	fset := vflag.NewFlagSet("ptnop-scan", vflag.ExitOnError)
	fset.Exit = deferexit.Panic

	fset.StringSliceVar(&alpn, 0, "alpn", "Negotiate `ALPN` protocol (repeatable).")
	fset.StringVar(&domain, 0, "domain", "Query for `NAME` instead of `@DEFAULT_VALUE@` (dns-* modes).")
	fset.StringVar(&endpoint, 0, "endpoint", "Use `ENDPOINT` instead of the mode default.")
	fset.BoolVar(&fail, 0, "fail", "Exit with exitcode 1 on failure.")
	fset.StringVar(&host, 0, "host", "Use HTTP `HOST` instead of `@DEFAULT_VALUE@`.")
	fset.StringVar(&method, 0, "method", "Use HTTP `METHOD` instead of `@DEFAULT_VALUE@`.")
	fset.StringVar(&mode, 0, "mode", "Use `MODE` instead of `@DEFAULT_VALUE@`.")
	fset.AutoHelp('h', "help", "Show this help text and exit.")
	fset.StringVar(&path, 0, "path", "Use URL `PATH` instead of the mode default.")
	fset.StringVar(&proto, 'p', "protocol", "Use `PROTO` instead of the mode default.")
	fset.StringVar(&queryType, 0, "query-type", "Use DNS query `TYPE` instead of `@DEFAULT_VALUE@` (dns-* modes).")
	fset.BoolVar(&skipVerify, 'k', "insecure", "Skip TLS certificate verification.")
	fset.StringVar(&sni, 0, "sni", "Use `SNI` instead of `@DEFAULT_VALUE@`.")
	fset.BoolVar(&source, 0, "source", "Add file/line annotation for debugging.")
	fset.DurationVar(&timeout, 't', "timeout", "Use `TIMEOUT` instead of `@DEFAULT_VALUE@`.")
	fset.BoolVar(&verbose, 'v', "verbose", "Emit more detailed logs.")

	runtimex.PanicOnError0(fset.Parse(args)) // using ExitOnError anyway

	// 3. apply the mode defaults to the flags left empty.
	defaults, ok := modeDefaults[mode]
	if !ok {
		fmt.Fprintf(os.Stderr, "ptnop-scan: unknown --mode: %s\n", mode)
		deferexit.Panic(2)
	}
	if endpoint == "" {
		endpoint = defaults.endpoint
	}
	if path == "" {
		path = defaults.path
	}
	if proto == "" {
		proto = defaults.proto
	}

	// 4. parse the DNS query type.
	dnsType, ok := dns.StringToType[queryType]
	if !ok {
		fmt.Fprintf(os.Stderr, "ptnop-scan: unknown --query-type: %s\n", queryType)
		deferexit.Panic(2)
	}
	dnsQuery := dnscodec.NewQuery(domain, dnsType)

	// 5. parse the input endpoint.
	parsedEpnt, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ptnop-scan: invalid endpoint: %s\n", err.Error())
		deferexit.Panic(2)
	}

	// 6. initialize the slog logger.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: source,
		Level:     slogVerboseLevel[verbose],
		ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
			if attr.Key == slog.TimeKey && len(groups) <= 0 {
				return slog.Attr{}
			}
			return attr
		},
	}))

	// 7. initialize the [ptnop] configuration.
	cfg := ptnop.NewConfig()
	cfg.SLogger = logger

	// 8. pre-create all the possible pipeline stages.
	connectStage := ptnop.NewConnectFunc(cfg, proto)
	observeConnStage := ptnop.NewObserveConnFunc(cfg)
	autoCloseStage := ptnop.NewCancelWatchFunc()
	tlsHandshakeStage := ptnop.NewTLSHandshakeFunc(cfg, &tls.Config{
		InsecureSkipVerify: skipVerify,
		NextProtos:         alpn,
		ServerName:         sni,
	})
	httpConnStage := ptnop.NewHTTPConnFunc(cfg)
	dnsOverUDPStage := ptnop.NewDNSOverUDPConnFunc(cfg)
	dnsOverTCPStage := ptnop.NewDNSOverTCPConnFunc(cfg)
	dnsOverTLSStage := ptnop.NewDNSOverTLSConnFunc(cfg)

	// 9. honor -t/--timeout
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 10. proactively create HTTP request.
	targetURL := &url.URL{
		Scheme: "http",
		Host:   host,
		Path:   path,
	}
	if mode == "https" || mode == "dns-https" {
		targetURL.Scheme += "s"
	}
	dnsOverHTTPSStage := ptnop.NewDNSOverHTTPSConnFunc(cfg, targetURL.String())
	req, err := http.NewRequestWithContext(ctx, method, targetURL.String(), http.NoBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ptnop-scan: cannot create HTTP request: %s\n", err.Error())
		deferexit.Panic(2)
	}

	// 11. choose what to do depending on the selected mode.
	var exitcode int
	switch mode {
	case "http":
		pipeline := ptnop.Compose4(
			connectStage,
			observeConnStage,
			autoCloseStage,
			httpConnStage,
		)
		hconn := pipeline.Call(ctx, parsedEpnt)
		resp, err := hconn.RoundTrip(req)
		if err != nil {
			exitcode = 1
		} else {
			if _, err = io.ReadAll(resp.Body); err != nil { // body events: RoundTrip wraps
				exitcode = 1
			}
			resp.Body.Close()
		}
		hconn.Close() // explicit so the close events are logged before exit

	case "https":
		pipeline := ptnop.Compose5(
			connectStage,
			observeConnStage,
			autoCloseStage,
			tlsHandshakeStage,
			httpConnStage,
		)
		hconn := pipeline.Call(ctx, parsedEpnt)
		resp, err := hconn.RoundTrip(req)
		if err != nil {
			exitcode = 1
		} else {
			if _, err = io.ReadAll(resp.Body); err != nil { // body events: RoundTrip wraps
				exitcode = 1
			}
			resp.Body.Close()
		}
		hconn.Close() // explicit so the close events are logged before exit

	case "tcp":
		pipeline := ptnop.Compose3(
			connectStage,
			observeConnStage,
			autoCloseStage,
		)
		result := pipeline.Call(ctx, parsedEpnt)
		if result.Err != nil {
			exitcode = 1
		} else {
			result.V.Close() // explicit so the close events are logged before exit
		}

	case "tls":
		pipeline := ptnop.Compose4(
			connectStage,
			observeConnStage,
			autoCloseStage,
			tlsHandshakeStage,
		)
		result := pipeline.Call(ctx, parsedEpnt)
		if result.Err != nil {
			exitcode = 1
		} else {
			result.V.Close() // explicit so the close events are logged before exit
		}

	case "dns-udp":
		pipeline := ptnop.Compose4(
			connectStage,
			observeConnStage,
			autoCloseStage,
			dnsOverUDPStage,
		)
		dnsConn := pipeline.Call(ctx, parsedEpnt)
		exitcode = dnsExchange(ctx, dnsConn, dnsQuery)
		dnsConn.Close() // explicit so the close events are logged before exit

	case "dns-tcp":
		pipeline := ptnop.Compose4(
			connectStage,
			observeConnStage,
			autoCloseStage,
			dnsOverTCPStage,
		)
		dnsConn := pipeline.Call(ctx, parsedEpnt)
		exitcode = dnsExchange(ctx, dnsConn, dnsQuery)
		dnsConn.Close() // explicit so the close events are logged before exit

	case "dns-tls":
		pipeline := ptnop.Compose5(
			connectStage,
			observeConnStage,
			autoCloseStage,
			tlsHandshakeStage,
			dnsOverTLSStage,
		)
		dnsConn := pipeline.Call(ctx, parsedEpnt)
		exitcode = dnsExchange(ctx, dnsConn, dnsQuery)
		dnsConn.Close() // explicit so the close events are logged before exit

	case "dns-https":
		pipeline := ptnop.Compose6(
			connectStage,
			observeConnStage,
			autoCloseStage,
			tlsHandshakeStage,
			httpConnStage,
			dnsOverHTTPSStage,
		)
		dnsConn := pipeline.Call(ctx, parsedEpnt)
		exitcode = dnsExchange(ctx, dnsConn, dnsQuery)
		dnsConn.Close() // explicit so the close events are logged before exit

	default:
		panic("ptnop-scan: mode validated above")
	}

	// 12. explicitly cancel the context to trigger close
	cancel()

	// 13. decide whether to exit with failure
	if !fail {
		exitcode = 0
	}
	deferexit.Panic(exitcode)
	return nil
}

// modeDefaults maps each --mode to the defaults for the flags left empty.
var modeDefaults = map[string]struct {
	endpoint string
	path     string
	proto    string
}{
	"dns-https": {"8.8.8.8:443", "/dns-query", "tcp"},
	"dns-tcp":   {"8.8.8.8:53", "/", "tcp"},
	"dns-tls":   {"8.8.8.8:853", "/", "tcp"},
	"dns-udp":   {"8.8.8.8:53", "/", "udp"},
	"http":      {"8.8.8.8:80", "/", "tcp"},
	"https":     {"8.8.8.8:443", "/", "tcp"},
	"tcp":       {"8.8.8.8:443", "/", "tcp"},
	"tls":       {"8.8.8.8:443", "/", "tcp"},
}

// dnsExchanger is the common interface of the DNSOver*Conn types.
type dnsExchanger interface {
	Exchange(ctx context.Context, query *dnscodec.Query) (*dnscodec.Response, error)
}

// dnsExchange runs the exchange and prints the records to stderr, keeping
// stdout for ptnop events only. Returns the exit code.
func dnsExchange(ctx context.Context, conn dnsExchanger, query *dnscodec.Query) int {
	resp, err := conn.Exchange(ctx, query)
	if err != nil {
		return 1
	}
	if cnames, err := resp.RecordsCNAME(); err == nil {
		fmt.Fprintf(os.Stderr, "CNAME: %v\n", cnames)
	}
	if addrs, err := resp.RecordsA(); err == nil {
		fmt.Fprintf(os.Stderr, "A: %v\n", addrs)
	}
	if addrs, err := resp.RecordsAAAA(); err == nil {
		fmt.Fprintf(os.Stderr, "AAAA: %v\n", addrs)
	}
	return 0
}
