// SPDX-License-Identifier: GPL-3.0-or-later

package ptnop

import (
	"context"
	"errors"
	"net/netip"
)

// ErrInvalidAddrPort is the sentinel error returned when the [*AddrPortFunc]
// is configured with an invalid [netip.AddrPort].
var ErrInvalidAddrPort = errors.New("ptnop: invalid AddrPort")

// NewAddrPortFunc returns a new [*AddrPortFunc] that takes a [Unit]
// in input and returns the given [netip.AddrPort] in output.
//
// If the [netip.AddrPort] is invalid, calling the function causes
// the [ErrInvalidAddrPort] to be returned instead.
func NewAddrPortFunc(addr netip.AddrPort) *AddrPortFunc {
	return &AddrPortFunc{addr}
}

// AddrPortFunc returns the configured [netip.AddrPort], if valid, and
// otherwise returns the [ErrInvalidAddrPort] to the caller.
//
// This [Func] emits no log events: it performs no observable network
// operation, a valid address is surfaced by the next stage's start event,
// and an invalid address is the zero value, which carries no additional
// configuration worth logging.
//
// All fields are safe to modify after construction but before first use.
type AddrPortFunc struct {
	// Addr is the [netip.AddrPort] to use.
	//
	// Set by [NewAddrPortFunc] to the given value.
	Addr netip.AddrPort
}

var _ Func[Unit, netip.AddrPort] = &AddrPortFunc{}

// Call invokes the [*AddrPortFunc] to return the configured [netip.AddrPort] or [ErrInvalidAddrPort].
func (op *AddrPortFunc) Call(ctx context.Context, input Result[Unit]) Result[netip.AddrPort] {
	switch {
	case input.Err != nil:
		return Result[netip.AddrPort]{Err: NewErrSkip(input.Err)}
	case !op.Addr.IsValid():
		return Result[netip.AddrPort]{Err: ErrInvalidAddrPort}
	default:
		return Result[netip.AddrPort]{Value: op.Addr}
	}
}
