// SPDX-License-Identifier: GPL-3.0-or-later

package ptnop

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NewAddrPortFunc stores the given address.
func TestNewAddrPortFunc(t *testing.T) {
	addr := netip.MustParseAddrPort("93.184.216.34:443")

	fn := NewAddrPortFunc(addr)

	require.NotNil(t, fn)
	assert.Equal(t, addr, fn.Addr)
}

// Call returns the configured address, ErrInvalidAddrPort, or ErrSkip.
func TestAddrPortFunc(t *testing.T) {
	// errMocked is the canonical mocked error used by this test.
	errMocked := errors.New("mocked error")

	t.Run("pre-existing error", func(t *testing.T) {
		fn := NewAddrPortFunc(netip.MustParseAddrPort("93.184.216.34:443"))

		value, err := fn.Call(context.Background(), Result[Unit]{Err: errMocked}).Unpack()

		require.Error(t, err)
		underlying, ok := errors.AsType[ErrSkip](err)
		assert.True(t, ok)
		assert.Same(t, errMocked, underlying.Err)
		assert.False(t, value.IsValid())
	})

	t.Run("invalid address", func(t *testing.T) {
		fn := NewAddrPortFunc(netip.AddrPort{})

		value, err := fn.Call(context.Background(), Result[Unit]{}).Unpack()

		require.ErrorIs(t, err, ErrInvalidAddrPort)
		assert.False(t, value.IsValid())
	})

	t.Run("valid address", func(t *testing.T) {
		addr := netip.MustParseAddrPort("93.184.216.34:443")
		fn := NewAddrPortFunc(addr)

		value, err := fn.Call(context.Background(), Result[Unit]{}).Unpack()

		require.NoError(t, err)
		assert.Equal(t, addr, value)
	})
}
