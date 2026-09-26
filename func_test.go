// SPDX-License-Identifier: GPL-3.0-or-later

package ptnop

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// Make sure that [FuncAdapter] adapts a func to become a [Func].
func TestFuncAdapter(t *testing.T) {
	fx := FuncAdapter[int, int](func(ctx context.Context, value int) int {
		return value + 1
	})
	res := fx.Call(context.Background(), 0)
	require.Equal(t, 1, res)
}

// Make sure that [Compose2] ... [Compose8] work as intended.
func TestCompose(t *testing.T) {
	fx := FuncAdapter[int, int](func(ctx context.Context, value int) int {
		return value + 1
	})

	pipe2 := Compose2(fx, fx)
	require.Equal(t, 2, pipe2.Call(context.Background(), 0))

	pipe3 := Compose3(fx, fx, fx)
	require.Equal(t, 3, pipe3.Call(context.Background(), 0))

	pipe4 := Compose4(fx, fx, fx, fx)
	require.Equal(t, 4, pipe4.Call(context.Background(), 0))

	pipe5 := Compose5(fx, fx, fx, fx, fx)
	require.Equal(t, 5, pipe5.Call(context.Background(), 0))

	pipe6 := Compose6(fx, fx, fx, fx, fx, fx)
	require.Equal(t, 6, pipe6.Call(context.Background(), 0))

	pipe7 := Compose7(fx, fx, fx, fx, fx, fx, fx)
	require.Equal(t, 7, pipe7.Call(context.Background(), 0))

	pipe8 := Compose8(fx, fx, fx, fx, fx, fx, fx, fx)
	require.Equal(t, 8, pipe8.Call(context.Background(), 0))
}
