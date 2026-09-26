//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/ooni/probe-cli/blob/v3.20.0/internal/x/dslx/fxasync.go
// Adapted from: https://github.com/ooni/probe-cli/blob/v3.20.0/internal/x/dslx/fxcore.go
// Adapted from: https://github.com/ooni/probe-cli/blob/v3.20.0/internal/x/dslx/fxstream.go
// Adapted from: https://github.com/bassosimone/nop/blob/89b21810488/func.go
// Adapted from: https://github.com/bassosimone/nop/blob/89b21810488/compose.go
//

package ptnop

import "context"

// Result represents the result of an operation that may fail.
type Result[T any] struct {
	// Err indicates whether the [Func] failed.
	Err error

	// V is a zero value on failure.
	V T
}

// Func is a function that accepts an input and returns a result.
type Func[A, B any] interface {
	Call(ctx context.Context, input A) B
}

// FuncAdapter creates a [Func] from an ordinary func.
type FuncAdapter[A, B any] func(ctx context.Context, input A) B

// Call implements [Func].
func (fx FuncAdapter[A, B]) Call(ctx context.Context, input A) B {
	return fx(ctx, input)
}

// Compose2 chains two [Func] instances together into a pipeline.
func Compose2[A, B, C any](op1 Func[A, B], op2 Func[B, C]) Func[A, C] {
	return &compose2[A, B, C]{op1, op2}
}

type compose2[A, B, C any] struct {
	op1 Func[A, B]
	op2 Func[B, C]
}

func (c *compose2[A, B, C]) Call(ctx context.Context, input A) C {
	return c.op2.Call(ctx, c.op1.Call(ctx, input))
}

// Compose3 chains three [Func] instances together.
func Compose3[A, B, C, D any](op1 Func[A, B], op2 Func[B, C], op3 Func[C, D]) Func[A, D] {
	return Compose2(op1, Compose2(op2, op3))
}

// Compose4 chains four [Func] instances together.
func Compose4[A, B, C, D, E any](op1 Func[A, B], op2 Func[B, C],
	op3 Func[C, D], op4 Func[D, E]) Func[A, E] {
	return Compose2(op1, Compose3(op2, op3, op4))
}

// Compose5 chains five [Func] instances together.
func Compose5[A, B, C, D, E, F any](op1 Func[A, B], op2 Func[B, C],
	op3 Func[C, D], op4 Func[D, E], op5 Func[E, F]) Func[A, F] {
	return Compose2(op1, Compose4(op2, op3, op4, op5))
}

// Compose6 chains six [Func] instances together.
func Compose6[A, B, C, D, E, F, G any](
	op1 Func[A, B], op2 Func[B, C], op3 Func[C, D], op4 Func[D, E],
	op5 Func[E, F], op6 Func[F, G]) Func[A, G] {
	return Compose2(op1, Compose5(op2, op3, op4, op5, op6))
}

// Compose7 chains seven [Func] instances together.
func Compose7[A, B, C, D, E, F, G, H any](
	op1 Func[A, B], op2 Func[B, C], op3 Func[C, D], op4 Func[D, E],
	op5 Func[E, F], op6 Func[F, G], op7 Func[G, H]) Func[A, H] {
	return Compose2(op1, Compose6(op2, op3, op4, op5, op6, op7))
}

// Compose8 chains eight [Func] instances together.
func Compose8[A, B, C, D, E, F, G, H, I any](op1 Func[A, B],
	op2 Func[B, C], op3 Func[C, D], op4 Func[D, E], op5 Func[E, F],
	op6 Func[F, G], op7 Func[G, H], op8 Func[H, I]) Func[A, I] {
	return Compose2(op1, Compose7(op2, op3, op4, op5, op6, op7, op8))
}
