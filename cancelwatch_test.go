// SPDX-License-Identifier: GPL-3.0-or-later

package ptnop

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/bassosimone/netstub"
	"github.com/stretchr/testify/assert"
)

// Make sure [CancelWatchFunc.Call] does nothing on previous stage failures.
func TestCancelWatchFunc_Call_failure(t *testing.T) {
	mocked := errors.New("mocked")
	fx := NewCancelWatchFunc()
	input := Result[net.Conn]{Err: mocked}
	output := fx.Call(context.Background(), input)
	assert.Equal(t, input, output)
}

// Make sure [CancelWatchFunc.Call] arranges for Close when the context is canceled.
func TestCancelWatchFunc_Call_success(t *testing.T) {
	// 1. setup
	var (
		called bool
		ready  = make(chan struct{})
	)
	origConn := &netstub.FuncConn{
		CloseFunc: func() error {
			called = true
			close(ready)
			return nil
		},
	}
	input := Result[net.Conn]{V: origConn}
	ctx, cancel := context.WithCancel(context.Background())
	fx := NewCancelWatchFunc()

	// 2. invoke
	output := fx.Call(ctx, input)

	// 3. check
	_, ok := output.V.(*cancelWatchedConn)
	assert.True(t, ok)
	cancel()
	<-ready
	assert.True(t, called)
}

// Make sure closing the conn returned by [CancelWatchFunc.Call] unregisters the watcher.
func TestCancelWatchFunc_Call_closeUnregisters(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// 1. setup
		var closeCount atomic.Int32
		origConn := &netstub.FuncConn{
			CloseFunc: func() error {
				closeCount.Add(1)
				return nil
			},
		}
		input := Result[net.Conn]{V: origConn}
		ctx, cancel := context.WithCancel(context.Background())
		fx := NewCancelWatchFunc()

		// 2. invoke: close, then cancel
		output := fx.Call(ctx, input)
		err := output.V.Close()
		cancel()
		synctest.Wait() // a still-registered watcher would have run by now

		// 3. check
		assert.NoError(t, err)
		assert.Equal(t, int32(1), closeCount.Load())
	})
}
