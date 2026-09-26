// SPDX-License-Identifier: GPL-3.0-or-later

package ptnop

import (
	"context"
	"errors"
	"net"
	"testing"

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
