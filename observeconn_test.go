// SPDX-License-Identifier: GPL-3.0-or-later

package ptnop

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/bassosimone/netstub"
	"github.com/stretchr/testify/assert"
)

// Make sure [NewObserveConnFunc] initializes all [*ObserveConnFunc] fields.
func TestNewObserveConnFunc(t *testing.T) {
	cfg := NewConfig()
	fx := NewObserveConnFunc(cfg)
	assert.Same(t, cfg.ErrClassifier, fx.ErrClassifier)
	assert.Same(t, cfg.SLogger, fx.SLogger)
	assert.Same(t, cfg.TimeNow, fx.TimeNow)
}

// Make sure [ObserveConnFunc.Call] does nothing on previous-stage failure.
func TestObserveConnFunc_Call_failure(t *testing.T) {
	// 1. setup
	mocked := errors.New("mocked")
	fx := NewObserveConnFunc(NewConfig())
	input := Result[net.Conn]{Err: mocked}

	// 2. invoke
	output := fx.Call(context.Background(), input)

	// 3. check
	assert.Equal(t, input, output)
}

// Make sure [ObserveConnFunc.Call] wraps the conn if the previous stage succeeded.
func TestObserveConnFunc_Call_success(t *testing.T) {
	// 1. setup
	origConn := &netstub.FuncConn{
		LocalAddrFunc: func() net.Addr {
			return &net.TCPAddr{
				IP:   net.IPv4(10, 0, 0, 1),
				Port: 19774,
				Zone: "",
			}
		},
		RemoteAddrFunc: func() net.Addr {
			return &net.TCPAddr{
				IP:   net.IPv4(10, 0, 0, 2),
				Port: 80,
				Zone: "",
			}
		},
	}
	input := Result[net.Conn]{V: origConn}

	// 2. invoke
	fx := NewObserveConnFunc(NewConfig())
	output := fx.Call(context.Background(), input)

	// 3. check
	expect := Result[net.Conn]{V: &observedConn{
		closeonce: sync.Once{},
		conn:      origConn,
		laddr:     "10.0.0.1:19774",
		op:        fx,
		protocol:  "tcp",
		raddr:     "10.0.0.2:80",
	}}
	assert.Equal(t, expect, output)
}

// Make sure [observedConn.Close] works as expected.
func Test_observedConn_Close(t *testing.T) {
	// mockedErr is the error mock we use
	mockedErr := errors.New("mocked")

	// We use testcases to check for success and failure
	type testcase struct {
		// name is the test case name
		name string

		// err is the error that close should return
		err error

		// expectations for `closeDone` fields
		expectErr      string
		expectErrClass string
	}

	cases := []testcase{
		{
			name:           "failure",
			err:            mockedErr,
			expectErr:      "mocked",
			expectErrClass: "EGENERIC",
		},
		{
			name:           "success",
			err:            nil,
			expectErr:      "<nil>",
			expectErrClass: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 1. setup
			logHelper := &slogValidationHelper{}
			conn := &observedConn{
				conn: &netstub.FuncConn{
					CloseFunc: func() error {
						return tc.err
					},
				},
				laddr: "10.0.0.1:19774",
				op: &ObserveConnFunc{
					ErrClassifier: DefaultErrClassifier(),
					SLogger:       logHelper,
					TimeNow:       logHelper,
				},
				protocol: "tcp",
				raddr:    "10.0.0.2:80",
			}

			// 2. invoke
			err1 := conn.Close()
			err2 := conn.Close() // test for subsequent invocations

			// 3. check
			assert.Equal(t, tc.err, err1)
			assert.True(t, errors.Is(err2, net.ErrClosed))

			// 4. events
			expect := []slogSimpleRecord{{
				Level: "info",
				Msg:   "closeStart",
				Attrs: []string{
					"localAddr=10.0.0.1:19774",
					"protocol=tcp",
					"remoteAddr=10.0.0.2:80",
					"t=2026-01-01 00:00:00 +0000 UTC",
				},
			}, {
				Level: "info",
				Msg:   "closeDone",
				Attrs: []string{
					"err=" + tc.expectErr,
					"errClass=" + tc.expectErrClass,
					"localAddr=10.0.0.1:19774",
					"protocol=tcp",
					"remoteAddr=10.0.0.2:80",
					"t=2026-01-01 00:00:00 +0000 UTC",
					"t0=2026-01-01 00:00:00 +0000 UTC",
				},
			}}

			assert.Equal(t, expect, logHelper.Got)
		})
	}
}

// Make sure [observedConn.LocalAddr] and [observedConn.RemoteAddr] works as expected.
func Test_observedConn_LocalRemoteAddr(t *testing.T) {
	// 1. setup
	mockedLocalAddr := &net.TCPAddr{
		IP:   net.IPv4(10, 0, 0, 1),
		Port: 19774,
		Zone: "",
	}
	mockedRemoteAddr := &net.TCPAddr{
		IP:   net.IPv4(10, 0, 0, 1),
		Port: 80,
		Zone: "",
	}
	conn := &observedConn{
		conn: &netstub.FuncConn{
			LocalAddrFunc: func() net.Addr {
				return mockedLocalAddr
			},
			RemoteAddrFunc: func() net.Addr {
				return mockedRemoteAddr
			},
		},
	}

	// 2. invoke
	localAddr := conn.LocalAddr()
	remoteAddr := conn.RemoteAddr()

	// 3. check
	assert.Equal(t, mockedLocalAddr, localAddr)
	assert.Equal(t, mockedRemoteAddr, remoteAddr)
}

// Make sure [observedConn.Read] and [observedConn.Write] work as expected.
func Test_observedConn_ReadWrite(t *testing.T) {
	// mockedErr is the error mock we use
	mockedErr := errors.New("mocked")

	// We use test cases to setup success/failure scenarios.
	type testcase struct {
		// name is the test case name.
		name string

		// count and err that Read/Write should return.
		count int
		err   error

		// expectations in the "done" events.
		expectErr      string
		expectErrClass string
	}

	cases := []testcase{
		{
			name:           "failure",
			count:          0,
			err:            mockedErr,
			expectErr:      "mocked",
			expectErrClass: "EGENERIC",
		},
		{
			name:           "success",
			count:          17,
			err:            nil,
			expectErr:      "<nil>",
			expectErrClass: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 1. setup
			logHelper := &slogValidationHelper{}
			conn := &observedConn{
				closeonce: sync.Once{},
				conn: &netstub.FuncConn{
					ReadFunc: func(data []byte) (int, error) {
						return tc.count, tc.err
					},
					WriteFunc: func(data []byte) (int, error) {
						return tc.count, tc.err
					},
				},
				laddr: "10.0.0.1:19774",
				op: &ObserveConnFunc{
					ErrClassifier: DefaultErrClassifier(),
					SLogger:       logHelper,
					TimeNow:       logHelper,
				},
				protocol: "tcp",
				raddr:    "10.0.0.2:80",
			}
			buf := make([]byte, 1024)

			// 2. invoke
			countRead, errRead := conn.Read(buf)
			countWrite, errWrite := conn.Write(buf)

			// 3. check
			assert.Equal(t, tc.err, errRead)
			assert.Equal(t, tc.count, countRead)
			assert.Equal(t, tc.err, errWrite)
			assert.Equal(t, tc.count, countWrite)

			expect := []slogSimpleRecord{{
				Level: "debug",
				Msg:   "readStart",
				Attrs: []string{
					"ioBufferSize=1024",
					"localAddr=10.0.0.1:19774",
					"protocol=tcp",
					"remoteAddr=10.0.0.2:80",
					"t=2026-01-01 00:00:00 +0000 UTC",
				},
			}, {
				Level: "debug",
				Msg:   "readDone",
				Attrs: []string{
					"ioBytesCount=" + strconv.Itoa(tc.count),
					"err=" + tc.expectErr,
					"errClass=" + tc.expectErrClass,
					"localAddr=10.0.0.1:19774",
					"protocol=tcp",
					"remoteAddr=10.0.0.2:80",
					"t=2026-01-01 00:00:00 +0000 UTC",
					"t0=2026-01-01 00:00:00 +0000 UTC",
				},
			}, {
				Level: "debug",
				Msg:   "writeStart",
				Attrs: []string{
					"ioBufferSize=1024",
					"localAddr=10.0.0.1:19774",
					"protocol=tcp",
					"remoteAddr=10.0.0.2:80",
					"t=2026-01-01 00:00:00 +0000 UTC",
				},
			}, {
				Level: "debug",
				Msg:   "writeDone",
				Attrs: []string{
					"ioBytesCount=" + strconv.Itoa(tc.count),
					"err=" + tc.expectErr,
					"errClass=" + tc.expectErrClass,
					"localAddr=10.0.0.1:19774",
					"protocol=tcp",
					"remoteAddr=10.0.0.2:80",
					"t=2026-01-01 00:00:00 +0000 UTC",
					"t0=2026-01-01 00:00:00 +0000 UTC",
				},
			}}

			assert.Equal(t, expect, logHelper.Got)
		})
	}
}

// Make sure [observedConn.SetDeadline] and other deadline funcs works as expected.
func Test_observedConn_Deadlines(t *testing.T) {
	// mockedErr is the error mock we use
	mockedErr := errors.New("mocked")

	// We use test cases to check for success/failure conditions
	type testcase struct {
		// name is the testcase name
		name string

		// err is what deadline setting funcs should return
		err error

		// expectations for the emitted event
		expectErr      string
		expectErrClass string
	}

	cases := []testcase{
		{
			name:           "failure",
			err:            mockedErr,
			expectErr:      "mocked",
			expectErrClass: "EGENERIC",
		},
		{
			name:           "success",
			err:            nil,
			expectErr:      "<nil>",
			expectErrClass: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 1. setup
			logHelper := &slogValidationHelper{}
			conn := &observedConn{
				closeonce: sync.Once{},
				conn: &netstub.FuncConn{
					SetDeadlineFunc: func(t time.Time) error {
						return tc.err
					},
					SetReadDeadlineFunc: func(t time.Time) error {
						return tc.err
					},
					SetWriteDeadlineFunc: func(t time.Time) error {
						return tc.err
					},
				},
				laddr: "10.0.0.1:19774",
				op: &ObserveConnFunc{
					ErrClassifier: DefaultErrClassifier(),
					SLogger:       logHelper,
					TimeNow:       logHelper,
				},
				protocol: "tcp",
				raddr:    "10.0.0.2:80",
			}
			deadline := logHelper.Get().Add(10 * time.Second)

			// 2. invoke
			err1 := conn.SetDeadline(deadline)
			err2 := conn.SetReadDeadline(deadline)
			err3 := conn.SetWriteDeadline(deadline)

			// 3. check
			assert.Equal(t, tc.err, err1)
			assert.Equal(t, tc.err, err2)
			assert.Equal(t, tc.err, err3)

			expect := []slogSimpleRecord{{
				Level: "debug",
				Msg:   "setDeadline",
				Attrs: []string{
					"deadline=2026-01-01 00:00:10 +0000 UTC",
					"err=" + tc.expectErr,
					"errClass=" + tc.expectErrClass,
					"localAddr=10.0.0.1:19774",
					"protocol=tcp",
					"remoteAddr=10.0.0.2:80",
					"t=2026-01-01 00:00:00 +0000 UTC",
				},
			}, {
				Level: "debug",
				Msg:   "setReadDeadline",
				Attrs: []string{
					"deadline=2026-01-01 00:00:10 +0000 UTC",
					"err=" + tc.expectErr,
					"errClass=" + tc.expectErrClass,
					"localAddr=10.0.0.1:19774",
					"protocol=tcp",
					"remoteAddr=10.0.0.2:80",
					"t=2026-01-01 00:00:00 +0000 UTC",
				},
			}, {
				Level: "debug",
				Msg:   "setWriteDeadline",
				Attrs: []string{
					"deadline=2026-01-01 00:00:10 +0000 UTC",
					"err=" + tc.expectErr,
					"errClass=" + tc.expectErrClass,
					"localAddr=10.0.0.1:19774",
					"protocol=tcp",
					"remoteAddr=10.0.0.2:80",
					"t=2026-01-01 00:00:00 +0000 UTC",
				},
			}}

			assert.Equal(t, expect, logHelper.Got)
		})
	}
}
