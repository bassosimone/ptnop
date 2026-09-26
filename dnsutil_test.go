// SPDX-License-Identifier: GPL-3.0-or-later

package ptnop

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_dnsUnusedDialer_DialContext_panics(t *testing.T) {
	dialer := dnsUnusedDialer{}
	assert.Panics(t, func() {
		dialer.DialContext(context.Background(), "udp", "10.0.0.2:53")
	})
}
