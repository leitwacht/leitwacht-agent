//go:build linux

package enforcer

import (
	"net"
	"testing"
)

func TestPackAllowKey_Size(t *testing.T) {
	key := PackAllowKey(net.ParseIP("93.184.216.34"), 443)

	// Must be exactly 6 bytes — mismatched struct padding causes silent map lookup failures.
	if len(key) != 6 {
		t.Fatalf("key size = %d, want 6", len(key))
	}

	// Verify IP bytes (network byte order)
	if key[0] != 93 || key[1] != 184 || key[2] != 216 || key[3] != 34 {
		t.Fatalf("ip bytes = %v", key[0:4])
	}

	// Verify port bytes (network byte order: 443 = 0x01BB)
	if key[4] != 0x01 || key[5] != 0xBB {
		t.Fatalf("port bytes = %x %x, want 01 BB", key[4], key[5])
	}
}

func TestPackAllowKey_IPv6ReturnsZero(t *testing.T) {
	key := PackAllowKey(net.ParseIP("::1"), 443)
	var zero [6]byte
	if key != zero {
		t.Fatal("IPv6 should return zero key")
	}
}
