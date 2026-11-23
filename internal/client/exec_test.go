package client

import (
	"net/netip"
	"testing"
)

func TestIPv6LeakDecision(t *testing.T) {
	full, isFull := splitDefault([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")})
	if !isFull || len(full) != 2 {
		t.Fatalf("full tunnel split wrong: %v", full)
	}
	if !blockIPv6(true, netip.MustParseAddr("203.0.113.1")) {
		t.Fatal("full tunnel over IPv4 must block IPv6")
	}
	if blockIPv6(false, netip.MustParseAddr("203.0.113.1")) {
		t.Fatal("split tunnel must not touch IPv6")
	}
	if blockIPv6(true, netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("IPv6 endpoint would loop")
	}
	if got := v6TunnelAddr(netip.MustParseAddr("10.8.0.6")).String(); got != "fd77:2fa::a08:6/128" {
		t.Fatalf("v6 addr %s", got)
	}
}
