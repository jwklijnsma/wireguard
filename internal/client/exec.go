package client

import (
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	hideWindow(cmd)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%s %s: %v %s", name, strings.Join(args, " "), err, strings.TrimSpace(errb.String()+" "+out.String()))
	}
	return out.String(), nil
}

// splitDefault replaces 0.0.0.0/0 by 0.0.0.0/1 + 128.0.0.0/1 so the original
// default route stays in place (same trick as wg-quick) and reports whether
// the tunnel captures all traffic. IPv6 routes are dropped: the tunnel only
// carries IPv4 in this version.
func splitDefault(routes []netip.Prefix) (out []netip.Prefix, full bool) {
	for _, r := range routes {
		if !r.Addr().Is4() {
			continue
		}
		if r.Bits() == 0 {
			full = true
			out = append(out, netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1"))
			continue
		}
		out = append(out, r)
	}
	return out, full
}

type undo []func()

func (u *undo) add(f func()) { *u = append(*u, f) }

func (u undo) run() {
	for i := len(u) - 1; i >= 0; i-- {
		u[i]()
	}
}

// IPv6 leak protection. The tunnel carries IPv4 only, so on a full-tunnel
// profile all global IPv6 (2000::/3) is routed into the tunnel interface,
// where wireguard-go drops it (no peer has an IPv6 allowed-ip). Without this,
// IPv6 traffic would silently bypass the VPN on dual-stack networks.
const v6Blackhole = "2000::/3"

// blockIPv6 reports whether IPv6 must be captured: only for full tunnels, and
// not when the server itself is reached over IPv6 (that would loop).
func blockIPv6(full bool, endpoint netip.Addr) bool {
	return full && endpoint.Is4()
}

// v6TunnelAddr gives the tunnel interface a unique-local address derived from
// its IPv4 address (fd77:2fa::a.b.c.d), needed before IPv6 routes can use it.
func v6TunnelAddr(v4 netip.Addr) netip.Prefix {
	b := v4.As4()
	a := netip.AddrFrom16([16]byte{0xfd, 0x77, 0x02, 0xfa, 12: b[0], 13: b[1], 14: b[2], 15: b[3]})
	return netip.PrefixFrom(a, 128)
}
