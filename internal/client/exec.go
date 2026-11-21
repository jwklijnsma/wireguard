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
