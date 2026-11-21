//go:build linux

package client

import (
	"fmt"
	"net/netip"
	"strings"
)

const defaultIfName = "wg2fa0"

func configureOS(ifname string, addr netip.Prefix, routes []netip.Prefix, dns []string, endpoint netip.Addr, mtu int, logf func(string, ...any)) (func(), error) {
	var u undo
	if _, err := run("ip", "address", "add", addr.String(), "dev", ifname); err != nil {
		return u.run, err
	}
	if _, err := run("ip", "link", "set", "mtu", fmt.Sprint(mtu), "up", "dev", ifname); err != nil {
		return u.run, err
	}
	rs, full := splitDefault(routes)
	if full && endpoint.Is4() {
		out, _ := run("ip", "-4", "route", "get", endpoint.String())
		f := strings.Fields(out)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "via" {
				gw := f[i+1]
				if _, err := run("ip", "route", "replace", endpoint.String()+"/32", "via", gw); err == nil {
					u.add(func() { run("ip", "route", "del", endpoint.String()+"/32") })
				}
				break
			}
		}
	}
	for _, r := range rs {
		r := r
		if _, err := run("ip", "route", "replace", r.String(), "dev", ifname); err != nil {
			logf("route %s: %v", r, err)
		}
	}
	if len(dns) > 0 {
		if _, err := run("resolvectl", append([]string{"dns", ifname}, dns...)...); err == nil {
			run("resolvectl", "domain", ifname, "~.")
		} else {
			logf("DNS not configured (resolvectl unavailable): %v", err)
		}
	}
	// routes and resolvectl settings disappear with the interface
	return u.run, nil
}
