//go:build windows

package client

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

const defaultIfName = "WG2FA"

func ifIndex(name string) (int, error) {
	var last error
	for i := 0; i < 20; i++ { // the adapter can take a moment to appear
		ifc, err := net.InterfaceByName(name)
		if err == nil {
			return ifc.Index, nil
		}
		last = err
		time.Sleep(250 * time.Millisecond)
	}
	return 0, last
}

func defaultGateway() (gw string, idx string) {
	out, err := run("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.InterfaceAlias -ne 'WG2FA' } | Sort-Object RouteMetric | Select-Object -First 1 | ForEach-Object { \"$($_.NextHop) $($_.InterfaceIndex)\" }")
	if err != nil {
		return "", ""
	}
	f := strings.Fields(out)
	if len(f) == 2 {
		return f[0], f[1]
	}
	return "", ""
}

func configureOS(ifname string, addr netip.Prefix, routes []netip.Prefix, dns []string, endpoint netip.Addr, mtu int, logf func(string, ...any)) (func(), error) {
	var u undo
	idx, err := ifIndex(ifname)
	if err != nil {
		return u.run, fmt.Errorf("adapter %s not found: %w", ifname, err)
	}
	id := fmt.Sprint(idx)
	mask := net.IP(net.CIDRMask(addr.Bits(), 32)).String()
	if _, err := run("netsh", "interface", "ipv4", "set", "address", "name="+id, "source=static", "address="+addr.Addr().String(), "mask="+mask, "gateway=none"); err != nil {
		return u.run, err
	}
	run("netsh", "interface", "ipv4", "set", "subinterface", id, fmt.Sprintf("mtu=%d", mtu), "store=active")
	run("netsh", "interface", "ipv4", "set", "interface", id, "metric=5")

	rs, full := splitDefault(routes)
	if full && endpoint.Is4() {
		if gw, gidx := defaultGateway(); gw != "" {
			ep := endpoint.String() + "/32"
			if _, err := run("netsh", "interface", "ipv4", "add", "route", "prefix="+ep, "interface="+gidx, "nexthop="+gw, "store=active"); err == nil {
				u.add(func() {
					run("netsh", "interface", "ipv4", "delete", "route", "prefix="+ep, "interface="+gidx, "nexthop="+gw, "store=active")
				})
			} else {
				logf("endpoint route: %v", err)
			}
		}
	}
	for _, r := range rs {
		if _, err := run("netsh", "interface", "ipv4", "add", "route", "prefix="+r.String(), "interface="+id, "nexthop=0.0.0.0", "metric=5", "store=active"); err != nil {
			logf("route %s: %v", r, err)
		}
	}
	for i, d := range dns {
		if i == 0 {
			run("netsh", "interface", "ipv4", "set", "dnsservers", "name="+id, "source=static", "address="+d, "register=none", "validate=no")
		} else {
			run("netsh", "interface", "ipv4", "add", "dnsservers", "name="+id, "address="+d, fmt.Sprintf("index=%d", i+1), "validate=no")
		}
	}
	if len(dns) > 0 {
		run("ipconfig", "/flushdns")
	}
	// interface routes and DNS vanish together with the Wintun adapter
	if blockIPv6(full, endpoint) {
		v6 := v6TunnelAddr(addr.Addr())
		if _, err := run("netsh", "interface", "ipv6", "add", "address", "interface="+id, "address="+v6.String(), "store=active"); err != nil {
			logf("IPv6 leak protection: %v", err)
		} else if _, err := run("netsh", "interface", "ipv6", "add", "route", "prefix="+v6Blackhole, "interface="+id, "metric=1", "store=active"); err != nil {
			logf("IPv6 leak protection: %v", err)
		} else {
			run("netsh", "interface", "ipv6", "set", "interface", id, "metric=5")
			logf("IPv6 leak protection active (%s -> %s)", v6Blackhole, ifname)
		}
	}
	return u.run, nil
}
