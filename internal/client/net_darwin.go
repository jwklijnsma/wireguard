//go:build darwin

package client

import (
	"fmt"
	"net/netip"
	"strings"
)

const defaultIfName = "utun"

func defaultGateway() (gw, iface string) {
	out, err := run("route", "-n", "get", "default")
	if err != nil {
		return "", ""
	}
	for _, l := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "gateway":
			gw = strings.TrimSpace(v)
		case "interface":
			iface = strings.TrimSpace(v)
		}
	}
	return
}

func networkServices() []string {
	out, err := run("networksetup", "-listallnetworkservices")
	if err != nil {
		return nil
	}
	var svcs []string
	for i, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if i == 0 || l == "" || strings.HasPrefix(l, "*") {
			continue
		}
		svcs = append(svcs, l)
	}
	return svcs
}

func configureOS(ifname string, addr netip.Prefix, routes []netip.Prefix, dns []string, endpoint netip.Addr, mtu int, logf func(string, ...any)) (func(), error) {
	var u undo
	ip := addr.Addr().String()
	if _, err := run("ifconfig", ifname, "inet", addr.String(), ip, "alias"); err != nil {
		return u.run, err
	}
	if _, err := run("ifconfig", ifname, "mtu", fmt.Sprint(mtu), "up"); err != nil {
		return u.run, err
	}
	rs, full := splitDefault(routes)
	if full {
		gw, _ := defaultGateway()
		if gw != "" && endpoint.Is4() {
			if _, err := run("route", "-q", "-n", "add", "-inet", endpoint.String()+"/32", gw); err == nil {
				u.add(func() { run("route", "-q", "-n", "delete", "-inet", endpoint.String()+"/32", gw) })
			}
		}
	}
	for _, r := range rs {
		if r.Contains(addr.Addr()) && r.Bits() == 32 {
			continue
		}
		r := r
		if _, err := run("route", "-q", "-n", "add", "-inet", r.String(), "-interface", ifname); err != nil {
			logf("route %s: %v", r, err)
			continue
		}
		u.add(func() { run("route", "-q", "-n", "delete", "-inet", r.String(), "-interface", ifname) })
	}
	if len(dns) > 0 {
		for _, svc := range networkServices() {
			svc := svc
			out, err := run("networksetup", "-getdnsservers", svc)
			if err != nil {
				continue
			}
			prev := []string{"Empty"}
			if !strings.Contains(out, "aren't any") {
				prev = strings.Fields(out)
			}
			if _, err := run("networksetup", append([]string{"-setdnsservers", svc}, dns...)...); err == nil {
				u.add(func() { run("networksetup", append([]string{"-setdnsservers", svc}, prev...)...) })
			}
		}
		run("dscacheutil", "-flushcache")
		run("killall", "-HUP", "mDNSResponder")
	}
	if blockIPv6(full, endpoint) {
		v6 := v6TunnelAddr(addr.Addr())
		if _, err := run("ifconfig", ifname, "inet6", v6.Addr().String(), "prefixlen", "128", "alias"); err != nil {
			logf("IPv6 leak protection: %v", err)
		} else if _, err := run("route", "-q", "-n", "add", "-inet6", v6Blackhole, "-interface", ifname); err != nil {
			logf("IPv6 leak protection: %v", err)
		} else {
			u.add(func() { run("route", "-q", "-n", "delete", "-inet6", v6Blackhole, "-interface", ifname) })
			logf("IPv6 leak protection active (%s -> %s)", v6Blackhole, ifname)
		}
	}
	return u.run, nil
}
