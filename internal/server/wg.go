package server

import (
	"bytes"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WG drives the kernel (or wireguard-go userspace) interface through the
// standard `wg` and `ip` tools, so it behaves exactly like wg-quick.
type WG struct {
	Iface   string
	Port    int
	Subnet  netip.Prefix
	MTU     int
	DataDir string
	DryRun  bool

	mu     sync.Mutex
	routes map[string]bool // routes we added for router LANs
	stats  map[string]PeerStats
}

type PeerStats struct {
	Endpoint      string
	LastHandshake time.Time
	RX, TX        int64
}

func (w *WG) run(stdin string, name string, args ...string) (string, error) {
	if w.DryRun {
		log.Printf("[dry-run] %s %s", name, strings.Join(args, " "))
		return "", nil
	}
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// Setup creates/configures the interface. Safe to call repeatedly.
func (w *WG) Setup(privateKey string) error {
	w.routes = map[string]bool{}
	if w.DryRun {
		log.Printf("[dry-run] would configure %s on udp/%d, %s", w.Iface, w.Port, w.Subnet)
		return nil
	}
	if _, err := w.run("", "ip", "link", "show", w.Iface); err != nil {
		if _, err := w.run("", "ip", "link", "add", w.Iface, "type", "wireguard"); err != nil {
			log.Printf("kernel wireguard unavailable (%v); trying wireguard-go", err)
			if _, err2 := w.run("", "wireguard-go", w.Iface); err2 != nil {
				return fmt.Errorf("cannot create %s: %v / %v", w.Iface, err, err2)
			}
		}
	}
	keyFile := filepath.Join(w.DataDir, ".server.key")
	if err := os.WriteFile(keyFile, []byte(privateKey+"\n"), 0o600); err != nil {
		return err
	}
	defer os.Remove(keyFile)
	if _, err := w.run("", "wg", "set", w.Iface, "listen-port", strconv.Itoa(w.Port), "private-key", keyFile); err != nil {
		return err
	}
	srvAddr := netip.PrefixFrom(w.Subnet.Masked().Addr().Next(), w.Subnet.Bits())
	if _, err := w.run("", "ip", "address", "replace", srvAddr.String(), "dev", w.Iface); err != nil {
		return err
	}
	if _, err := w.run("", "ip", "link", "set", "mtu", strconv.Itoa(w.MTU), "up", "dev", w.Iface); err != nil {
		return err
	}
	return nil
}

type desiredPeer struct {
	PSK        string
	AllowedIPs []string
}

type currentPeer struct {
	PSK        string
	AllowedIPs []string
}

func (w *WG) dump() (map[string]currentPeer, error) {
	out, err := w.run("", "wg", "show", w.Iface, "dump")
	if err != nil {
		return nil, err
	}
	cur := map[string]currentPeer{}
	stats := map[string]PeerStats{}
	for i, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Split(line, "\t")
		if i == 0 || len(f) < 8 {
			continue
		}
		psk := f[1]
		if psk == "(none)" {
			psk = ""
		}
		var aips []string
		if f[3] != "(none)" {
			aips = strings.Split(f[3], ",")
		}
		sort.Strings(aips)
		cur[f[0]] = currentPeer{PSK: psk, AllowedIPs: aips}
		hs, _ := strconv.ParseInt(f[4], 10, 64)
		rx, _ := strconv.ParseInt(f[5], 10, 64)
		tx, _ := strconv.ParseInt(f[6], 10, 64)
		ps := PeerStats{RX: rx, TX: tx}
		if f[2] != "(none)" {
			ps.Endpoint = f[2]
		}
		if hs > 0 {
			ps.LastHandshake = time.Unix(hs, 0)
		}
		stats[f[0]] = ps
	}
	w.stats = stats
	return cur, nil
}

// Stats returns the last observed per-peer statistics.
func (w *WG) Stats() map[string]PeerStats {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make(map[string]PeerStats, len(w.stats))
	for k, v := range w.stats {
		out[k] = v
	}
	return out
}

// Apply makes the interface match desired. Peers not in desired are removed
// (this is what enforces 2FA session expiry).
func (w *WG) Apply(desired map[string]desiredPeer) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.DryRun {
		return nil
	}
	cur, err := w.dump()
	if err != nil {
		return err
	}
	var errs []string
	for pub, d := range desired {
		sort.Strings(d.AllowedIPs)
		c, ok := cur[pub]
		if ok && c.PSK == d.PSK && strings.Join(c.AllowedIPs, ",") == strings.Join(d.AllowedIPs, ",") {
			continue
		}
		args := []string{"set", w.Iface, "peer", pub, "allowed-ips", strings.Join(d.AllowedIPs, ",")}
		stdin := ""
		if d.PSK != "" {
			args = append(args, "preshared-key", "/dev/stdin")
			stdin = d.PSK + "\n"
		}
		if _, err := w.run(stdin, "wg", args...); err != nil {
			errs = append(errs, err.Error())
		} else {
			log.Printf("wg: peer %s… enabled (%s)", pub[:8], strings.Join(d.AllowedIPs, ","))
		}
	}
	for pub := range cur {
		if _, ok := desired[pub]; !ok {
			if _, err := w.run("", "wg", "set", w.Iface, "peer", pub, "remove"); err != nil {
				errs = append(errs, err.Error())
			} else {
				log.Printf("wg: peer %s… removed (inactive / 2FA session expired)", pub[:8])
			}
		}
	}
	// Kernel routes for LANs behind routers.
	want := map[string]bool{}
	for _, d := range desired {
		for _, a := range d.AllowedIPs {
			p, err := netip.ParsePrefix(a)
			if err != nil || w.Subnet.Contains(p.Addr()) && p.Bits() >= w.Subnet.Bits() {
				continue
			}
			want[p.Masked().String()] = true
		}
	}
	for r := range want {
		if !w.routes[r] {
			if _, err := w.run("", "ip", "route", "replace", r, "dev", w.Iface); err != nil {
				errs = append(errs, err.Error())
				continue
			}
			w.routes[r] = true
		}
	}
	for r := range w.routes {
		if !want[r] {
			_, _ = w.run("", "ip", "route", "del", r, "dev", w.Iface)
			delete(w.routes, r)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	_, _ = w.dump() // refresh stats
	return nil
}
