package client

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/jwklijnsma/wireguard/internal/wgkey"
)

// TunnelConfig is what the server hands out at login.
type TunnelConfig struct {
	Address         string   `json:"address"`
	DNS             []string `json:"dns"`
	MTU             int      `json:"mtu"`
	ServerPublicKey string   `json:"server_public_key"`
	PresharedKey    string   `json:"preshared_key"`
	Endpoint        string   `json:"endpoint"`
	AllowedIPs      []string `json:"allowed_ips"`
	Keepalive       int      `json:"keepalive"`
}

// Tunnel is an in-process wireguard-go device plus OS network config.
type Tunnel struct {
	mu      sync.Mutex
	dev     *device.Device
	tun     tun.Device
	ifname  string
	cleanup func()
	log     func(string, ...any)
}

type Stats struct {
	RX, TX        int64
	LastHandshake time.Time
	Interface     string
}

// Up creates the interface and brings the tunnel up.
func (t *Tunnel) Up(cfg TunnelConfig, privateKey string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dev != nil {
		return fmt.Errorf("tunnel already up")
	}
	addr, err := netip.ParsePrefix(cfg.Address)
	if err != nil {
		return fmt.Errorf("bad address %q: %w", cfg.Address, err)
	}
	host, port, err := net.SplitHostPort(cfg.Endpoint)
	if err != nil {
		return fmt.Errorf("bad endpoint %q: %w", cfg.Endpoint, err)
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("resolve %s: %v", host, err)
	}
	var ep netip.Addr
	for _, ip := range ips { // prefer IPv4
		if v4 := ip.To4(); v4 != nil {
			ep, _ = netip.AddrFromSlice(v4)
			break
		}
	}
	if !ep.IsValid() {
		ep, _ = netip.AddrFromSlice(ips[0])
	}
	var routes []netip.Prefix
	for _, a := range cfg.AllowedIPs {
		p, err := netip.ParsePrefix(strings.TrimSpace(a))
		if err != nil {
			continue
		}
		routes = append(routes, p.Masked())
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = 1420
	}

	td, err := tun.CreateTUN(defaultIfName, mtu)
	if err != nil {
		return fmt.Errorf("create tun (are you running as administrator/root?): %w", err)
	}
	name, err := td.Name()
	if err != nil {
		td.Close()
		return err
	}
	logger := device.NewLogger(device.LogLevelError, "wg: ")
	dev := device.NewDevice(td, conn.NewDefaultBind(), logger)

	uapi, err := uapiConfig(cfg, privateKey, netip.AddrPortFrom(ep, mustPort(port)))
	if err != nil {
		dev.Close()
		return err
	}
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return fmt.Errorf("configure device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return err
	}
	cleanup, err := configureOS(name, addr, routes, cfg.DNS, ep, mtu, t.logf)
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		dev.Close()
		return fmt.Errorf("network setup: %w", err)
	}
	t.dev, t.tun, t.ifname, t.cleanup = dev, td, name, cleanup
	t.logf("tunnel up on %s, %s via %s", name, cfg.Address, cfg.Endpoint)
	return nil
}

func (t *Tunnel) logf(f string, a ...any) {
	if t.log != nil {
		t.log(f, a...)
	}
}

func mustPort(s string) uint16 {
	p, _ := strconv.Atoi(s)
	return uint16(p)
}

func uapiConfig(cfg TunnelConfig, priv string, ep netip.AddrPort) (string, error) {
	hk, err := wgkey.Hex(priv)
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}
	hp, err := wgkey.Hex(cfg.ServerPublicKey)
	if err != nil {
		return "", fmt.Errorf("server key: %w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\nreplace_peers=true\npublic_key=%s\n", hk, hp)
	if cfg.PresharedKey != "" {
		hs, err := wgkey.Hex(cfg.PresharedKey)
		if err != nil {
			return "", fmt.Errorf("psk: %w", err)
		}
		fmt.Fprintf(&b, "preshared_key=%s\n", hs)
	}
	fmt.Fprintf(&b, "endpoint=%s\npersistent_keepalive_interval=%d\nreplace_allowed_ips=true\n", ep, cfg.Keepalive)
	for _, a := range cfg.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", strings.TrimSpace(a))
	}
	return b.String(), nil
}

// Down tears the tunnel down and restores routes/DNS.
func (t *Tunnel) Down() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dev == nil {
		return
	}
	if t.cleanup != nil {
		t.cleanup()
	}
	t.dev.Close()
	t.dev, t.tun, t.cleanup = nil, nil, nil
	t.logf("tunnel down")
}

func (t *Tunnel) IsUp() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.dev != nil
}

func (t *Tunnel) Stats() Stats {
	t.mu.Lock()
	defer t.mu.Unlock()
	var s Stats
	if t.dev == nil {
		return s
	}
	s.Interface = t.ifname
	out, err := t.dev.IpcGet()
	if err != nil {
		return s
	}
	var sec int64
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		n, _ := strconv.ParseInt(v, 10, 64)
		switch k {
		case "rx_bytes":
			s.RX += n
		case "tx_bytes":
			s.TX += n
		case "last_handshake_time_sec":
			sec = n
		}
	}
	if sec > 0 {
		s.LastHandshake = time.Unix(sec, 0)
	}
	return s
}
