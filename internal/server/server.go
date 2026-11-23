package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/jwklijnsma/wireguard/internal/wgkey"
)

type Config struct {
	Listen         string // web GUI + client API, e.g. :8080
	DataDir        string
	Iface          string
	Endpoint       string // public host[:port] clients connect to
	Port           int    // WireGuard UDP port
	Subnet         string // VPN subnet, e.g. 10.8.0.0/24
	MTU            int
	DryRun         bool
	AdminUser      string
	AdminPassword  string
	TLSCert        string
	TLSKey         string
	Issuer         string   // name shown in authenticator apps
	TrustProxy     bool     // honour X-Forwarded-* from TrustedProxies (default: loopback + private ranges)
	TrustedProxies []string // CIDRs of reverse proxies whose X-Forwarded-* headers are trusted
	AdminNets      []string // if set, /admin/* is only reachable from these CIDRs
	HSTS           bool     // send Strict-Transport-Security on HTTPS responses
	Firewall       bool     // manage the default-deny forwarding policy (iptables)
	BlockNets      []string // destinations no VPN peer may reach (management networks, ...)
	StateKey       string   // passphrase encrypting state.json at rest (optional)
	Version        string
	DownloadDirs   []string // client installers offered on the "Get connected" page
}

type Server struct {
	cfg     Config
	store   *Store
	wg      *WG
	subnet  netip.Prefix
	sess    *sessions
	limit   *limiter
	changed chan struct{}
	tmpl    *templates

	trusted      []netip.Prefix
	adminNets    []netip.Prefix
	blockNets    []netip.Prefix
	lastFirewall string
}

func parseNets(list []string, what string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, a := range list {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		p, err := netip.ParsePrefix(a)
		if err != nil {
			ad, err2 := netip.ParseAddr(a)
			if err2 != nil {
				return nil, fmt.Errorf("%s: invalid network %q", what, a)
			}
			p = netip.PrefixFrom(ad, ad.BitLen())
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func New(cfg Config) (*Server, error) {
	subnet, err := netip.ParsePrefix(cfg.Subnet)
	if err != nil || !subnet.Addr().Is4() {
		return nil, fmt.Errorf("invalid IPv4 subnet %q", cfg.Subnet)
	}
	if cfg.Endpoint == "" {
		return nil, errors.New("endpoint (public hostname of this server) is required")
	}
	if !strings.Contains(cfg.Endpoint, ":") || strings.HasSuffix(cfg.Endpoint, "]") {
		cfg.Endpoint = net.JoinHostPort(strings.Trim(cfg.Endpoint, "[]"), fmt.Sprint(cfg.Port))
	}
	trusted, err := parseNets(cfg.TrustedProxies, "trusted proxies")
	if err != nil {
		return nil, err
	}
	if cfg.TrustProxy && len(trusted) == 0 {
		trusted, _ = parseNets([]string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"}, "")
	}
	adminNets, err := parseNets(cfg.AdminNets, "admin networks")
	if err != nil {
		return nil, err
	}
	blockNets, err := parseNets(cfg.BlockNets, "blocked networks")
	if err != nil {
		return nil, err
	}
	st, err := OpenStore(cfg.DataDir, cfg.StateKey)
	if err != nil {
		return nil, err
	}
	t, err := loadTemplates()
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg: cfg, store: st, subnet: subnet.Masked(),
		sess: newSessions(), limit: newLimiter(),
		changed: make(chan struct{}, 1), tmpl: t,
		trusted: trusted, adminNets: adminNets, blockNets: blockNets,
		wg: &WG{Iface: cfg.Iface, Port: cfg.Port, Subnet: subnet.Masked(), MTU: cfg.MTU, DataDir: cfg.DataDir, DryRun: cfg.DryRun},
	}
	if err := s.bootstrap(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) bootstrap() error {
	return s.store.Update(func(st *state) error {
		if st.ServerPrivateKey == "" {
			priv, pub, err := wgkey.Generate()
			if err != nil {
				return err
			}
			st.ServerPrivateKey, st.ServerPublicKey = priv, pub
			log.Printf("generated server key, public key %s", pub)
		}
		if len(st.Profiles) == 0 {
			st.Profiles = []*Profile{
				{ID: newID(), Name: "Full tunnel (2FA)", Description: "All traffic through the VPN, 2FA session of 12 hours",
					AllowedIPs: []string{"0.0.0.0/0"}, DNS: []string{"1.1.1.1", "9.9.9.9"}, MTU: 1420, Keepalive: 25, SessionHours: 12, Require2FA: true},
				{ID: newID(), Name: "Split tunnel (2FA)", Description: "Only the VPN network through the tunnel",
					AllowedIPs: []string{s.subnet.String()}, MTU: 1420, Keepalive: 25, SessionHours: 12, Require2FA: true},
				{ID: newID(), Name: "Site-to-site router", Description: "For routers (MikroTik, OpenWrt, pfSense, ...): always on, no 2FA",
					AllowedIPs: []string{s.subnet.String()}, MTU: 1420, Keepalive: 25, SessionHours: 0, Require2FA: false},
			}
		}
		if len(st.Users) == 0 {
			name := s.cfg.AdminUser
			if name == "" {
				name = "admin"
			}
			pw := s.cfg.AdminPassword
			if pw == "" {
				pw = randToken()[:20]
				log.Printf("=====================================================")
				log.Printf(" first start: created admin user %q", name)
				log.Printf(" password: %s", pw)
				log.Printf(" log in to the web GUI and enrol 2FA right away")
				log.Printf("=====================================================")
			}
			st.Users = append(st.Users, &User{ID: newID(), Username: name, PassHash: HashPassword(pw),
				IsAdmin: true, ProfileID: st.Profiles[0].ID, CreatedAt: time.Now().UTC()})
		}
		return nil
	})
}

// notify asks the reconciler to push state into WireGuard now.
func (s *Server) notify() {
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

func (s *Server) desired() map[string]desiredPeer {
	now := time.Now()
	out := map[string]desiredPeer{}
	s.store.View(func(st *state) {
		for _, p := range st.Peers {
			if !st.isActive(p, now) {
				continue
			}
			aips := []string{p.Address + "/32"}
			if p.Kind == KindRouter {
				aips = append(aips, p.RemoteSubnets...)
			}
			out[p.PublicKey] = desiredPeer{PSK: p.PresharedKey, AllowedIPs: aips}
		}
	})
	return out
}

func (s *Server) reconcileLoop(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		s.applyFirewall() // rules first, so a peer is never live without its policy
		if err := s.wg.Apply(s.desired()); err != nil {
			log.Printf("reconcile: %v", err)
		}
		s.applyFirewall()
		s.sess.gc()
		s.limit.gc()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.changed:
		}
	}
}

func (s *Server) Run(ctx context.Context) error {
	var priv string
	s.store.View(func(st *state) { priv = st.ServerPrivateKey })
	if err := s.wg.Setup(priv); err != nil {
		return fmt.Errorf("wireguard setup: %w", err)
	}
	go s.reconcileLoop(ctx)

	srv := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sc)
	}()
	log.Printf("web GUI + client API on %s (wireguard %s udp/%d, endpoint %s)", s.cfg.Listen, s.cfg.Iface, s.cfg.Port, s.cfg.Endpoint)
	var err error
	if s.cfg.TLSCert != "" {
		err = srv.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
	} else {
		err = srv.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// clientConfig is what both the native client and the .conf export use.
type clientConfig struct {
	Address         string   `json:"address"`
	PrivateKey      string   `json:"private_key,omitempty"`
	DNS             []string `json:"dns"`
	MTU             int      `json:"mtu"`
	ServerPublicKey string   `json:"server_public_key"`
	PresharedKey    string   `json:"preshared_key"`
	Endpoint        string   `json:"endpoint"`
	AllowedIPs      []string `json:"allowed_ips"`
	Keepalive       int      `json:"keepalive"`
}

func (s *Server) buildConfig(st *state, p *Peer) clientConfig {
	prof := st.profile(p.ProfileID)
	c := clientConfig{
		Address: p.Address + "/32", PrivateKey: p.PrivateKey, ServerPublicKey: st.ServerPublicKey,
		PresharedKey: p.PresharedKey, Endpoint: s.cfg.Endpoint, MTU: 1420, Keepalive: 25,
	}
	if prof != nil {
		c.DNS = prof.DNS
		c.AllowedIPs = append([]string(nil), prof.AllowedIPs...)
		if prof.MTU > 0 {
			c.MTU = prof.MTU
		}
		c.Keepalive = prof.Keepalive
	}
	if p.Kind == KindRouter {
		c.Address = netip.PrefixFrom(netip.MustParseAddr(p.Address), s.subnet.Bits()).String()
		// routers also reach the LANs of all other routers
		for _, o := range st.Peers {
			if o.Kind == KindRouter && o.ID != p.ID && o.Enabled {
				c.AllowedIPs = append(c.AllowedIPs, o.RemoteSubnets...)
			}
		}
	}
	if len(c.AllowedIPs) == 0 {
		c.AllowedIPs = []string{s.subnet.String()}
	}
	return c
}
