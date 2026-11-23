package server

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func ruleStrings(rules []fwRule) []string {
	var out []string
	for _, r := range rules {
		out = append(out, strings.Join(r.spec, " "))
	}
	return out
}

func TestFirewallDefaultDeny(t *testing.T) {
	s, _ := newTestServer(t)
	s.blockNets = []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	future := time.Now().Add(time.Hour)
	var rules []string
	s.store.Update(func(st *state) error {
		var full, split, router string
		for _, p := range st.Profiles {
			switch {
			case strings.HasPrefix(p.Name, "Full"):
				full = p.ID
			case strings.HasPrefix(p.Name, "Split"):
				split = p.ID
				p.AllowPeerToPeer = true
			default:
				router = p.ID
			}
		}
		uid := st.Users[0].ID
		st.Peers = append(st.Peers,
			&Peer{ID: "a", Name: "laptop", Kind: KindDevice, UserID: uid, ProfileID: full, Address: "10.8.0.2", Enabled: true, ActiveUntil: future, PublicKey: "a"},
			&Peer{ID: "b", Name: "phone", Kind: KindDevice, UserID: uid, ProfileID: split, Address: "10.8.0.3", Enabled: true, ActiveUntil: future, PublicKey: "b"},
			&Peer{ID: "c", Name: "locked", Kind: KindDevice, UserID: uid, ProfileID: full, Address: "10.8.0.4", Enabled: true, PublicKey: "c"},
			&Peer{ID: "d", Name: "office", Kind: KindRouter, ProfileID: router, Address: "10.8.0.5", RemoteSubnets: []string{"192.168.20.0/24"}, Enabled: true, PublicKey: "d"},
			&Peer{ID: "e", Name: "dc", Kind: KindRouter, ProfileID: router, Address: "10.8.0.6", RemoteSubnets: []string{"10.20.0.0/16"}, Enabled: true, PublicKey: "e"},
		)
		rules = ruleStrings(s.firewallRules(st, time.Now()))
		return nil
	})
	joined := strings.Join(rules, "\n")
	has := func(r string) bool {
		for _, x := range rules {
			if x == r {
				return true
			}
		}
		return false
	}
	index := func(r string) int {
		for i, x := range rules {
			if x == r {
				return i
			}
		}
		return -1
	}
	if rules[0] != "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" || rules[len(rules)-1] != "-j DROP" {
		t.Fatalf("must start with established and end with default drop:\n%s", joined)
	}
	// blocked network comes before any accept
	if b := index("-i wg0 -d 192.168.1.0/24 -j DROP"); b < 0 || b > index("-i wg0 -s 10.8.0.2/32 -d 0.0.0.0/0 -j ACCEPT") {
		t.Fatalf("block-net rule missing or after accepts:\n%s", joined)
	}
	// full tunnel: internet yes, other peers no (drop placed before the accept)
	if index("-i wg0 -s 10.8.0.2/32 -d 10.8.0.0/24 -j DROP") > index("-i wg0 -s 10.8.0.2/32 -d 0.0.0.0/0 -j ACCEPT") {
		t.Fatal("peer-to-peer drop must precede full-tunnel accept")
	}
	// split tunnel with peer-to-peer allowed: only the VPN subnet, no drop
	if !has("-i wg0 -s 10.8.0.3/32 -d 10.8.0.0/24 -j ACCEPT") || has("-i wg0 -s 10.8.0.3/32 -d 10.8.0.0/24 -j DROP") || strings.Contains(joined, "-s 10.8.0.3/32 -d 0.0.0.0/0") {
		t.Fatalf("split tunnel rules wrong:\n%s", joined)
	}
	// locked peer (no 2FA session) gets nothing
	if strings.Contains(joined, "10.8.0.4") {
		t.Fatal("locked peer must not have accept rules")
	}
	// routers: their LAN is a source, other routers' LANs are destinations
	for _, r := range []string{
		"-i wg0 -s 192.168.20.0/24 -d 10.20.0.0/16 -j ACCEPT",
		"-i wg0 -s 10.20.0.0/16 -d 192.168.20.0/24 -j ACCEPT",
		"-i wg0 -s 10.8.0.5/32 -d 10.8.0.0/24 -j DROP",
	} {
		if !has(r) {
			t.Errorf("missing %q", r)
		}
	}
	script := restoreScript(s.firewallRules(&s.store.s, time.Now()))
	if !strings.HasPrefix(script, "*filter\n:WG2FA-FWD - [0:0]\n") || !strings.HasSuffix(script, "COMMIT\n") {
		t.Fatal("bad restore script")
	}
}

func TestProxyTrust(t *testing.T) {
	s, _ := newTestServer(t)
	s.cfg.TrustProxy = true
	s.trusted, _ = parseNets([]string{"172.18.0.0/16"}, "")
	req := func(remote, xff, proto string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		if proto != "" {
			r.Header.Set("X-Forwarded-Proto", proto)
		}
		return r
	}
	// direct client bypassing the proxy cannot spoof
	if ip := s.clientIP(req("203.0.113.9:5000", "10.0.0.1", "https")); ip != "203.0.113.9" {
		t.Fatalf("spoofed via direct access: %s", ip)
	}
	if s.isHTTPS(req("203.0.113.9:5000", "", "https")) {
		t.Fatal("X-Forwarded-Proto honoured from untrusted peer")
	}
	// through the proxy: rightmost untrusted hop wins, client-supplied left part ignored
	if ip := s.clientIP(req("172.18.0.2:5000", "1.2.3.4, 198.51.100.7", "https")); ip != "198.51.100.7" {
		t.Fatalf("got %s want 198.51.100.7", ip)
	}
	if !s.isHTTPS(req("172.18.0.2:5000", "", "https")) {
		t.Fatal("trusted proxy proto ignored")
	}
}

func TestAdminNetsAndHSTS(t *testing.T) {
	s, ts := newTestServer(t)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	// admin without 2FA would be forced to /account; give it a password-only profile for this test
	s.store.Update(func(st *state) error {
		st.Users[0].TOTPEnabled = true
		st.Users[0].TOTPSecret = "JBSWY3DPEHPK3PXP"
		return nil
	})
	tok := s.sess.create(s.store.s.Users[0].ID, false, time.Hour)
	u, _ := url.Parse(ts.URL)
	jar.SetCookies(u, []*http.Cookie{{Name: cookieName, Value: tok}})

	s.adminNets, _ = parseNets([]string{"10.8.0.0/24"}, "")
	r, _ := c.Get(ts.URL + "/admin/users")
	if r.StatusCode != 403 {
		t.Fatalf("admin page from outside admin nets: %d", r.StatusCode)
	}
	r, _ = c.Get(ts.URL + "/")
	var b strings.Builder
	buf := make([]byte, 1<<16)
	for {
		n, err := r.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	if strings.Contains(b.String(), "All peers") || strings.Contains(b.String(), `href="/admin/users"`) {
		t.Fatal("admin view leaked outside admin nets")
	}
	s.adminNets, _ = parseNets([]string{"127.0.0.0/8"}, "")
	if r, _ := c.Get(ts.URL + "/admin/users"); r.StatusCode != 200 {
		t.Fatalf("admin page from admin net: %d", r.StatusCode)
	}

	s.cfg.HSTS = true
	h := s.routes()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://vpn.example.nl/login", nil)
	h.ServeHTTP(rec, req)
	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("HSTS missing on HTTPS")
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://vpn.example.nl/login", nil))
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS must not be sent over plain HTTP")
	}
}

func TestLimiterBounded(t *testing.T) {
	l := newLimiter()
	for i := 0; i < limiterMaxKeys+5000; i++ {
		l.failed(fmt.Sprintf("spray-%d", i))
	}
	if n := l.size(); n > limiterMaxKeys {
		t.Fatalf("limiter grew to %d keys", n)
	}
	for i := 0; i < 500; i++ {
		l.failed("hot")
	}
	if len(l.fail["hot"]) > limitMax*2 || !l.blocked("hot") {
		t.Fatal("per-key history must be capped and still block")
	}
}

func TestStateEncryption(t *testing.T) {
	dir := t.TempDir()
	// start plaintext, then migrate
	st, err := OpenStore(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	st.Update(func(s *state) error { s.ServerPrivateKey = "TOP-SECRET-KEY"; return nil })
	key := "correct horse battery staple"
	if _, err := OpenStore(dir, key); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if !isEncrypted(raw) || strings.Contains(string(raw), "TOP-SECRET-KEY") {
		t.Fatal("state not encrypted after migration")
	}
	if _, err := OpenStore(dir, ""); err == nil {
		t.Fatal("encrypted state opened without key")
	}
	if _, err := OpenStore(dir, "wrong key wrong key"); err == nil {
		t.Fatal("encrypted state opened with wrong key")
	}
	st2, err := OpenStore(dir, key)
	if err != nil || st2.s.ServerPrivateKey != "TOP-SECRET-KEY" {
		t.Fatalf("reopen failed: %v", err)
	}
	// tampering is detected
	tampered := append([]byte{}, raw...)
	tampered[len(tampered)-10] ^= 1
	os.WriteFile(filepath.Join(dir, "state.json"), tampered, 0o600)
	if _, err := OpenStore(dir, key); err == nil {
		t.Fatal("tampered state accepted")
	}
	os.WriteFile(filepath.Join(dir, "state.json"), raw, 0o600)

	// encrypted backup restores with the backup key
	out := filepath.Join(t.TempDir(), "backup.enc")
	if err := Backup(dir, key, "another backup passphrase", out); err != nil {
		t.Fatal(err)
	}
	rdir := t.TempDir()
	b, _ := os.ReadFile(out)
	os.WriteFile(filepath.Join(rdir, "state.json"), b, 0o600)
	st3, err := OpenStore(rdir, "another backup passphrase")
	if err != nil || st3.s.ServerPrivateKey != "TOP-SECRET-KEY" {
		t.Fatalf("restore failed: %v", err)
	}
	if _, err := OpenStore(t.TempDir(), "short"); err == nil {
		t.Fatal("short key accepted")
	}
}
