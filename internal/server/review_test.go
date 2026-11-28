package server

import (
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jwklijnsma/wireguard/internal/totp"
	"github.com/jwklijnsma/wireguard/internal/wgkey"
)

// Tests for the security review feedback on PR "tie peer lifetime to the
// 2FA session": revoke sweep, TOTP replay + rate limiting, key storage.

func TestTOTPReplayWithinWindow(t *testing.T) {
	secret := totp.NewSecret()
	u := &User{TOTPSecret: secret, TOTPEnabled: true}
	now := time.Now()
	code, _ := totp.Code(secret, now)
	if !acceptTOTP(u, code, now) {
		t.Fatal("fresh code rejected")
	}
	// same code, same 30 s window, a few seconds later
	if acceptTOTP(u, code, now.Add(5*time.Second)) {
		t.Fatal("replayed code accepted inside its window")
	}
	// the previous step's code is still within the skew window but older
	prev, _ := totp.Code(secret, now.Add(-30*time.Second))
	if acceptTOTP(u, prev, now) {
		t.Fatal("older code accepted after a newer one")
	}
	next, _ := totp.Code(secret, now.Add(30*time.Second))
	if !acceptTOTP(u, next, now.Add(30*time.Second)) {
		t.Fatal("next step's code rejected")
	}
}

func TestTOTPRateLimitPerUserAndPerIP(t *testing.T) {
	s, _ := newTestServer(t)
	// one user attacked from many IPs
	for i := 0; i < limitMax; i++ {
		s.totpFailed("victim", netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}).String())
	}
	if !s.totpBlocked("victim", "203.0.113.9") {
		t.Fatal("per-user 2FA limit not enforced across IPs")
	}
	// one IP guessing codes for many users
	for i := 0; i < limitMax; i++ {
		s.totpFailed(newID(), "203.0.113.50")
	}
	if !s.totpBlocked("someone-else", "203.0.113.50") {
		t.Fatal("per-IP 2FA limit not enforced across users")
	}
	// success clears the user budget but not the IP budget
	s.totpSucceeded("someone-else")
	if !s.totpBlocked("someone-else", "203.0.113.50") {
		t.Fatal("a success must not reset the per-IP budget")
	}
}

func TestAPILoginTOTPLimitedPerUser(t *testing.T) {
	s, ts := newTestServer(t)
	var secret, uid string
	s.store.Update(func(st *state) error {
		u := st.userByName("admin")
		u.TOTPSecret, u.TOTPEnabled = totp.NewSecret(), true
		secret, uid = u.TOTPSecret, u.ID
		return nil
	})
	_, pub, _ := wgkey.Generate()
	post := func(code string) int {
		b, _ := json.Marshal(loginReq{Username: "admin", Password: "correct-horse-battery", TOTP: code, PublicKey: pub, DeviceName: "x"})
		r, err := http.Post(ts.URL+"/api/v1/client/login", "application/json", strings.NewReader(string(b)))
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}
	if c := post("000000"); c != 401 {
		t.Fatalf("wrong code: %d", c)
	}
	s.limit.mu.Lock()
	n := len(s.limit.fail[totpUserKey(uid)])
	s.limit.mu.Unlock()
	if n != 1 {
		t.Fatalf("2FA failure counted %d times against the user, want 1", n)
	}
	// burn the rest of the per-user budget from "other IPs"
	for i := 1; i < limitMax; i++ {
		s.limit.failed(totpUserKey(uid))
	}
	code, _ := totp.Code(secret, time.Now())
	if c := post(code); c != 429 {
		t.Fatalf("valid code while user is rate limited: want 429, got %d", c)
	}
}

// newDevice drives the real handler without the auth middleware.
func newDevice(t *testing.T, s *Server, form url.Values) (*Peer, *User) {
	t.Helper()
	var me User
	s.store.View(func(st *state) { me = *st.userByName("admin") })
	req := httptest.NewRequest("POST", "/devices", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.deviceCreate(httptest.NewRecorder(), req, &me, &webSession{UserID: me.ID})
	var p *Peer
	s.store.View(func(st *state) {
		for _, x := range st.Peers {
			if x.Name == form.Get("name") {
				c := *x
				p = &c
			}
		}
	})
	if p == nil {
		t.Fatal("device not created")
	}
	return p, &me
}

func TestGeneratedPrivateKeyNeverPersisted(t *testing.T) {
	s, _ := newTestServer(t)
	p, _ := newDevice(t, s, url.Values{"name": {"phone"}})
	var cfg clientConfig
	s.store.View(func(st *state) { cfg = s.buildConfig(st, st.peer(p.ID)) })
	if cfg.PrivateKey == "" {
		t.Fatal("one-time private key not available for the QR/config")
	}
	raw, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), cfg.PrivateKey) || strings.Contains(string(raw), `"private_key"`) {
		t.Fatal("client private key was written to state.json")
	}
	// the device page shows the one-time key, the warning and the rotate form
	var me User
	s.store.View(func(st *state) { me = *st.userByName("admin") })
	req := httptest.NewRequest("GET", "/devices/"+p.ID, nil)
	req.SetPathValue("id", p.ID)
	rec := httptest.NewRecorder()
	s.devicePage(rec, req, &me, &webSession{UserID: me.ID, CSRF: "t"})
	if body := html.UnescapeString(rec.Body.String()); rec.Code != 200 || !strings.Contains(body, cfg.PrivateKey) ||
		!strings.Contains(body, "never written to disk") || !strings.Contains(body, "Rotate keys") {
		t.Fatalf("device page: %d\n%s", rec.Code, body)
	}
	// first handshake -> key is forgotten
	s.keys.sweep(func(pub string) bool { return pub == p.PublicKey })
	if s.keys.get(p.ID, p.PublicKey) != "" {
		t.Fatal("private key still held after the first handshake")
	}
	// TTL
	s.keys.put(p.ID, "x", p.PublicKey)
	s.keys.mu.Lock()
	k := s.keys.m[p.ID]
	k.expires = time.Now().Add(-time.Second)
	s.keys.m[p.ID] = k
	s.keys.mu.Unlock()
	if s.keys.get(p.ID, p.PublicKey) != "" {
		t.Fatal("expired private key still revealed")
	}
}

func TestDeviceWithOwnPublicKey(t *testing.T) {
	s, _ := newTestServer(t)
	_, pub, _ := wgkey.Generate()
	p, _ := newDevice(t, s, url.Values{"name": {"laptop"}, "public_key": {pub}})
	if p.PublicKey != pub {
		t.Fatalf("public key not used: %s", p.PublicKey)
	}
	if s.keys.get(p.ID, pub) != "" {
		t.Fatal("server must not hold a private key for a bring-your-own-key device")
	}
}

func TestRotateKeysRevokesOldKey(t *testing.T) {
	s, _ := newTestServer(t)
	p, me := newDevice(t, s, url.Values{"name": {"tablet"}})
	s.store.Update(func(st *state) error {
		st.peer(p.ID).ActiveUntil = time.Now().Add(time.Hour)
		st.profile(p.ProfileID).Require2FA = false
		return nil
	})
	if _, ok := s.desired()[p.PublicKey]; !ok {
		t.Fatal("precondition: peer should be active")
	}
	req := httptest.NewRequest("POST", "/devices/"+p.ID+"/rotate", nil)
	req.SetPathValue("id", p.ID)
	s.deviceRotate(httptest.NewRecorder(), req, me, &webSession{UserID: me.ID})
	var newPub string
	s.store.View(func(st *state) { newPub = st.peer(p.ID).PublicKey })
	d := s.desired()
	if _, ok := d[p.PublicKey]; ok || newPub == p.PublicKey {
		t.Fatal("old key still desired after rotation")
	}
	if _, ok := d[newPub]; !ok || s.keys.get(p.ID, newPub) == "" {
		t.Fatal("new key not active / not revealable")
	}
	if s.keys.get(p.ID, p.PublicKey) != "" {
		t.Fatal("old private key still revealable")
	}
}

func TestLegacyPrivateKeysScrubbed(t *testing.T) {
	dir := t.TempDir()
	priv, pub, _ := wgkey.Generate()
	legacy := state{Peers: []*Peer{{ID: "p1", Name: "old", Kind: KindDevice, PublicKey: pub, PrivateKey: priv, Address: "10.8.0.7", Enabled: true}}}
	b, _ := json.Marshal(legacy)
	if err := os.WriteFile(filepath.Join(dir, "state.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{DataDir: dir, Iface: "wg0", Endpoint: "vpn.example.nl", Port: 51820,
		Subnet: "10.8.0.0/24", MTU: 1420, DryRun: true, AdminPassword: "correct-horse-battery"}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if strings.Contains(string(raw), priv) {
		t.Fatal("legacy private key not scrubbed from state.json")
	}
}

func TestNextExpiryWakesReconciler(t *testing.T) {
	s, _ := newTestServer(t)
	p, _ := newDevice(t, s, url.Values{"name": {"watch"}})
	if d := s.nextExpiry(time.Now()); d != 0 {
		t.Fatalf("no session yet, got %v", d)
	}
	s.store.Update(func(st *state) error { st.peer(p.ID).ActiveUntil = time.Now().Add(3 * time.Second); return nil })
	if d := s.nextExpiry(time.Now()); d <= 0 || d > 3*time.Second {
		t.Fatalf("next expiry %v, want ~3s (well under the %v resync)", d, reconcileInterval)
	}
}

func TestAdminPasswordResetEndsVPNSessions(t *testing.T) {
	s, _ := newTestServer(t)
	p, me := newDevice(t, s, url.Values{"name": {"desk"}})
	s.store.Update(func(st *state) error {
		x := st.peer(p.ID)
		x.ActiveUntil, x.TokenHash = time.Now().Add(time.Hour), "abc"
		return nil
	})
	form := url.Values{"password": {"a-brand-new-password"}}
	req := httptest.NewRequest("POST", "/admin/users/"+me.ID+"/password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("id", me.ID)
	s.userPassword(httptest.NewRecorder(), req, me, &webSession{UserID: me.ID})
	s.store.View(func(st *state) {
		if x := st.peer(p.ID); !x.ActiveUntil.IsZero() || x.TokenHash != "" {
			t.Fatal("VPN session survived a password reset")
		}
	})
}

func TestConntrackArgs(t *testing.T) {
	got := conntrackArgs(netip.MustParsePrefix("10.8.0.5/32"))
	if strings.Join(got[0], " ") != "-D -s 10.8.0.5" || strings.Join(got[1], " ") != "-D -d 10.8.0.5" {
		t.Fatalf("host: %v", got)
	}
	got = conntrackArgs(netip.MustParsePrefix("192.168.20.0/24"))
	if strings.Join(got[0], " ") != "-D -s 192.168.20.0 --mask-src 255.255.255.0" ||
		strings.Join(got[1], " ") != "-D -d 192.168.20.0 --mask-dst 255.255.255.0" {
		t.Fatalf("subnet: %v", got)
	}
}
