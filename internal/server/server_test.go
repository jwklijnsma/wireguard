package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jwklijnsma/wireguard/internal/totp"
	"github.com/jwklijnsma/wireguard/internal/wgkey"
)

func newTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	s, err := New(Config{DataDir: t.TempDir(), Iface: "wg0", Endpoint: "vpn.example.nl", Port: 51820,
		Subnet: "10.8.0.0/24", MTU: 1420, DryRun: true, AdminUser: "admin", AdminPassword: "correct-horse-battery", Issuer: "Test"})
	if err != nil {
		t.Fatal(err)
	}
	s.wg.routes = map[string]bool{}
	ts := httptest.NewServer(s.routes())
	t.Cleanup(ts.Close)
	return s, ts
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`)

func csrf(t *testing.T, c *http.Client, u string) string {
	t.Helper()
	res, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var b bytes.Buffer
	b.ReadFrom(res.Body)
	m := csrfRe.FindStringSubmatch(b.String())
	if m == nil {
		t.Fatalf("no csrf on %s (status %d, final %s)", u, res.StatusCode, res.Request.URL)
	}
	return m[1]
}

func TestFull2FAFlow(t *testing.T) {
	s, ts := newTestServer(t)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}

	// password login, admin is forced to /account until 2FA is enrolled
	res, _ := c.PostForm(ts.URL+"/login", url.Values{"username": {"admin"}, "password": {"correct-horse-battery"}})
	if !strings.HasSuffix(res.Request.URL.Path, "/account") {
		t.Fatalf("expected redirect to /account, got %s", res.Request.URL)
	}
	tok := csrf(t, c, ts.URL+"/account")
	c.PostForm(ts.URL+"/account/2fa/start", url.Values{"csrf": {tok}})
	var secret string
	s.store.View(func(st *state) { secret = st.userByName("admin").TOTPSecret })
	if secret == "" {
		t.Fatal("no pending secret")
	}
	if r, _ := c.Get(ts.URL + "/account/2fa/qr.png"); r.Header.Get("Content-Type") != "image/png" {
		t.Fatal("qr not served")
	}
	// confirm with previous-step code so the current step stays unused
	code, _ := totp.Code(secret, time.Now().Add(-30*time.Second))
	c.PostForm(ts.URL+"/account/2fa/confirm", url.Values{"csrf": {tok}, "code": {code}})
	s.store.View(func(st *state) {
		if !st.userByName("admin").TOTPEnabled {
			t.Fatal("2FA not enabled")
		}
	})

	// native client login without/with wrong code fails
	_, pub, _ := wgkey.Generate()
	body := func(code string) *bytes.Reader {
		b, _ := json.Marshal(loginReq{Username: "admin", Password: "correct-horse-battery", TOTP: code, PublicKey: pub, DeviceName: "MacBook"})
		return bytes.NewReader(b)
	}
	r, _ := http.Post(ts.URL+"/api/v1/client/login", "application/json", body("000000"))
	if r.StatusCode != 401 {
		t.Fatalf("wrong code: want 401 got %d", r.StatusCode)
	}
	// replay of the code used for enrolment is rejected
	r, _ = http.Post(ts.URL+"/api/v1/client/login", "application/json", body(code))
	if r.StatusCode != 401 {
		t.Fatalf("replayed code: want 401 got %d", r.StatusCode)
	}
	now, _ := totp.Code(secret, time.Now())
	r, _ = http.Post(ts.URL+"/api/v1/client/login", "application/json", body(now))
	if r.StatusCode != 200 {
		t.Fatalf("login: %d", r.StatusCode)
	}
	var lr loginResp
	json.NewDecoder(r.Body).Decode(&lr)
	if lr.Config.Address != "10.8.0.2/32" || lr.Config.ServerPublicKey == "" || lr.Config.PrivateKey != "" || lr.Token == "" {
		t.Fatalf("bad config %+v", lr)
	}
	if lr.Config.Endpoint != "vpn.example.nl:51820" {
		t.Fatalf("endpoint %s", lr.Config.Endpoint)
	}
	if d := s.desired(); len(d) != 1 || d[pub].AllowedIPs[0] != "10.8.0.2/32" {
		t.Fatalf("peer not active: %+v", d)
	}

	// status + logout
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/client/status", nil)
	req.Header.Set("Authorization", "Bearer "+lr.Token)
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != 200 {
		t.Fatal("status failed")
	}
	req, _ = http.NewRequest("POST", ts.URL+"/api/v1/client/logout", nil)
	req.Header.Set("Authorization", "Bearer "+lr.Token)
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != 200 {
		t.Fatal("logout failed")
	}
	if d := s.desired(); len(d) != 0 {
		t.Fatalf("peer still active after logout: %+v", d)
	}

	// expiry: an expired session is not active
	s.store.Update(func(st *state) error { st.Peers[0].ActiveUntil = time.Now().Add(-time.Minute); return nil })
	if len(s.desired()) != 0 {
		t.Fatal("expired peer active")
	}
}

func TestRouterAlwaysOnAndExports(t *testing.T) {
	s, _ := newTestServer(t)
	var cfg clientConfig
	err := s.store.Update(func(st *state) error {
		priv, pub, _ := wgkey.Generate()
		var prof string
		for _, p := range st.Profiles {
			if !p.Require2FA {
				prof = p.ID
			}
		}
		p := &Peer{ID: newID(), Name: "office", Kind: KindRouter, ProfileID: prof, PublicKey: pub,
			Address: "10.8.0.10", RemoteSubnets: []string{"192.168.20.0/24"}, Enabled: true}
		s.keys.put(p.ID, priv, pub)
		st.Peers = append(st.Peers, p)
		cfg = s.buildConfig(st, p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	d := s.desired()
	if len(d) != 1 {
		t.Fatal("router should be always on")
	}
	for _, f := range exportFormats {
		out, err := renderConfig(f.ID, "office", cfg)
		if err != nil || !strings.Contains(out, cfg.ServerPublicKey) {
			t.Fatalf("%s export broken: %v", f.ID, err)
		}
	}
	if cfg.Address != "10.8.0.10/24" {
		t.Fatalf("router address %s", cfg.Address)
	}
}

func TestPasswordHash(t *testing.T) {
	h := HashPassword("hunter2hunter2")
	if !CheckPassword(h, "hunter2hunter2") || CheckPassword(h, "nope") {
		t.Fatal("hash mismatch")
	}
}

func TestCSRFRequired(t *testing.T) {
	_, ts := newTestServer(t)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	c.PostForm(ts.URL+"/login", url.Values{"username": {"admin"}, "password": {"correct-horse-battery"}})
	r, _ := c.PostForm(ts.URL+"/account/2fa/start", url.Values{})
	if r.StatusCode != 403 {
		t.Fatalf("missing csrf should be 403, got %d", r.StatusCode)
	}
}

func TestConnectPageAndDownloads(t *testing.T) {
	s, ts := newTestServer(t)
	dir := t.TempDir()
	s.cfg.DownloadDirs = []string{dir}
	os.WriteFile(filepath.Join(dir, "WG2FA-v1.0.0-macos-universal.dmg"), []byte("dmg"), 0o644)
	os.WriteFile(filepath.Join(dir, "WG2FA-1.0.0-windows-x64-setup.exe"), []byte("exe"), 0o644)
	os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("no"), 0o644)

	// a regular user on a profile without 2FA requirement, no devices yet
	s.store.Update(func(st *state) error {
		var prof string
		for _, p := range st.Profiles {
			if !p.Require2FA {
				prof = p.ID
			}
		}
		st.Users = append(st.Users, &User{ID: "u2", Username: "jan", PassHash: HashPassword("jan-password-1"), ProfileID: prof})
		return nil
	})
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	req, _ := http.NewRequest("POST", ts.URL+"/login", strings.NewReader("username=jan&password=jan-password-1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)")
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Request.URL.Path != "/connect" {
		t.Fatalf("new user should land on /connect, got %s", res.Request.URL.Path)
	}
	var b bytes.Buffer
	b.ReadFrom(res.Body)
	html := b.String()
	for _, want := range []string{"macos-universal.dmg", "windows-x64-setup.exe", "We detected <b>macOS</b>", ts.URL} {
		if !strings.Contains(html, want) {
			t.Errorf("connect page missing %q", want)
		}
	}
	if strings.Contains(html, "secret.txt") {
		t.Error("non-installer file listed")
	}
	r, _ := c.Get(ts.URL + "/downloads/WG2FA-v1.0.0-macos-universal.dmg")
	if r.StatusCode != 200 || r.Header.Get("Content-Disposition") == "" {
		t.Fatalf("download failed: %d", r.StatusCode)
	}
	for _, bad := range []string{"secret.txt", "..%2fstate.json", "%2e%2e%2fsecret.txt"} {
		if r, _ := c.Get(ts.URL + "/downloads/" + bad); r.StatusCode == 200 {
			t.Fatalf("%s should not be downloadable", bad)
		}
	}
	// anonymous users can't download
	if r, _ := http.Get(ts.URL + "/downloads/WG2FA-v1.0.0-macos-universal.dmg"); r.Request.URL.Path != "/login" {
		t.Fatal("download must require login")
	}
}
