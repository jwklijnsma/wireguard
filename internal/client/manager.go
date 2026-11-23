package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/jwklijnsma/wireguard/internal/wgkey"
)

// Settings persisted in the state dir (only readable by root/SYSTEM).
type Settings struct {
	ServerURL  string `json:"server_url"`
	Username   string `json:"username"`
	DeviceName string `json:"device_name"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

type Status struct {
	State      string    `json:"state"` // disconnected, connecting, connected, expired, error
	Message    string    `json:"message,omitempty"`
	ServerURL  string    `json:"server_url"`
	Username   string    `json:"username"`
	DeviceName string    `json:"device_name"`
	PublicKey  string    `json:"public_key"`
	Profile    string    `json:"profile,omitempty"`
	Address    string    `json:"address,omitempty"`
	Endpoint   string    `json:"endpoint,omitempty"`
	Routes     []string  `json:"routes,omitempty"`
	DNS        []string  `json:"dns,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	RX         int64     `json:"rx"`
	TX         int64     `json:"tx"`
	Handshake  time.Time `json:"handshake,omitempty"`
	Interface  string    `json:"interface,omitempty"`
	Version    string    `json:"version"`
	Insecure   bool      `json:"insecure"`
	IPv6       string    `json:"ipv6,omitempty"`
}

type Manager struct {
	Dir     string
	Version string

	mu       sync.Mutex
	set      Settings
	tun      Tunnel
	status   Status
	token    string
	cancelEx context.CancelFunc
	http     *http.Client
}

func DefaultDir() string {
	if d := os.Getenv("WG2FA_CLIENT_DIR"); d != "" {
		return d
	}
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/WG2FA"
	case "windows":
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pd, "WG2FA")
	}
	return "/var/lib/wg2fa"
}

func NewManager(dir, version string) (*Manager, error) {
	m := &Manager{Dir: dir, Version: version, http: &http.Client{Timeout: 20 * time.Second}}
	m.tun.log = func(f string, a ...any) { log.Printf(f, a...) }
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(m.settingsPath())
	if err == nil {
		_ = json.Unmarshal(b, &m.set)
	}
	if m.set.PrivateKey == "" || !wgkey.Valid(m.set.PrivateKey) {
		priv, pub, err := wgkey.Generate()
		if err != nil {
			return nil, err
		}
		m.set.PrivateKey, m.set.PublicKey = priv, pub
	}
	if m.set.DeviceName == "" {
		h, _ := os.Hostname()
		m.set.DeviceName = h
	}
	if err := m.save(); err != nil {
		return nil, err
	}
	m.status.State = "disconnected"
	return m, nil
}

func (m *Manager) settingsPath() string { return filepath.Join(m.Dir, "client.json") }

func (m *Manager) save() error {
	b, _ := json.MarshalIndent(m.set, "", "  ")
	tmp := m.settingsPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.settingsPath())
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	s := m.status
	s.ServerURL, s.Username, s.DeviceName, s.PublicKey, s.Version = m.set.ServerURL, m.set.Username, m.set.DeviceName, m.set.PublicKey, m.Version
	m.mu.Unlock()
	if st := m.tun.Stats(); st.Interface != "" {
		s.RX, s.TX, s.Handshake, s.Interface = st.RX, st.TX, st.LastHandshake, st.Interface
	}
	s.Insecure = strings.HasPrefix(s.ServerURL, "http://")
	return s
}

type apiError struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

func normalizeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("server address is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("invalid server address %q", raw)
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.Path, "/"), nil
}

type ConnectRequest struct {
	ServerURL  string `json:"server_url"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	TOTP       string `json:"totp"`
	DeviceName string `json:"device_name"`
}

// Connect authenticates (password + TOTP) and brings the tunnel up.
func (m *Manager) Connect(req ConnectRequest) error {
	srv, err := normalizeURL(req.ServerURL)
	if err != nil {
		return err
	}
	m.mu.Lock()
	if m.status.State == "connecting" {
		m.mu.Unlock()
		return errors.New("already connecting")
	}
	m.set.ServerURL, m.set.Username = srv, strings.TrimSpace(req.Username)
	if d := strings.TrimSpace(req.DeviceName); d != "" {
		m.set.DeviceName = d
	}
	_ = m.save()
	m.status = Status{State: "connecting"}
	set := m.set
	m.mu.Unlock()

	fail := func(err error) error {
		m.mu.Lock()
		m.status = Status{State: "error", Message: err.Error()}
		m.mu.Unlock()
		return err
	}

	body, _ := json.Marshal(map[string]string{
		"username": set.Username, "password": req.Password, "totp": strings.TrimSpace(req.TOTP),
		"public_key": set.PublicKey, "device_name": set.DeviceName,
	})
	res, err := m.http.Post(srv+"/api/v1/client/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return fail(fmt.Errorf("cannot reach server: %w", err))
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		var e apiError
		_ = json.NewDecoder(res.Body).Decode(&e)
		if e.Error == "" {
			e.Error = res.Status
		}
		return fail(errors.New(e.Error))
	}
	var lr struct {
		Token     string       `json:"token"`
		ExpiresAt time.Time    `json:"expires_at"`
		Profile   string       `json:"profile"`
		Config    TunnelConfig `json:"config"`
	}
	if err := json.NewDecoder(res.Body).Decode(&lr); err != nil {
		return fail(fmt.Errorf("bad server response: %w", err))
	}

	m.tun.Down() // re-login while connected: rebuild with fresh config
	if err := m.tun.Up(lr.Config, set.PrivateKey); err != nil {
		// close the server-side session so the peer is not left unlocked
		if r, _ := http.NewRequest("POST", srv+"/api/v1/client/logout", nil); r != nil {
			r.Header.Set("Authorization", "Bearer "+lr.Token)
			if res, err := m.http.Do(r); err == nil {
				res.Body.Close()
			}
		}
		return fail(err)
	}
	m.mu.Lock()
	m.token = lr.Token
	m.status = Status{State: "connected", Profile: lr.Profile, Address: lr.Config.Address, Endpoint: lr.Config.Endpoint,
		Routes: lr.Config.AllowedIPs, DNS: lr.Config.DNS, ExpiresAt: lr.ExpiresAt, IPv6: "not routed (split tunnel)"}
	for _, a := range lr.Config.AllowedIPs {
		if strings.TrimSpace(a) == "0.0.0.0/0" {
			m.status.IPv6 = "blocked (leak protection)"
		}
	}
	if m.cancelEx != nil {
		m.cancelEx()
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancelEx = cancel
	m.mu.Unlock()
	go m.watch(ctx, lr.ExpiresAt)
	return nil
}

// watch tears the tunnel down when the 2FA session expires or the admin
// revokes it, so routes/DNS are restored instead of black-holing traffic.
func (m *Manager) watch(ctx context.Context, exp time.Time) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	timer := time.NewTimer(time.Until(exp))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			m.expire("2FA session expired — sign in again")
			return
		case <-t.C:
			if active, ok := m.remoteActive(); ok && !active {
				m.expire("session ended by the server (revoked or expired)")
				return
			}
		}
	}
}

func (m *Manager) remoteActive() (active, ok bool) {
	m.mu.Lock()
	srv, tok := m.set.ServerURL, m.token
	m.mu.Unlock()
	if tok == "" {
		return false, false
	}
	req, _ := http.NewRequest("GET", srv+"/api/v1/client/status", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err := m.http.Do(req)
	if err != nil {
		return false, false // server unreachable: keep tunnel, it may be a blip
	}
	defer res.Body.Close()
	if res.StatusCode == 401 {
		return false, true
	}
	var s struct {
		Active bool `json:"active"`
	}
	if json.NewDecoder(res.Body).Decode(&s) != nil {
		return false, false
	}
	return s.Active, true
}

func (m *Manager) expire(msg string) {
	m.tun.Down()
	m.mu.Lock()
	m.token = ""
	m.status = Status{State: "expired", Message: msg}
	m.mu.Unlock()
}

// Disconnect ends the session on the server and tears the tunnel down.
func (m *Manager) Disconnect() {
	m.mu.Lock()
	srv, tok := m.set.ServerURL, m.token
	if m.cancelEx != nil {
		m.cancelEx()
		m.cancelEx = nil
	}
	m.token = ""
	m.mu.Unlock()
	if tok != "" {
		req, _ := http.NewRequest("POST", srv+"/api/v1/client/logout", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		if res, err := m.http.Do(req); err == nil {
			res.Body.Close()
		}
	}
	m.tun.Down()
	m.mu.Lock()
	m.status = Status{State: "disconnected"}
	m.mu.Unlock()
}

// Shutdown is called when the service stops.
func (m *Manager) Shutdown() { m.Disconnect() }
