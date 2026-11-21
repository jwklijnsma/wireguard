package server

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"rsc.io/qr"

	"github.com/jwklijnsma/wireguard/internal/totp"
	"github.com/jwklijnsma/wireguard/internal/wgkey"
)

//go:embed web/templates/*.html web/static/*
var webFS embed.FS

const (
	cookieName = "wg2fa_session"
	webTTL     = 8 * time.Hour
)

type templates struct{ pages map[string]*template.Template }

var funcs = template.FuncMap{
	"since": func(t time.Time) string {
		if t.IsZero() {
			return "never"
		}
		d := time.Since(t).Round(time.Second)
		switch {
		case d < time.Minute:
			return fmt.Sprintf("%ds ago", int(d.Seconds()))
		case d < time.Hour:
			return fmt.Sprintf("%dm ago", int(d.Minutes()))
		case d < 48*time.Hour:
			return fmt.Sprintf("%dh ago", int(d.Hours()))
		}
		return t.Local().Format("2006-01-02")
	},
	"until": func(t time.Time) string {
		d := time.Until(t).Round(time.Minute)
		if d <= 0 {
			return "expired"
		}
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	},
	"bytes": func(n int64) string {
		const u = 1024
		if n < u {
			return fmt.Sprintf("%d B", n)
		}
		div, exp := int64(u), 0
		for m := n / u; m >= u; m /= u {
			div *= u
			exp++
		}
		return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
	},
	"join": strings.Join,
	"ts":   func(t time.Time) string { return t.Local().Format("2006-01-02 15:04:05") },
}

func loadTemplates() (*templates, error) {
	t := &templates{pages: map[string]*template.Template{}}
	files, err := fs.Glob(webFS, "web/templates/*.html")
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		name := path.Base(f)
		if name == "base.html" {
			continue
		}
		tp, err := template.New("base.html").Funcs(funcs).ParseFS(webFS, "web/templates/base.html", f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		t.pages[strings.TrimSuffix(name, ".html")] = tp
	}
	return t, nil
}

type page struct {
	Title   string
	Me      *User
	CSRF    string
	Flash   string
	Error   string
	Version string
	Data    any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, p page) {
	tp := s.tmpl.pages[name]
	if tp == nil {
		http.Error(w, "template not found", 500)
		return
	}
	if c, err := r.Cookie("flash"); err == nil {
		if v, err := url.QueryUnescape(c.Value); err == nil && p.Flash == "" {
			p.Flash = v
		}
		http.SetCookie(w, &http.Cookie{Name: "flash", Path: "/", MaxAge: -1})
	}
	p.Version = s.cfg.Version
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tp.ExecuteTemplate(w, "base.html", p); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

func flash(w http.ResponseWriter, msg string) {
	http.SetCookie(w, &http.Cookie{Name: "flash", Value: url.QueryEscape(msg), Path: "/", MaxAge: 30, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func redirect(w http.ResponseWriter, r *http.Request, to, msg string) {
	if msg != "" {
		flash(w, msg)
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) routes() http.Handler {
	m := http.NewServeMux()
	static, _ := fs.Sub(webFS, "web/static")
	m.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	m.HandleFunc("GET /login", s.loginPage)
	m.HandleFunc("POST /login", s.loginPost)
	m.HandleFunc("GET /login/2fa", s.login2FAPage)
	m.HandleFunc("POST /login/2fa", s.login2FAPost)
	m.HandleFunc("POST /logout", s.logout)

	m.HandleFunc("POST /api/v1/client/login", s.apiLogin)
	m.HandleFunc("GET /api/v1/client/status", s.apiStatus)
	m.HandleFunc("POST /api/v1/client/logout", s.apiLogout)

	user := func(p string, h func(http.ResponseWriter, *http.Request, *User, *webSession)) {
		m.Handle(p, s.auth(false, h))
	}
	admin := func(p string, h func(http.ResponseWriter, *http.Request, *User, *webSession)) {
		m.Handle(p, s.auth(true, h))
	}
	user("GET /{$}", s.dashboard)
	user("GET /account", s.accountPage)
	user("POST /account/password", s.accountPassword)
	user("POST /account/2fa/start", s.totpStart)
	user("POST /account/2fa/confirm", s.totpConfirm)
	user("GET /account/2fa/qr.png", s.totpQR)
	user("POST /vpn/activate", s.vpnActivate)
	user("POST /vpn/deactivate", s.vpnDeactivate)
	user("POST /devices", s.deviceCreate)
	user("GET /devices/{id}", s.devicePage)
	user("GET /devices/{id}/config", s.deviceConfig)
	user("GET /devices/{id}/qr.png", s.deviceQR)
	user("POST /devices/{id}/delete", s.deviceDelete)

	admin("GET /admin/users", s.usersPage)
	admin("POST /admin/users", s.userCreate)
	admin("POST /admin/users/{id}", s.userUpdate)
	admin("POST /admin/users/{id}/reset2fa", s.userReset2FA)
	admin("POST /admin/users/{id}/password", s.userPassword)
	admin("POST /admin/users/{id}/delete", s.userDelete)
	admin("GET /admin/profiles", s.profilesPage)
	admin("POST /admin/profiles", s.profileSave)
	admin("POST /admin/profiles/{id}/delete", s.profileDelete)
	admin("GET /admin/routers", s.routersPage)
	admin("POST /admin/routers", s.routerCreate)
	admin("POST /admin/peers/{id}/toggle", s.peerToggle)
	admin("POST /admin/peers/{id}/revoke", s.peerRevoke)
	admin("GET /admin/audit", s.auditPage)
	return securityHeaders(m)
}

// ---------- auth middleware ----------

func (s *Server) currentSession(r *http.Request) (string, *webSession) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", nil
	}
	return c.Value, s.sess.get(c.Value)
}

func (s *Server) mustEnrol2FA(st *state, u *User) bool {
	if u.TOTPEnabled {
		return false
	}
	if u.IsAdmin {
		return true
	}
	p := st.profile(u.ProfileID)
	return p != nil && p.Require2FA
}

func (s *Server) auth(adminOnly bool, h func(http.ResponseWriter, *http.Request, *User, *webSession)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ws := s.currentSession(r)
		if ws == nil || ws.Pending2F {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		var u *User
		var enrol bool
		s.store.View(func(st *state) {
			if x := st.user(ws.UserID); x != nil && !x.Disabled {
				c := *x
				u = &c
				enrol = s.mustEnrol2FA(st, x)
			}
		})
		if u == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost && r.FormValue("csrf") != ws.CSRF {
			http.Error(w, "invalid CSRF token, reload the page", http.StatusForbidden)
			return
		}
		if enrol && !strings.HasPrefix(r.URL.Path, "/account") {
			redirect(w, r, "/account", "Set up two-factor authentication before continuing.")
			return
		}
		if adminOnly && !u.IsAdmin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h(w, r, u, ws)
	})
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, tok string) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", HttpOnly: true,
		Secure: s.isHTTPS(r), SameSite: http.SameSiteStrictMode, MaxAge: int(webTTL.Seconds())})
}

// ---------- login ----------

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "login", page{Title: "Sign in"})
}

func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	name := strings.TrimSpace(r.FormValue("username"))
	key := "web:" + ip + ":" + strings.ToLower(name)
	if s.limit.blocked(key) || s.limit.blocked("ip:"+ip) {
		s.render(w, r, "login", page{Title: "Sign in", Error: "Too many failed attempts. Try again in 15 minutes."})
		return
	}
	var u *User
	s.store.View(func(st *state) {
		x := st.userByName(name)
		if x == nil {
			CheckPassword(dummyHash, r.FormValue("password"))
			return
		}
		if CheckPassword(x.PassHash, r.FormValue("password")) && !x.Disabled {
			c := *x
			u = &c
		}
	})
	if u == nil {
		s.limit.failed(key)
		s.limit.failed("ip:" + ip)
		_ = s.store.Update(func(st *state) error { st.audit(name, "web.login.failed", "", ip); return nil })
		s.render(w, r, "login", page{Title: "Sign in", Error: "Invalid username or password."})
		return
	}
	if u.TOTPEnabled {
		tok := s.sess.create(u.ID, true, 5*time.Minute)
		s.setSessionCookie(w, r, tok)
		http.Redirect(w, r, "/login/2fa", http.StatusSeeOther)
		return
	}
	s.limit.reset(key)
	_ = s.store.Update(func(st *state) error { st.audit(u.Username, "web.login", "password only", ip); return nil })
	s.setSessionCookie(w, r, s.sess.create(u.ID, false, webTTL))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) login2FAPage(w http.ResponseWriter, r *http.Request) {
	if _, ws := s.currentSession(r); ws == nil || !ws.Pending2F {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, "login2fa", page{Title: "Two-factor authentication"})
}

func (s *Server) login2FAPost(w http.ResponseWriter, r *http.Request) {
	tok, ws := s.currentSession(r)
	if ws == nil || !ws.Pending2F {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	ip := s.clientIP(r)
	key := "2fa:" + ws.UserID
	if s.limit.blocked(key) {
		s.sess.delete(tok)
		s.render(w, r, "login", page{Title: "Sign in", Error: "Too many failed 2FA attempts. Try again later."})
		return
	}
	ok := false
	_ = s.store.Update(func(st *state) error {
		u := st.user(ws.UserID)
		if u == nil {
			return nil
		}
		if c, valid := totp.Validate(u.TOTPSecret, r.FormValue("code"), time.Now()); valid && c > u.TOTPLast {
			u.TOTPLast = c
			ok = true
			st.audit(u.Username, "web.login", "password + 2FA", ip)
		} else {
			st.audit(u.Username, "web.login.2fa_failed", "", ip)
		}
		return nil
	})
	if !ok {
		s.limit.failed(key)
		s.render(w, r, "login2fa", page{Title: "Two-factor authentication", Error: "Invalid or already used code."})
		return
	}
	s.limit.reset(key)
	s.sess.delete(tok)
	s.setSessionCookie(w, r, s.sess.create(ws.UserID, false, webTTL))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if tok, ws := s.currentSession(r); ws != nil {
		if r.FormValue("csrf") == ws.CSRF || ws.Pending2F {
			s.sess.delete(tok)
		}
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---------- dashboard ----------

type peerRow struct {
	Peer
	UserName    string
	ProfileName string
	Require2FA  bool
	Active      bool
	Stats       PeerStats
	Online      bool
}

func (s *Server) rows(st *state, filter func(*Peer) bool) []peerRow {
	stats := s.wg.Stats()
	now := time.Now()
	var out []peerRow
	for _, p := range st.sortedPeers() {
		if filter != nil && !filter(p) {
			continue
		}
		row := peerRow{Peer: *p, Active: st.isActive(p, now), Stats: stats[p.PublicKey]}
		row.PrivateKey, row.TokenHash = "", ""
		if u := st.user(p.UserID); u != nil {
			row.UserName = u.Username
		}
		if pr := st.profile(p.ProfileID); pr != nil {
			row.ProfileName, row.Require2FA = pr.Name, pr.Require2FA
		}
		row.Online = !row.Stats.LastHandshake.IsZero() && now.Sub(row.Stats.LastHandshake) < 3*time.Minute
		out = append(out, row)
	}
	return out
}

type dashData struct {
	Peers      []peerRow
	Mine       []peerRow
	Total      int
	Active     int
	Online     int
	Routers    int
	PublicKey  string
	Endpoint   string
	Subnet     string
	MyProfile  *Profile
	SessionEnd time.Time
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	var d dashData
	s.store.View(func(st *state) {
		if me.IsAdmin {
			d.Peers = s.rows(st, nil)
		}
		d.Mine = s.rows(st, func(p *Peer) bool { return p.UserID == me.ID })
		for _, p := range s.rows(st, nil) {
			d.Total++
			if p.Active {
				d.Active++
			}
			if p.Online {
				d.Online++
			}
			if p.Kind == KindRouter {
				d.Routers++
			}
		}
		for _, p := range d.Mine {
			if p.ActiveUntil.After(d.SessionEnd) {
				d.SessionEnd = p.ActiveUntil
			}
		}
		if pr := st.profile(me.ProfileID); pr != nil {
			c := *pr
			d.MyProfile = &c
		}
		d.PublicKey, d.Endpoint, d.Subnet = st.ServerPublicKey, s.cfg.Endpoint, s.subnet.String()
	})
	s.render(w, r, "dashboard", page{Title: "Dashboard", Me: me, CSRF: ws.CSRF, Data: d})
}

// ---------- account / 2FA ----------

type accountData struct {
	PendingSecret string
	PendingURI    string
	Enrol         bool
}

func (s *Server) accountPage(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	d := accountData{}
	s.store.View(func(st *state) { d.Enrol = s.mustEnrol2FA(st, me) })
	if !me.TOTPEnabled && me.TOTPSecret != "" {
		d.PendingSecret = me.TOTPSecret
		d.PendingURI = totp.URI(s.cfg.Issuer, me.Username, me.TOTPSecret)
	}
	s.render(w, r, "account", page{Title: "My account", Me: me, CSRF: ws.CSRF, Data: d})
}

func (s *Server) accountPassword(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	cur, nw := r.FormValue("current"), r.FormValue("new")
	if len(nw) < 10 {
		redirect(w, r, "/account", "New password must be at least 10 characters.")
		return
	}
	msg := "Password changed."
	_ = s.store.Update(func(st *state) error {
		u := st.user(me.ID)
		if !CheckPassword(u.PassHash, cur) {
			msg = "Current password is wrong."
			return nil
		}
		u.PassHash = HashPassword(nw)
		st.audit(u.Username, "account.password", "", s.clientIP(r))
		return nil
	})
	redirect(w, r, "/account", msg)
}

func (s *Server) totpStart(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	if me.TOTPEnabled {
		redirect(w, r, "/account", "2FA is already active. Ask an admin to reset it.")
		return
	}
	_ = s.store.Update(func(st *state) error {
		st.user(me.ID).TOTPSecret = totp.NewSecret()
		return nil
	})
	redirect(w, r, "/account", "")
}

func (s *Server) totpConfirm(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	msg := "Code did not match — check the time on your phone and try again."
	_ = s.store.Update(func(st *state) error {
		u := st.user(me.ID)
		if u.TOTPEnabled || u.TOTPSecret == "" {
			return nil
		}
		if c, ok := totp.Validate(u.TOTPSecret, r.FormValue("code"), time.Now()); ok {
			u.TOTPEnabled, u.TOTPLast = true, c
			msg = "Two-factor authentication is now active."
			st.audit(u.Username, "account.2fa.enabled", "", s.clientIP(r))
		}
		return nil
	})
	redirect(w, r, "/account", msg)
}

func pngQR(w http.ResponseWriter, text string) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	c.Scale = 6
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(c.PNG())
}

func (s *Server) totpQR(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	if me.TOTPEnabled || me.TOTPSecret == "" {
		http.NotFound(w, r)
		return
	}
	pngQR(w, totp.URI(s.cfg.Issuer, me.Username, me.TOTPSecret))
}

// ---------- VPN session (web based 2FA activation for wg-quick/app users) ----------

func (s *Server) vpnActivate(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	ip := s.clientIP(r)
	if s.limit.blocked("2fa:" + me.ID) {
		redirect(w, r, "/", "Too many failed codes, try again later.")
		return
	}
	msg := "Invalid or already used 2FA code."
	ok := false
	_ = s.store.Update(func(st *state) error {
		u := st.user(me.ID)
		c, valid := totp.Validate(u.TOTPSecret, r.FormValue("code"), time.Now())
		if !u.TOTPEnabled || !valid || c <= u.TOTPLast {
			st.audit(u.Username, "vpn.activate.failed", "", ip)
			return nil
		}
		u.TOTPLast = c
		ok = true
		n := 0
		now := time.Now().UTC()
		for _, p := range st.Peers {
			if p.UserID != u.ID || !p.Enabled {
				continue
			}
			if id := r.FormValue("peer"); id != "" && id != p.ID {
				continue
			}
			hours := 12
			if pr := st.profile(p.ProfileID); pr != nil && pr.SessionHours > 0 {
				hours = pr.SessionHours
			}
			p.ActiveUntil, p.LastAuth = now.Add(time.Duration(hours)*time.Hour), now
			n++
		}
		msg = fmt.Sprintf("VPN unlocked for %d device(s).", n)
		st.audit(u.Username, "vpn.activate", fmt.Sprintf("%d devices", n), ip)
		return nil
	})
	if ok {
		s.limit.reset("2fa:" + me.ID)
		s.notify()
	} else {
		s.limit.failed("2fa:" + me.ID)
	}
	redirect(w, r, "/", msg)
}

func (s *Server) vpnDeactivate(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	_ = s.store.Update(func(st *state) error {
		for _, p := range st.Peers {
			if p.UserID == me.ID {
				p.ActiveUntil, p.TokenHash = time.Time{}, ""
			}
		}
		st.audit(me.Username, "vpn.deactivate", "", s.clientIP(r))
		return nil
	})
	s.notify()
	redirect(w, r, "/", "VPN sessions ended.")
}

// ---------- devices ----------

func (s *Server) deviceCreate(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" || len(name) > 64 {
		redirect(w, r, "/", "Device name is required (max 64 chars).")
		return
	}
	var id, msg string
	err := s.store.Update(func(st *state) error {
		n := 0
		for _, p := range st.Peers {
			if p.UserID == me.ID {
				n++
			}
		}
		if n >= maxDevicesPerUser {
			msg = "Device limit reached."
			return nil
		}
		addr, err := st.allocIP(s.subnet)
		if err != nil {
			return err
		}
		priv, pub, err := wgkey.Generate()
		if err != nil {
			return err
		}
		p := &Peer{ID: newID(), Name: name, Kind: KindDevice, UserID: me.ID, ProfileID: me.ProfileID,
			PublicKey: pub, PrivateKey: priv, PresharedKey: wgkey.PresharedKey(), Address: addr, Enabled: true, CreatedAt: time.Now().UTC()}
		st.Peers = append(st.Peers, p)
		st.audit(me.Username, "device.created", name+" "+addr, s.clientIP(r))
		id = p.ID
		return nil
	})
	if err != nil {
		redirect(w, r, "/", err.Error())
		return
	}
	if id == "" {
		redirect(w, r, "/", msg)
		return
	}
	s.notify()
	redirect(w, r, "/devices/"+id, "Device created. Import the config, then unlock it with your 2FA code.")
}

// peerFor returns a copy of the peer if me may see it.
func (s *Server) peerFor(me *User, id string) (*Peer, clientConfig, bool) {
	var out *Peer
	var cfg clientConfig
	s.store.View(func(st *state) {
		p := st.peer(id)
		if p == nil || (!me.IsAdmin && p.UserID != me.ID) {
			return
		}
		c := *p
		out = &c
		cfg = s.buildConfig(st, p)
	})
	return out, cfg, out != nil
}

type deviceData struct {
	Peer    *Peer
	Config  string
	Formats any
	Format  string
	HasKey  bool
}

func (s *Server) devicePage(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	p, cfg, ok := s.peerFor(me, r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	f := r.URL.Query().Get("format")
	if f == "" {
		f = FormatWGQuick
		if p.Kind == KindRouter {
			f = FormatMikroTik
		}
	}
	text, err := renderConfig(f, p.Name, cfg)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	s.render(w, r, "device", page{Title: p.Name, Me: me, CSRF: ws.CSRF, Data: deviceData{
		Peer: p, Config: text, Formats: exportFormats, Format: f, HasKey: p.PrivateKey != ""}})
}

func (s *Server) deviceConfig(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	p, cfg, ok := s.peerFor(me, r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	f := r.URL.Query().Get("format")
	text, err := renderConfig(f, p.Name, cfg)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	fn := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, p.Name)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.%s"`, fn, formatExt(f)))
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(text))
}

func (s *Server) deviceQR(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	p, cfg, ok := s.peerFor(me, r.PathValue("id"))
	if !ok || p.PrivateKey == "" {
		http.NotFound(w, r)
		return
	}
	text, _ := renderConfig(FormatWGQuick, p.Name, cfg)
	pngQR(w, text)
}

func (s *Server) deviceDelete(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	id := r.PathValue("id")
	_ = s.store.Update(func(st *state) error {
		p := st.peer(id)
		if p == nil || (!me.IsAdmin && p.UserID != me.ID) {
			return nil
		}
		st.audit(me.Username, "peer.deleted", p.Name+" "+p.Address, s.clientIP(r))
		st.deletePeer(id)
		return nil
	})
	s.notify()
	back := "/"
	if r.FormValue("back") == "routers" {
		back = "/admin/routers"
	}
	redirect(w, r, back, "Deleted.")
}

// ---------- admin: users ----------

type usersData struct {
	Users    []User
	Profiles []Profile
	Devices  map[string]int
}

func (s *Server) usersPage(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	d := usersData{Devices: map[string]int{}}
	s.store.View(func(st *state) {
		for _, u := range st.Users {
			c := *u
			c.PassHash, c.TOTPSecret = "", ""
			d.Users = append(d.Users, c)
		}
		for _, p := range st.Profiles {
			d.Profiles = append(d.Profiles, *p)
		}
		for _, p := range st.Peers {
			d.Devices[p.UserID]++
		}
	})
	sort.Slice(d.Users, func(i, j int) bool { return d.Users[i].Username < d.Users[j].Username })
	s.render(w, r, "users", page{Title: "Users", Me: me, CSRF: ws.CSRF, Data: d})
}

func validUsername(n string) bool {
	if len(n) < 2 || len(n) > 64 {
		return false
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-@", r)) {
			return false
		}
	}
	return true
}

func (s *Server) userCreate(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	name, pw := strings.TrimSpace(r.FormValue("username")), r.FormValue("password")
	if !validUsername(name) || len(pw) < 10 {
		redirect(w, r, "/admin/users", "Username: 2-64 chars [a-zA-Z0-9._-@]; password at least 10 chars.")
		return
	}
	msg := "User " + name + " created. They must enrol 2FA on first login."
	_ = s.store.Update(func(st *state) error {
		if st.userByName(name) != nil {
			msg = "Username already exists."
			return nil
		}
		prof := st.profile(r.FormValue("profile"))
		u := &User{ID: newID(), Username: name, PassHash: HashPassword(pw), IsAdmin: r.FormValue("admin") == "on", CreatedAt: time.Now().UTC()}
		if prof != nil {
			u.ProfileID = prof.ID
		}
		st.Users = append(st.Users, u)
		st.audit(me.Username, "user.created", name, s.clientIP(r))
		return nil
	})
	redirect(w, r, "/admin/users", msg)
}

func (s *Server) userUpdate(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	id := r.PathValue("id")
	msg := "Saved."
	_ = s.store.Update(func(st *state) error {
		u := st.user(id)
		if u == nil {
			return nil
		}
		if prof := st.profile(r.FormValue("profile")); prof != nil && prof.ID == r.FormValue("profile") {
			u.ProfileID = prof.ID
			for _, p := range st.Peers {
				if p.UserID == u.ID {
					p.ProfileID = prof.ID
				}
			}
		}
		if u.ID != me.ID { // never lock yourself out
			u.IsAdmin = r.FormValue("admin") == "on"
			u.Disabled = r.FormValue("disabled") == "on"
		}
		st.audit(me.Username, "user.updated", u.Username, s.clientIP(r))
		if u.Disabled {
			s.sess.deleteUser(u.ID)
		}
		return nil
	})
	s.notify()
	redirect(w, r, "/admin/users", msg)
}

func (s *Server) userReset2FA(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	_ = s.store.Update(func(st *state) error {
		if u := st.user(r.PathValue("id")); u != nil {
			u.TOTPEnabled, u.TOTPSecret, u.TOTPLast = false, "", 0
			for _, p := range st.Peers {
				if p.UserID == u.ID {
					p.ActiveUntil, p.TokenHash = time.Time{}, ""
				}
			}
			st.audit(me.Username, "user.2fa.reset", u.Username, s.clientIP(r))
		}
		return nil
	})
	s.notify()
	redirect(w, r, "/admin/users", "2FA reset; the user must enrol again at next login.")
}

func (s *Server) userPassword(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	pw := r.FormValue("password")
	if len(pw) < 10 {
		redirect(w, r, "/admin/users", "Password must be at least 10 characters.")
		return
	}
	_ = s.store.Update(func(st *state) error {
		if u := st.user(r.PathValue("id")); u != nil {
			u.PassHash = HashPassword(pw)
			s.sess.deleteUser(u.ID)
			st.audit(me.Username, "user.password.reset", u.Username, s.clientIP(r))
		}
		return nil
	})
	redirect(w, r, "/admin/users", "Password set.")
}

func (s *Server) userDelete(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	id := r.PathValue("id")
	if id == me.ID {
		redirect(w, r, "/admin/users", "You cannot delete yourself.")
		return
	}
	_ = s.store.Update(func(st *state) error {
		u := st.user(id)
		if u == nil {
			return nil
		}
		out := st.Users[:0]
		for _, x := range st.Users {
			if x.ID != id {
				out = append(out, x)
			}
		}
		st.Users = out
		peers := st.Peers[:0]
		for _, p := range st.Peers {
			if p.UserID != id {
				peers = append(peers, p)
			}
		}
		st.Peers = peers
		st.audit(me.Username, "user.deleted", u.Username, s.clientIP(r))
		return nil
	})
	s.sess.deleteUser(id)
	s.notify()
	redirect(w, r, "/admin/users", "User and their devices deleted.")
}

// ---------- admin: profiles ----------

func (s *Server) profilesPage(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	var list []Profile
	s.store.View(func(st *state) {
		for _, p := range st.Profiles {
			list = append(list, *p)
		}
	})
	s.render(w, r, "profiles", page{Title: "VPN profiles", Me: me, CSRF: ws.CSRF, Data: list})
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
		out = append(out, strings.TrimSpace(f))
	}
	return out
}

func parsePrefixes(list []string) ([]string, error) {
	var out []string
	for _, a := range list {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			if ad, err2 := netip.ParseAddr(a); err2 == nil {
				p = netip.PrefixFrom(ad, ad.BitLen())
			} else {
				return nil, fmt.Errorf("invalid network %q", a)
			}
		}
		out = append(out, p.Masked().String())
	}
	return out, nil
}

func (s *Server) profileSave(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	name := strings.TrimSpace(r.FormValue("name"))
	aips, err := parsePrefixes(splitList(r.FormValue("allowed_ips")))
	if err != nil || name == "" {
		redirect(w, r, "/admin/profiles", fmt.Sprintf("Invalid profile: name required; %v", err))
		return
	}
	var dns []string
	for _, d := range splitList(r.FormValue("dns")) {
		if _, err := netip.ParseAddr(d); err != nil {
			redirect(w, r, "/admin/profiles", "Invalid DNS server "+d)
			return
		}
		dns = append(dns, d)
	}
	atoi := func(k string, def, lo, hi int) int {
		v, err := strconv.Atoi(r.FormValue(k))
		if err != nil || v < lo || v > hi {
			return def
		}
		return v
	}
	p := Profile{Name: name, Description: strings.TrimSpace(r.FormValue("description")), AllowedIPs: aips, DNS: dns,
		MTU: atoi("mtu", 1420, 1280, 1500), Keepalive: atoi("keepalive", 25, 0, 600),
		SessionHours: atoi("session_hours", 12, 0, 24*30), Require2FA: r.FormValue("require_2fa") == "on"}
	_ = s.store.Update(func(st *state) error {
		if id := r.FormValue("id"); id != "" {
			for _, x := range st.Profiles {
				if x.ID == id {
					p.ID = id
					*x = p
				}
			}
		} else {
			p.ID = newID()
			st.Profiles = append(st.Profiles, &p)
		}
		st.audit(me.Username, "profile.saved", name, s.clientIP(r))
		return nil
	})
	s.notify()
	redirect(w, r, "/admin/profiles", "Profile saved. Clients pick up route/DNS changes at their next login.")
}

func (s *Server) profileDelete(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	id := r.PathValue("id")
	msg := "Profile deleted."
	_ = s.store.Update(func(st *state) error {
		for _, u := range st.Users {
			if u.ProfileID == id {
				msg = "Profile is still assigned to user " + u.Username + "."
				return nil
			}
		}
		for _, p := range st.Peers {
			if p.ProfileID == id {
				msg = "Profile is still used by " + p.Name + "."
				return nil
			}
		}
		out := st.Profiles[:0]
		for _, p := range st.Profiles {
			if p.ID != id {
				out = append(out, p)
			}
		}
		st.Profiles = out
		st.audit(me.Username, "profile.deleted", id, s.clientIP(r))
		return nil
	})
	redirect(w, r, "/admin/profiles", msg)
}

// ---------- admin: routers (site-to-site) ----------

type routersData struct {
	Routers  []peerRow
	Profiles []Profile
}

func (s *Server) routersPage(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	var d routersData
	s.store.View(func(st *state) {
		d.Routers = s.rows(st, func(p *Peer) bool { return p.Kind == KindRouter })
		for _, p := range st.Profiles {
			d.Profiles = append(d.Profiles, *p)
		}
	})
	s.render(w, r, "routers", page{Title: "Routers / site-to-site", Me: me, CSRF: ws.CSRF, Data: d})
}

func (s *Server) routerCreate(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	name := strings.TrimSpace(r.FormValue("name"))
	subnets, err := parsePrefixes(splitList(r.FormValue("subnets")))
	if name == "" || err != nil {
		redirect(w, r, "/admin/routers", fmt.Sprintf("Name required; %v", err))
		return
	}
	for _, sn := range subnets {
		if p := netip.MustParsePrefix(sn); p.Overlaps(s.subnet) || p.Bits() == 0 {
			redirect(w, r, "/admin/routers", "LAN "+sn+" overlaps the VPN subnet or is a default route.")
			return
		}
	}
	pub := strings.TrimSpace(r.FormValue("public_key"))
	var id string
	err = s.store.Update(func(st *state) error {
		for _, o := range st.Peers {
			for _, a := range o.RemoteSubnets {
				for _, b := range subnets {
					if netip.MustParsePrefix(a).Overlaps(netip.MustParsePrefix(b)) {
						return fmt.Errorf("LAN %s overlaps %s of router %s", b, a, o.Name)
					}
				}
			}
		}
		addr, err := st.allocIP(s.subnet)
		if err != nil {
			return err
		}
		p := &Peer{ID: newID(), Name: name, Kind: KindRouter, ProfileID: r.FormValue("profile"), PresharedKey: wgkey.PresharedKey(),
			Address: addr, RemoteSubnets: subnets, Enabled: true, CreatedAt: time.Now().UTC()}
		if pub != "" {
			if !wgkey.Valid(pub) || st.peerByKey(pub) != nil {
				return fmt.Errorf("invalid or duplicate public key")
			}
			p.PublicKey = pub
		} else {
			p.PrivateKey, p.PublicKey, err = wgkey.Generate()
			if err != nil {
				return err
			}
		}
		if st.profile(p.ProfileID) == nil || st.profile(p.ProfileID).ID != p.ProfileID {
			p.ProfileID = ""
			for _, pr := range st.Profiles {
				if !pr.Require2FA {
					p.ProfileID = pr.ID
				}
			}
		}
		st.Peers = append(st.Peers, p)
		st.audit(me.Username, "router.created", name+" "+strings.Join(subnets, ","), s.clientIP(r))
		id = p.ID
		return nil
	})
	if err != nil {
		redirect(w, r, "/admin/routers", err.Error())
		return
	}
	s.notify()
	redirect(w, r, "/devices/"+id, "Router created. Pick the export format for your router below.")
}

func (s *Server) peerToggle(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	_ = s.store.Update(func(st *state) error {
		if p := st.peer(r.PathValue("id")); p != nil {
			p.Enabled = !p.Enabled
			st.audit(me.Username, "peer.toggled", fmt.Sprintf("%s enabled=%v", p.Name, p.Enabled), s.clientIP(r))
		}
		return nil
	})
	s.notify()
	redirect(w, r, refBack(r), "")
}

func (s *Server) peerRevoke(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	_ = s.store.Update(func(st *state) error {
		if p := st.peer(r.PathValue("id")); p != nil {
			p.ActiveUntil, p.TokenHash = time.Time{}, ""
			st.audit(me.Username, "peer.session.revoked", p.Name, s.clientIP(r))
		}
		return nil
	})
	s.notify()
	redirect(w, r, refBack(r), "Session revoked; the device must authenticate with 2FA again.")
}

func refBack(r *http.Request) string {
	if b := r.FormValue("back"); b == "routers" {
		return "/admin/routers"
	}
	return "/"
}

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	var list []AuditEntry
	s.store.View(func(st *state) {
		for i := len(st.Audit) - 1; i >= 0 && len(list) < 500; i-- {
			list = append(list, st.Audit[i])
		}
	})
	s.render(w, r, "audit", page{Title: "Audit log", Me: me, CSRF: ws.CSRF, Data: list})
}
