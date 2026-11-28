package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jwklijnsma/wireguard/internal/wgkey"
)

// Native client API (macOS / Windows app).
//
//   POST /api/v1/client/login   {username,password,totp,public_key,device_name}
//   GET  /api/v1/client/status  Authorization: Bearer <token>
//   POST /api/v1/client/logout  Authorization: Bearer <token>
//
// The private key never leaves the client: it registers its public key and
// receives the tunnel parameters. The peer is only loaded into WireGuard
// while the 2FA session is valid.

const maxDevicesPerUser = 10

type loginReq struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	TOTP       string `json:"totp"`
	PublicKey  string `json:"public_key"`
	DeviceName string `json:"device_name"`
}

type loginResp struct {
	Token     string       `json:"token"`
	ExpiresAt time.Time    `json:"expires_at"`
	Profile   string       `json:"profile"`
	Config    clientConfig `json:"config"`
}

type apiErr struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

var (
	errAuth        = errors.New("invalid username, password or 2FA code")
	errRateLimited = errors.New("too many failed attempts, try again later")
)

// authenticate checks password + TOTP. Caller holds the write lock.
// When the password is right but the code is wrong (or replayed) it returns
// the user together with errAuth, so the caller can charge the per-user 2FA
// limiter; the client only ever sees the generic error.
func (s *Server) authenticate(st *state, username, password, code, ip string, now time.Time) (*User, error) {
	u := st.userByName(username)
	if u == nil {
		CheckPassword(dummyHash, password)
		return nil, errAuth
	}
	if !CheckPassword(u.PassHash, password) || u.Disabled {
		return nil, errAuth
	}
	if u.TOTPEnabled {
		if s.totpBlocked(u.ID, ip) {
			return u, errRateLimited
		}
		if !acceptTOTP(u, code, now) {
			return u, errAuth
		}
	}
	return u, nil
}

func (s *Server) apiLogin(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		writeJSON(w, 400, apiErr{Error: "bad request"})
		return
	}
	ip := s.clientIP(r)
	key := "api:" + ip + ":" + strings.ToLower(req.Username)
	if s.limit.blocked(key) || s.limit.blocked("ip:"+ip) {
		writeJSON(w, 429, apiErr{Error: errRateLimited.Error(), Code: "rate_limited"})
		return
	}
	if !wgkey.Valid(req.PublicKey) {
		writeJSON(w, 400, apiErr{Error: "invalid public key"})
		return
	}
	name := strings.TrimSpace(req.DeviceName)
	if name == "" {
		name = "device"
	}
	if len(name) > 64 {
		name = name[:64]
	}
	var resp loginResp
	var status int
	var apiError apiErr
	var totpUser string // set when the password was right but the 2FA code was not
	now := time.Now().UTC()
	err := s.store.Update(func(st *state) error {
		u, err := s.authenticate(st, req.Username, req.Password, req.TOTP, ip, now)
		if errors.Is(err, errRateLimited) {
			st.audit(req.Username, "client.login.rate_limited", name, ip)
			status, apiError = 429, apiErr{Error: err.Error(), Code: "rate_limited"}
			return nil
		}
		if err != nil {
			if u != nil {
				totpUser = u.ID
			}
			st.audit(req.Username, "client.login.failed", name, ip)
			status, apiError = 401, apiErr{Error: err.Error(), Code: "auth"}
			return nil
		}
		prof := st.profile(u.ProfileID)
		if prof != nil && prof.Require2FA && !u.TOTPEnabled {
			status, apiError = 403, apiErr{Error: "2FA is required: enrol an authenticator app in the web portal first", Code: "totp_enrol"}
			return nil
		}
		p := st.peerByKey(req.PublicKey)
		if p != nil && (p.Kind != KindDevice || p.UserID != u.ID) {
			status, apiError = 409, apiErr{Error: "this key belongs to another account"}
			return nil
		}
		if p == nil {
			n := 0
			for _, x := range st.Peers {
				if x.UserID == u.ID {
					n++
				}
			}
			if n >= maxDevicesPerUser {
				status, apiError = 403, apiErr{Error: "device limit reached, remove a device in the web portal"}
				return nil
			}
			addr, err := st.allocIP(s.subnet)
			if err != nil {
				return err
			}
			p = &Peer{ID: newID(), Name: name, Kind: KindDevice, UserID: u.ID, ProfileID: u.ProfileID,
				PublicKey: req.PublicKey, PresharedKey: wgkey.PresharedKey(), Address: addr, Enabled: true, CreatedAt: now}
			st.Peers = append(st.Peers, p)
			st.audit(u.Username, "device.registered", name+" "+addr, ip)
		}
		if !p.Enabled {
			status, apiError = 403, apiErr{Error: "this device was disabled by an administrator"}
			return nil
		}
		p.ProfileID = u.ProfileID
		prof = st.profile(p.ProfileID)
		hours := 12
		if prof != nil && prof.SessionHours > 0 {
			hours = prof.SessionHours
		}
		p.ActiveUntil = now.Add(time.Duration(hours) * time.Hour)
		p.LastAuth = now
		tok := randToken()
		p.TokenHash = hashToken(tok)
		st.audit(u.Username, "client.login", p.Name, ip)
		totpUser = u.ID
		resp = loginResp{Token: tok, ExpiresAt: p.ActiveUntil, Config: s.buildConfig(st, p)}
		resp.Config.PrivateKey = ""
		if prof != nil {
			resp.Profile = prof.Name
		}
		status = 200
		return nil
	})
	if err != nil {
		writeJSON(w, 500, apiErr{Error: err.Error()})
		return
	}
	if status != 200 {
		if status == 401 {
			s.limit.failed(key)
			s.limit.failed("ip:" + ip)
			if totpUser != "" {
				s.totpFailed(totpUser, ip)
			}
		}
		writeJSON(w, status, apiError)
		return
	}
	s.limit.reset(key)
	s.totpSucceeded(totpUser)
	s.notify()
	writeJSON(w, 200, resp)
}

func (s *Server) peerFromBearer(st *state, r *http.Request) *Peer {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return nil
	}
	th := hashToken(strings.TrimPrefix(h, "Bearer "))
	for _, p := range st.Peers {
		if p.TokenHash != "" && p.TokenHash == th {
			return p
		}
	}
	return nil
}

func (s *Server) apiStatus(w http.ResponseWriter, r *http.Request) {
	var out map[string]any
	s.store.View(func(st *state) {
		p := s.peerFromBearer(st, r)
		if p == nil {
			return
		}
		out = map[string]any{"active": st.isActive(p, time.Now()), "expires_at": p.ActiveUntil, "name": p.Name, "address": p.Address}
	})
	if out == nil {
		writeJSON(w, 401, apiErr{Error: "unknown token", Code: "auth"})
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) apiLogout(w http.ResponseWriter, r *http.Request) {
	found := false
	_ = s.store.Update(func(st *state) error {
		p := s.peerFromBearer(st, r)
		if p == nil {
			return nil
		}
		found = true
		p.ActiveUntil = time.Time{}
		p.TokenHash = ""
		st.audit(p.Name, "client.logout", p.Address, s.clientIP(r))
		return nil
	})
	if !found {
		writeJSON(w, 401, apiErr{Error: "unknown token", Code: "auth"})
		return
	}
	s.notify()
	writeJSON(w, 200, map[string]bool{"ok": true})
}
