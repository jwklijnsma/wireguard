package server

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jwklijnsma/wireguard/internal/totp"
)

const pbkdf2Iter = 600_000

// HashPassword returns "pbkdf2-sha256$iter$salt$hash".
func HashPassword(pw string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	dk, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, 32)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iter,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(dk))
}

func CheckPassword(hash, pw string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[2])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(dk, want) == 1
}

// dummyHash is checked against for unknown users so timing does not leak
// whether a username exists.
var dummyHash = HashPassword("not-a-real-password")

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---- web sessions (in memory; a restart logs everyone out of the GUI,
// VPN sessions are persisted on the peer) ----

type webSession struct {
	UserID    string
	CSRF      string
	Expires   time.Time
	Pending2F bool // password OK, TOTP still required
}

type sessions struct {
	mu sync.Mutex
	m  map[string]*webSession
}

func newSessions() *sessions { return &sessions{m: map[string]*webSession{}} }

func (s *sessions) create(uid string, pending bool, ttl time.Duration) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	tok := randToken()
	s.m[tok] = &webSession{UserID: uid, CSRF: randToken(), Expires: time.Now().Add(ttl), Pending2F: pending}
	return tok
}

func (s *sessions) get(tok string) *webSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	ws := s.m[tok]
	if ws == nil {
		return nil
	}
	if time.Now().After(ws.Expires) {
		delete(s.m, tok)
		return nil
	}
	c := *ws
	return &c
}

func (s *sessions) delete(tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, tok)
}

func (s *sessions) deleteUser(uid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if v.UserID == uid {
			delete(s.m, k)
		}
	}
}

func (s *sessions) gc() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.m {
		if now.After(v.Expires) {
			delete(s.m, k)
		}
	}
}

// ---- brute-force limiter: 10 failures per key per 15 minutes ----

type limiter struct {
	mu   sync.Mutex
	fail map[string][]time.Time
}

func newLimiter() *limiter { return &limiter{fail: map[string][]time.Time{}} }

const (
	limitWindow = 15 * time.Minute
	limitMax    = 10
)

func (l *limiter) blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := time.Now().Add(-limitWindow)
	ts := l.fail[key]
	n := 0
	for _, t := range ts {
		if t.After(cut) {
			ts[n] = t
			n++
		}
	}
	l.fail[key] = ts[:n]
	return n >= limitMax
}

// limiterMaxKeys bounds memory: an attacker spraying usernames/IPs cannot
// grow the table without limit.
const limiterMaxKeys = 50_000

func (l *limiter) failed(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.fail[key]; !ok && len(l.fail) >= limiterMaxKeys {
		l.gcLocked()
		if len(l.fail) >= limiterMaxKeys {
			l.evictOldestLocked(limiterMaxKeys / 10)
		}
	}
	ts := append(l.fail[key], time.Now())
	if len(ts) > limitMax*2 {
		ts = ts[len(ts)-limitMax*2:]
	}
	l.fail[key] = ts
}

// gc drops entries whose failures are all outside the window.
func (l *limiter) gc() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.gcLocked()
}

func (l *limiter) gcLocked() {
	cut := time.Now().Add(-limitWindow)
	for k, ts := range l.fail {
		if len(ts) == 0 || !ts[len(ts)-1].After(cut) {
			delete(l.fail, k)
		}
	}
}

func (l *limiter) evictOldestLocked(n int) {
	type kv struct {
		k string
		t time.Time
	}
	all := make([]kv, 0, len(l.fail))
	for k, ts := range l.fail {
		all = append(all, kv{k, ts[len(ts)-1]})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
	for i := 0; i < n && i < len(all); i++ {
		delete(l.fail, all[i].k)
	}
}

func (l *limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.fail)
}

func (l *limiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fail, key)
}

// ---- TOTP: replay protection + per-user / per-IP rate limiting ----
//
// Every place that accepts a one-time code goes through acceptTOTP and the
// totp* limiter helpers, so the rules cannot drift apart between the web
// login, VPN unlock, enrolment and the native client API.

// acceptTOTP validates code for u and consumes it. A code is accepted only if
// its time step is strictly newer than the last accepted one, so a code
// (or an older one still inside the ±1 step skew window) can never be used
// twice — not even within its own 30 s window, and not across endpoints.
// Caller holds the store write lock.
func acceptTOTP(u *User, code string, now time.Time) bool {
	if u == nil || u.TOTPSecret == "" {
		return false
	}
	c, ok := totp.Validate(u.TOTPSecret, code, now)
	if !ok || c <= u.TOTPLast {
		return false
	}
	u.TOTPLast = c
	return true
}

func totpUserKey(uid string) string { return "2fa:" + uid }
func totpIPKey(ip string) string    { return "2fa-ip:" + ip }

// totpBlocked reports whether 2FA attempts are currently rate limited for
// this user (from any IP) or from this IP (for any user).
func (s *Server) totpBlocked(uid, ip string) bool {
	return s.limit.blocked(totpUserKey(uid)) || s.limit.blocked(totpIPKey(ip))
}

func (s *Server) totpFailed(uid, ip string) {
	s.limit.failed(totpUserKey(uid))
	s.limit.failed(totpIPKey(ip))
}

// totpSucceeded clears the per-user counter. The per-IP counter is left to
// expire on its own so one valid account cannot be used to reset the budget
// of an IP that is guessing codes for others.
func (s *Server) totpSucceeded(uid string) { s.limit.reset(totpUserKey(uid)) }
