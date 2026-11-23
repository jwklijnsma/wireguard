package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// PeerKind distinguishes end-user devices from site-to-site routers.
type PeerKind string

const (
	KindDevice PeerKind = "device"
	KindRouter PeerKind = "router"
)

type User struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	PassHash    string    `json:"pass_hash"`
	TOTPSecret  string    `json:"totp_secret,omitempty"`
	TOTPEnabled bool      `json:"totp_enabled"`
	TOTPLast    uint64    `json:"totp_last,omitempty"` // last accepted counter (replay protection)
	IsAdmin     bool      `json:"is_admin"`
	Disabled    bool      `json:"disabled"`
	ProfileID   string    `json:"profile_id"`
	CreatedAt   time.Time `json:"created_at"`
}

// Profile is a VPN profile: what a client gets pushed and how strict 2FA is.
type Profile struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	AllowedIPs   []string `json:"allowed_ips"` // routes on the client side
	DNS          []string `json:"dns"`
	MTU          int      `json:"mtu"`
	Keepalive    int      `json:"keepalive"`
	SessionHours int      `json:"session_hours"`
	Require2FA   bool     `json:"require_2fa"`
	// AllowPeerToPeer lets peers on this profile reach other VPN peers;
	// by default the firewall only lets them reach their routes.
	AllowPeerToPeer bool `json:"allow_peer_to_peer"`
}

type Peer struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Kind          PeerKind  `json:"kind"`
	UserID        string    `json:"user_id,omitempty"`
	ProfileID     string    `json:"profile_id"`
	PublicKey     string    `json:"public_key"`
	PrivateKey    string    `json:"private_key,omitempty"` // only for server-generated configs
	PresharedKey  string    `json:"preshared_key"`
	Address       string    `json:"address"`        // tunnel IP, e.g. 10.8.0.5
	RemoteSubnets []string  `json:"remote_subnets"` // router: LANs behind it
	Enabled       bool      `json:"enabled"`
	ActiveUntil   time.Time `json:"active_until"` // 2FA session expiry
	LastAuth      time.Time `json:"last_auth"`
	TokenHash     string    `json:"token_hash,omitempty"` // native client bearer token (sha256)
	CreatedAt     time.Time `json:"created_at"`
}

type AuditEntry struct {
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Detail string    `json:"detail"`
	IP     string    `json:"ip"`
}

type state struct {
	ServerPrivateKey string       `json:"server_private_key"`
	ServerPublicKey  string       `json:"server_public_key"`
	Users            []*User      `json:"users"`
	Profiles         []*Profile   `json:"profiles"`
	Peers            []*Peer      `json:"peers"`
	Audit            []AuditEntry `json:"audit"`
}

// Store is a small JSON-file database guarded by a mutex. It is plenty for
// thousands of peers and keeps the deployment a single binary + volume.
type Store struct {
	mu   sync.RWMutex
	path string
	s    state
	enc  *stateCipher // nil = plaintext
}

const maxAudit = 1000

// OpenStore loads state.json. With a non-empty key the file is encrypted at
// rest (AES-256-GCM, key from PBKDF2-SHA256); an existing plaintext file is
// migrated on first start.
func OpenStore(dir, key string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	st := &Store{path: filepath.Join(dir, "state.json")}
	b, err := os.ReadFile(st.path)
	if errors.Is(err, os.ErrNotExist) {
		if key != "" {
			if st.enc, err = newStateCipher(key, nil); err != nil {
				return nil, err
			}
		}
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	migrate := false
	if isEncrypted(b) {
		if key == "" {
			return nil, fmt.Errorf("%s is encrypted: set WG2FA_STATE_KEY or WG2FA_STATE_KEY_FILE", st.path)
		}
		st.enc, b, err = decryptState(key, b)
		if err != nil {
			return nil, err
		}
	} else if key != "" {
		if st.enc, err = newStateCipher(key, nil); err != nil {
			return nil, err
		}
		migrate = true
	}
	if err := json.Unmarshal(b, &st.s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", st.path, err)
	}
	if migrate {
		st.mu.Lock()
		err := st.saveLocked()
		st.mu.Unlock()
		if err != nil {
			return nil, err
		}
		log.Printf("state: %s is now encrypted at rest", st.path)
	}
	return st, nil
}

// saveLocked writes atomically. Caller holds mu (write).
func (st *Store) saveLocked() error {
	b, err := json.MarshalIndent(&st.s, "", "  ")
	if err != nil {
		return err
	}
	if st.enc != nil {
		if b, err = st.enc.seal(b); err != nil {
			return err
		}
	}
	tmp := st.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, st.path)
}

// Update runs fn under the write lock and persists the result.
func (st *Store) Update(fn func(s *state) error) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if err := fn(&st.s); err != nil {
		return err
	}
	return st.saveLocked()
}

// View runs fn under the read lock. fn must not keep references.
func (st *Store) View(fn func(s *state)) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	fn(&st.s)
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *state) userByName(name string) *User {
	for _, u := range s.Users {
		if u.Username == name {
			return u
		}
	}
	return nil
}

func (s *state) user(id string) *User {
	for _, u := range s.Users {
		if u.ID == id {
			return u
		}
	}
	return nil
}

func (s *state) profile(id string) *Profile {
	for _, p := range s.Profiles {
		if p.ID == id {
			return p
		}
	}
	if len(s.Profiles) > 0 {
		return s.Profiles[0]
	}
	return nil
}

func (s *state) peer(id string) *Peer {
	for _, p := range s.Peers {
		if p.ID == id {
			return p
		}
	}
	return nil
}

func (s *state) peerByKey(pub string) *Peer {
	for _, p := range s.Peers {
		if p.PublicKey == pub {
			return p
		}
	}
	return nil
}

func (s *state) deletePeer(id string) {
	out := s.Peers[:0]
	for _, p := range s.Peers {
		if p.ID != id {
			out = append(out, p)
		}
	}
	s.Peers = out
}

func (s *state) audit(actor, action, detail, ip string) {
	s.Audit = append(s.Audit, AuditEntry{Time: time.Now().UTC(), Actor: actor, Action: action, Detail: detail, IP: ip})
	if len(s.Audit) > maxAudit {
		s.Audit = s.Audit[len(s.Audit)-maxAudit:]
	}
}

// allocIP returns the first free host address in subnet. The first host
// (.1) is reserved for the server.
func (s *state) allocIP(subnet netip.Prefix) (string, error) {
	used := map[netip.Addr]bool{}
	for _, p := range s.Peers {
		if a, err := netip.ParseAddr(p.Address); err == nil {
			used[a] = true
		}
	}
	srv := subnet.Masked().Addr().Next()
	used[srv] = true
	for a := srv.Next(); subnet.Contains(a); a = a.Next() {
		// skip broadcast for IPv4
		if a.Is4() && !subnet.Contains(a.Next()) {
			break
		}
		if !used[a] {
			return a.String(), nil
		}
	}
	return "", errors.New("address pool exhausted")
}

// IsActive tells whether a peer should currently be present in WireGuard.
func (s *state) isActive(p *Peer, now time.Time) bool {
	if !p.Enabled {
		return false
	}
	if p.Kind == KindRouter {
		return true
	}
	if u := s.user(p.UserID); u == nil || u.Disabled {
		return false
	}
	prof := s.profile(p.ProfileID)
	if prof != nil && !prof.Require2FA {
		return true
	}
	return now.Before(p.ActiveUntil)
}

func (s *state) sortedPeers() []*Peer {
	out := append([]*Peer(nil), s.Peers...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out
}
