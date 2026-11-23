package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Client installers are offered to signed-in users. The release Docker image
// bundles the matching macOS/Windows/Linux builds in /usr/share/wg2fa/downloads;
// admins can drop their own (e.g. signed) builds in /data/downloads, which wins.

type download struct {
	Name     string
	Platform string // macOS, Windows, Linux
	Detail   string
	Size     string
}

var downloadKinds = []struct{ suffix, platform, detail string }{
	{"-macos-universal.dmg", "macOS", "Apple Silicon + Intel, macOS 11+"},
	{".dmg", "macOS", "disk image"},
	{".pkg", "macOS", "installer package"},
	{"-windows-x64-setup.exe", "Windows", "64-bit (Intel/AMD) installer"},
	{"-windows-arm64-setup.exe", "Windows", "ARM64 installer"},
	{"-setup.exe", "Windows", "installer"},
	{".msi", "Windows", "installer"},
	{"-windows-x64-portable.zip", "Windows", "64-bit portable (zip)"},
	{"-windows-arm64-portable.zip", "Windows", "ARM64 portable (zip)"},
	{"-linux-amd64.tar.gz", "Linux", "x86_64 (client + server)"},
	{"-linux-arm64.tar.gz", "Linux", "ARM64 (client + server)"},
}

func classify(name string) (platform, detail string, ok bool) {
	l := strings.ToLower(name)
	for _, k := range downloadKinds {
		if strings.HasSuffix(l, k.suffix) {
			return k.platform, k.detail, true
		}
	}
	return "", "", false
}

func humanSize(n int64) string {
	if n < 1<<20 {
		return fmt.Sprintf("%d KB", n>>10)
	}
	return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
}

// downloads lists installers; files in earlier dirs shadow later ones by name.
func (s *Server) downloads() []download {
	seen := map[string]bool{}
	var out []download
	for _, dir := range s.cfg.DownloadDirs {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.IsDir() || seen[e.Name()] {
				continue
			}
			plat, detail, ok := classify(e.Name())
			if !ok {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			seen[e.Name()] = true
			out = append(out, download{Name: e.Name(), Platform: plat, Detail: detail, Size: humanSize(info.Size())})
		}
	}
	order := map[string]int{"macOS": 0, "Windows": 1, "Linux": 2}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Platform != out[j].Platform {
			return order[out[i].Platform] < order[out[j].Platform]
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (s *Server) download(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	name := r.PathValue("file")
	if name != filepath.Base(name) || strings.HasPrefix(name, ".") {
		http.NotFound(w, r)
		return
	}
	if _, _, ok := classify(name); !ok {
		http.NotFound(w, r)
		return
	}
	for _, dir := range s.cfg.DownloadDirs {
		p := filepath.Join(dir, name)
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || st.IsDir() {
			continue
		}
		_ = s.store.Update(func(sta *state) error { sta.audit(me.Username, "client.downloaded", name, s.clientIP(r)); return nil })
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
		http.ServeContent(w, r, name, st.ModTime(), f)
		return
	}
	http.NotFound(w, r)
}

// landing sends users without any device to the setup guide after login.
func (s *Server) landing(uid string) string {
	dest := "/connect"
	s.store.View(func(st *state) {
		u := st.user(uid)
		if u == nil || u.IsAdmin {
			dest = "/"
			return
		}
		for _, p := range st.Peers {
			if p.UserID == uid {
				dest = "/"
				return
			}
		}
	})
	return dest
}

type connectData struct {
	ServerURL  string
	Downloads  []download
	OS         string // detected from the browser: macOS, Windows, Linux, iOS, Android
	TwoFA      bool
	Require2FA bool
	Profile    *Profile
	Devices    []peerRow
	SessionEnd time.Time
	Unlocked   bool
	MustEnrol  bool
}

func detectOS(ua string) string {
	switch u := strings.ToLower(ua); {
	case strings.Contains(u, "iphone"), strings.Contains(u, "ipad"):
		return "iOS"
	case strings.Contains(u, "android"):
		return "Android"
	case strings.Contains(u, "windows"):
		return "Windows"
	case strings.Contains(u, "mac os"), strings.Contains(u, "macintosh"):
		return "macOS"
	case strings.Contains(u, "linux"):
		return "Linux"
	}
	return ""
}

func (s *Server) connectPage(w http.ResponseWriter, r *http.Request, me *User, ws *webSession) {
	scheme := "http"
	if s.isHTTPS(r) {
		scheme = "https"
	}
	host := r.Host
	if s.fromTrustedProxy(r) && r.Header.Get("X-Forwarded-Host") != "" {
		host = r.Header.Get("X-Forwarded-Host")
	}
	d := connectData{ServerURL: scheme + "://" + host, Downloads: s.downloads(), OS: detectOS(r.UserAgent()), TwoFA: me.TOTPEnabled}
	s.store.View(func(st *state) {
		if pr := st.profile(me.ProfileID); pr != nil {
			c := *pr
			d.Profile, d.Require2FA = &c, pr.Require2FA
		}
		d.Devices = s.rows(st, func(p *Peer) bool { return p.UserID == me.ID })
		d.MustEnrol = s.mustEnrol2FA(st, me)
	})
	for _, p := range d.Devices {
		if p.ActiveUntil.After(d.SessionEnd) {
			d.SessionEnd = p.ActiveUntil
		}
	}
	d.Unlocked = time.Now().Before(d.SessionEnd)
	s.render(w, r, "connect", page{Title: "Get connected", Me: me, CSRF: ws.CSRF, Data: d})
}
