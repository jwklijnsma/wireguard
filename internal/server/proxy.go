package server

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

func remoteAddr(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, _ := netip.ParseAddr(host)
	return a.Unmap()
}

func contains(nets []netip.Prefix, a netip.Addr) bool {
	for _, n := range nets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

// fromTrustedProxy reports whether the TCP peer is a configured reverse proxy;
// only then are X-Forwarded-* headers looked at. Requests that reach the app
// directly (bypassing the proxy) cannot spoof their address or scheme.
func (s *Server) fromTrustedProxy(r *http.Request) bool {
	return s.cfg.TrustProxy && contains(s.trusted, remoteAddr(r))
}

// clientIP returns the real client address. X-Forwarded-For is walked from
// right to left, skipping trusted proxies, so values a client prepends itself
// are ignored.
func (s *Server) clientIP(r *http.Request) string {
	ip := remoteAddr(r)
	if s.fromTrustedProxy(r) {
		var hops []string
		for _, h := range r.Header.Values("X-Forwarded-For") {
			hops = append(hops, strings.Split(h, ",")...)
		}
		for i := len(hops) - 1; i >= 0; i-- {
			a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
			if err != nil {
				break
			}
			ip = a.Unmap()
			if !contains(s.trusted, ip) {
				break
			}
		}
	}
	if !ip.IsValid() {
		return r.RemoteAddr
	}
	return ip.String()
}

func (s *Server) isHTTPS(r *http.Request) bool {
	return r.TLS != nil || (s.fromTrustedProxy(r) && r.Header.Get("X-Forwarded-Proto") == "https")
}

// adminAllowed enforces WG2FA_ADMIN_NETS for the management pages.
func (s *Server) adminAllowed(r *http.Request) bool {
	if len(s.adminNets) == 0 {
		return true
	}
	a, err := netip.ParseAddr(s.clientIP(r))
	return err == nil && contains(s.adminNets, a)
}

func (s *Server) hsts(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.HSTS && s.isHTTPS(r) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}
