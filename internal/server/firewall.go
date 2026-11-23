package server

import (
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Forwarding policy (default deny).
//
// Everything that enters or leaves the WireGuard interface in the FORWARD
// path goes through chain WG2FA-FWD:
//
//	1. RELATED,ESTABLISHED          -> ACCEPT (return traffic)
//	2. INVALID                       -> DROP
//	3. destination in WG2FA_BLOCK_NETS -> DROP  (management networks etc., for everyone)
//	4. per active peer: source = tunnel IP (+ LANs for routers)
//	     destination inside the VPN subnet -> DROP unless the profile allows peer-to-peer
//	     destination in the profile's routes -> ACCEPT
//	5. everything else -> DROP
//
// So a peer can only reach what its profile routes to, peers cannot reach each
// other unless allowed, and nothing from outside can open connections into the
// tunnel. Locked peers (expired 2FA) have no rules at all.

const fwChain = "WG2FA-FWD"

type fwRule struct {
	comment string
	spec    []string
}

func (s *Server) firewallRules(st *state, now time.Time) []fwRule {
	iface := s.cfg.Iface
	var rules []fwRule
	add := func(comment string, spec ...string) {
		rules = append(rules, fwRule{comment, spec})
	}
	add("return traffic", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	add("invalid", "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP")
	for _, b := range s.blockNets {
		add("blocked network", "-i", iface, "-d", b.String(), "-j", "DROP")
	}
	subnet := s.subnet.String()
	for _, p := range st.sortedPeers() {
		if !st.isActive(p, now) {
			continue
		}
		prof := st.profile(p.ProfileID)
		sources := []string{p.Address + "/32"}
		var dests []string
		p2p := false
		if prof != nil {
			dests = append(dests, prof.AllowedIPs...)
			p2p = prof.AllowPeerToPeer
		}
		if p.Kind == KindRouter {
			sources = append(sources, p.RemoteSubnets...)
			for _, o := range st.Peers { // site-to-site: other routers' LANs
				if o.Kind == KindRouter && o.ID != p.ID && st.isActive(o, now) {
					dests = append(dests, o.RemoteSubnets...)
				}
			}
		}
		dests = v4Only(dests)
		name := fwComment(p.Name)
		for _, src := range v4Only(sources) {
			if !p2p {
				add(name+": no peer-to-peer", "-i", iface, "-s", src, "-d", subnet, "-j", "DROP")
			}
			for _, d := range dests {
				if dp := netip.MustParsePrefix(d); !p2p && s.subnet.Contains(dp.Addr()) && dp.Bits() >= s.subnet.Bits() {
					continue // only other peers live there; dropped above
				}
				add(name, "-i", iface, "-s", src, "-d", d, "-j", "ACCEPT")
			}
		}
	}
	add("default deny", "-j", "DROP")
	return rules
}

func v4Only(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range in {
		p, err := netip.ParsePrefix(strings.TrimSpace(a))
		if err != nil || !p.Addr().Is4() {
			continue
		}
		k := p.Masked().String()
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func fwComment(s string) string {
	s = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, s)
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// restoreScript renders rules for `iptables-restore --noflush`; declaring the
// chain flushes and refills it atomically, other rules are left untouched.
func restoreScript(rules []fwRule) string {
	var b strings.Builder
	b.WriteString("*filter\n:" + fwChain + " - [0:0]\n")
	for _, r := range rules {
		fmt.Fprintf(&b, "-A %s %s -m comment --comment \"wg2fa %s\"\n", fwChain, strings.Join(r.spec, " "), r.comment)
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

// applyFirewall installs the policy; it is a no-op when nothing changed.
func (s *Server) applyFirewall() {
	if !s.cfg.Firewall || s.cfg.DryRun {
		return
	}
	var rules []fwRule
	s.store.View(func(st *state) { rules = s.firewallRules(st, time.Now()) })
	script := restoreScript(rules)
	if script == s.lastFirewall {
		return
	}
	if _, err := s.wg.run(script, "iptables-restore", "--noflush"); err != nil {
		log.Printf("firewall: %v", err)
		return
	}
	for _, dir := range []string{"-i", "-o"} {
		if _, err := s.wg.run("", "iptables", "-C", "FORWARD", dir, s.cfg.Iface, "-j", fwChain); err != nil {
			if _, err := s.wg.run("", "iptables", "-I", "FORWARD", "1", dir, s.cfg.Iface, "-j", fwChain); err != nil {
				log.Printf("firewall: hook FORWARD %s: %v", dir, err)
				return
			}
		}
	}
	if s.lastFirewall == "" {
		log.Printf("firewall: default-deny forwarding policy active (%d rules)", len(rules))
	}
	s.lastFirewall = script
}
