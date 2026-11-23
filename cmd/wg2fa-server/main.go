// wg2fa-server: WireGuard VPN server with 2FA, VPN profiles, site-to-site
// routers and a web GUI.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/jwklijnsma/wireguard/internal/server"
)

var version = "dev"

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return v
	}
	return def
}

func envBool(k string) bool {
	b, _ := strconv.ParseBool(os.Getenv(k))
	return b
}

func envBoolDefault(k string, def bool) bool {
	if b, err := strconv.ParseBool(os.Getenv(k)); err == nil {
		return b
	}
	return def
}

func splitCSV(v string) []string {
	var out []string
	for _, f := range strings.Split(v, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// secret reads NAME or the file named by NAME_FILE (Docker/Kubernetes secrets).
func secret(name string) (string, error) {
	if f := os.Getenv(name + "_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("%s_FILE: %w", name, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return os.Getenv(name), nil
}

func main() {
	var c server.Config
	flag.StringVar(&c.Listen, "listen", env("WG2FA_LISTEN", ":8080"), "web GUI / API listen address")
	flag.StringVar(&c.DataDir, "data", env("WG2FA_DATA", "/data"), "data directory")
	flag.StringVar(&c.Iface, "iface", env("WG2FA_IFACE", "wg0"), "WireGuard interface")
	flag.StringVar(&c.Endpoint, "endpoint", env("WG2FA_ENDPOINT", ""), "public hostname[:port] clients connect to (required)")
	flag.IntVar(&c.Port, "port", envInt("WG2FA_WG_PORT", 51820), "WireGuard UDP port")
	flag.StringVar(&c.Subnet, "subnet", env("WG2FA_SUBNET", "10.8.0.0/24"), "VPN IPv4 subnet")
	flag.IntVar(&c.MTU, "mtu", envInt("WG2FA_MTU", 1420), "interface MTU")
	flag.BoolVar(&c.DryRun, "dry-run", envBool("WG2FA_DRYRUN"), "do not touch WireGuard (GUI testing)")
	flag.StringVar(&c.AdminUser, "admin-user", env("WG2FA_ADMIN_USER", "admin"), "initial admin user")
	flag.StringVar(&c.TLSCert, "tls-cert", env("WG2FA_TLS_CERT", ""), "TLS certificate (PEM)")
	flag.StringVar(&c.TLSKey, "tls-key", env("WG2FA_TLS_KEY", ""), "TLS key (PEM)")
	flag.StringVar(&c.Issuer, "issuer", env("WG2FA_ISSUER", "WG2FA VPN"), "issuer name in authenticator apps")
	flag.BoolVar(&c.TrustProxy, "trust-proxy", envBool("WG2FA_TRUST_PROXY"), "trust X-Forwarded-For/-Proto (behind a reverse proxy)")
	var trusted, adminNets, blockNets string
	flag.StringVar(&trusted, "trusted-proxies", env("WG2FA_TRUSTED_PROXIES", ""), "comma-separated CIDRs of reverse proxies (default with -trust-proxy: loopback + private ranges)")
	flag.StringVar(&adminNets, "admin-nets", env("WG2FA_ADMIN_NETS", ""), "comma-separated CIDRs allowed to use the admin pages (default: anywhere)")
	flag.StringVar(&blockNets, "block-nets", env("WG2FA_BLOCK_NETS", ""), "comma-separated CIDRs no VPN peer may reach")
	flag.BoolVar(&c.HSTS, "hsts", envBool("WG2FA_HSTS"), "send Strict-Transport-Security on HTTPS")
	flag.BoolVar(&c.Firewall, "firewall", envBoolDefault("WG2FA_FIREWALL", true), "manage the default-deny forwarding firewall (iptables)")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()
	c.TrustedProxies, c.AdminNets, c.BlockNets = splitCSV(trusted), splitCSV(adminNets), splitCSV(blockNets)
	key, err := secret("WG2FA_STATE_KEY")
	if err != nil {
		log.Fatal(err)
	}
	c.StateKey = key
	if flag.Arg(0) == "backup" {
		// wg2fa-server backup <file>: encrypted copy of the state
		if flag.NArg() != 2 {
			log.Fatal("usage: wg2fa-server backup <output-file>")
		}
		bkey, err := secret("WG2FA_BACKUP_KEY")
		if err != nil {
			log.Fatal(err)
		}
		if bkey == "" {
			bkey = key
		}
		if err := server.Backup(c.DataDir, key, bkey, flag.Arg(1)); err != nil {
			log.Fatal(err)
		}
		fmt.Println("encrypted backup written to", flag.Arg(1))
		return
	}
	if *showVersion {
		fmt.Println(version)
		return
	}
	c.AdminPassword = os.Getenv("WG2FA_ADMIN_PASSWORD")
	c.Version = version
	c.DownloadDirs = filepath.SplitList(env("WG2FA_DOWNLOADS", "/data/downloads"+string(filepath.ListSeparator)+"/usr/share/wg2fa/downloads"))

	s, err := server.New(c)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := s.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
