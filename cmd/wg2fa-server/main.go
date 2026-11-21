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
	"strconv"
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
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	c.AdminPassword = os.Getenv("WG2FA_ADMIN_PASSWORD")
	c.Version = version

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
