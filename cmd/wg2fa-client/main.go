// wg2fa-client: desktop VPN client (macOS / Windows / Linux) for wg2fa-server.
//
// It runs as a privileged background service that embeds wireguard-go, and
// serves a small control UI on http://127.0.0.1:51821 where the user signs in
// with password + 2FA code.
//
//	wg2fa-client run        run in the foreground (service mode)
//	wg2fa-client install    install + start as service (LaunchDaemon / Windows service / systemd)
//	wg2fa-client uninstall  remove the service
//	wg2fa-client open       open the UI in the browser
//	wg2fa-client version
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/jwklijnsma/wireguard/internal/client"
)

var version = "dev"

func openUI() {
	u := "http://" + client.UIAddr
	switch runtime.GOOS {
	case "darwin":
		exec.Command("open", u).Start()
	case "windows":
		exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
	default:
		exec.Command("xdg-open", u).Start()
	}
}

func main() {
	if client.IsWindowsService() {
		if err := client.RunWindowsService(version); err != nil {
			os.Exit(1)
		}
		return
	}
	cmd := "open"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "run":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		err = client.RunDaemon(ctx, version)
	case "install":
		if err = client.Install(); err == nil {
			fmt.Println("WG2FA service installed and started. UI: http://" + client.UIAddr)
		}
	case "uninstall":
		err = client.Uninstall()
	case "open":
		openUI()
	case "version", "-v", "--version":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, "usage: %s [run|install|uninstall|open|version]\n", os.Args[0])
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
