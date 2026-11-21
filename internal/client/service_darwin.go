//go:build darwin

package client

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	launchdLabel = "nl.jwklijnsma.wg2fa"
	launchdPlist = "/Library/LaunchDaemons/" + launchdLabel + ".plist"
	installedBin = "/Library/Application Support/WG2FA/bin/wg2fa-client"
)

// Install copies the binary to a root-owned location and registers a
// LaunchDaemon (the tunnel needs root to create utun interfaces).
func Install() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root (use sudo)")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(installedBin), 0o755); err != nil {
		return err
	}
	b, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	if err := os.WriteFile(installedBin+".new", b, 0o755); err != nil {
		return err
	}
	if err := os.Rename(installedBin+".new", installedBin); err != nil {
		return err
	}
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key><array><string>%s</string><string>run</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/Library/Application Support/WG2FA/daemon.err</string>
</dict>
</plist>
`, launchdLabel, installedBin)
	run("launchctl", "bootout", "system/"+launchdLabel)
	if err := os.WriteFile(launchdPlist, []byte(plist), 0o644); err != nil {
		return err
	}
	if _, err := run("launchctl", "bootstrap", "system", launchdPlist); err != nil {
		return err
	}
	_, _ = run("launchctl", "enable", "system/"+launchdLabel)
	return nil
}

func Uninstall() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root (use sudo)")
	}
	run("launchctl", "bootout", "system/"+launchdLabel)
	os.Remove(launchdPlist)
	os.Remove(installedBin)
	return nil
}

func IsWindowsService() bool         { return false }
func RunWindowsService(string) error { return nil }
