//go:build linux

package client

import (
	"fmt"
	"os"
)

const unitPath = "/etc/systemd/system/wg2fa-client.service"

func Install() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	unit := fmt.Sprintf("[Unit]\nDescription=WG2FA VPN client\nAfter=network-online.target\n\n[Service]\nExecStart=%s run\nRestart=always\n\n[Install]\nWantedBy=multi-user.target\n", self)
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return err
	}
	run("systemctl", "daemon-reload")
	_, err = run("systemctl", "enable", "--now", "wg2fa-client")
	return err
}

func Uninstall() error {
	run("systemctl", "disable", "--now", "wg2fa-client")
	os.Remove(unitPath)
	run("systemctl", "daemon-reload")
	return nil
}

func IsWindowsService() bool         { return false }
func RunWindowsService(string) error { return nil }
