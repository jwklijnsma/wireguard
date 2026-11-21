//go:build windows

package client

import (
	"context"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "WG2FA"

func IsWindowsService() bool {
	ok, _ := svc.IsWindowsService()
	return ok
}

type winService struct{ version string }

func (s *winService) Execute(args []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunDaemon(ctx, s.version) }()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				st <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
				}
				return false, 0
			}
		case err := <-done:
			cancel()
			if err != nil {
				return false, 1
			}
			return false, 0
		}
	}
}

func RunWindowsService(version string) error {
	return svc.Run(serviceName, &winService{version: version})
}

// Install registers and starts the Windows service (runs as LocalSystem,
// required to create the Wintun adapter and set routes).
func Install() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager (run as Administrator): %w", err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		s.Control(svc.Stop)
		time.Sleep(2 * time.Second)
		s.Delete()
		s.Close()
		time.Sleep(time.Second)
	}
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName: "WG2FA VPN client",
		Description: "WireGuard VPN with two-factor authentication",
		StartType:   mgr.StartAutomatic,
	}, "run")
	if err != nil {
		return err
	}
	defer s.Close()
	s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 5 * time.Second}}, 60)
	return s.Start()
}

func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return nil
	}
	defer s.Close()
	s.Control(svc.Stop)
	time.Sleep(2 * time.Second)
	return s.Delete()
}
