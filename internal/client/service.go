package client

import (
	"context"
	"log"
	"os"
	"path/filepath"
)

// RunDaemon starts the tunnel manager and the local UI until ctx ends.
func RunDaemon(ctx context.Context, version string) error {
	dir := DefaultDir()
	if f, err := os.OpenFile(filepath.Join(dir, "client.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		log.SetOutput(f)
	} else if err := os.MkdirAll(dir, 0o700); err == nil {
		if f, err := os.OpenFile(filepath.Join(dir, "client.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			log.SetOutput(f)
		}
	}
	m, err := NewManager(dir, version)
	if err != nil {
		return err
	}
	log.Printf("wg2fa client %s started, UI on http://%s", version, UIAddr)
	defer m.Shutdown()
	return ServeUI(ctx, m, UIAddr)
}
