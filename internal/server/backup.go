package server

import (
	"encoding/json"
	"fmt"
	"os"
)

// Backup writes an encrypted copy of the state (keys, TOTP secrets, password
// hashes) to out. Restore by copying it to <data>/state.json and starting the
// server with WG2FA_STATE_KEY set to the backup key.
func Backup(dataDir, stateKey, backupKey, out string) error {
	if backupKey == "" {
		return fmt.Errorf("a backup key is required (WG2FA_BACKUP_KEY or WG2FA_STATE_KEY)")
	}
	st, err := OpenStore(dataDir, stateKey)
	if err != nil {
		return err
	}
	st.mu.RLock()
	b, err := json.MarshalIndent(&st.s, "", "  ")
	st.mu.RUnlock()
	if err != nil {
		return err
	}
	c, err := newStateCipher(backupKey, nil)
	if err != nil {
		return err
	}
	enc, err := c.seal(b)
	if err != nil {
		return err
	}
	return os.WriteFile(out, enc, 0o600)
}
