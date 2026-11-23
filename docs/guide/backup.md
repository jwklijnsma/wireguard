# Backup & restore

All state (keys, users, peers, audit) lives in `/data/state.json`.

## Backup

Write an encrypted backup. It uses `WG2FA_BACKUP_KEY`, or the state key when that isn't set:

=== "Docker"

    ```bash
    docker exec wg2fa wg2fa-server backup /data/backup-$(date +%F).enc
    ```

=== "Podman"

    ```bash
    sudo podman exec wg2fa wg2fa-server backup /data/backup-$(date +%F).enc
    ```

Copy the file off the host. Store the backup key separately from the backups.

## Restore

1. Stop the server.
2. Copy the backup to `/data/state.json`.
3. Start the server with `WG2FA_STATE_KEY` set to the backup key.

## State encryption

With `WG2FA_STATE_KEY` or `WG2FA_STATE_KEY_FILE` set, `state.json` is encrypted at rest (AES-256-GCM, PBKDF2-derived key, 16+ characters). Existing plaintext state is migrated on start.
