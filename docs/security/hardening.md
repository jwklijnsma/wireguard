# Hardening

| Option | Purpose |
|---|---|
| `WG2FA_FIREWALL` (default `true`) | Server manages the default-deny forwarding chain `WG2FA-FWD`. See [Forwarding policy](forwarding-policy.md). |
| `WG2FA_BLOCK_NETS` | Destinations no VPN peer may ever reach, e.g. management networks: `192.168.1.0/24,10.0.99.0/24`. |
| Profile option *allow peer-to-peer* | Off by default: peers cannot reach each other. |
| `WG2FA_ADMIN_NETS` | Restricts `/admin/*` to these CIDRs, e.g. `10.8.0.0/24,192.168.10.0/24`. Outside them, admins only get user rights. |
| `WG2FA_TRUST_PROXY` + `WG2FA_TRUSTED_PROXIES` | `X-Forwarded-*` headers are honoured **only** when the TCP peer is a listed proxy (default: loopback and private ranges). The client IP is taken from the right-most untrusted `X-Forwarded-For` hop, so direct requests cannot spoof it. |
| `WG2FA_HSTS` | Sends `Strict-Transport-Security` on HTTPS. Enable it once HTTPS is enforced everywhere. |
| `WG2FA_STATE_KEY` / `WG2FA_STATE_KEY_FILE` | Encrypts `state.json` (AES-256-GCM, PBKDF2 key, 16+ chars). Existing plaintext state is migrated on start. Use a Docker, Podman or Kubernetes secret with `_FILE`. |
| `wg2fa-server backup <file>` | Writes an encrypted backup. See [Backup & restore](../guide/backup.md). |

## Container

The container needs only `NET_ADMIN` (plus `/dev/net/tun` for the userspace fallback). Mount only `/data`, and deploy images by digest.
