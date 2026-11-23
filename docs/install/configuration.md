# Configuration

The server is configured with environment variables.

| Variable | Default | Description |
|---|---|---|
| `WG2FA_ENDPOINT` | — (required) | Public host[:port] clients connect to |
| `WG2FA_SUBNET` | `10.8.0.0/24` | VPN IPv4 subnet (`.1` is the server) |
| `WG2FA_WG_PORT` | `51820` | WireGuard UDP port |
| `WG2FA_LISTEN` | `:8080` | Web GUI / API |
| `WG2FA_ISSUER` | `WG2FA VPN` | Name shown in authenticator apps |
| `WG2FA_ADMIN_USER` / `WG2FA_ADMIN_PASSWORD` | `admin` / random | Initial admin (first start only) |
| `WG2FA_TLS_CERT` / `WG2FA_TLS_KEY` | — | Serve HTTPS directly |
| `WG2FA_TRUST_PROXY` | `false` | Honour `X-Forwarded-For/-Proto` |
| `WG2FA_TRUSTED_PROXIES` | private ranges | Proxies whose `X-Forwarded-*` headers are trusted (with `WG2FA_TRUST_PROXY`) |
| `WG2FA_NAT` | `1` | MASQUERADE VPN traffic to the default interface |
| `WG2FA_MTU` | `1420` | Interface MTU |
| `WG2FA_DOWNLOADS` | `/data/downloads:/usr/share/wg2fa/downloads` | Folders whose client installers are offered on *Get connected*. Files in `/data/downloads` override the bundled ones, e.g. your own signed builds |
| `WG2FA_FIREWALL` | `true` | Default-deny forwarding policy per peer/profile (see [Forwarding policy](../security/forwarding-policy.md)) |
| `WG2FA_BLOCK_NETS` | — | CIDRs no VPN peer may reach (management networks) |
| `WG2FA_ADMIN_NETS` | — | CIDRs allowed to use the admin pages |
| `WG2FA_HSTS` | `false` | Send HSTS on HTTPS |
| `WG2FA_STATE_KEY` / `_FILE` | — | Encrypt `state.json` at rest (16+ chars) |
| `WG2FA_BACKUP_KEY` | state key | Key for `wg2fa-server backup` |
| `WG2FA_DRYRUN` | `false` | Don't touch WireGuard (GUI development) |

## State

All state (keys, users, peers, audit) lives in `/data/state.json` (mode 0600, optionally encrypted with AES-256-GCM). See [Backup & restore](../guide/backup.md).

!!! danger
    Never share `/data`, `state.json`, backups, QR codes or `.conf` files. They contain private keys, preshared keys, TOTP secrets and password hashes.
