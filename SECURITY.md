# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's *Security → Report a vulnerability* on this repository. Don't open a public issue. Include the version, how to reproduce, and the impact.

## Security model

- **Authentication:** passwords are hashed with PBKDF2-SHA256 (600,000 iterations). TOTP 2FA (RFC 6238) is mandatory for admins. A code is consumed on first use: its time step must be newer than the last accepted one, so it can't be replayed inside its 30-second window or on another endpoint. Logins are rate-limited per IP and per user, and 2FA codes additionally per user (across IPs) and per IP (across users), on every endpoint that takes a code. The limiter's memory is bounded. Unknown and known usernames take the same time to check.
- **VPN access is session-bound.** A device's WireGuard peer is only loaded while its owner has a valid 2FA session. When the session expires or is revoked, the peer (with its endpoint and session keys) and its firewall rules are removed right away: the reconciler wakes at the exact expiry time and on every revoke, and flushes the peer's conntrack entries so no established flow survives. An admin password reset also ends the user's VPN sessions.
- **Network policy is default-deny.** See [Forwarding policy](#forwarding-policy).
- **Web security:** CSRF tokens, `SameSite=Strict`/`HttpOnly`/`Secure` cookies, a strict CSP without inline script, `X-Frame-Options: DENY`, and optional HSTS.
- **Client tokens** are random 256-bit values, stored only as SHA-256 hashes.
- **Private keys are never stored.** The desktop client generates its own key pair, and phones / wg-quick / routers can register just a public key. When the server does generate a key (for a QR code), it is held in memory only until the first handshake or 15 minutes, never written to `state.json` or backups. Keys stored by older versions are scrubbed on start; use *Rotate keys* to issue a new config.
- **State at rest:** `state.json` has mode 0600 and can be encrypted with AES-256-GCM.

## Hardening options

| Variable | Purpose |
|---|---|
| `WG2FA_FIREWALL` (default `true`) | Server manages the default-deny forwarding chain `WG2FA-FWD`. |
| `WG2FA_BLOCK_NETS` | Destinations no VPN peer may ever reach, e.g. management networks: `192.168.1.0/24,10.0.99.0/24`. |
| Profile option *allow peer-to-peer* | Off by default: peers cannot reach each other. |
| `WG2FA_ADMIN_NETS` | Restricts `/admin/*` to these CIDRs, e.g. `10.8.0.0/24,192.168.10.0/24`. Outside them, admins only get user rights. |
| `WG2FA_TRUST_PROXY` + `WG2FA_TRUSTED_PROXIES` | `X-Forwarded-*` headers are honoured **only** when the TCP peer is a listed proxy (default: loopback and private ranges). The client IP is taken from the right-most untrusted `X-Forwarded-For` hop, so direct requests cannot spoof it. |
| `WG2FA_HSTS` | Sends `Strict-Transport-Security` on HTTPS. Enable it once HTTPS is enforced everywhere. |
| `WG2FA_STATE_KEY` / `WG2FA_STATE_KEY_FILE` | Encrypts `state.json` (AES-256-GCM, PBKDF2 key, 16+ chars). Existing plaintext state is migrated on start. Use a Docker or Kubernetes secret with `_FILE`. |
| `wg2fa-server backup <file>` | Writes an encrypted backup using `WG2FA_BACKUP_KEY` or the state key. To restore, copy it to `/data/state.json` and start with `WG2FA_STATE_KEY` set to the backup key. |

### Forwarding policy

The server installs this chain and keeps it in sync with peers and sessions:

```
WG2FA-FWD (hooked from FORWARD for -i wg0 and -o wg0)
  RELATED,ESTABLISHED                       ACCEPT   return traffic
  INVALID                                   DROP
  -d <WG2FA_BLOCK_NETS>                     DROP     everyone, before any accept
  per unlocked peer / always-on router:
    -s <tunnel IP / router LANs> -d <VPN subnet>    DROP   unless profile allows peer-to-peer
    -s <tunnel IP / router LANs> -d <profile route> ACCEPT
  everything else                           DROP     incl. new connections INTO the tunnel
```

To check it, run `docker exec wg2fa iptables -S WG2FA-FWD`.

A full-tunnel profile (`0.0.0.0/0`) can reach the internet and any internal network not listed in `WG2FA_BLOCK_NETS`. For road-warriors that should only reach specific systems, use a split-tunnel profile that lists exactly those networks.

### IPv6

The tunnel carries IPv4 only. On full-tunnel profiles the desktop client routes all global IPv6 (`2000::/3`) into the tunnel, where WireGuard drops it. So IPv6 cannot bypass the VPN on dual-stack networks; the client shows *IPv6: blocked*. Phones and wg-quick configs use the official WireGuard apps, which do not block IPv6 on their own. Add `::/0` to a profile's routes to capture IPv6 there too.

### Supply chain

- Release images are multi-arch and come with an **SBOM** and **max-mode build provenance**. They are scanned with Grype before publishing (the build fails on fixable High/Critical findings) and signed with **cosign**:
  - **public repo:** keyless signing.
  - **private repo:** key-based signing via `COSIGN_PRIVATE_KEY`/`COSIGN_PASSWORD` secrets, without the public transparency log, so image names don't leak.
- The release notes include the image digest. In production, deploy `ghcr.io/jwklijnsma/wireguard@sha256:…`.
- Renovate pins base images and GitHub Actions by digest (`renovate.json`).
- Release files get `SHA256SUMS.txt`, signed when a cosign key is configured, and GitHub build attestations on public repositories. The Wintun driver download is SHA-256 verified.

Verify an image (key-based):

```bash
cosign verify --key cosign.pub --insecure-ignore-tlog ghcr.io/jwklijnsma/wireguard@sha256:<digest>
```

## Deployment OPSEC checklist

- [ ] Put the web GUI behind a TLS reverse proxy. Set `WG2FA_TRUST_PROXY=true` and `WG2FA_TRUSTED_PROXIES` to the proxy's address, and make sure the proxy *overwrites* `X-Forwarded-For`/`-Proto`/`-Host`.
- [ ] Don't publish port 8080 directly. Bind it to `127.0.0.1` (default compose) so only the proxy reaches the app.
- [ ] Restrict the admin pages with `WG2FA_ADMIN_NETS`, e.g. VPN subnet + office LAN, and/or an access rule at the proxy.
- [ ] Add proxy-level rate limiting for `/login`, `/login/2fa` and `/api/v1/client/login`. The built-in limiter is per instance and resets on restart.
- [ ] Set `WG2FA_BLOCK_NETS` for management networks (hypervisors, BMC/iDRAC, switches, the Docker host).
- [ ] Use split-tunnel profiles with explicit routes where possible, and leave *peer-to-peer* off.
- [ ] Review router LANs. Routers are always-on (no 2FA), so their LANs are trusted entry points.
- [ ] Encrypt state at rest (`WG2FA_STATE_KEY_FILE`) and make backups with `wg2fa-server backup`. Store backup keys separately from backups.
- [ ] Never share `/data`, `state.json`, backups, QR codes or `.conf` files. They contain preshared keys, TOTP secrets and password hashes (and `.conf` files / QR codes a private key).
- [ ] Enable HSTS (`WG2FA_HSTS=true`) once HTTPS is enforced.
- [ ] Deploy images by digest and keep the host updated. Mount only `/data`; the container needs only `NET_ADMIN` (+ `/dev/net/tun` for the userspace fallback).
- [ ] From a real client, check that IPv4 and IPv6 leave through the VPN (e.g. <https://ipleak.net>, `curl -6 ifconfig.co` should fail on full tunnel).
- [ ] Don't post internal hostnames, IP ranges, endpoints or operational screenshots in public issues. The screenshots in this repo come from a throwaway demo instance.

## Known limitations

- IPv4-only tunnel (see above).
- Windows: on full-tunnel profiles a WFP filter blocks DNS (port 53) to everything except the pushed DNS servers. It is a stopgap, not a full kill switch: other traffic is still governed by routes only. Split-tunnel profiles get no DNS block.
- The rate limiter and web sessions live in memory: a restart resets them, and multiple instances don't share them.
- Routers cannot do 2FA. Protect them with their own controls and the forwarding policy.
