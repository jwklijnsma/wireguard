# Security

!!! tip "Before going to production"
    Work through the [OPSEC checklist](checklist.md).

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's [*Security → Report a vulnerability*](https://github.com/jwklijnsma/wireguard/security/advisories/new). Don't open a public issue. Include the version, how to reproduce, and the impact.

## Security model

- **Authentication:** passwords are hashed with PBKDF2-SHA256 (600,000 iterations). TOTP 2FA (RFC 6238) is mandatory for admins. A code is consumed on first use: its time step must be newer than the last accepted one, so it can't be replayed inside its 30-second window or on another endpoint. Logins are rate-limited per IP and per user, and 2FA codes additionally per user (across IPs) and per IP (across users), on every endpoint that takes a code. The limiter's memory is bounded. Unknown and known usernames take the same time to check.
- **VPN access is session-bound.** A device's WireGuard peer is only loaded while its owner has a valid 2FA session. When the session expires or is revoked, the peer (with its endpoint and session keys) and its firewall rules are removed right away: the reconciler wakes at the exact expiry time and on every revoke, and flushes the peer's conntrack entries so no established flow survives. An admin password reset also ends the user's VPN sessions.
- **Network policy is default-deny.** See [Forwarding policy](forwarding-policy.md).
- **Web security:** CSRF tokens, `SameSite=Strict`/`HttpOnly`/`Secure` cookies, a strict CSP without inline script, `X-Frame-Options: DENY`, and optional HSTS.
- **Client tokens** are random 256-bit values, stored only as SHA-256 hashes.
- **Private keys are never stored.** The desktop client generates its own key pair, and phones / wg-quick / routers can register just a public key. When the server does generate a key (for a QR code), it is held in memory only until the first handshake or 15 minutes, never written to `state.json` or backups. Keys stored by older versions are scrubbed on start; use *Rotate keys* to issue a new config.
- **State at rest:** `state.json` has mode 0600 and can be encrypted with AES-256-GCM.

## IPv6

The tunnel carries IPv4 only. On full-tunnel profiles the desktop client routes all global IPv6 (`2000::/3`) into the tunnel, where WireGuard drops it. So IPv6 cannot bypass the VPN on dual-stack networks; the client shows *IPv6: blocked*. Phones and wg-quick configs use the official WireGuard apps, which do not block IPv6 on their own. Add `::/0` to a profile's routes to capture IPv6 there too.

## Known limitations

- IPv4-only tunnel (see above).
- Windows: on full-tunnel profiles a WFP filter blocks DNS (port 53) to everything except the pushed DNS servers. It is a stopgap, not a full kill switch: other traffic is still governed by routes only. Split-tunnel profiles get no DNS block.
- The rate limiter and web sessions live in memory: a restart resets them, and multiple instances don't share them.
- Routers cannot do 2FA. Protect them with their own controls and the forwarding policy.
