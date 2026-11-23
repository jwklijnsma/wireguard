# Security

!!! tip "Before going to production"
    Work through the [OPSEC checklist](checklist.md).

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's [*Security → Report a vulnerability*](https://github.com/jwklijnsma/wireguard/security/advisories/new). Don't open a public issue. Include the version, how to reproduce, and the impact.

## Security model

- **Authentication:** passwords are hashed with PBKDF2-SHA256 (600,000 iterations). TOTP 2FA (RFC 6238) has replay protection and is mandatory for admins. Logins are rate-limited per IP and per user, and the limiter's memory is bounded. Unknown and known usernames take the same time to check.
- **VPN access is session-bound.** A device's WireGuard peer is only loaded while its owner has a valid 2FA session. When the session expires or is revoked, the peer and its firewall rules are removed.
- **Network policy is default-deny.** See [Forwarding policy](forwarding-policy.md).
- **Web security:** CSRF tokens, `SameSite=Strict`/`HttpOnly`/`Secure` cookies, a strict CSP without inline script, `X-Frame-Options: DENY`, and optional HSTS.
- **Client tokens** are random 256-bit values, stored only as SHA-256 hashes. Device private keys are generated on the device and never leave it (desktop client).
- **State at rest:** `state.json` has mode 0600 and can be encrypted with AES-256-GCM.

## IPv6

The tunnel carries IPv4 only. On full-tunnel profiles the desktop client routes all global IPv6 (`2000::/3`) into the tunnel, where WireGuard drops it. So IPv6 cannot bypass the VPN on dual-stack networks; the client shows *IPv6: blocked*. Phones and wg-quick configs use the official WireGuard apps, which do not block IPv6 on their own. Add `::/0` to a profile's routes to capture IPv6 there too.

## Known limitations

- IPv4-only tunnel (see above).
- Windows: DNS is set on the tunnel adapter with a low metric, but there are no WFP firewall rules against DNS leaks yet.
- The rate limiter and web sessions live in memory: a restart resets them, and multiple instances don't share them.
- Routers cannot do 2FA. Protect them with their own controls and the forwarding policy.
