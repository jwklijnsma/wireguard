# Deployment OPSEC checklist

- [ ] Put the web GUI behind a TLS reverse proxy. Set `WG2FA_TRUST_PROXY=true` and `WG2FA_TRUSTED_PROXIES` to the proxy's address, and make sure the proxy *overwrites* `X-Forwarded-For`/`-Proto`/`-Host`.
- [ ] Don't publish port 8080 directly. Bind it to `127.0.0.1` (default compose) so only the proxy reaches the app.
- [ ] Restrict the admin pages with `WG2FA_ADMIN_NETS`, e.g. VPN subnet + office LAN, and/or an access rule at the proxy.
- [ ] Add proxy-level rate limiting for `/login`, `/login/2fa` and `/api/v1/client/login`. The built-in limiter is per instance and resets on restart.
- [ ] Set `WG2FA_BLOCK_NETS` for management networks (hypervisors, BMC/iDRAC, switches, the Docker host).
- [ ] Use split-tunnel profiles with explicit routes where possible, and leave *peer-to-peer* off.
- [ ] Review router LANs. Routers are always-on (no 2FA), so their LANs are trusted entry points.
- [ ] Encrypt state at rest (`WG2FA_STATE_KEY_FILE`) and make backups with `wg2fa-server backup`. Store backup keys separately from backups.
- [ ] Never share `/data`, `state.json`, backups, QR codes or `.conf` files. They contain private keys, preshared keys, TOTP secrets and password hashes.
- [ ] Enable HSTS (`WG2FA_HSTS=true`) once HTTPS is enforced.
- [ ] Deploy images by digest and keep the host updated. Mount only `/data`; the container needs only `NET_ADMIN` (+ `/dev/net/tun` for the userspace fallback).
- [ ] From a real client, check that IPv4 and IPv6 leave through the VPN (e.g. <https://ipleak.net>, `curl -6 ifconfig.co` should fail on full tunnel).
- [ ] Don't post internal hostnames, IP ranges, endpoints or operational screenshots in public issues.
