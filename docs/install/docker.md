# Docker

```bash
mkdir wg2fa && cd wg2fa
curl -O https://raw.githubusercontent.com/jwklijnsma/wireguard/main/docker-compose.yml
# edit WG2FA_ENDPOINT to your public hostname
openssl rand -base64 32 > state.key && chmod 600 state.key   # encrypts state at rest
docker compose up -d
docker compose logs wg2fa | grep -A2 "first start"   # initial admin password
```

!!! warning "Back up `state.key`"
    `state.json` is encrypted with this key. Without it, your state (users, keys, TOTP secrets) cannot be read.

## The compose file

```yaml
services:
  wg2fa:
    image: ghcr.io/jwklijnsma/wireguard:latest
    container_name: wg2fa
    restart: unless-stopped
    cap_add: [NET_ADMIN]
    devices: ["/dev/net/tun:/dev/net/tun"]   # only needed for the userspace fallback
    sysctls:
      net.ipv4.ip_forward: "1"
      net.ipv4.conf.all.src_valid_mark: "1"
    environment:
      WG2FA_ENDPOINT: vpn.example.nl          # public hostname clients connect to (required)
      WG2FA_SUBNET: 10.8.0.0/24
      WG2FA_ISSUER: "My VPN"                  # name shown in authenticator apps
      WG2FA_STATE_KEY_FILE: /run/secrets/wg2fa_state_key   # encrypts state.json at rest
    secrets: [wg2fa_state_key]
    ports:
      - "51820:51820/udp"
      - "127.0.0.1:8080:8080"   # put a TLS reverse proxy in front, or set WG2FA_TLS_CERT/KEY
    volumes:
      - ./data:/data

secrets:
  wg2fa_state_key:
    file: ./state.key
```

See [Configuration](configuration.md) for all environment variables.

## Pin by digest

Every release lists the image digest in its notes. In production, deploy the signed image by digest instead of `:latest`:

```yaml
    image: ghcr.io/jwklijnsma/wireguard@sha256:<digest>
```

## Updating

```bash
docker compose pull && docker compose up -d
```
