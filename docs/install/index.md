# Install

The server runs as a container that needs `NET_ADMIN` (to create `wg0` and manage iptables) and a persistent `/data` volume.

| Method | When to use it |
|---|---|
| [Docker Compose](docker.md) | Quickest start on any Docker host. |
| [Podman + systemd](podman.md) | RHEL/Fedora/Debian hosts without Docker; runs as `wg2fa.service` with auto-updates. |

After installing:

1. Put the web GUI [behind HTTPS](reverse-proxy.md). Clients send passwords and 2FA codes to it.
2. Open UDP **51820** on your firewall.
3. Review the [configuration](configuration.md) and the [OPSEC checklist](../security/checklist.md).

## Requirements

- Linux host with a public IP or port forward for UDP 51820.
- amd64 or arm64.
- The kernel WireGuard module is used when the host has it. Otherwise the image falls back to the bundled userspace `wireguard-go`, which needs `/dev/net/tun`.
