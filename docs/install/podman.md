# Podman + systemd (Quadlet)

[`deploy/podman`](https://github.com/jwklijnsma/wireguard/tree/main/deploy/podman) has [Podman Quadlet](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html) units and an installer. systemd turns them into `wg2fa.service`, so the container starts at boot, restarts when its health check fails, logs to the journal and can auto-update.

Requires Podman 4.6 or newer (RHEL/Alma/Rocky 9.3+, Fedora 39+, Debian 13, Ubuntu 24.04+).

!!! info "Rootful only"
    The container creates the `wg0` interface and installs iptables NAT/forwarding rules, which does not work with rootless networking. `install.sh` refuses to run without root.

## Install

```bash
git clone https://github.com/jwklijnsma/wireguard && cd wireguard/deploy/podman
sudo ./install.sh vpn.example.nl                # your public hostname
sudo systemctl start wg2fa
sudo journalctl -u wg2fa -o cat | grep -A2 "first start"   # initial admin password
```

`install.sh`:

1. Checks for root and Podman 4.6+.
2. Installs `wg2fa.container`, `wg2fa.network` and `wg2fa-data.volume` into `/etc/containers/systemd/`.
3. Creates `/etc/wg2fa/wg2fa.env` (mode 600) from `wg2fa.env.example` if it doesn't exist yet, and sets `WG2FA_ENDPOINT` when you pass a hostname.
4. Creates the podman secret `wg2fa_state_key`, which encrypts `state.json` at rest, if it doesn't exist yet.
5. Loads the `wireguard` kernel module and adds it to `/etc/modules-load.d/` (when available; otherwise the image uses `wireguard-go`).
6. Runs `systemctl daemon-reload`.

Running it again updates the unit files and leaves your settings and secret alone.

There is no `systemctl enable` step: the generated unit starts at boot through the `[Install]` section of the `.container` file.

!!! warning "Back up the state key"
    Without it, `state.json` and backups can't be read:

    ```bash
    sudo podman secret inspect --showsecret --format '{{.SecretData}}' wg2fa_state_key
    ```

Then open UDP **51820** in the host firewall and put a [reverse proxy](reverse-proxy.md) in front of `127.0.0.1:8080`:

```bash
sudo firewall-cmd --permanent --add-port=51820/udp && sudo firewall-cmd --reload
```

## Units

| File | Installed to | Purpose |
|---|---|---|
| `wg2fa.container` | `/etc/containers/systemd/` | the service (`wg2fa.service`) |
| `wg2fa.network` | `/etc/containers/systemd/` | dedicated bridge network `wg2fa` |
| `wg2fa-data.volume` | `/etc/containers/systemd/` | named volume `wg2fa-data`, mounted at `/data` |
| `wg2fa.env.example` | `/etc/wg2fa/wg2fa.env` | settings, see [Configuration](configuration.md) |

The container gets `NET_ADMIN`, `/dev/net/tun`, the forwarding sysctls and `no-new-privileges`. It publishes UDP 51820 and `127.0.0.1:8080`.

## Manage

```bash
systemctl status wg2fa                 # state
journalctl -u wg2fa -f                 # logs
systemctl restart wg2fa                # after editing /etc/wg2fa/wg2fa.env
podman healthcheck run wg2fa           # manual health check
podman exec wg2fa iptables -S WG2FA-FWD   # forwarding policy
```

After changing a unit in `/etc/containers/systemd/` (or re-running `install.sh`), run `systemctl daemon-reload` before restarting. To check the generated units for errors: `/usr/libexec/podman/quadlet -dryrun`.

## Data

State lives in the `wg2fa-data` volume:

```bash
podman volume inspect wg2fa-data --format '{{.Mountpoint}}'   # /var/lib/containers/storage/volumes/wg2fa-data/_data
```

For backups, see [Backup & restore](../guide/backup.md).

## Automatic updates

The unit sets `AutoUpdate=registry`. Turn on the timer to pull new `:latest` images daily. Podman rolls back if the new container fails to start.

```bash
sudo systemctl enable --now podman-auto-update.timer
sudo podman auto-update --dry-run      # see what would be updated
```

To stay on a fixed release instead, set `Image=ghcr.io/jwklijnsma/wireguard:<version>` in `/etc/containers/systemd/wg2fa.container` and remove `AutoUpdate=`.

## Uninstall

```bash
sudo systemctl stop wg2fa
sudo rm /etc/containers/systemd/wg2fa{.container,.network,-data.volume}
sudo systemctl daemon-reload
# only if you want to delete all VPN state too:
sudo podman volume rm wg2fa-data && sudo podman secret rm wg2fa_state_key && sudo rm -r /etc/wg2fa
```

## Proxmox LXC

Podman runs fine in an LXC container with *nesting* enabled, but an LXC can't load kernel modules and has no `/dev/net/tun` by default. WG2FA needs one of the two:

=== "Kernel module (preferred)"

    On the **Proxmox host** (the LXC shares its kernel):

    ```bash
    modprobe wireguard
    echo wireguard > /etc/modules-load.d/wireguard.conf   # also after a reboot
    ```

    Kernel WireGuard is faster than `wireguard-go` and needs no device inside the container.

=== "/dev/net/tun (userspace fallback)"

    On the **Proxmox host** (Proxmox VE 8.1+):

    ```bash
    pct set <CTID> -dev0 /dev/net/tun
    pct reboot <CTID>
    ```

    On older versions, add to `/etc/pve/lxc/<CTID>.conf` and restart the container:

    ```
    lxc.cgroup2.devices.allow: c 10:200 rwm
    lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file
    ```

Also make sure the container has nesting enabled (`pct set <CTID> -features nesting=1`) for Podman.

Then, inside the container:

```bash
sudo systemctl daemon-reload     # re-evaluates the optional /dev/net/tun device
sudo systemctl restart wg2fa
```

`install.sh` checks for both and prints these steps when neither is available. The unit adds `/dev/net/tun` only when it exists (`AddDevice=-/dev/net/tun`), so with the kernel module the container starts without it.

!!! failure "`Error: stat /dev/net/tun: no such file or directory`"
    Units installed before this fix require the device. Re-run `sudo ./install.sh` from an up-to-date checkout, or change the line to `AddDevice=-/dev/net/tun` in `/etc/containers/systemd/wg2fa.container`, then `systemctl daemon-reload`.

## Notes

- **SELinux:** the `:Z` volume option labels the volume for the container.
- **Podman 5+:** uncomment `Notify=healthy` so `systemctl start` only returns once the web GUI answers.
- **Private image:** if the GHCR package is private, run `sudo podman login ghcr.io` first.
