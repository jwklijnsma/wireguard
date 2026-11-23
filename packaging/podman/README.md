# Running WG2FA with Podman + systemd (Quadlet)

`wg2fa.container` is a [Podman Quadlet](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
unit. systemd turns it into `wg2fa.service`, so the container starts at boot,
restarts on failure, logs to the journal and can auto-update.
Requires Podman 4.6 or newer (RHEL/Alma/Rocky 9.3+, Fedora 39+, Debian 13, Ubuntu 24.04+).

Run it **rootful**. The container creates the `wg0` interface and installs
iptables NAT/forwarding rules, which does not work in rootless networking.

## Install

```bash
curl -O https://raw.githubusercontent.com/jwklijnsma/wireguard/main/packaging/podman/wg2fa.container
curl -O https://raw.githubusercontent.com/jwklijnsma/wireguard/main/packaging/podman/wg2fa.env

sudo install -m 644 wg2fa.container /etc/containers/systemd/wg2fa.container
sudo install -d -m 700 /etc/wg2fa /var/lib/wg2fa
sudo install -m 600 wg2fa.env /etc/wg2fa/wg2fa.env
sudoedit /etc/wg2fa/wg2fa.env                       # set WG2FA_ENDPOINT at least

# key that encrypts state.json at rest - back it up, state is unreadable without it
openssl rand -base64 32 | sudo podman secret create wg2fa_state_key -

sudo systemctl daemon-reload
sudo systemctl start wg2fa.service
sudo journalctl -u wg2fa -o cat | grep -A2 "first start"   # initial admin password
```

There is no `systemctl enable` step: the generated unit is started at boot
through the `[Install]` section of the `.container` file.

Open UDP **51820** in the host firewall (`firewall-cmd --permanent --add-port=51820/udp && firewall-cmd --reload`)
and put a TLS reverse proxy in front of `127.0.0.1:8080`, as described in the main README.

## Manage

```bash
systemctl status wg2fa                 # state
journalctl -u wg2fa -f                 # logs
systemctl restart wg2fa                # after editing /etc/wg2fa/wg2fa.env
podman healthcheck run wg2fa           # manual health check
```

After editing `/etc/containers/systemd/wg2fa.container`, run `systemctl daemon-reload` before restarting.
To check the generated unit for errors: `/usr/libexec/podman/quadlet -dryrun`.

## Automatic updates

The unit sets `AutoUpdate=registry`. Turn on the timer to pull new `:latest`
images daily. Podman rolls back if the new container fails to start.

```bash
sudo systemctl enable --now podman-auto-update.timer
sudo podman auto-update --dry-run      # see what would be updated
```

To stay on a fixed release instead, set `Image=ghcr.io/jwklijnsma/wireguard:<version>` and remove `AutoUpdate=`.

## Notes

- **Data** lives in `/var/lib/wg2fa` on the host. Back up this folder together with the `wg2fa_state_key` secret
  (`podman secret inspect --showsecret wg2fa_state_key`).
- **SELinux:** the `:Z` volume option relabels `/var/lib/wg2fa` for the container.
- **Podman 5+:** uncomment `Notify=healthy` so `systemctl start` only returns once the web GUI answers.
- **Kernel module:** the host's `wireguard` module is used when it is loaded (`modprobe wireguard`).
  Otherwise the bundled userspace `wireguard-go` takes over through `/dev/net/tun`.
