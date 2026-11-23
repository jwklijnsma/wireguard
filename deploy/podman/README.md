# WG2FA with Podman + systemd (Quadlet)

Quadlet units for Podman 4.6+: the `wg2fa` container (web GUI on `127.0.0.1:8080`, WireGuard on UDP 51820) on its own `wg2fa` network, with state in the `wg2fa-data` volume. systemd turns them into `wg2fa.service`.

```bash
git clone https://github.com/jwklijnsma/wireguard && cd wireguard/deploy/podman
sudo ./install.sh vpn.example.nl                # units, /etc/wg2fa/wg2fa.env, state-key secret
sudoedit /etc/wg2fa/wg2fa.env                   # optional: issuer, admin nets, proxy settings
sudo systemctl start wg2fa
sudo journalctl -u wg2fa -o cat | grep -A2 "first start"   # initial admin password
```

Rootful only: the container creates `wg0` and manages iptables NAT and forwarding.

| File | Installed to | Purpose |
|---|---|---|
| `wg2fa.container` | `/etc/containers/systemd/` | the service (`wg2fa.service`) |
| `wg2fa.network` | `/etc/containers/systemd/` | dedicated bridge network `wg2fa` |
| `wg2fa-data.volume` | `/etc/containers/systemd/` | named volume `wg2fa-data` for `/data` |
| `wg2fa.env.example` | `/etc/wg2fa/wg2fa.env` (600) | settings; never overwritten on re-install |
| `install.sh` | | installs the above, creates the `wg2fa_state_key` secret, loads the `wireguard` module |

The unit has `AutoUpdate=registry`, so `sudo systemctl enable --now podman-auto-update.timer` keeps it on the latest release.

Full guide: <https://jwklijnsma.github.io/wireguard/install/podman/>
