#!/usr/bin/env bash
# Install the WG2FA Podman Quadlet units (rootful).
#   sudo ./install.sh                    # then edit /etc/wg2fa/wg2fa.env
#   sudo ./install.sh vpn.example.nl     # also sets WG2FA_ENDPOINT
#
# Rootful only: the container creates wg0 and manages iptables NAT/forwarding,
# which needs real NET_ADMIN and host-reachable networking.
set -euo pipefail
cd "$(dirname "$0")"

endpoint="${1:-}"
unit_dir=/etc/containers/systemd
env_dir=/etc/wg2fa

[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo $0 $*" >&2; exit 1; }
command -v podman >/dev/null || { echo "podman is not installed" >&2; exit 1; }
ver=$(podman version --format '{{.Client.Version}}')
if [ "$(printf '%s\n4.6\n' "${ver%%-*}" | sort -V | head -n1)" != 4.6 ]; then
  echo "Podman $ver is too old for this Quadlet unit (need 4.6+)" >&2; exit 1
fi

install -d -m 755 "$unit_dir"
install -d -m 700 "$env_dir"
for f in wg2fa.network wg2fa-data.volume wg2fa.container; do
  install -m 644 "$f" "$unit_dir/$f"
done

if [ ! -f "$env_dir/wg2fa.env" ]; then
  install -m 600 wg2fa.env.example "$env_dir/wg2fa.env"
  echo "Created $env_dir/wg2fa.env"
fi
if [ -n "$endpoint" ]; then
  sed -i "s|^WG2FA_ENDPOINT=.*|WG2FA_ENDPOINT=$endpoint|" "$env_dir/wg2fa.env"
  echo "Set WG2FA_ENDPOINT=$endpoint"
fi

if ! podman secret exists wg2fa_state_key 2>/dev/null; then
  head -c 32 /dev/urandom | base64 | tr -d '\n' | podman secret create wg2fa_state_key - >/dev/null
  echo "Created podman secret wg2fa_state_key (encrypts state.json)."
  echo "  Back it up: podman secret inspect --showsecret --format '{{.SecretData}}' wg2fa_state_key"
fi

# WireGuard needs the kernel module, or /dev/net/tun for the wireguard-go fallback
virt=$(systemd-detect-virt --container 2>/dev/null || true)
if [ "$virt" != lxc ] && modprobe wireguard 2>/dev/null; then
  echo wireguard > /etc/modules-load.d/wg2fa.conf     # load at boot too
fi
if [ -d /sys/module/wireguard ]; then
  echo "WireGuard kernel module: loaded"
elif [ -c /dev/net/tun ]; then
  echo "WireGuard kernel module: not available, using wireguard-go via /dev/net/tun"
else
  echo "WARNING: no WireGuard kernel module and no /dev/net/tun: the VPN can't start." >&2
  if [ "$virt" = lxc ]; then
    cat >&2 <<'MSG'
This is an LXC container. On the Proxmox host, either load the module (preferred):
    modprobe wireguard && echo wireguard > /etc/modules-load.d/wireguard.conf
or pass /dev/net/tun into the container and restart it:
    pct set <CTID> -dev0 /dev/net/tun && pct reboot <CTID>
See https://jwklijnsma.github.io/wireguard/install/podman/#proxmox-lxc
MSG
  fi
fi

systemctl daemon-reload
echo
echo "Installed to $unit_dir. Next:"
grep -q '^WG2FA_ENDPOINT=vpn.example.nl$' "$env_dir/wg2fa.env" && \
  echo "  \$EDITOR $env_dir/wg2fa.env          # set WG2FA_ENDPOINT"
echo "  systemctl start wg2fa.service"
echo "  journalctl -u wg2fa -o cat | grep -A2 'first start'   # initial admin password"
echo "  firewall-cmd --permanent --add-port=51820/udp && firewall-cmd --reload   # if firewalld runs"
echo "  systemctl enable --now podman-auto-update.timer      # optional: daily image updates"
