#!/bin/sh
# Prepares forwarding/NAT, then starts wg2fa-server (which creates wg0,
# falling back to userspace wireguard-go when the kernel module is missing).
set -e
IFACE="${WG2FA_IFACE:-wg0}"
SUBNET="${WG2FA_SUBNET:-10.8.0.0/24}"

if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" != "1" ]; then
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || \
    echo "WARNING: net.ipv4.ip_forward is off; add 'sysctls: net.ipv4.ip_forward=1' to your compose file"
fi

if [ "${WG2FA_NAT:-1}" = "1" ]; then
  OUT="${WG2FA_NAT_IFACE:-$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')}"
  if [ -n "$OUT" ]; then
    iptables -t nat -C POSTROUTING -s "$SUBNET" -o "$OUT" -j MASQUERADE 2>/dev/null || \
      iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$OUT" -j MASQUERADE
    if [ "${WG2FA_FIREWALL:-1}" = "0" ]; then
      # legacy allow-all forwarding; by default wg2fa-server installs a
      # default-deny policy per peer/profile (chain WG2FA-FWD) instead
      echo "WARNING: WG2FA_FIREWALL=0, VPN peers can reach everything"
      iptables -C FORWARD -i "$IFACE" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$IFACE" -j ACCEPT
      iptables -C FORWARD -o "$IFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -o "$IFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    fi
    echo "NAT: $SUBNET -> $OUT"
  fi
fi

exec /usr/local/bin/wg2fa-server "$@"
