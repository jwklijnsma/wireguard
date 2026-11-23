# Forwarding policy

With `WG2FA_FIREWALL=true` (default), the server installs this chain and keeps it in sync with peers and sessions:

```
WG2FA-FWD (hooked from FORWARD for -i wg0 and -o wg0)
  RELATED,ESTABLISHED                       ACCEPT   return traffic
  INVALID                                   DROP
  -d <WG2FA_BLOCK_NETS>                     DROP     everyone, before any accept
  per unlocked peer / always-on router:
    -s <tunnel IP / router LANs> -d <VPN subnet>    DROP   unless profile allows peer-to-peer
    -s <tunnel IP / router LANs> -d <profile route> ACCEPT
  everything else                           DROP     incl. new connections INTO the tunnel
```

To check it:

```bash
docker exec wg2fa iptables -S WG2FA-FWD
```

A full-tunnel profile (`0.0.0.0/0`) can reach the internet and any internal network not listed in `WG2FA_BLOCK_NETS`. For road-warriors that should only reach specific systems, use a split-tunnel profile that lists exactly those networks.

!!! danger "`WG2FA_FIREWALL=0`"
    Falls back to legacy allow-all forwarding: VPN peers can reach everything. Only use it when you manage forwarding rules yourself.
