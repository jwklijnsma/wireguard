#!/bin/bash
# WG2FA.app entry point: makes sure the privileged VPN service is installed
# (asks for an admin password once), then opens the control UI.
DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$DIR/Resources/wg2fa-client"
INSTALLED="/Library/Application Support/WG2FA/bin/wg2fa-client"
UI="http://127.0.0.1:51821/"

need_install=0
if [ ! -x "$INSTALLED" ]; then
  need_install=1
elif [ "$("$INSTALLED" version 2>/dev/null)" != "$("$BIN" version)" ]; then
  need_install=1   # upgrade after a new DMG
elif ! curl -fs -m 2 "${UI}api/status" >/dev/null; then
  need_install=1
fi

if [ "$need_install" = 1 ]; then
  osascript \
    -e 'on run argv' \
    -e 'do shell script (quoted form of item 1 of argv) & " install" with prompt "WG2FA needs to install its VPN service." with administrator privileges' \
    -e 'end run' "$BIN" || exit 1
  for _ in $(seq 1 30); do curl -fs -m 1 "${UI}api/status" >/dev/null && break; sleep 0.5; done
fi
open "$UI"
