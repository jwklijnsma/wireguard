#!/bin/bash
# Removes the WG2FA VPN service, its settings and the app.
echo "Removing WG2FA (you will be asked for your password)…"
sudo launchctl bootout system/nl.jwklijnsma.wg2fa 2>/dev/null
sudo rm -f /Library/LaunchDaemons/nl.jwklijnsma.wg2fa.plist
sudo rm -rf "/Library/Application Support/WG2FA"
sudo rm -rf /Applications/WG2FA.app
echo "Done."
