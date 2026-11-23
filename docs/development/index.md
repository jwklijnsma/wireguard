# Development

```bash
go mod tidy            # first time
go test ./...
WG2FA_DATA=./data WG2FA_DRYRUN=1 WG2FA_ENDPOINT=localhost WG2FA_ADMIN_PASSWORD=changeme123 \
  go run ./cmd/wg2fa-server -listen 127.0.0.1:8080
sudo WG2FA_CLIENT_DIR=/tmp/wg2fa go run ./cmd/wg2fa-client run    # client on Linux
```

`WG2FA_DRYRUN=1` keeps the server away from WireGuard and iptables, so you can work on the GUI without root.

## Layout

```
cmd/wg2fa-server      server entry point
cmd/wg2fa-client      desktop client entry point
internal/server       store, auth, 2FA flow, wg reconciler, web GUI, API, router exports
internal/client       wireguard-go tunnel, OS network config (darwin/windows/linux), services, local UI
internal/totp         RFC 6238 TOTP (stdlib only)
packaging/            Docker entrypoint, Podman Quadlet, macOS app/DMG, Windows Inno Setup
docs/                 this site (MkDocs Material)
```

## CI

Every pull request runs `go vet`, `go test -race`, a cross-compile of all client targets, and a Docker build with a Grype vulnerability scan. Renovate keeps dependencies and pinned action digests up to date.

## Documentation

This site is built with [MkDocs Material](https://squidfunk.github.io/mkdocs-material/) from `docs/` and deployed to GitHub Pages on every push to `main`. To preview it locally:

```bash
pip install -r docs/requirements.txt
mkdocs serve        # http://127.0.0.1:8000
```
