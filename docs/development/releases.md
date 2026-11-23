# Releases

Every push to `main` is released automatically by the *Auto release* workflow. It works out the next version from the commit messages since the last tag, then runs the *Release* workflow: tests, client builds, the scanned and signed Docker image, and the GitHub release.

| Commits since last release | Bump |
|---|---|
| `feat:` / `feat(scope):` (also as PR title in a merge commit) | minor: `v1.2.0` → `v1.3.0` |
| `type!:` or `BREAKING CHANGE` | major (minor while on `0.x`) |
| anything else | patch: `v1.2.0` → `v1.2.1` |

No release is made when:

- only CI, docs or Renovate config changed (`.github/`, `docs/`, `*.md`, `renovate.json`, `LICENSE`), or
- the commit message contains `[skip release]`.

## Manual releases

- **Force a bump:** *Actions → Auto release → Run workflow* and pick `patch`, `minor` or `major`.
- **Exact version:** *Actions → Release → Run workflow* with a version, or push a tag:

    ```bash
    git tag v1.0.0 && git push origin v1.0.0
    ```

## What a release contains

- `WG2FA-v1.0.0-macos-universal.dmg`
- `WG2FA-1.0.0-windows-x64-setup.exe`, `…-arm64-setup.exe` and portable zips (with `wintun.dll`)
- `wg2fa-v1.0.0-linux-{amd64,arm64}.tar.gz`
- Docker image `ghcr.io/jwklijnsma/wireguard:1.0.0`, `:1.0` and `:latest` (multi-arch, scanned, signed)
- `SHA256SUMS.txt`

Podman installs with `AutoUpdate=registry` pick up the new `:latest` image through `podman-auto-update.timer`.

## wireguard-go updates

The *wireguard-go update* workflow checks [git.zx2c4.com/wireguard-go](https://git.zx2c4.com/wireguard-go) daily. When a release newer than the version in `go.mod` appears, it opens a `fix(deps)` PR, runs CI on it and merges it when CI passes. The merge then triggers a patch release.

## macOS signing (optional)

Without secrets the app is ad-hoc signed, so Gatekeeper asks once: right-click → *Open*. For a Developer ID signed and notarized DMG, add these repository secrets:

| Secret | Example |
|---|---|
| `MACOS_CERT_P12_BASE64` | base64 of the exported `.p12` |
| `MACOS_CERT_PASSWORD` | password of the `.p12` |
| `MACOS_SIGN_IDENTITY` | `Developer ID Application: Name (TEAMID)` |
| `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_APP_PASSWORD` | for notarization |
