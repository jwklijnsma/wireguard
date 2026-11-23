# Supply chain

- Release images are multi-arch and come with an **SBOM** and **max-mode build provenance**. They are scanned with Grype before publishing (the build fails on fixable High/Critical findings) and signed with **cosign**:
    - **public repo:** keyless signing.
    - **private repo:** key-based signing via `COSIGN_PRIVATE_KEY`/`COSIGN_PASSWORD` secrets, without the public transparency log, so image names don't leak.
- The release notes include the image digest. In production, deploy `ghcr.io/jwklijnsma/wireguard@sha256:…`.
- Renovate pins base images and GitHub Actions by digest (`renovate.json`).
- Release files get `SHA256SUMS.txt`, signed when a cosign key is configured, and GitHub build attestations on public repositories. The Wintun driver download is SHA-256 verified.

## Verify an image

=== "Keyless (public repo)"

    ```bash
    cosign verify \
      --certificate-identity-regexp '^https://github.com/jwklijnsma/wireguard/' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      ghcr.io/jwklijnsma/wireguard@sha256:<digest>
    ```

=== "Key-based"

    ```bash
    cosign verify --key cosign.pub --insecure-ignore-tlog ghcr.io/jwklijnsma/wireguard@sha256:<digest>
    ```

## Verify release files

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
gh attestation verify WG2FA-*-macos-universal.dmg --repo jwklijnsma/wireguard
```
