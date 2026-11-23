# Reverse proxy & TLS

Clients send passwords and 2FA codes to the web GUI (port 8080), so it must not run over plain HTTP on the internet. The default compose file and Podman unit publish it on `127.0.0.1` only, for a reverse proxy on the same host.

## Behind a proxy

=== "Caddy"

    ```caddyfile
    vpn.example.nl {
        reverse_proxy 127.0.0.1:8080
    }
    ```

=== "nginx"

    ```nginx
    server {
        listen 443 ssl;
        server_name vpn.example.nl;
        ssl_certificate     /etc/letsencrypt/live/vpn.example.nl/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/vpn.example.nl/privkey.pem;

        location / {
            proxy_pass http://127.0.0.1:8080;
            proxy_set_header Host              $host;
            proxy_set_header X-Forwarded-For   $remote_addr;   # overwrite, don't append
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-Host  $host;
        }
    }
    ```

Then set:

```bash
WG2FA_TRUST_PROXY=true
WG2FA_TRUSTED_PROXIES=127.0.0.1/32   # the proxy's address as seen by the container
WG2FA_HSTS=true                      # once HTTPS is enforced everywhere
```

`X-Forwarded-*` headers are honoured **only** when the TCP peer is a listed proxy. The client IP is taken from the right-most untrusted `X-Forwarded-For` hop, so direct requests cannot spoof it.

!!! tip
    Add proxy-level rate limiting for `/login`, `/login/2fa` and `/api/v1/client/login`. The built-in limiter is per instance and resets on restart.

## Direct TLS

Alternatively, let the server do TLS itself and publish 8080 on all interfaces:

```bash
WG2FA_TLS_CERT=/data/tls/fullchain.pem
WG2FA_TLS_KEY=/data/tls/privkey.pem
```
