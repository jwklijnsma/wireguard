# Client API

The desktop clients use this API. It is served next to the web GUI.

| Endpoint | Body / auth | Result |
|---|---|---|
| `POST /api/v1/client/login` | `{username,password,totp,public_key,device_name}` | `{token, expires_at, profile, config}` |
| `GET /api/v1/client/status` | `Authorization: Bearer <token>` | `{active, expires_at, …}` |
| `POST /api/v1/client/logout` | `Authorization: Bearer <token>` | ends the session |

The device generates its own key pair and sends only the public key; the private key never leaves the device. Tokens are random 256-bit values that the server stores only as SHA-256 hashes.

`/api/v1/client/login` is rate-limited per IP and per user. Add proxy-level rate limiting too (see the [OPSEC checklist](../security/checklist.md)).
