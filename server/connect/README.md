# Public device enrollment

This is a separate public enrollment application, not the owner panel. It uses
an existing EVN1 account token to register one independent WireGuard device.
The account keeps one token across Linux, Android, Windows and imported profiles.
Device names, separate keys, revocation and account lifecycle belong to the
restricted issuer backend.

The browser generates its private key locally using an unmodified, pinned
WireGuard tools implementation in `static/vendor/wireguard.js`. A profile is
assembled and downloaded locally. Private keys never enter an HTTP request,
the issuer socket, a server response or browser storage. Failed requests retain
the same key and device identifier in page memory for an idempotent retry.
Closing the page loses its private key; another profile creates another device.

## Runtime contract

Install the dependencies in a dedicated virtual environment:

```sh
python3 -m venv /opt/evgenium-connect/venv
/opt/evgenium-connect/venv/bin/pip install -r requirements.txt
```

Run a dedicated unprivileged account with a private writable state directory.
Set `EVG_CONNECT_CONFIG=/etc/evgenium-connect/config.json`; copy the example config.
Bind gunicorn to **127.0.0.1:9082 only**, never to a public interface. The direct
HSVDS HTTPS reverse proxy must overwrite `X-Forwarded-Proto: https` and
`X-Forwarded-For` with the real source address. `ProxyFix` trusts exactly one
proxy for those headers; a publicly exposed gunicorn port would break that trust.
Only the proxy may reach gunicorn. Keep proxy access logs off for this host to
avoid logging accidental tokens pasted into a URL. The app itself rejects all
query strings and never logs enrollment bodies or returned keys.

The process needs group access only to
`/run/evgenium-wireguard/enroll.sock` (restricted to `wireguard-enroll`). It must
not receive access to the administrative issuer socket, owner panel config,
account database, CA or server private key. No owner password/TOTP is required
by this public application, because the high entropy client token authorizes
only device enrollment within its own account.

```sh
gunicorn --bind 127.0.0.1:9082 --workers 2 --threads 2 --timeout 30 wsgi:app
```

The frontend requires HTTPS and `crypto.getRandomValues`. It works without
experimental WebCrypto X25519 support and without external CDNs. Safari imports
the downloaded `.conf` through the official WireGuard app. No real iPhone has
been tested yet; do not claim device validation based on browser or StarFive tests.
This first WireGuard transport does not provide the Linux/Android tunnel ranking.
An operator that blocks WireGuard UDP can still prevent a VPN connection even
when the public HTTPS enrollment page is reachable.

The public page guides iPhone users through three steps: the official App Store
app, a token-authorized local file download, then import and activation in
WireGuard. It displays the actual download filename in the import instructions.
Re-downloading uses the existing profile/key without another enrollment. A
download click never claims the file was saved or the VPN is connected. Optional
device naming and troubleshooting are collapsed; iCloud Drive and On My iPhone
download locations are both explained. Browser layout checks do not substitute
for testing Safari downloads and WireGuard import on a real iPhone.

## Native client API

1. `GET /api/session` over HTTPS. Save the `__Host-evg_connect` cookie and JSON
   `csrf` value. The cookie is Secure, HttpOnly, SameSite Strict, with a 2 hour TTL.
2. `POST /api/enroll` as JSON, same cookie and `X-CSRF-Token` header. Browser
   requests must have same-origin Origin when present. Native clients may omit it.

Request:

```json
{
  "token": "EVN1-<43 base64url characters>",
  "device": "<32 lowercase hexadecimal characters>",
  "name": "Optional device name, up to 64 characters",
  "public_key": "<base64 encoded 32 byte WireGuard public key>"
}
```

The native client keeps its key and device identifier for retries. It must not
send a private key or include token values in command lines, URLs or logs.
Success:

```json
{
  "ok": true,
  "profile": {
    "schema": 1,
    "device": "<same device identifier>",
    "account": "<account id>",
    "device_name": "Устройство-1",
    "device_number": 1,
    "public_key": "<SERVER public key>",
    "endpoint": "195.209.211.163:51820",
    "address": "10.78.0.2/32",
    "dns": ["1.1.1.1", "1.0.0.1"],
    "mtu": 1280,
    "allowed_ips": ["0.0.0.0/0", "::/0"]
  }
}
```

The response example address is illustrative; the issuer chooses its managed
pool. The `::/0` route deliberately captures IPv6: until the server has an IPv6
exit, IPv6 traffic must fail closed rather than escape over the client's direct
connection. The profile uses `PersistentKeepalive = 25`. Device keys are unique;
sharing one `.conf` across devices causes WireGuard endpoint roaming conflicts.

Errors contain only a stable `error` string: 400 `invalid_request`, 401
`token_invalid`, 403 `request_rejected`, 409 `device_conflict`, 429
`too_many_attempts`, 503 `enrollment_unavailable`. Rate limits are persistent
SQLite buckets, per source address and globally, shared across workers. Session
creation and enrollment have separate limits. No tokens are stored in this app's
database. It stores only session hashes, CSRF values, expiry and rate counters.

## Tests

```sh
python3 -m unittest discover -s server/connect/tests -v
```

The tests cover no-cookie/CSRF/cross-origin rejection, TLS/host/query guards,
input and profile injection, stable native-client contract, session expiry,
persistent rate limits, private key exclusion from server and browser requests,
idempotent browser retry, local profile download, and an RFC 7748 key vector
through the exact vendored browser generator. Node is needed for browser tests.

Upstream source (pinned locally, no runtime download):

```text
https://github.com/WireGuard/wireguard-tools/tree/a998407747005ea7e4e0258d96f105c97241e1d3/contrib/keygen-html
```

Downloaded browser profiles assign a deterministic private IPv6 address as well
as IPv4 to the client adapter, and capture the IPv6 default route. This address
is local to the VPN interface; it does not provide an IPv6 Internet exit. The
server only authorizes the peer's IPv4 source and blocks forwarded IPv6. Native
clients retain the original `address` field for protocol compatibility; browser
profiles use the additional validated `addresses` list.
