# auth-proxy

A single-file, environment-adaptive HTTP + CONNECT proxy with **Ed25519 public-key
authentication** — SSH-style. No passwords. The server only stores public keys;
clients prove identity by signing a canonical request string with a private key
that never leaves their machine.

Works on: **Termux, plain VPS, Docker, Render, Railway, Fly, Heroku, Cloud Run,
Vercel, anywhere Python 3.8+ and `openssl` exist.**

---

## What it does

- **HTTP proxy** — `GET /?url=https://target` fetches through the server.
  Auth once via signature; server returns a session token that the client reuses
  until it expires (sliding TTL, default 600 s idle).
- **Raw TCP CONNECT tunnel** — standard `CONNECT host:port` for HTTPS or any
  TCP stream. **One connection = one auth.** Once established, bytes flow freely
  until either side closes.

Two independent layers:

| Layer | Controls | Env var |
|---|---|---|
| Ed25519 pubkey | *who* may use the proxy | `PROXY_PUBKEYS` |
| Host allowlist | *what* they can reach | `PROXY_ALLOWED_HOSTS` |

---

## Platform auto-detection

On startup the server detects where it's running and adjusts itself:

| Platform | Detected by | TCP proxy default |
|---|---|---|
| Render | `RENDER` env | **off** (one public port) |
| Railway | `RAILWAY_ENVIRONMENT` | **off** |
| Heroku | `DYNO` | **off** |
| Cloud Run | `K_SERVICE` | **off** |
| Vercel | `VERCEL` | **off** |
| Fly | `FLY_APP_NAME` | **on** |
| Termux | `TERMUX_VERSION` / `PREFIX` | **on** |
| Docker | `/.dockerenv` | **on** |
| Generic VPS | fallback | **on** |

Override any time with `ENABLE_TCP_PROXY=0` or `=1`.

Current state is visible in the JSON at `GET /` (`platform`, `tcp_port`, etc.).

---

## Auth model (SSH-like)

1. **Client** holds a private Ed25519 key.
2. **Server** holds the matching public key.
3. Per-request, the client signs a canonical string:
   - HTTP: `METHOD\nPATH\nURL\nTIMESTAMP\nNONCE\nsha256(BODY)`
   - CONNECT: `CONNECT\nhost:port\nTIMESTAMP\nNONCE`
4. Server checks:
   - fingerprint is a known key
   - timestamp within `AUTH_WINDOW` seconds (default 60)
   - nonce hasn't been seen (replay protection)
   - `openssl pkeyutl -verify` accepts the signature
5. On success, HTTP mints a **session token** (random 32 bytes) good for
   `SESSION_TTL` seconds of idle time, refreshed on each use.
   CONNECT simply proceeds — the tunnel itself *is* the session.

**A leaked server config cannot authenticate.** The server only has public keys.
**A leaked password doesn't exist.** There is no password.

---

## Quick start

### Server

```bash
# 1. deps (Termux: `pkg install openssl python`)
pip install Flask==2.3.3 requests==2.31.0

# 2. generate your keypair (once, keep the .key private)
openssl genpkey -algorithm ED25519 -out proxy_client.key
openssl pkey -in proxy_client.key -pubout -out proxy_client.pub
chmod 600 proxy_client.key

# 3. point the server at the public key
export PROXY_PUBKEYS="$PWD/proxy_client.pub"

# 4. run
python server.py
```

Startup log:

```
[env] platform=termux
[auth] loaded 1 public key(s); window=60s session_ttl=600s
[tcp] listening on 0.0.0.0:10001 (ed25519 auth)
[http] listening on 0.0.0.0:10000
```

### Client

```bash
# signed HTTP fetch (auto-caches session to .proxy_session)
python proxycall.py http https://example.com

# print a signed CONNECT request (pipe into socat/nc for manual tunneling)
python proxycall.py connect example.com:443

# print fingerprint (must match server's)
python proxycall.py fp
```

---

## Environment variables

| Var | Default | Meaning |
|---|---|---|
| `PORT` | `10000` | HTTP port (PaaS usually injects this) |
| `HOST` | `0.0.0.0` | bind address |
| `TCP_PORT` | `10001` | CONNECT tunnel port |
| `ENABLE_TCP_PROXY` | auto | force TCP listener on/off |
| `PROXY_PUBKEYS` | *(empty)* | see *Pubkey formats* below |
| `PROXY_ALLOWED_HOSTS` | *(empty = all)* | comma-separated hostname allowlist |
| `PROXY_TIMEOUT` | `30` | upstream request timeout (s) |
| `PROXY_BUFFER` | `8192` | stream chunk size |
| `PROXY_VERIFY_TLS` | `1` | verify upstream TLS certs |
| `PROXY_AUTH_WINDOW` | `60` | signature freshness window (s) |
| `PROXY_SESSION_TTL` | `600` | HTTP session idle expiry (s) |
| `PROXY_CLIENT_KEY` | `proxy_client.key` | client: path to private key |
| `PROXY_URL` | `http://127.0.0.1:10000` | client: proxy base URL |
| `PROXY_SESSION_FILE` | `.proxy_session` | client: cached session token |

### Pubkey formats accepted by `PROXY_PUBKEYS`

The server auto-detects among three forms:

**A. A single PEM file**

```bash
export PROXY_PUBKEYS=/path/to/authorized_keys.pub
```

**B. A list file** (one entry per line)

```
# comments allowed
/abs/path/to/alice.pub
bdf7f0... /abs/path/to/bob.pub       # declared fp, checked against actual
```

**C. Inline PEM** (env var contains the `-----BEGIN PUBLIC KEY-----` block)

```bash
export PROXY_PUBKEYS="-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA...
-----END PUBLIC KEY-----"
```

Multiple keys = append to the list file (B) or concatenate PEM blocks (C).

---

## Deploying

### Termux / VPS / Docker

`python server.py`. Both HTTP and TCP listeners come up. Done.

### Render / Railway / Heroku / Cloud Run / Vercel

These give you **one public port** (`$PORT`). Use the bundled Flask app as a
WSGI target:

```
gunicorn -w 1 -k gthread --threads 8 -t 120 -b 0.0.0.0:$PORT server:app
```

Use `-w 1` — the session and nonce stores are per-process. Multiple workers
would each have their own store, which weakens replay protection and session
consistency. If you need multiple workers, back the stores with Redis.

Set `PROXY_PUBKEYS` to your public key content or a path. Then set
`PROXY_ALLOWED_HOSTS` to the domains you actually use. The TCP listener
is automatically disabled.

### Fly

`fly.toml` should expose both `$PORT` (HTTP) and `10001` (TCP):

```toml
[[services]]
  internal_port = 10000
  protocol = "tcp"
  [[services.ports]]
    port = 443
    handlers = ["tls", "http"]

[[services]]
  internal_port = 10001
  protocol = "tcp"
  [[services.ports]]
    port = 10001
    handlers = ["tcp"]
```

Then `fly deploy`. TCP proxy comes up automatically.

---

## Security notes

- **Never commit `proxy_client.key`.** Add to `.gitignore`:

  ```
  proxy_client.key
  proxy_client.pub
  pubkeys.txt
  .proxy_session
  proxy.log
  ```

- **Use the allowlist** on any public deployment. Open proxies get abused
  within hours of appearing on Shodan.
- **TLS in front of the HTTP port** if the PaaS doesn't provide it (Render,
  Fly, Cloud Run do; a bare VPS does not — put Caddy or nginx in front).
- **Rotate keys** by adding a new PEM to `pubkeys.txt` and restarting, then
  removing the old line once clients have switched.
- **Session tokens are in-memory.** Restart = all sessions invalidated. The
  client detects this automatically and re-signs.
- **The nonce store is per-process.** Single worker only, or move to Redis.

---

## Troubleshooting

**`[auth] loaded 0 public key(s)`**
`PROXY_PUBKEYS` is unset, points to a missing file, or the key isn't Ed25519.
Check `openssl pkey -pubin -in <file> -noout -text | head -1` — should say
`ED25519 Public-Key:`.

**`{"error":"unauthorized","reason":"no_pubkeys_configured"}`**
Same as above — server has no keys loaded.

**`{"error":"unauthorized","reason":"timestamp_out_of_window"}`**
Client clock is off by more than `AUTH_WINDOW` seconds. Fix with `ntpd`/`date -s`,
or raise `PROXY_AUTH_WINDOW`.

**`{"error":"unauthorized","reason":"bad_session"}`**
Cached `.proxy_session` no longer valid (server restarted, or TTL expired).
The client auto-recovers — just retry.

**`{"error":"Connection failed","status":502,"detail":"..."}`**
The server can't reach the upstream. The `detail` field shows the real reason.
Common causes: DNS in the server process, missing CA bundle, `HTTP_PROXY` env
leaking into the server's environment.

**TCP listener missing on Render/Railway/Heroku**
Expected. Those platforms expose one port. Deploy the CONNECT side on Fly or
a VPS if you need raw TCP.

**`openssl pkeyutl: unknown option -rawin`**
OpenSSL < 1.1.1. Upgrade: `pkg upgrade openssl` (Termux) or `apt install openssl`.

---

## Files

| File | Purpose |
|---|---|
| `server.py` | proxy server (HTTP + TCP) |
| `proxycall.py` | client helper — sign requests, manage session |
| `requirements.txt` | server deps |
| `proxy_client.key` | **your private key — never commit** |
| `proxy_client.pub` | your public key (goes to server) |
| `pubkeys.txt` | optional list of authorized public keys |
| `.proxy_session` | cached session token (client side) |
| `proxy.log` | server log when run with `nohup` |

---

## License

Do what you want. Don't run it open to the world without the allowlist.

---

## Forked TCP child

The TCP listener runs in a **forked child process**, not a thread:

- The fork happens before Flask starts any threads, so it's safe.
- The child binds `TCP_PORT` and dies automatically if the parent dies:
  `prctl(PR_SET_PDEATHSIG)` on Linux/Android, plus a `getppid()` watchdog as
  a portable fallback.
- `kill -9` on the parent never leaves an orphan holding the port.
- Optional `PROXY_PROBE_URL` + `PROXY_PUBLIC_HOST`: the child asks an external
  probe service whether `TCP_PORT` is reachable before binding. If not, it
  exits silently.

### Tiny probe service

`probe_service.py` — deploy on any always-on host with a public IP:

    PROBE_ALLOW_SUFFIXES=".yourdomain.com,proxy." PORT=8100 python probe_service.py

Then on the proxy:

    PROXY_PROBE_URL=https://probe.yourdomain.com/probe
    PROXY_PUBLIC_HOST=proxy.yourdomain.com

Refuses to probe private/loopback IPs and any hostname not matching
`PROBE_ALLOW_SUFFIXES`.

---

## Retry with calculated backoff

Upstream HTTP fetches retry on transient network errors (`ConnectionError`,
`Timeout`). The delay is exponential with jitter — a formula, not a lookup
table:

    delay = min(PROXY_RETRY_CAP, PROXY_RETRY_BASE * 2^attempt) * (1 ± jitter)

| Var | Default | Meaning |
|---|---|---|
| `PROXY_RETRY_MAX` | `2` | retries after first attempt |
| `PROXY_RETRY_BASE` | `0.5` | seconds |
| `PROXY_RETRY_CAP` | `10.0` | max seconds per sleep |
| `PROXY_RETRY_JITTER` | `0.3` | ±30% randomization |

HTTP status errors from upstream (404, 500) are **not** retried.
Retries log as `[retry] METHOD URL attempt N failed: ...; sleeping X.XXs`.

---

## Startup self-test

Before binding, the server runs checks and prints one line each:

    [self-test] openssl: OpenSSL 3.6.5 ...
    [self-test] openssl pkeyutl -rawin: ok
    [self-test] pubkeys loaded: 1
    [self-test] store: memory writable
    [self-test] users.json: not present (ok)
    [self-test] probe: not configured (ok)
    [self-test] port 10000 (HTTP): free
    [self-test] port 10001 (TCP): free

Critical failures (openssl missing, no `-rawin`, store unwritable) exit 1
unless `PROXY_SELF_TEST_FATAL=0`.

### Live key reload

    kill -HUP <parent-pid>

Re-reads `PROXY_PUBKEYS`, swaps the key set in place. Logs
`[sig] SIGHUP: pubkeys reloaded (N -> M)`.

---

## Metrics

`GET /_metrics` returns Prometheus text format:

    proxy2_http_requests_total 42
    proxy2_retries_total 6
    proxy2_pubkeys 1
    proxy2_sessions 3
    proxy2_uptime_seconds 812

Counters: `http_requests_total`, `http_errors_total`,
`connect_requests_total`, `connect_errors_total`, `auth_failures_total`,
`rate_limited_total`, `bytes_in_total`, `bytes_out_total`, `retries_total`.

### Per-host rate limit

`PROXY_HOST_RATE_LIMIT` (default `0` = off) adds a second bucket keyed on
`(fingerprint, hostname)`. Prevents one slow upstream from eating the whole
per-fingerprint budget.

---

## Streaming request bodies

Uploads are streamed to the upstream as an iterator, not buffered in memory.
The body is still read once to compute the signature hash (SHA256 over body),
capped at `PROXY_MAX_BODY` (default 100 MB). Over the cap → `413`.
