import os
import sys
import json
import base64
import hashlib
import socket
import select
import signal
import subprocess
import tempfile
import threading
import time
import urllib.parse
from flask import Flask, request, jsonify, Response
import requests

# ---------------------------------------------------------------------------
# Environment detection
# ---------------------------------------------------------------------------

def detect_platform():
    e = os.environ
    if e.get("RENDER"): return "render"
    if e.get("FLY_APP_NAME") or e.get("FLY_MACHINE_ID"): return "fly"
    if e.get("RAILWAY_ENVIRONMENT") or e.get("RAILWAY_PROJECT_ID"): return "railway"
    if e.get("DYNO"): return "heroku"
    if e.get("K_SERVICE"): return "cloudrun"
    if e.get("VERCEL"): return "vercel"
    if e.get("KUBERNETES_SERVICE_HOST"): return "k8s"
    if "com.termux" in e.get("PREFIX", "") or e.get("TERMUX_VERSION"): return "termux"
    if os.path.exists("/.dockerenv"): return "docker"
    return "generic"


PLATFORM = detect_platform()
SINGLE_PORT_PLATFORMS = {"render", "railway", "heroku", "cloudrun", "vercel"}

PORT     = int(os.environ.get("PORT", 10000))
HOST     = os.environ.get("HOST", "0.0.0.0")
TCP_PORT = int(os.environ.get("TCP_PORT", 10001))

_env_tcp = os.environ.get("ENABLE_TCP_PROXY")
ENABLE_TCP_PROXY = (env_tcp_flag := (_env_tcp == "1")) if _env_tcp is not None \
                   else PLATFORM not in SINGLE_PORT_PLATFORMS

# Probe: if set, the TCP child asks an outside service whether the port
# is reachable before binding. Operator override always wins.
PROBE_URL     = os.environ.get("PROXY_PROBE_URL", "").strip()
PROBE_HOST    = os.environ.get("PROXY_PUBLIC_HOST", "").strip()
PROBE_TIMEOUT = float(os.environ.get("PROXY_PROBE_TIMEOUT", "5"))

# Retry policy for upstream HTTP fetches (ConnectionError / Timeout).
# Backoff is exponential with jitter, calculated - not a lookup table.
PROXY_RETRY_MAX   = int(os.environ.get("PROXY_RETRY_MAX", "2"))     # 2 => 3 total tries
PROXY_RETRY_BASE  = float(os.environ.get("PROXY_RETRY_BASE", "0.5")) # seconds
PROXY_RETRY_CAP   = float(os.environ.get("PROXY_RETRY_CAP", "10.0")) # seconds
PROXY_RETRY_JITTER = float(os.environ.get("PROXY_RETRY_JITTER", "0.3"))

# Optional per-host rate limiting (in addition to per-fingerprint).
# 0 = off. When on, each (fp, hostname) pair gets its own bucket.
PROXY_HOST_RATE = int(os.environ.get("PROXY_HOST_RATE_LIMIT", "0"))

# Self-test behavior: if critical checks fail, exit before binding.
PROXY_SELF_TEST_FATAL = os.environ.get("PROXY_SELF_TEST_FATAL", "1") == "1"

DEFAULT_TIMEOUT   = int(os.environ.get("PROXY_TIMEOUT", 30))
DEFAULT_BUFFER    = int(os.environ.get("PROXY_BUFFER", 8192))
VERIFY_TLS        = os.environ.get("PROXY_VERIFY_TLS", "1") == "1"
AUTH_WINDOW       = int(os.environ.get("PROXY_AUTH_WINDOW", 60))
SESSION_TTL       = int(os.environ.get("PROXY_SESSION_TTL", 600))
IDLE_TIMEOUT      = int(os.environ.get("PROXY_IDLE_TIMEOUT", 3600))   # 0 = infinite
MAX_BODY          = int(os.environ.get("PROXY_MAX_BODY", 100 * 1024 * 1024))
DEFAULT_RATE      = int(os.environ.get("PROXY_RATE_LIMIT", 0))        # req/min, 0 = off
ACCESS_LOG        = os.environ.get("PROXY_ACCESS_LOG", "1") == "1"

# ---------------------------------------------------------------------------
# Shared store: memory | file | redis
# ---------------------------------------------------------------------------

REDIS_URL    = os.environ.get("REDIS_URL", "").strip()
MULTIWORKER  = os.environ.get("PROXY_MULTIWORKER", "0") == "1"

if REDIS_URL:
    STORE_KIND = "redis"
elif MULTIWORKER:
    STORE_KIND = "file"
else:
    STORE_KIND = "memory"

def _resolve_store_dir():
    """Pick a writable store dir. Returns path or None."""
    candidates = []
    env_dir = os.environ.get("PROXY_STORE_DIR")
    if env_dir:
        candidates.append(env_dir)
    candidates.append(os.path.join(tempfile.gettempdir(), "proxy2_store"))
    candidates.append(os.path.join(os.getcwd(), ".proxy_store"))
    candidates.append("/var/tmp/proxy2_store")

    for d in candidates:
        try:
            os.makedirs(d, exist_ok=True)
            test = os.path.join(d, ".write_test")
            with open(test, "wb") as fh:
                fh.write(b"ok")
            with open(test, "rb") as fh:
                if fh.read() != b"ok":
                    raise OSError("readback mismatch")
            os.unlink(test)
            return d
        except OSError:
            continue
    return None


FILE_STORE_DIR = _resolve_store_dir()


class MemoryStore:
    kind = "memory"

    def __init__(self):
        self._lock = threading.Lock()
        self._d = {}

    def setex(self, key, ttl, value=b"1"):
        with self._lock:
            self._d[key] = (value, time.time() + ttl)

    def get(self, key):
        with self._lock:
            v = self._d.get(key)
            if not v:
                return None
            val, exp = v
            if exp < time.time():
                del self._d[key]
                return None
            return val

    def del_(self, key):
        with self._lock:
            self._d.pop(key, None)

    def touch(self, key, ttl):
        with self._lock:
            v = self._d.get(key)
            if not v:
                return None
            val, exp = v
            if exp < time.time():
                del self._d[key]
                return None
            self._d[key] = (val, time.time() + ttl)
            return val

    def incr_with_ttl(self, key, ttl):
        with self._lock:
            now = time.time()
            v = self._d.get(key)
            if not v or v[1] < now:
                self._d[key] = (b"1", now + ttl)
                return 1
            val, exp = v
            n = int(val) + 1
            self._d[key] = (str(n).encode(), exp)
            return n


class FileStore:
    kind = "file"

    def __init__(self, d, cleanup_on_init=True):
        self.d = d
        if cleanup_on_init:
            self._cleanup()

    def _cleanup(self):
        """Delete files whose first line (expiry) is in the past."""
        now = time.time()
        removed = 0
        try:
            for name in os.listdir(self.d):
                if name.startswith("."):
                    continue
                path = os.path.join(self.d, name)
                try:
                    with open(path, "rb") as fh:
                        head = fh.readline()
                    if float(head.strip()) < now:
                        os.unlink(path)
                        removed += 1
                except (OSError, ValueError):
                    continue
        except OSError:
            pass
        if removed:
            print(f"[store] file cleanup: removed {removed} expired entries", flush=True)

    def _path(self, key):
        h = hashlib.sha256(key.encode()).hexdigest()
        return os.path.join(self.d, h)

    def setex(self, key, ttl, value=b"1"):
        exp = time.time() + ttl
        with open(self._path(key), "wb") as fh:
            fh.write(f"{exp}\n".encode() + value)

    def get(self, key):
        p = self._path(key)
        try:
            with open(p, "rb") as fh:
                data = fh.read()
        except OSError:
            return None
        nl = data.find(b"\n")
        if nl < 0:
            return None
        exp = float(data[:nl])
        if exp < time.time():
            try: os.unlink(p)
            except OSError: pass
            return None
        return data[nl + 1:]

    def del_(self, key):
        try: os.unlink(self._path(key))
        except OSError: pass

    def touch(self, key, ttl):
        p = self._path(key)
        try:
            with open(p, "rb") as fh:
                data = fh.read()
        except OSError:
            return None
        nl = data.find(b"\n")
        if nl < 0:
            return None
        exp = float(data[:nl])
        if exp < time.time():
            try: os.unlink(p)
            except OSError: pass
            return None
        val = data[nl + 1:]
        self.setex(key, ttl, val)
        return val

    def incr_with_ttl(self, key, ttl):
        p = self._path(key)
        now = time.time()
        try:
            with open(p, "rb") as fh:
                data = fh.read()
            nl = data.find(b"\n")
            exp = float(data[:nl])
            val = data[nl + 1:]
            if exp < now:
                raise ValueError
            n = int(val) + 1
            self.setex(key, exp - now, str(n).encode())
            return n
        except (OSError, ValueError):
            self.setex(key, ttl, b"1")
            return 1


class RedisStore:
    kind = "redis"

    def __init__(self, url):
        import redis  # noqa
        self.r = redis.from_url(url, decode_responses=False)

    def setex(self, key, ttl, value=b"1"):
        self.r.setex(key, ttl, value)

    def get(self, key):
        return self.r.get(key)

    def del_(self, key):
        self.r.delete(key)

    def touch(self, key, ttl):
        v = self.r.get(key)
        if v is None:
            return None
        self.r.expire(key, ttl)
        return v

    def incr_with_ttl(self, key, ttl):
        n = self.r.incr(key)
        if n == 1:
            self.r.expire(key, ttl)
        return n


if STORE_KIND == "redis":
    try:
        STORE = RedisStore(REDIS_URL)
    except Exception as e:
        print(f"[store] redis failed ({e}); falling back to memory", flush=True)
        STORE = MemoryStore()
elif STORE_KIND == "file":
    if FILE_STORE_DIR is None:
        print("[store] no writable dir for file store; using memory", flush=True)
        STORE = MemoryStore()
    else:
        STORE = FileStore(FILE_STORE_DIR)
else:
    STORE = MemoryStore()

# ---------------------------------------------------------------------------
# Multi-worker guard
# ---------------------------------------------------------------------------

def _in_multi_worker_context():
    if os.environ.get("GUNICORN_CMD_ARGS", "").find("-w ") >= 0:
        return True
    if os.environ.get("WEB_CONCURRENCY"):
        try:
            return int(os.environ["WEB_CONCURRENCY"]) > 1
        except ValueError:
            pass
    return False


if STORE.kind == "memory" and _in_multi_worker_context():
    print("[store] WARNING: multiple workers with in-memory store. "
          "Replay/session protection will be per-worker. "
          "Set REDIS_URL or PROXY_MULTIWORKER=1.", flush=True)

# ---------------------------------------------------------------------------
# Proxy env sanitizer
# ---------------------------------------------------------------------------

def _scrub_proxy_env():
    killed = []
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
              "http_proxy", "https_proxy", "all_proxy"):
        if k in os.environ:
            killed.append(k)
            del os.environ[k]
    if killed:
        print(f"[env] unset proxy vars: {','.join(killed)}", flush=True)


_scrub_proxy_env()

# ---------------------------------------------------------------------------
# Access log
# ---------------------------------------------------------------------------

_log_lock = threading.Lock()

def log_access(**kw):
    if not ACCESS_LOG:
        return
    kw["ts"] = time.time()
    with _log_lock:
        print(json.dumps(kw, separators=(",", ":")), flush=True)


# ---------------------------------------------------------------------------
# Pubkey loading
# ---------------------------------------------------------------------------

def _fingerprint_from_pem(path):
    out = subprocess.check_output(
        ["openssl", "pkey", "-in", path, "-pubin", "-outform", "DER"],
        stderr=subprocess.DEVNULL,
    )
    return out[-32:].hex()


def _key_type_is_ed25519(path):
    try:
        out = subprocess.check_output(
            ["openssl", "pkey", "-in", path, "-pubin", "-noout", "-text"],
            stderr=subprocess.DEVNULL,
        )
        return b"ED25519" in out.upper()
    except subprocess.CalledProcessError:
        return False


def _load_one_key(path, fp_declared=None):
    """Load a single PEM path. Returns (fp, path) or None."""
    if not os.path.exists(path):
        print(f"[auth] pubkey not found: {path}", flush=True)
        return None
    if not _key_type_is_ed25519(path):
        print(f"[auth] not an Ed25519 key: {path}", flush=True)
        return None
    try:
        fp = _fingerprint_from_pem(path)
    except subprocess.CalledProcessError as e:
        print(f"[auth] openssl failed on {path}: {e}", flush=True)
        return None
    if fp_declared and fp_declared.lower() != fp:
        print(f"[auth] fp mismatch {path}: declared={fp_declared} actual={fp}", flush=True)
        return None
    return fp, path


def _load_inline_pems(body):
    tmpdir = tempfile.mkdtemp(prefix="proxy_pub_")
    keys = {}
    idx = 0
    for chunk in body.split("-----BEGIN"):
        chunk = chunk.strip()
        if not chunk:
            continue
        path = os.path.join(tmpdir, f"k{idx}.pem")
        with open(path, "w") as fh:
            fh.write("-----BEGIN" + chunk)
        idx += 1
        got = _load_one_key(path)
        if got:
            keys[got[0]] = got[1]
    return keys


def _load_authorized_keys_line(line):
    """Parse a single OpenSSH-style line: '<type> <base64> [comment]'.
    Returns (fp_hex, pem_path) or None. Only ed25519 keys supported."""
    import binascii
    parts = line.strip().split()
    if len(parts) < 2:
        return None
    key_type, b64 = parts[0], parts[1]
    if "ed25519" not in key_type.lower():
        return None
    try:
        raw = base64.b64decode(b64)
    except (binascii.Error, ValueError):
        return None
    # OpenSSH wire format for ed25519: <len:str "ssh-ed25519"><len:str 32-byte pubkey>
    if len(raw) < 4:
        return None
    tlen = int.from_bytes(raw[:4], "big")
    if 4 + tlen + 4 > len(raw):
        return None
    klen = int.from_bytes(raw[4 + tlen: 8 + tlen], "big")
    if klen != 32:
        return None
    pub = raw[8 + tlen: 8 + tlen + 32]
    fp = hashlib.sha256(pub).hexdigest()[:16]

    # Write a PEM version so the existing openssl verifier can use it.
    tmpdir = tempfile.mkdtemp(prefix="proxy_ak_")
    pem_path = os.path.join(tmpdir, f"{fp}.pem")
    # Ed25519 SubjectPublicKeyInfo prefix for a 32-byte raw key:
    # 30 2a 30 05 06 03 2b 65 70 03 21 00 <32 bytes>
    spki_prefix = bytes.fromhex("302a300506032b6570032100")
    der = spki_prefix + pub
    b64der = base64.b64encode(der).decode()
    pem = "-----BEGIN PUBLIC KEY-----\n"
    for i in range(0, len(b64der), 64):
        pem += b64der[i:i+64] + "\n"
    pem += "-----END PUBLIC KEY-----\n"
    with open(pem_path, "w") as fh:
        fh.write(pem)
    return fp, pem_path


def _load_pubkeys():
    raw = os.environ.get("PROXY_PUBKEYS", "").strip()
    if not raw:
        return {}

    # Resolve env value to (content, source_path_or_None)
    source = None
    if os.path.exists(raw) and os.path.isfile(raw):
        source = raw
        with open(raw) as fh:
            body = fh.read().strip()
    else:
        body = raw

    # Case 1: content is inline PEM(s)
    if "-----BEGIN" in body:
        return _load_inline_pems(body)

    # Case 2: source is a file. Two sub-cases:
    #   2a. the file IS a PEM (list of one)
    #   2b. the file is a list file (fingerprint path | path per line)
    if source:
        if _key_type_is_ed25519(source):
            got = _load_one_key(source)
            return {got[0]: got[1]} if got else {}

        keys = {}
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            fp_declared = parts[0] if len(parts) >= 2 else None
            pem_path = parts[1] if len(parts) >= 2 else parts[0]
            got = _load_one_key(pem_path, fp_declared)
            if got:
                keys[got[0]] = got[1]
        return keys

    # Case 3: raw string is not a path and not PEM. Try as a bare path.
    if os.path.exists(body):
        got = _load_one_key(body)
        return {got[0]: got[1]} if got else {}

    # Case 4: authorized_keys-format text (one or more lines).
    keys = {}
    tried_lines = 0
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        tried_lines += 1
        got = _load_authorized_keys_line(line)
        if got:
            keys[got[0]] = got[1]
    if keys:
        return keys

    print(f"[auth] PROXY_PUBKEYS did not match any known format. "
          f"Tried: inline PEM, single PEM path, list file, authorized_keys "
          f"({tried_lines} candidate line(s)).", flush=True)
    return {}


PUBKEYS = _load_pubkeys()

# ---------------------------------------------------------------------------
# Per-user config (users.json)
# ---------------------------------------------------------------------------

USERS = {}
_users_path = os.environ.get("PROXY_USERS_FILE", "users.json")
if os.path.exists(_users_path):
    try:
        with open(_users_path) as fh:
            USERS = json.load(fh)
        print(f"[users] loaded {len(USERS)} entries from {_users_path}", flush=True)
    except Exception as e:
        print(f"[users] failed to load {_users_path}: {e}", flush=True)


def user_conf(fp):
    return USERS.get(fp, {})


def user_allowlist(fp):
    u = user_conf(fp)
    if "allow" in u:
        return {h.strip().lower() for h in u["allow"] if h.strip()}
    return ALLOWED_HOSTS


def user_rate(fp):
    return int(user_conf(fp).get("rate", DEFAULT_RATE))


def user_expired(fp):
    u = user_conf(fp)
    exp = u.get("expires")
    if not exp:
        return False
    try:
        import datetime as _dt
        return _dt.datetime.fromisoformat(exp).timestamp() < time.time()
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def _verify_sig(fp, canonical, signature_b64):
    pem_path = PUBKEYS.get(fp)
    if pem_path is None:
        return False
    try:
        sig = base64.b64decode(signature_b64)
    except Exception:
        return False
    msg_fd, msg_path = tempfile.mkstemp(prefix="proxy_msg_")
    sig_fd, sig_path = tempfile.mkstemp(prefix="proxy_sig_")
    try:
        with os.fdopen(msg_fd, "wb") as fh:
            fh.write(canonical.encode())
        with os.fdopen(sig_fd, "wb") as fh:
            fh.write(sig)
        r = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pem_path,
             "-rawin", "-in", msg_path, "-sigfile", sig_path],
            capture_output=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False
    finally:
        for p in (msg_path, sig_path):
            try: os.unlink(p)
            except OSError: pass


def _canonical_http(method, path, url, ts, nonce, body):
    return "\n".join([method.upper(), path, url or "", ts, nonce,
                      hashlib.sha256(body or b"").hexdigest()])


def _canonical_connect(target, ts, nonce):
    return "\n".join(["CONNECT", target, ts, nonce])


def _check_nonce(fp, nonce, now):
    key = f"nonce:{fp}:{nonce}"
    if STORE.get(key) is not None:
        return False
    STORE.setex(key, AUTH_WINDOW * 2)
    return True


def _rate_ok(fp, host=None):
    limit = user_rate(fp)
    if limit <= 0:
        return True, None
    key = f"rate:{fp}"
    n = STORE.incr_with_ttl(key, 60)
    if n > limit:
        return False, ("fp", limit, n)
    if PROXY_HOST_RATE > 0 and host:
        hkey = f"rate:{fp}:{host}"
        hn = STORE.incr_with_ttl(hkey, 60)
        if hn > PROXY_HOST_RATE:
            return False, ("host", PROXY_HOST_RATE, hn)
    return True, None


def verify_request(headers_get, method, path, url, body):
    if not PUBKEYS:
        return False, "no_pubkeys_configured", None

    now = int(time.time())

    sess = headers_get("X-Proxy-Session")
    if sess:
        fp = STORE.touch(f"session:{sess}", SESSION_TTL)
        if fp:
            fp = fp.decode() if isinstance(fp, bytes) else fp
            if user_expired(fp):
                return False, "user_expired", fp
            try:
                host = urllib.parse.urlparse(url).hostname or None
            except Exception:
                host = None
            ok, _ = _rate_ok(fp, host)
            if not ok:
                return False, "rate_limited", fp
            return True, "ok-session", fp
        if not headers_get("X-Proxy-Pubkey"):
            return False, "bad_session", None

    fp = headers_get("X-Proxy-Pubkey")
    ts = headers_get("X-Proxy-Timestamp")
    nonce = headers_get("X-Proxy-Nonce")
    sig = headers_get("X-Proxy-Signature")
    if not all([fp, ts, nonce, sig]):
        return False, "missing_auth_headers", None

    try:
        ts_i = int(ts)
    except ValueError:
        return False, "bad_timestamp", None
    if abs(now - ts_i) > AUTH_WINDOW:
        return False, "timestamp_out_of_window", None
    if fp not in PUBKEYS:
        return False, "unknown_pubkey", None
    if user_expired(fp):
        return False, "user_expired", fp

    canonical = _canonical_http(method, path, url, ts, nonce, body)
    if not _verify_sig(fp, canonical, sig):
        return False, "bad_signature", None
    if not _check_nonce(fp, nonce, now):
        return False, "nonce_replay", None

    try:
        host = urllib.parse.urlparse(url).hostname or None
    except Exception:
        host = None
    ok, _ = _rate_ok(fp, host)
    if not ok:
        return False, "rate_limited", fp

    return True, "ok", fp


def host_ok_for(fp, url):
    allow = user_allowlist(fp) if fp else ALLOWED_HOSTS
    if not allow:
        return True
    try:
        h = urllib.parse.urlparse(url).hostname
    except Exception:
        return False
    return bool(h) and h.lower() in allow


ALLOWED_HOSTS = {
    h.strip().lower()
    for h in os.environ.get("PROXY_ALLOWED_HOSTS", "").split(",")
    if h.strip()
}

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "*/*",
    "Accept-Encoding": "identity",
    "Connection": "close",
}

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    "content-encoding", "content-length",
}

app = Flask(__name__)

# ---------------------------------------------------------------------------
# HTTP proxy
# ---------------------------------------------------------------------------

def _backoff(attempt):
    """Exponential backoff with jitter, capped.
    attempt: 0 for first retry, 1 for second, ...
    Returns seconds to sleep."""
    import random
    raw = min(PROXY_RETRY_CAP, PROXY_RETRY_BASE * (2 ** attempt))
    return raw * (1.0 + random.uniform(-PROXY_RETRY_JITTER, PROXY_RETRY_JITTER))


def _request_with_retry(method, url, **kwargs):
    """requests.request with backoff on transient network errors.
    Retries on ConnectionError and Timeout only - not on HTTP status errors."""
    last_exc = None
    for attempt in range(PROXY_RETRY_MAX + 1):
        try:
            return requests.request(method=method, url=url, **kwargs), None
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout) as e:
            last_exc = e
            if attempt < PROXY_RETRY_MAX:
                delay = _backoff(attempt)
                print(f"[retry] {method} {url} attempt {attempt+1} failed: "
                      f"{type(e).__name__}; sleeping {delay:.2f}s", flush=True)
                _metric_inc("retries_total")
                time.sleep(delay)
                continue
            break
    return None, last_exc


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
def proxy_http(path):
    t0 = time.time()
    url = request.args.get("url")
    mode = request.args.get("mode", "anonymous")

    try:
        timeout = int(request.args.get("timeout", DEFAULT_TIMEOUT))
    except ValueError:
        timeout = DEFAULT_TIMEOUT

    # Bounded body read. Used for auth hashing.
    # Actual upstream send streams when possible (see data_stream below).
    if request.content_length and request.content_length > MAX_BODY:
        return jsonify({"error": "body too large"}), 413

    body = b""
    body_stream_factory = None
    if request.content_length and request.content_length > 0:
        # Hash requires full bytes; we read once, but send streaming downstream.
        body = request.get_data()
        def body_stream_factory(_b=body):
            yield _b

    resp_session = None
    fp = None

    if url:
        ok, reason, fp = verify_request(
            request.headers.get, request.method, "/" + path, url, body
        )
        if not ok:
            log_access(evt="http", fp=fp, url=url, status=401, reason=reason,
                       dur=round((time.time() - t0) * 1000))
            return jsonify({"error": "unauthorized", "reason": reason}), 401
        if reason == "ok":
            token = base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("=")
            STORE.setex(f"session:{token}", SESSION_TTL, fp.encode())
            resp_session = token

    if not url:
        return jsonify({
            "status": "proxy running",
            "platform": PLATFORM,
            "store": STORE.kind,
            "port": PORT,
            "tcp_port": TCP_PORT if ENABLE_TCP_PROXY else None,
            "auth": "ed25519-pubkey",
            "pubkeys_loaded": len(PUBKEYS),
            "users_loaded": len(USERS),
            "auth_window": AUTH_WINDOW,
            "session_ttl": SESSION_TTL,
            "idle_timeout": IDLE_TIMEOUT,
            "allowlist_enabled": bool(ALLOWED_HOSTS),
            "tls_verify": VERIFY_TLS,
            "health": "/_health",
        })

    if not host_ok_for(fp, url):
        log_access(evt="http", fp=fp, url=url, status=403,
                   dur=round((time.time() - t0) * 1000))
        return jsonify({"error": "host not allowed"}), 403

    if mode == "forward":
        headers = {k: v for k, v in request.headers
                   if k.lower() not in {"host", "content-length"}
                   and not k.lower().startswith("x-proxy-")}
        headers["Accept-Encoding"] = "identity"
    elif mode == "custom":
        headers = {}
        for key, value in request.args.items():
            if key.startswith("header_"):
                headers[key[len("header_"):].replace("_", "-")] = value
        headers.setdefault("Accept-Encoding", "identity")
    else:
        headers = DEFAULT_HEADERS.copy()

    passthrough = [
        (k, v) for k, v in request.args.lists()
        if not k.startswith("header_")
        and k not in {"url", "mode", "timeout", "bufsize"}
    ]

    # requests accepts a file-like or iterator for streaming uploads.
    # We hand it the generator when we have a body; otherwise None.
    send_data = body_stream_factory() if body_stream_factory else None

    resp, exc = _request_with_retry(
        request.method, url,
        headers=headers, data=send_data,
        cookies=request.cookies if mode == "forward" else {},
        params=passthrough, timeout=timeout, verify=VERIFY_TLS,
        allow_redirects=True, stream=True,
    )

    if exc is not None:
        # Retries exhausted (or a non-retryable error we catch explicitly).
        if isinstance(exc, requests.exceptions.Timeout):
            log_access(evt="http", fp=fp, url=url, status=504,
                       dur=round((time.time() - t0) * 1000))
            return jsonify({"error": "Request timeout", "status": 504}), 504
        if isinstance(exc, requests.exceptions.ConnectionError):
            log_access(evt="http", fp=fp, url=url, status=502,
                       dur=round((time.time() - t0) * 1000))
            return jsonify({"error": "Connection failed", "status": 502,
                            "detail": str(exc)[:300]}), 502
        if isinstance(exc, requests.exceptions.RequestException):
            code = exc.response.status_code if getattr(exc, "response", None) is not None else 502
            return jsonify({"error": str(exc), "status": code}), code
        return jsonify({"error": str(exc), "status": 500}), 500

    _metric_inc("http_requests_total")
    resp_headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in HOP_BY_HOP]
    sent = {"n": 0}

    def stream():
        try:
            for chunk in resp.iter_content(chunk_size=DEFAULT_BUFFER):
                if chunk:
                    sent["n"] += len(chunk)
                    yield chunk
        finally:
            resp.close()
            log_access(evt="http", fp=fp, url=url, status=resp.status_code,
                       bytes_out=sent["n"], dur=round((time.time() - t0) * 1000))

    r = Response(stream(), status=resp.status_code, headers=resp_headers)
    if resp_session:
        r.headers["X-Proxy-Session"] = resp_session
    return r


# ---------------------------------------------------------------------------
# Metrics (Prometheus text format)
# ---------------------------------------------------------------------------

_metrics_lock = threading.Lock()
_metrics = {
    "http_requests_total": 0,
    "http_errors_total": 0,
    "connect_requests_total": 0,
    "connect_errors_total": 0,
    "auth_failures_total": 0,
    "rate_limited_total": 0,
    "bytes_in_total": 0,
    "bytes_out_total": 0,
    "retries_total": 0,
}

def _metric_inc(name, by=1):
    with _metrics_lock:
        _metrics[name] = _metrics.get(name, 0) + by


@app.route("/_health")
def health():
    return "OK"


@app.route("/_metrics")
def metrics():
    with _metrics_lock:
        m = dict(_metrics)
    body = []
    for k, v in sorted(m.items()):
        body.append(f"# TYPE proxy2_{k} counter")
        body.append(f"proxy2_{k} {v}")
    body.append("# TYPE proxy2_uptime_seconds gauge")
    body.append(f"proxy2_uptime_seconds {int(time.time() - _start_time)}")
    body.append("# TYPE proxy2_pubkeys gauge")
    body.append(f"proxy2_pubkeys {len(PUBKEYS)}")
    body.append("# TYPE proxy2_sessions gauge")
    try:
        with _session_lock:
            body.append(f"proxy2_sessions {len(_sessions)}")
    except NameError:
        body.append("proxy2_sessions 0")
    return "\n".join(body) + "\n", 200, {"Content-Type": "text/plain; version=0.0.4"}


# ---------------------------------------------------------------------------
# CONNECT (raw TCP tunnel)
# ---------------------------------------------------------------------------

def _recv_headers(sock, bufsize):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(bufsize)
        if not chunk:
            return None
        data += chunk
        if len(data) > 64 * 1024:
            return None
    return data


def _parse_headers(head):
    hdrs = {}
    for line in head.split(b"\r\n")[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            hdrs[k.strip().decode("latin1").lower()] = v.strip().decode("latin1")
    return hdrs


def handle_client(client_sock):
    target_sock = None
    t0 = time.time()
    fp = None
    target = ""
    try:
        data = _recv_headers(client_sock, DEFAULT_BUFFER)
        if not data:
            return
        head, _, rest = data.partition(b"\r\n\r\n")
        first = head.split(b"\r\n", 1)[0].decode("latin1")
        parts = first.split()
        if len(parts) < 2:
            return

        method, target = parts[0], parts[1]

        if method != "CONNECT":
            client_sock.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return

        if not PUBKEYS:
            client_sock.sendall(b"HTTP/1.1 503 Auth Not Configured\r\n\r\n")
            return

        hdrs = _parse_headers(head)
        fp = hdrs.get("x-proxy-pubkey", "")
        ts = hdrs.get("x-proxy-timestamp", "")
        nonce = hdrs.get("x-proxy-nonce", "")
        sig = hdrs.get("x-proxy-signature", "")

        fail = None
        if not all([fp, ts, nonce, sig]):
            fail = "missing_auth_headers"
        else:
            try:
                ts_i = int(ts)
            except ValueError:
                ts_i = 0
            now = int(time.time())
            if abs(now - ts_i) > AUTH_WINDOW:
                fail = "timestamp_out_of_window"
            elif fp not in PUBKEYS:
                fail = "unknown_pubkey"
            elif user_expired(fp):
                fail = "user_expired"
            else:
                canonical = _canonical_connect(target, ts, nonce)
                if not _verify_sig(fp, canonical, sig):
                    fail = "bad_signature"
                elif not _check_nonce(fp, nonce, now):
                    fail = "nonce_replay"
                else:
                    tgt_host = target.rsplit(":", 1)[0] if ":" in target else target
                    ok, _ = _rate_ok(fp, tgt_host)
                    if not ok:
                        fail = "rate_limited"

        if fail:
            client_sock.sendall(
                f"HTTP/1.1 401 Unauthorized\r\nX-Proxy-Reason: {fail}\r\n\r\n".encode()
            )
            log_access(evt="connect", fp=fp, target=target, status=401, reason=fail,
                       dur=round((time.time() - t0) * 1000))
            return

        try:
            host, port_s = target.rsplit(":", 1)
            port = int(port_s)
        except Exception:
            client_sock.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return

        if not host_ok_for(fp, f"scheme://{host}"):
            client_sock.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            log_access(evt="connect", fp=fp, target=target, status=403,
                       dur=round((time.time() - t0) * 1000))
            return

        target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_sock.settimeout(30)
        try:
            target_sock.connect((host, port))
        except socket.timeout:
            client_sock.sendall(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n")
            return
        except OSError:
            client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return
        finally:
            try: target_sock.settimeout(None)
            except OSError: pass

        client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        if rest:
            target_sock.sendall(rest)

        idle = IDLE_TIMEOUT if IDLE_TIMEOUT > 0 else None
        bytes_in = bytes_out = 0
        sockets = [client_sock, target_sock]
        while True:
            rlist, _, _ = select.select(sockets, [], [], idle)
            if not rlist:
                break
            for sock in rlist:
                try:
                    chunk = sock.recv(DEFAULT_BUFFER)
                except OSError:
                    return
                if not chunk:
                    peer = target_sock if sock is client_sock else client_sock
                    try: peer.shutdown(socket.SHUT_WR)
                    except OSError: pass
                    return
                if sock is client_sock:
                    bytes_out += len(chunk)
                else:
                    bytes_in += len(chunk)
                try:
                    (target_sock if sock is client_sock else client_sock).sendall(chunk)
                except OSError:
                    return
    except Exception:
        pass
    finally:
        for s in (client_sock, target_sock):
            if s is None:
                continue
            try: s.close()
            except OSError: pass
        # Skip logging for probes/health-checks that sent nothing meaningful
        if target and fp:
            log_access(evt="connect", fp=fp, target=target,
                       status=locals().get("status", 200),
                       bytes_in=locals().get("bytes_in", 0),
                       bytes_out=locals().get("bytes_out", 0),
                       dur=round((time.time() - t0) * 1000))


# ---------------------------------------------------------------------------
# Reachability probe + forked TCP child
# ---------------------------------------------------------------------------

_tcp_child_pid = None
_start_time = time.time()


def probe_reachable(host, port):
    """Ask an outside service if host:port is reachable.
    Returns True/False, or None on error."""
    if not PROBE_URL or not PROBE_HOST:
        return None
    try:
        r = requests.get(
            PROBE_URL,
            params={"host": host, "port": port},
            timeout=PROBE_TIMEOUT,
        )
        data = r.json()
        if "open" in data:
            return bool(data["open"])
        if "reachable" in data:
            return bool(data["reachable"])
        return None
    except Exception as e:
        print(f"[tcp] probe error: {e}", flush=True)
        return None


def spawn_tcp_child():
    """Fork a child that runs the TCP proxy. Child probes if configured.
    Fork happens BEFORE Flask spawns threads -> safe."""
    global _tcp_child_pid
    if not hasattr(os, "fork"):
        print("[tcp] no fork() available; using thread", flush=True)
        threading.Thread(target=start_tcp_proxy, daemon=True).start()
        return None
    pid = os.fork()
    if pid == 0:
        # --- child ---
        try:
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            signal.signal(signal.SIGINT, signal.SIG_DFL)

            # Die when the parent dies, however the parent dies.
            # (1) prctl(PR_SET_PDEATHSIG): kernel auto-signals us.
            # Linux/Android: libc.so or libc.so.6. macOS: libc.dylib.
            # FreeBSD: libc.so.7. prctl only exists on Linux; the loop
            # just tries whatever's there and moves on if none work.
            for libname in ("libc.so", "libc.so.6", "libc.so.7",
                            "libc.dylib", "libSystem.B.dylib"):
                try:
                    import ctypes
                    libc = ctypes.CDLL(libname, use_errno=True)
                    if not hasattr(libc, "prctl"):
                        continue
                    PR_SET_PDEATHSIG = 1
                    libc.prctl(PR_SET_PDEATHSIG, 15, 0, 0, 0)
                    print(f"[tcp-child] prctl set via {libname}", flush=True)
                    break
                except Exception:
                    continue
            else:
                print("[tcp-child] prctl not available (non-Linux); "
                      "parent-death via getppid() watchdog only", flush=True)

            # (2) Watchdog: if getppid() changes, parent is gone.
            def _watch_parent():
                parent = os.getppid()
                while True:
                    time.sleep(2)
                    if os.getppid() != parent:
                        print("[tcp-child] parent gone, exiting", flush=True)
                        os._exit(0)
            import threading as _t
            _t.Thread(target=_watch_parent, daemon=True).start()

            start_tcp_proxy()
        except Exception as e:
            print(f"[tcp] child error: {e}", flush=True)
            os._exit(1)
        os._exit(0)
    # --- parent ---
    _tcp_child_pid = pid
    print(f"[tcp] child pid={pid}", flush=True)
    return pid


_shutdown = threading.Event()
_listen_sock = None


def start_tcp_proxy():
    global _listen_sock

    # Decide whether to bind at all, before touching the socket.
    if PROBE_URL and PROBE_HOST:
        result = probe_reachable(PROBE_HOST, TCP_PORT)
        if result is False:
            print(f"[tcp] probe: {PROBE_HOST}:{TCP_PORT} unreachable - not binding",
                  flush=True)
            return
        if result is True:
            print(f"[tcp] probe: {PROBE_HOST}:{TCP_PORT} confirmed reachable",
                  flush=True)
        else:
            print("[tcp] probe inconclusive - binding anyway", flush=True)
    elif PLATFORM in SINGLE_PORT_PLATFORMS:
        print(f"[tcp] platform={PLATFORM} is single-port - not binding", flush=True)
        return

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, TCP_PORT))
        s.listen(100)
        _listen_sock = s
    except OSError as e:
        print(f"[tcp] cannot bind {HOST}:{TCP_PORT}: {e} - disabling", flush=True)
        return
    print(f"[tcp] listening on {HOST}:{TCP_PORT}", flush=True)
    s.settimeout(1.0)
    while not _shutdown.is_set():
        try:
            client, _ = s.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()
    try: s.close()
    except OSError: pass


def _on_sigterm(signum, frame):
    print(f"[sig] received {signum}, shutting down", flush=True)
    _shutdown.set()
    if _tcp_child_pid:
        try:
            os.kill(_tcp_child_pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(_tcp_child_pid, 0)
        except ChildProcessError:
            pass
    if _listen_sock:
        try: _listen_sock.close()
        except OSError: pass
    sys.exit(0)


def reload_pubkeys(signum=None, frame=None):
    global PUBKEYS
    new_keys = _load_pubkeys()
    old_count = len(PUBKEYS)
    PUBKEYS = new_keys
    print(f"[sig] SIGHUP: pubkeys reloaded ({old_count} -> {len(new_keys)})",
          flush=True)


def _check_openssl():
    """Return (ok, version_string, has_rawin)."""
    try:
        out = subprocess.check_output(["openssl", "version"], stderr=subprocess.STDOUT,
                                       timeout=5).decode().strip()
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e), False
    # openssl 1.1.1+ required for Ed25519 (-rawin in pkeyutl)
    has_rawin = False
    try:
        r = subprocess.run(["openssl", "pkeyutl", "-help"],
                           capture_output=True, timeout=5)
        has_rawin = b"rawin" in (r.stdout + r.stderr).lower()
    except Exception:
        pass
    return True, out, has_rawin


def self_test():
    """Startup checks. Prints a block of lines. Fatal if critical fail."""
    critical_fail = False

    ok, ver, has_rawin = _check_openssl()
    if ok:
        print(f"[self-test] openssl: {ver}", flush=True)
    else:
        print(f"[self-test] openssl: NOT FOUND ({ver})", flush=True)
        critical_fail = True

    if ok and has_rawin:
        print("[self-test] openssl pkeyutl -rawin: ok", flush=True)
    elif ok:
        print("[self-test] openssl pkeyutl -rawin: MISSING (need OpenSSL >= 1.1.1)",
              flush=True)
        critical_fail = True

    print(f"[self-test] pubkeys loaded: {len(PUBKEYS)}"
          + ("" if PUBKEYS else "  (warning: no keys, all requests will 401)"),
          flush=True)

    # Store write/read test
    try:
        STORE.setex("__selftest__", 5, b"ok")
        got = STORE.get("__selftest__")
        STORE.del_("__selftest__")
        if got == b"ok":
            print(f"[self-test] store: {STORE.kind} writable", flush=True)
        else:
            print(f"[self-test] store: {STORE.kind} readback failed", flush=True)
            if PROXY_SELF_TEST_FATAL:
                critical_fail = True
    except Exception as e:
        print(f"[self-test] store: error ({e})", flush=True)
        if PROXY_SELF_TEST_FATAL:
            critical_fail = True

    # users.json
    if os.path.exists(_users_path):
        print(f"[self-test] users.json: {len(USERS)} entries", flush=True)
    else:
        print("[self-test] users.json: not present (ok)", flush=True)

    # probe config sanity
    if PROBE_URL and not PROBE_HOST:
        print("[self-test] probe: PROXY_PROBE_URL set but PROXY_PUBLIC_HOST "
              "missing - probe disabled", flush=True)
    elif PROBE_HOST and not PROBE_URL:
        print("[self-test] probe: PROXY_PUBLIC_HOST set but PROXY_PROBE_URL "
              "missing - probe disabled", flush=True)
    else:
        print("[self-test] probe: " +
              ("configured" if PROBE_URL else "not configured (ok)"), flush=True)

    # Port availability check
    for label, port in (("HTTP", PORT), ("TCP", TCP_PORT)):
        if label == "TCP" and not ENABLE_TCP_PROXY:
            continue
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            in_use = s.connect_ex(("127.0.0.1", port)) == 0
        finally:
            s.close()
        if in_use:
            print(f"[self-test] port {port} ({label}): IN USE", flush=True)
            if PROXY_SELF_TEST_FATAL:
                critical_fail = True
        else:
            print(f"[self-test] port {port} ({label}): free", flush=True)

    if critical_fail and PROXY_SELF_TEST_FATAL:
        print("[self-test] critical failure; refusing to start", flush=True)
        sys.exit(1)
    return not critical_fail


def main():
    signal.signal(signal.SIGTERM, _on_sigterm)
    signal.signal(signal.SIGINT, _on_sigterm)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, reload_pubkeys)

    self_test()

    print(f"[env] platform={PLATFORM} store={STORE.kind}", flush=True)
    print(f"[auth] loaded {len(PUBKEYS)} public key(s); window={AUTH_WINDOW}s "
          f"session_ttl={SESSION_TTL}s idle={IDLE_TIMEOUT}s", flush=True)
    if USERS:
        print(f"[users] {len(USERS)} user overrides active", flush=True)
    if ENABLE_TCP_PROXY:
        spawn_tcp_child()
    else:
        print(f"[tcp] disabled (platform={PLATFORM} single-port)", flush=True)
    print(f"[http] listening on {HOST}:{PORT}", flush=True)
    app.run(host=HOST, port=PORT, threaded=True)


if __name__ == "__main__":
    main()
