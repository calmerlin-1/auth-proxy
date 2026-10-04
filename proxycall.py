#!/usr/bin/env python3
import argparse, base64, hashlib, os, secrets, subprocess, sys, tempfile, time, urllib.parse
import requests


def fingerprint(key_path):
    out = subprocess.check_output(
        ["openssl", "pkey", "-in", key_path, "-pubout", "-outform", "DER"],
        stderr=subprocess.DEVNULL,
    )
    return out[-32:].hex()


def sign(key_path, message: bytes) -> bytes:
    msg_fd, msg_path = tempfile.mkstemp(prefix="pcall_msg_")
    sig_fd, sig_path = tempfile.mkstemp(prefix="pcall_sig_")
    try:
        with os.fdopen(msg_fd, "wb") as fh:
            fh.write(message)
        r = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", key_path,
             "-rawin", "-in", msg_path, "-out", sig_path],
            capture_output=True, timeout=5,
        )
        if r.returncode != 0:
            sys.stderr.write(r.stderr.decode())
            sys.exit(1)
        with open(sig_path, "rb") as fh:
            return fh.read()
    finally:
        for p in (msg_path, sig_path):
            try: os.unlink(p)
            except OSError: pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key",   default=os.environ.get("PROXY_CLIENT_KEY", "keys/proxy_client.key"))
    ap.add_argument("--proxy", default=os.environ.get("PROXY_URL", "http://127.0.0.1:10000"))
    ap.add_argument("--session-file", default=os.environ.get("PROXY_SESSION_FILE", "data/.proxy_session"))
    ap.add_argument("mode", choices=["http", "connect", "fp"])
    ap.add_argument("target", nargs="?", default="")
    ap.add_argument("--method", default="GET")
    ap.add_argument("--path",   default="/")
    ap.add_argument("--body",   default=None)
    args = ap.parse_args()

    fp = fingerprint(args.key)

    if args.mode == "fp":
        print(fp); return

    if args.mode == "connect":
        ts = str(int(time.time()))
        nonce = secrets.token_hex(16)
        canonical = "\n".join(["CONNECT", args.target, ts, nonce])
        sig = sign(args.key, canonical.encode())
        print(f"CONNECT {args.target} HTTP/1.1")
        print(f"X-Proxy-Pubkey: {fp}")
        print(f"X-Proxy-Timestamp: {ts}")
        print(f"X-Proxy-Nonce: {nonce}")
        print(f"X-Proxy-Signature: {base64.b64encode(sig).decode()}")
        print()
        return

    if args.mode == "http":
        body = args.body.encode() if args.body else b""
        body_hash = hashlib.sha256(body).hexdigest()
        ts = str(int(time.time()))
        nonce = secrets.token_hex(16)
        canonical = "\n".join([args.method.upper(), args.path, args.target, ts, nonce, body_hash])
        sig = sign(args.key, canonical.encode())

        session = os.environ.get("PROXY_SESSION", "").strip()
        if not session and os.path.exists(args.session_file):
            session = open(args.session_file).read().strip()

        def build(session_token):
            if session_token:
                return {"X-Proxy-Session": session_token}
            return {
                "X-Proxy-Pubkey": fp,
                "X-Proxy-Timestamp": ts,
                "X-Proxy-Nonce": nonce,
                "X-Proxy-Signature": base64.b64encode(sig).decode(),
            }

        headers = build(session)
        url = args.proxy.rstrip("/") + "/?url=" + urllib.parse.quote(args.target, safe="")
        r = requests.request(args.method, url, headers=headers,
                             data=body or None, verify=False, timeout=30)

        if r.status_code == 401 and b"bad_session" in r.content and session:
            try: os.unlink(args.session_file)
            except OSError: pass
            headers = build(None)
            r = requests.request(args.method, url, headers=headers,
                                 data=body or None, verify=False, timeout=30)

        new_sess = r.headers.get("X-Proxy-Session")
        if new_sess:
            try:
                with open(args.session_file, "w") as fh:
                    fh.write(new_sess)
            except OSError:
                pass

        sys.stdout.buffer.write(r.content)
        if not r.content.endswith(b"\n"):
            sys.stdout.buffer.write(b"\n")


if __name__ == "__main__":
    main()
