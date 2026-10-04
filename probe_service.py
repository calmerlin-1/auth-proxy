#!/usr/bin/env python3
"""
Tiny probe service for auth-proxy's optional reachability check.

Deploy on any always-on host with a public IP. Point auth-proxy's
PROXY_PROBE_URL at it: PROXY_PROBE_URL=https://your-probe.example.com/probe

Security: allowlist which hostnames this may be asked to probe, so an open
deployment can't be abused as an SSRF tool. Set PROBE_ALLOW_SUFFIXES to a
comma-separated list of suffixes you own (e.g. ".mydomain.com,proxy.").
"""
import os
import socket
import ipaddress
from flask import Flask, request, jsonify

app = Flask(__name__)

ALLOW_SUFFIXES = tuple(
    s.strip() for s in os.environ.get("PROBE_ALLOW_SUFFIXES", "").split(",") if s.strip()
)
PROBE_TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "3"))
PORT = int(os.environ.get("PORT", 8100))


def _host_allowed(host):
    if not ALLOW_SUFFIXES:
        return False
    return any(host.endswith(suf) or host == suf.lstrip(".") for suf in ALLOW_SUFFIXES)


@app.route("/probe")
def probe():
    host = request.args.get("host", "").strip()
    port_s = request.args.get("port", "").strip()

    if not host or not port_s:
        return jsonify({"error": "missing host or port"}), 400

    if not _host_allowed(host):
        return jsonify({"error": "host not allowed"}), 403

    # If the host is a literal IP, refuse — avoids probing internal ranges.
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return jsonify({"error": "private IP not allowed"}), 403
    except ValueError:
        pass

    try:
        port = int(port_s)
        if not (1 <= port <= 65535):
            raise ValueError
    except ValueError:
        return jsonify({"error": "invalid port"}), 400

    try:
        with socket.create_connection((host, port), timeout=PROBE_TIMEOUT):
            return jsonify({"open": True, "host": host, "port": port})
    except OSError:
        return jsonify({"open": False, "host": host, "port": port})


@app.route("/_health")
def health():
    return "OK"


if __name__ == "__main__":
    if not ALLOW_SUFFIXES:
        print("[probe] WARNING: PROBE_ALLOW_SUFFIXES empty; all probes will 403")
    print(f"[probe] listening on 0.0.0.0:{PORT}", flush=True)
    app.run(host="0.0.0.0", port=PORT, threaded=True)
