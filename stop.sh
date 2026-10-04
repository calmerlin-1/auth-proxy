#!/usr/bin/env bash
set -u

pkill -TERM -f 'server.py'    2>/dev/null || true
sleep 1
pkill -9    -f 'server.py'    2>/dev/null || true
pkill -9    -f 'test_connect' 2>/dev/null || true
pkill -9    -f 'python -u -'  2>/dev/null || true
sleep 1

echo "--- ports ---"
for p in 10000 10001; do
    python -c "import socket; s=socket.socket(); s.settimeout(0.5); print('$p', 'busy' if s.connect_ex(('127.0.0.1',$p))==0 else 'free')"
done
