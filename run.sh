#!/usr/bin/env bash
set -u

# 1. Kill anything already holding our ports, no matter its argv
pkill -9 -f 'server.py'    2>/dev/null || true
pkill -9 -f 'test_connect' 2>/dev/null || true
pkill -9 -f 'python -u -'  2>/dev/null || true
sleep 1

# 2. Fail fast if ports are still busy (invisible orphan case)
for port in 10000 10001; do
    if python -c "import socket,sys; s=socket.socket(); s.settimeout(0.5); sys.exit(0 if s.connect_ex(('127.0.0.1',$port))==0 else 1)" 2>/dev/null; then
        echo "port $port still busy — abort. run ./stop.sh or restart Termux."
        exit 1
    fi
done

# 3. Env
export PROXY_PUBKEYS="${PROXY_PUBKEYS:-$PWD/keys/pubkeys.txt}"
export ENABLE_TCP_PROXY="${ENABLE_TCP_PROXY:-1}"

if [ ! -f "$PROXY_PUBKEYS" ] && [ ! -e "$PROXY_PUBKEYS" ]; then
    echo "PROXY_PUBKEYS points to missing path: $PROXY_PUBKEYS"
    exit 1
fi

# 4. Start
nohup python -u server.py > logs/proxy.log 2>&1 &
disown
sleep 2

echo "--- startup ---"
head -n 8 logs/proxy.log
echo "--- procs ---"
ps -ef | grep -v grep | grep 'python -u server.py' || echo "(none — server failed to start)"
