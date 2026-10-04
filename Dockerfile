FROM python:3.12-slim

# openssl for Ed25519 sign/verify
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py proxycall.py README.md ./

RUN useradd -m -u 1000 proxy
USER proxy

ENV PORT=10000 \
    TCP_PORT=10001 \
    HOST=0.0.0.0 \
    ENABLE_TCP_PROXY=1 \
    PROXY_VERIFY_TLS=1 \
    PROXY_ACCESS_LOG=1 \
    PYTHONUNBUFFERED=1

EXPOSE 10000 10001

# python server.py, not gunicorn: the TCP listener runs in a forked child,
# which requires a single master process. Under gunicorn, use ENABLE_TCP_PROXY=0
# and run the TCP half as a separate service.
CMD ["python", "server.py"]
