# Self-contained validation environment: Debian trixie (OpenSSL 3.5, Mosquitto 2.0) + Python venv.
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      mosquitto mosquitto-clients openssl python3 python3-venv ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir -q cryptography==50.0.1 paho-mqtt==2.1.0
ENV PATH=/opt/venv/bin:$PATH
COPY broker /work
COPY reference /proto
RUN chown mosquitto:mosquitto /work/acl && chmod 0700 /work/acl && chmod +x /work/*.sh
WORKDIR /work
