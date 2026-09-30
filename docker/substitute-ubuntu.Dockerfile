# SUBSTITUTE validation base - NOT the canonical environment (design-validation/Dockerfile, Debian trixie).
#
# Used for the independent release audit and its remediation (2026-09-30) because the canonical base could not be
# built there: Docker Hub answered 429 for debian:trixie-slim and the Debian mirrors 403. Same Python pins and same
# COPYs as the canonical recipe; a different distribution and different OpenSSL / Mosquitto builds. Every result
# produced on it is labelled SUBSTITUTE; equivalence with the canonical environment is NOT demonstrated.
#
# Versions of the image the evidence was produced with (recorded from it): Ubuntu 25.10
# (ubuntu@sha256:7cc5e35f6567ee8c66d2abb4aab0fd866669e6207c237c3a8f0947a5c7f17092), openssl / libssl3t64
# 3.5.3-1ubuntu3.4, mosquitto 2.0.22-2, python3.13 3.13.7-1ubuntu0.4, SQLite 3.46.1, cryptography 50.0.1,
# paho-mqtt 2.1.0, pytest 9.1.1. apt package versions are not pinned here (the archive moves on): rebuild and
# compare them before claiming the same environment.
#
# Build (context = design-validation/, like the canonical recipe; `extra-ca` = a directory with optional *.crt
# files for a TLS-intercepting proxy, an empty directory otherwise):
#   docker build -f docker/substitute-ubuntu.Dockerfile --build-context extra-ca=<dir> \
#       -t pqgrid-validation-substitute design-validation
#   docker build -f docker/pqgrid-tests.Dockerfile --build-arg BASE=pqgrid-validation-substitute \
#       -t pqgrid-tests-substitute .
FROM ubuntu:25.10@sha256:7cc5e35f6567ee8c66d2abb4aab0fd866669e6207c237c3a8f0947a5c7f17092
RUN apt-get update && apt-get install -y --no-install-recommends \
      mosquitto mosquitto-clients openssl python3 python3-venv ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*
COPY --from=extra-ca . /usr/local/share/ca-certificates/extra/
RUN update-ca-certificates >/dev/null
RUN python3 -m venv /opt/venv && PIP_CERT=/etc/ssl/certs/ca-certificates.crt \
      /opt/venv/bin/pip install --no-cache-dir -q cryptography==50.0.1 paho-mqtt==2.1.0 pytest==9.1.1
ENV PATH=/opt/venv/bin:$PATH
COPY broker /work
COPY reference /proto
RUN chown mosquitto:mosquitto /work/acl && chmod 0700 /work/acl && chmod +x /work/*.sh
WORKDIR /work
