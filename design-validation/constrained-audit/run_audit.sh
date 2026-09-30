#!/bin/sh
# Constrained-IoT audit experiments. Everything runs INSIDE DOCKER: no host installs, no bind mounts,
# no --privileged, no host network. Results come back on stdout and are saved here by tee.
# Usage: ./run_audit.sh   (Docker Desktop must be running)
cd "$(dirname "$0")" || exit 1
docker image inspect pqgrid-validation >/dev/null 2>&1 || docker build -q -t pqgrid-validation .. >/dev/null || exit 1
docker build -q -t pqgrid-audit . >/dev/null || exit 1
mkdir -p results
LIMITS="--cpus 2 --memory 1g"     # tidy resource use only; this does NOT model an MCU

BROKER='/audit/pki_ecdsa.sh > /tmp/pki.txt; cat /tmp/pki.txt
  echo "meter-0009:$(openssl rand -hex 32)" > /audit/pskfile
  OPENSSL_CONF=/work/hybrid-only.cnf mosquitto -c /audit/mosquitto_audit.conf > /dev/null 2>&1 &
  OPENSSL_CONF=/work/hybrid-only.cnf mosquitto -c /audit/mosquitto_psk.conf > /dev/null 2>&1 &
  sleep 1.5'

echo "[1/4] persistent-state audit of the reference implementation -> results/state.txt"
docker run --rm $LIMITS pqgrid-audit sh -c 'cd /proto && python /audit/audit_state.py' 2>&1 | tee results/state.txt

echo "[2/4] TLS ticket lifetime, max_fragment_length, clock/certificate validity, PSK hop auth -> results/tls_time.txt"
docker run --rm $LIMITS pqgrid-audit sh -c "$BROKER
  export FT_LIB=\$(dpkg -L libfaketime | grep 'libfaketime.so.1\$' | head -1)
  python test_tls_time.py" 2>&1 | tee results/tls_time.txt

echo "[3/4] MQTT packet limits, bytes on the wire, modelled constrained links (takes several minutes) -> results/transport.txt"
docker run --rm $LIMITS pqgrid-audit sh -c "$BROKER
  python test_transport.py" 2>&1 | tee results/transport.txt

echo "[4/4] analytical budgets from cited inputs -> results/analysis.txt"
docker run --rm $LIMITS pqgrid-audit python analysis.py 2>&1 | tee results/analysis.txt
