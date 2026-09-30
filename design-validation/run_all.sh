#!/bin/sh
# Reproduces every design-validation result INSIDE DOCKER. Nothing is installed on the host,
# and the container never writes into this folder: results come back as output and are saved by tee.
# Usage:  ./run_all.sh        (Docker Desktop must be running)
cd "$(dirname "$0")" || exit 1
docker build -q -t pqgrid-validation . >/dev/null || exit 1
mkdir -p results
echo "[1/6] broker experiments (Mosquitto + OpenSSL 3.5 in container) -> results/broker.txt"
docker run --rm pqgrid-validation sh -c '
  /work/setup_pki.sh > /dev/null
  mosquitto -c /work/mosquitto.conf        > /dev/null 2>&1 &
  mosquitto -c /work/mosquitto_nodelay.conf > /dev/null 2>&1 &
  sleep 1
  echo "== TLS negotiation (device cert) =="
  echo Q | openssl s_client -connect localhost:8883 -CAfile /work/pki/ca.crt -cert /work/pki/meter1.crt -key /work/pki/meter1.key -brief 2>&1 | grep -E "Protocol|Ciphersuite|Signature type|group|Verification"
  echo "== access control, MQTT 5 properties, retained messages, resumption =="; python /work/test_broker.py
  echo "== delivery-time ACL + Nagle effect (broker WITHOUT set_tcp_nodelay) =="; python /work/test_followup.py 8883
  echo "== Nagle effect (broker WITH set_tcp_nodelay) =="; python /work/test_followup.py 8884 | grep F2
  echo "== paho subclass TLS resumption =="; python /work/test_paho_resume.py
  echo "== certificate type vs handshake bytes =="; /work/cert_compare.sh' 2>&1 | tee results/broker.txt
echo "[2/6] network attacks: captured-byte replay, in-flight bit flip, classical fallback, clone, restart, size, IP change -> results/network.txt"
docker run --rm pqgrid-validation sh -c '
  /work/setup_pki.sh > /dev/null; mkdir -p /tmp/mqp
  for c in plain persist nopersist maxpkt; do mosquitto -c /work/mosquitto_$c.conf > /dev/null 2>&1 & done
  OPENSSL_CONF=/work/hybrid-only.cnf mosquitto -c /work/mosquitto_pinned.conf > /dev/null 2>&1 &
  sleep 1.5; python /work/test_network_attacks.py' 2>&1 | tee results/network.txt
echo "[3/6] protocol validation (core, edge cases, documented risks) -> results/validate.txt"
docker run --rm -w /proto pqgrid-validation python validate.py | tee results/validate.txt | grep -E '^===|^TOTAL'
echo "[4/6] cost measurements -> results/bench.txt"
docker run --rm -w /proto pqgrid-validation python bench.py | tee results/bench.txt
echo "[5/6] signature speeds (openssl speed, in container) -> results/signature_speed.txt"
docker run --rm pqgrid-validation sh -c 'openssl version; echo "algorithm  keygen(s)  sign(s)  verify(s)  keygens/s  signs/s  verifies/s"; for a in ML-DSA-65 SLH-DSA-SHA2-192s SLH-DSA-SHA2-128s; do openssl speed -seconds 2 "$a" 2>/dev/null | tail -1; done' | tee results/signature_speed.txt
echo "[6/6] hybrid key-exchange cost: X25519 vs ML-KEM-768 (in container) -> results/hybrid_cost.txt"
docker run --rm pqgrid-validation python -c "
import time, statistics as st
from cryptography.hazmat.primitives.asymmetric import x25519, mlkem
def bench(fn, n=400, warm=40):
    for _ in range(warm): fn()
    t=[]
    for _ in range(n):
        a=time.perf_counter(); fn(); t.append((time.perf_counter()-a)*1e6)
    return st.median(t)
def x_round():
    a=x25519.X25519PrivateKey.generate(); b=x25519.X25519PrivateKey.generate(); a.exchange(b.public_key()); b.exchange(a.public_key())
def k_round():
    sk=mlkem.MLKEM768PrivateKey.generate(); ss,ct=sk.public_key().encapsulate(); sk.decapsulate(ct)
xm, km = bench(x_round), bench(k_round)
print(f'container: X25519 exchange (both sides) {xm:.1f} us | ML-KEM-768 exchange (keygen+encap+decap) {km:.1f} us | hybrid adds {100*xm/km:.0f}% compute, 64 bytes')
" | tee results/hybrid_cost.txt
