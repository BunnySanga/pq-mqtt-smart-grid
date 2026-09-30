# design-validation

Evidence behind the design decisions in [`../BalaMP.md`](../BalaMP.md) and
[`../BalaMP-Rationale.md`](../BalaMP-Rationale.md). This folder is **not** the product code. It is a small reference implementation and a set of broker experiments that prove the design works
before the team builds it properly in Semester 2.

Everything runs **inside Docker**. Nothing is installed on your machine, and the container never writes
into this folder.

## Run it

```bash
./run_all.sh
```

Docker Desktop must be running. The first run downloads a Debian image and takes a few minutes. Later runs
take about a minute. Results are written to `results/`.

## What it checks

| Step | What it proves | Output |
|---|---|---|
| 1 · `broker/` experiments | Mosquitto negotiates hybrid `X25519MLKEM768` by default; mutual TLS with certificates; per-device access control enforced at delivery time; MQTT 5 metadata passes through; large retained messages; TLS 1.3 resumption (raw Python and a paho-mqtt subclass); the Nagle/`TCP_NODELAY` trap; handshake size for three certificate types | `results/broker.txt` |
| 2 · `broker/test_network_attacks.py` | An interception proxy between a real meter and the broker. Replaying every captured byte delivers nothing; one flipped bit is rejected; default TLS silently accepts classical-only clients while hybrid-only pinning refuses them; clone takeover; retained artifacts survive restarts only with persistence; packet-size limit; TLS resumption after an IP change | `results/network.txt` |
| 3 · `reference/validate.py` | The whole protocol design. **80 scenarios**: 47 core (every attack fails closed), 31 edge cases (duplicates, losses, crashes, restarts, clock resets, clones, fuzzing with 3,300 corrupted messages), 2 documented risks shown succeeding on purpose | `results/validate.txt` |
| 4 · `reference/bench.py` | Compute time and bytes: full handshake vs resumption, per-message overhead per tier, FOTA costs | `results/bench.txt` |
| 5 · `openssl speed` | Signature algorithm speeds in the container | `results/signature_speed.txt` |
| 6 · hybrid cost | X25519 vs ML-KEM-768 computation in the container | `results/hybrid_cost.txt` |

## Environment

Debian trixie · OpenSSL 3.5 · Mosquitto 2.0 · Python 3.13 · `cryptography==50.0.1` · `paho-mqtt==2.1.0`.
SLH-DSA is not in the Python `cryptography` library, so `reference/pqgrid_ref/suite.py` verifies it through
OpenSSL's `libcrypto` (about 30 lines of `ctypes`), and the offline signing station signs with the
`openssl` command-line tool.

## Honest scope

- These are **laptop measurements inside a Linux container**, not smart-meter hardware. The same code ran
  about 5× slower in a macOS Python environment, so compare numbers only within one environment and always
  report which one.
- The reference implementation exercises the cryptography and protocol logic directly, not over a network.
  Only the `broker/` experiments use real MQTT.
- The broker experiments use ML-DSA-65 certificates to prove post-quantum certificates work. The design
  itself uses ECDSA P-256 at the broker hop; see BalaMP.md §3.
- The network-attack configurations run Mosquitto as `root` for convenience inside the container. That is
  test-only; the real build runs it as the `mosquitto` user.

## Clean up

```bash
docker rmi pqgrid-validation
```
