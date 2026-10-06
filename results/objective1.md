# Objective 1 (PCHC-MQTT) on the final pqgrid code

ENVIRONMENT [DOCKER]: Linux aarch64 | Python 3.13.5 | cryptography 50.0.1 | OpenSSL 3.5.7 9 Jun 2026 | median of 180 runs after 20 warm-up. On a laptop: not a device measurement.

## 1. Which tier a topic gets (signed policy, strongest rule wins, no rule -> CONTROL)

| Topic | Tier | Why |
|---|---|---|
| `grid/smart_meter/meter-0001/telemetry` | TELEMETRY | rule: TELEMETRY |
| `grid/smart_meter/meter-0001/alert` | ALERT | rule: ALERT |
| `grid/der_ctrl/der-0001/control` | CONTROL | rule: CONTROL |
| `grid/dr/f7/AES256GCM/event` | CONTROL | rule: CONTROL (broadcast) |
| `grid/smart_meter/meter-0001/debug` | CONTROL | no rule matches: the default |
| `grid/smart_meter/meter-0001/alert` | ALERT | plus `grid/#` -> TELEMETRY: strongest wins |
| `grid/+/meter-0001/alert` | CONTROL | not a valid topic: the default | 

## 2. Per-tier cost for a 64-byte payload

| Tier | Protection on top of hybrid TLS | E2E envelope (B) | Overhead vs 64 B | MQTT PUBLISH (B) | Device (ms, median) | Utility (ms, median) |
|---|---|---|---|---|---|---|
| TELEMETRY | hybrid TLS hop only | none: the 64 B as is | 0 | 108 | — | — |
| ALERT | + E2E AEAD, sequence number, end-to-end ACK | 137 | 73 | 178 | seal 0.0056 | open 0.0100 |
| CONTROL: command | + E2E AEAD + ML-DSA-65 signature | 3466 | 3402 | 3504 | open + verify + apply 0.1125 | sign + seal 0.5572 |
| CONTROL: GRANT | + E2E AEAD + ML-DSA-65, session-bound limits | 3477 | — | 3515 | open + verify 0.1126 | sign + seal 0.4399 |
| CONTROL: SETPOINT | + E2E AEAD within a GRANT (no signature) | 97 | — | 135 | open + check + apply 0.0077 | seal 0.0071 |
| CONTROL: broadcast event | + zone-key AEAD + ML-DSA-65 | 3484 | 3420 | 3525 | — | — |

Acknowledgements: ALERT ACK 65 B (utility -> device); command status ACK 83 B (device -> utility). 

## 3. The full end-to-end handshake (device <-> utility, through the broker)

| Device class (resume mode) | CH (B) | SH (B) | DF (B) | NT/FIN (B) | Total (B) | Device (ms, median) | Utility (ms, median) |
|---|---|---|---|---|---|---|---|
| smart_meter (PSK) | 2493 | 2411 | 46 | 271 | 5221 | 0.299 | 0.229 |
| der_ctrl (PSK_KEM) | 2488 | 2415 | 46 | 270 | 5219 | 0.296 | 0.226 |

Three hybrid KEMs (ML-KEM-768 + X25519, X-Wing): ephemeral (forward secrecy), to the utility's key (authenticates the utility), to the device's key (authenticates the device); POLICY_INFO inside the encrypted CH and SH, hashed into K_master. 

## 4. Downgrade, tamper, replay and forgery attempts

| ID | Attack | Expected refusal | Observed | Result |
|---|---|---|---|---|
| A1 | Broker changes POLICY_INFO in the client hello | `client hello failed authentication` | HandshakeError: client hello failed authentication | REFUSED as expected |
| A2 | Broker changes POLICY_INFO in the server hello | `server hello failed authentication` | HandshakeError: server hello failed authentication | REFUSED as expected |
| A2b | Broker changes the utility's key confirmation | `key confirmation` | HandshakeError: utility key confirmation failed | REFUSED as expected |
| A4 | Device still on an older (weaker) policy | `POLICY_INFO mismatch` | PolicyMismatchError: POLICY_INFO mismatch: device must install the current policy | REFUSED as expected |
| A5 | Broker looks for the alert's text in the envelope | `not found` | not found | REFUSED as expected |
| A6 | Plaintext (tier-stripped) message on an ALERT topic | `EnvelopeError` | EnvelopeError: malformed alert envelope | REFUSED as expected |
| A7 | Device asked to send an ALERT on a TELEMETRY topic | `not ALERT tier` | EnvelopeError: topic is not ALERT tier under the installed policy | REFUSED as expected |
| A8 | Broker replays an alert already delivered | `ReplayError` | ReplayError: sequence 1 not newer than 1 | REFUSED as expected |
| A9 | Broker replays a command already applied | `ReplayError` | ReplayError: sequence 1 not newer than 1 | REFUSED as expected |
| A10 | Someone with the session key (not the command key) forges a command | `REJECTED:signature` | status REJECTED:signature; forged command applied: no | REFUSED as expected | 

## 5. Hybrid-only TLS at the broker

| N3: TLS client | Expected | Observed (openssl s_client) | Result |
|---|---|---|---|
| Device with the default group list | `Negotiated TLS1.3 group: X25519MLKEM768` | Negotiated TLS1.3 group: X25519MLKEM768 | as expected |
| Client offering ONLY classical X25519 | `alert handshake failure` | 20C01E94FFFF0000:error:0A000410:SSL routines:ssl3_read_bytes:ssl/tls alert handshake failure:../ssl/ | as expected |
| Client offering only TLS 1.2 | `alert protocol version` | 2090FA7FFFFF0000:error:0A00042E:SSL routines:ssl3_read_bytes:tlsv1 alert protocol version:../ssl/rec | as expected | 

RESULT: every attempt refused as expected
