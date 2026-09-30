# Master Design Document
## Post-Quantum Secure MQTT for Smart Grid Communication

**Version:** Master, design **v2.2**, amended 2026-09-29 by the eight finalized clarifications of the remediation
(Appendix F; the implementation status of each item is in IMPLEMENTATION-ROADMAP §13)
**Status:** Design Authority / source of truth
**Team 14, NIT Karnataka:** Sanga Balanarsimha (231IT062) · C. Lohith Kumar Reddy (231IT016) · P. Pavan Kumar (231IT046)
**Guide:** Dr. Bhawana Rudra · B.Tech IT · Major Project IT449
**Date:** 2026-09-22

---

# 0. Purpose of This Document

This document is the **single authority** for what the project builds, why each part is shaped the way it
is, what evidence supports it, and what it must not claim.

It consolidates four earlier sources:

| Source | What it holds | Status after this document |
|---|---|---|
| [BalaMP.md](BalaMP.md) | Design v2.1 (frozen 2026-09-22) | Historical record; superseded here |
| [BalaMP-Rationale.md](BalaMP-Rationale.md) | Why each v2.1 choice was made | Historical record; its reasoning is carried into §7, §20 and §21 |
| [BalaMP-Audit.md](BalaMP-Audit.md) | Constrained-IoT / smart-grid audit of v2.1 | Its findings and changes are adopted here (§17–§19) |
| [design-validation/](design-validation/) | Docker evidence: 80 validation scenarios, network attacks, costs, audit experiments | Evidence registry (§32) |

**The two older documents have not been edited.** They record v2.1 as it was frozen. Where they disagree
with this document, this document wins.

**How decisions change from now on.** Every decision is a record in §20. To change one:
1. write a new record that states the evidence and the trigger;
2. re-run the tests listed in §28;
3. only then edit the design text.

The critical invariants in §34 may not change without re-evaluating the whole design.

**Honesty rules** (they apply to every number in this document):
- Every number carries an evidence label from §17.3.
- Docker and laptop numbers are never presented as smart-meter numbers.
- No energy value is invented.
- Anything modelled rather than measured is labelled **[SIM]** or **[ANALYTICAL]**.
- **v2.2 mechanisms that are specified but not yet implemented in the reference code are marked
  "specified, not yet validated".**

---

# 1. Executive Summary

Smart meters, DER (solar and battery) controllers, EV chargers and field gateways exchange data with the
utility through an MQTT broker. Data recorded today can be decrypted once large quantum computers exist
("record now, decrypt later"). Devices installed now stay in the field for 15–20 years (report §1.2). The
project protects this traffic with post-quantum cryptography. Heavy cryptography is spent only where the
security need justifies it, and the design has been checked against what constrained devices can actually
afford.

**Three objectives, one lifecycle**

| Objective | What it is | Core mechanism |
|---|---|---|
| **PCHC-MQTT** · Per-topic Cryptographic Hierarchy Control | A signed policy assigns every topic a tier: TELEMETRY, ALERT or CONTROL | Hybrid TLS 1.3 on every hop. An end-to-end hybrid KEM-MQTT session between device and utility, with the policy bound into its keys. Commands signed with ML-DSA-65. High-rate set-points authorised by signed, session-bound GRANTs |
| **PQC-FOTA** · Post-Quantum Firmware and policy Over-The-Air | Firmware **and** the policy itself are updated through one signed pipeline | SLH-DSA-SHA2-128s manifests from an offline station; at least two trust anchors with revocation; RFC 6962 Merkle-authenticated chunks; A/B slots with commit after boot; anti-rollback counters |
| **PASR-MQTT** · Policy-Aware Session Resumption | Devices recover after outages without repeating the full post-quantum handshake, only as the policy allows | Utility-issued single-use tickets (STEK-sealed); PSK or PSK+KEM modes; crash-safe persistence; one-round-trip resume over persistent MQTT sessions |

**What changed in v2.2** (the result of the constrained-IoT audit, §18–§19):

- **Clock handling.** The device's TLS no longer checks certificate time. Device certificates never expire.
  A time floor is kept in flash. (The audit found that a 1970 clock locked devices out.)
- **Command handling.**
  - The command sequence is persistent, of the form epoch ‖ counter.
  - The device keeps an intent log with honest status codes.
  - High-rate set-points use signed GRANTs instead of one signature each.
- **Storage.** Utility storage is crash-safe (SQLite WAL, persist before responding).
- **Firmware.**
  - Firmware and policy are signed with **SLH-DSA-SHA2-128s**, not 192s.
  - The manifest is delivered in parts no larger than the device's packet limit.
  - There are two or more anchors, with revocation.
- **Resumption.** Persistent MQTT sessions plus a one-round-trip resume. The v2.1 "confirm before use"
  rule is replaced by "finished carries data".
- **Profiles.** An explicit list of device classes; a constrained profile for C2 devices; reconnect
  strategy and back-off set per class.

**What the project claims** (§11 of v2.1, refined in §26):
- post-quantum confidentiality of every hop, and of alerts and commands end to end;
- operator-controlled per-topic protection that fails closed against downgrade;
- policy-aware resumption with **measured** savings, each quoted with its environment label;
- a firmware and policy pipeline resistant to forgery, tampering and rollback.

**What it does not claim:**
- "hardware-independent";
- smart-meter performance;
- exactly-once actuation;
- formal verification;
- "60–70% faster reconnection".

---

# 2. Problem Statement

## 2.1 Threat Model

| Adversary | Capabilities | In scope? |
|---|---|---|
| **Network attacker** | Observe, inject, replay, delay, drop and **record** all traffic on any link, for decryption by a future quantum computer | Yes |
| **Curious or compromised broker** | Everything the network attacker can do, plus: read what it terminates (TLS), store and serve stale retained messages, drop or reorder, attempt to modify relayed messages | Yes, for confidentiality and integrity; **not** for availability |
| **Captured device(s)** | Full access to their own keys and flash (including through side channels). Act beyond their authorisation: other devices' topics, forged commands, cloning | Yes; damage must stay per-device |
| **Future quantum computer** | Breaks X25519, ECDSA and RSA on recorded data, or live once it exists | Yes |
| **Stolen utility secrets** | STEK, utility E2E key, command key | Analysed as risks (§23.7): the STEK and command key belong in an HSM |
| **Compromised utility headend** (signing service included) | Anything | **No**, but GRANT bounds give devices local safety limits (§13.4) |
| **Compromised offline signing station** | Sign malicious firmware | **No**; mitigated by anchor revocation (§15.14) |
| **Denial of service** | Flooding, radio jamming, broker dropping messages | **No** (detectable only; §2.4) |

**Trusted:** the offline signing station, the utility headend (with the command-signing key separated from
the E2E key, §4.4), manufacturing and provisioning, and the private CA.

## 2.2 Security Goals

| # | Goal | Mechanism (section) |
|---|---|---|
| G1 | All traffic confidential against the network, including record-now-decrypt-later | Hybrid TLS 1.3, pinned hybrid-only, TLS 1.3-only listeners (§8) |
| G2 | Alerts and commands confidential and intact against the broker | E2E hybrid KEM-MQTT session (§9) |
| G3 | Commands authentic against the broker and captured devices | ML-DSA-65 for discrete commands and GRANTs; SETPOINTs only within a signed GRANT (§13) |
| G4 | No silent downgrade of policy or tier | Signed, monotonic policy; POLICY_INFO bound into keys; strongest rule wins with CONTROL as default; receivers enforce tier by topic (§11, §12) |
| G5 | Replay protection for messages, handshakes, tickets, updates and commands | Two-phase sequence checks, nonces, key confirmation, single-use tickets, monotonic versions, epoch-based command sequence (§9.6, §13.6, §14.5) |
| G6 | Firmware and policy authentic, intact, not rollback-able | SLH-DSA-128s + Merkle + persisted monotonic versions; ≥ 2 anchors with revocation (§15) |
| G7 | Least privilege for captured devices | Per-device certificates, ACL and keys; utility-only signing (§10.1, §4.7) |
| G8 | Forward secrecy | Ephemeral hybrid KEM in full handshakes and PSK+KEM resumes; PSK chains capped at 7 days (§9.4, §14) |
| G9 | Cheap resumption within policy limits, invalidated on any change | PASR (§14) |
| G10 | Correct behaviour despite duplicates, loss, crashes, restarts and clock faults | Idempotent handlers; finished-carries-data; outbox + ACKs; intent log; crash-safe persistence; clock recovery (§9.8, §16, §8.9) |
| G11 | **Feasible on the target device classes** (new in v2.2) | Class profiles; constrained profile; artifact sizes within packet limits (§5, §22) |

## 2.3 IoT / Smart-Grid Constraints

These constraints shaped v2.2. The evidence is in §22 and the audit.

| Constraint | Value range | Consequence for the design |
|---|---|---|
| Device RAM | 6 KB (8-bit AVR) … 304 KB (metering SoC) … GBs (gateway) | Class-dependent profiles; 8/16-bit meters cannot run TLS, so they sit behind gateways (§5) |
| Device flash | 48 KB … 2 MB | A/B firmware slots need 2 × image; small parts need external flash (§15.10) |
| Link | NB-IoT: latency up to ~10 s, tens of kbit/s [LIT 3GPP primer]; LTE-M; Ethernet or LTE for gateways | Round trips dominate time; the number of round trips and reconnects matters more than cycles (§22) |
| Radio energy | One NB-IoT UDP exchange ≈ 280 mAs, measured on a live network [LIT Lukic 2020] | Reduce wake-ups, round trips and active-waiting time (§22.9) |
| MQTT packet limits | A device's declared MQTT 5 Maximum Packet Size may be 4–16 KiB | Every artifact is split to fit; otherwise the broker drops it silently [DOCKER T1] |
| Lifetime | 15–20 years (report §1.2) | Flash wear; post-quantum signatures for firmware; anchor revocation |
| Power | Electricity meters, DER and chargers are mains-powered; gas and water meters run on batteries | Energy matters most for battery classes (§22.9) |
| Clock | Many devices have no battery-backed RTC; clocks reset after outages | The design must never need a correct clock to reconnect (§8.8–§8.9) |
| Traffic | AMI interval data every 15 min; DER control a few events per day (IEEE 2030.5 polling 10–15 min) | Handshakes, not payloads, dominate meter bytes; per-command signatures are fine at real DER rates but not at 5-s set-points (§13.3) |

## 2.4 Non-Goals / Out of Scope

- **Denial of service**, including a broker dropping messages. It can be detected (the freshness heartbeat
  stretch goal) but not prevented.
- **Traffic analysis**: who talks to whom, when, and message sizes.
- **A compromised utility headend.** GRANT bounds limit the damage but do not stop it.
- **Side-channel resistance proofs.** Per-device keys limit the damage from any single device (§23.9).
- **A formal proof.** A ProVerif or Tamarin model of §9.4 is future work. The project never claims "formally
  verified".
- **Security of the meter ↔ gateway link** for C0/C1 meters (DLMS/COSEM security suites). End-to-end
  protection ends at the gateway for those meters (§4.2).
- **Wire compatibility** with other KEM-MQTT implementations.
- **Production PKI operations and HSM integration**, beyond stating the requirements (§27).

---

# 3. Design Principles

| # | Principle | What it means in practice |
|---|---|---|
| P1 | **Record-now rule** | Any key exchange protecting traffic that can be recorded is post-quantum **today** and **hybrid** (classical + ML-KEM): TLS hop and E2E layer alike |
| P2 | **Replaceability rule** | A key that can never be replaced (bootloader anchor) uses the most conservative post-quantum scheme (hash-based SLH-DSA), **and** there is more than one of them. A key that can be rotated (command key) uses the standard lattice scheme (ML-DSA-65) |
| P3 | **Live-only authentication may be classical** | Authentication checked only at connection time, and replaceable through the PQ update channel, may stay classical for now (ECDSA P-256 hop certificates). A future quantum computer cannot attack a handshake that already happened |
| P4 | **Fail closed, never fail weak** | Every failed check leads to refusal or a full handshake, never to a weaker session. Unknown topics default to CONTROL |
| P5 | **The broker is not trusted with alerts or commands** | End-to-end protection runs device ↔ utility; the broker only relays ciphertext |
| P6 | **Nothing depends on the device clock to connect** | Time comes from the authenticated utility handshake; TLS on the device skips time checks (§8.8) |
| P7 | **Idempotent under MQTT reality** | QoS 1 duplicates, loss, reordering, crashes and restarts are normal; every handler is idempotent or explicitly ordered |
| P8 | **Persist, then respond** | Any state that makes a promise (a consumed ticket, an allocated command sequence, an applied command) is durable before the promise is sent |
| P9 | **Fit the device, not the laptop** | Every artifact and buffer respects the smallest class that must receive it (packet limit, RAM, flash). Class profiles live in the signed policy, never negotiated on the wire |
| P10 | **Round trips and wake-ups before cycles** | On cellular links, remove round trips and reconnects first; cryptographic cycles are rarely the bottleneck (§22) |
| P11 | **Evidence before claims** | No number without a label; no claim without a test; laptop numbers are never meter numbers |
| P12 | **Frozen decisions** | Change a decision only through a new decision record (§20) with evidence and a trigger |

---

# 4. Complete System Architecture

```
                    ┌──────────────────── Offline signing station (network_mode: none) ─────────────┐
                    │  SLH-DSA-SHA2-128s anchors A (primary) and B (backup) · signs FIRMWARE, POLICY,│
                    │  KEYREVOKE manifests · output carried by "USB stick" to the utility          │
                    └──────────────────────────────────────────────┬─────────────────────────────────┘
                                                                   │ signed artifacts
 ┌────────── Field ──────────┐        ┌──────── Broker ────────┐   ▼   ┌───────────── Utility / control center ──────────┐
 │ C3 device (e.g. nRF9160)  │        │ Mosquitto 2.0           │       │ E2E endpoint · ticket issuer (STEK, SQLite WAL)│
 │ C2 device (constrained)   │══TLS══▶│ TLS 1.3 only, hybrid-   │◀═TLS═▶│ command service (ML-DSA-65 key in HSM,         │
 │ C4 gateway ◀─DLMS/COSEM─  │ 1.3    │ only groups, ECDSA certs│  1.3  │   separate from the E2E KEM key)               │
 │   C0/C1 meters            │ hybrid │ ACL from signed policy  │       │ artifact publisher · registry · zone keys      │
 └────────────┬──────────────┘        │ persistence, persistent │       └──────────────────────┬─────────────────────────┘
              │                       │ MQTT sessions, packet   │                              │
              │                       │ limits, retained FOTA   │                              │
              │                       └─────────────────────────┘                              │
              └══════════════ end-to-end hybrid KEM-MQTT session (ALERT, CONTROL) ═════════════┘
                         the broker relays ciphertext it can neither read nor forge

 Private CA (ECDSA P-256): issues broker and device certificates; CA set pinned on devices; rolled over through signed policy.
```

**Layer model**

| Layer | Protects | Against | Endpoints |
|---|---|---|---|
| Application tiers | Alert and command content; command authority | Broker, captured devices | Device ↔ utility |
| E2E session (PCHC) + resumption (PASR) | Keys for ALERT and CONTROL, with the policy bound in | Broker, network, quantum recorder | Device ↔ utility |
| MQTT 5 | Routing, sessions, QoS, retained artifacts | — (not a security layer) | Client ↔ broker |
| TLS 1.3 hybrid | Everything on each hop, including TELEMETRY and topic names | Network, quantum recorder | Device ↔ broker, utility ↔ broker |

## 4.1 Device

**Role:** MQTT client. It publishes TELEMETRY and ALERT, and receives CONTROL (discrete commands, GRANTs,
SETPOINTs, zone keys), demand-response broadcasts and FOTA artifacts.

**Classes:** C2 and C3 connect directly; C4 gateways act for C0/C1 meters (§5).

**Holds:**
- in flash: its E2E hybrid key pair, its TLS key and certificate, the pinned CA set, the installed policy,
  the ticket, the command intent log, the alert outbox and the time floor;
- in bootloader ROM/OTP: the firmware anchors and the committed version counters.

**Never holds** any key that lets it act for another device or for the utility.

**Runs:**
- TLS on its **application MCU**, with a hybrid-capable library. Modem-offloaded TLS is not post-quantum
  (§8.1).
- The E2E state machine (§9), the policy engine (§12), the FOTA installer (§15), and the persistence layer
  (§16).

## 4.2 Gateway

**Role:** a class C4 device (Linux-class) that aggregates legacy C0/C1 meters over DLMS/COSEM (PLC/RF), as
described by Domingo Martín et al. It is the MQTT client and the **E2E endpoint** for those meters' data.

**Honest boundary:** for C0/C1 meters, post-quantum end-to-end protection covers **gateway ↔ utility only**.
The meter ↔ gateway link uses the DLMS/COSEM security suite (AES-GCM, ECDSA), which is classical and out of
scope (§2.4).

**Topics:** the gateway publishes under its own device ID. Payloads identify the meter. The ACL allows only
the gateway's own topics. DER controllers and EV chargers that speak IEEE 2030.5 or OCPP rather than MQTT
also reach the system through a gateway.

## 4.3 MQTT Broker

**Product:** Eclipse Mosquitto 2.0 (verified with 2.0.21 on OpenSSL 3.5).

**Trusted for:** availability and honest routing only.

**Configuration** (full list in §27.1):
- TLS 1.3 on **every** listener;
- only hybrid groups (`X25519MLKEM768:SecP256r1MLKEM768`) through `OPENSSL_CONF`;
- mutual ECDSA certificates, with `use_identity_as_username`;
- the ACL compiled from the signed policy and hot-reloaded with SIGHUP;
- `persistence true` (retained artifacts, persistent MQTT sessions);
- `max_packet_size 300000`;
- `set_tcp_nodelay true`;
- queue limits sized for the persistent sessions of sleeping devices.

**Sees:** TELEMETRY in plaintext (by design: the utility runs the broker and bills from readings), plus
topic names, sizes and timing. **Never sees:** ALERT or CONTROL plaintext, or any E2E or command key.

## 4.4 Utility / Control Center

| Component | Function | Key material | Persistence |
|---|---|---|---|
| E2E endpoint | Runs the utility side of the handshake and PASR; opens alerts, sends ACKs | Utility E2E hybrid key (static) | Sessions in RAM (recoverable through resync + PASR) |
| Ticket issuer | Issues and validates tickets (9 checks); maintains the used-ticket set | STEK (rotated every 24 h; **HSM in production**) | **SQLite WAL**: used tickets, STEK metadata |
| **Command service** | Allocates epoch ‖ counter sequences; signs discrete commands and GRANTs; keeps the redelivery queue | ML-DSA-65 command key, **held apart from the E2E key** (HSM or a separate service) | **SQLite WAL**: sequences, queue, statuses |
| Artifact publisher | Relays station-signed manifests (split into parts) and chunks as retained messages; cleans up after the retention window | none (the station signs) | Rollout state |
| Registry | device ID → class, E2E public key, active/revoked, declared max packet size | — | SQLite |
| ACL compiler | Verifies the signed policy, reads the registry, writes the ACL, sends SIGHUP to Mosquitto | — | — |
| Zone manager | Holds the zone key per zone and epoch; sends keys under each member's session | Zone keys | SQLite |

**Separation of duties** is a requirement, not an option. It is what makes the command signature more than
decoration. If one process held both the E2E key and the command key, one compromise would forge commands
too (§23.7).

## 4.5 PKI / CA

| Item | Design |
|---|---|
| CA | Private CA, ECDSA P-256, self-signed. `basicConstraints CA:TRUE` (critical), `keyUsage keyCertSign, cRLSign`. These extensions are required by Python 3.13's strict checks (verified) |
| Broker certificate | ECDSA P-256; SAN = the broker's DNS name or IP; EKU serverAuth; normal lifetime (e.g. 825 days) |
| Device certificate | ECDSA P-256; **CN = device ID** (must match `^[a-z0-9][a-z0-9-]{0,31}$`); EKU clientAuth; **notAfter = 99991231235959Z** (RFC 5280 §4.1.2.5: no well-defined expiry; verified accepted by the broker [DOCKER T4-g]) |
| Device-side validation | Chain to the **pinned CA set**, with **validity-time checks disabled** (`X509_V_FLAG_NO_CHECK_TIME` or equivalent; verified [DOCKER T4-d]). Hostname/SAN checked |
| Broker-side validation | Normal, including time: the broker has a correct clock |
| Revocation | Registry deactivation (durable first) → every live session and half-open handshake of the device closed at once, its ALERTs, status ACKs and new commands refused, the device removed from its zones and every crypto-group key of those zones rotated → ACL removal (SIGHUP). E2E refusal never depends on the ACL step (tested P9, H1 [DOCKER, broker with no ACL change]). Optional CRL file at the broker |
| CA roll-over | The new CA certificate travels in a signed policy **before** the broker switches. Devices pin {current, next} during the overlap (Rationale OPS-1) |

## 4.6 Firmware Authority

- **Offline signing station**, never networked (`network_mode: none` in the Docker build). Artifacts leave
  on removable media.
- **Algorithm:** SLH-DSA-SHA2-128s (FIPS 205).
- **Anchors:** at least two key pairs, **A** (primary) and **B** (backup), generated separately and stored
  separately (different custodians or escrow). Their public keys (32 B each) are burned into every
  bootloader.
- **Signs:** FIRMWARE, POLICY and KEYREVOKE manifests. A KEYREVOKE for anchor X must be signed by a
  different, non-revoked anchor.
- **Production note:** LMS/HSS (SP 800-208) is the standards-preferred firmware scheme when a
  hardware-backed station can guarantee that signing state never repeats (§21).

## 4.7 Key Management

| Key | Algorithm | Private part held by | Public part known to | Generated | Rotation | Revocation | Impact if stolen |
|---|---|---|---|---|---|---|---|
| Station anchors A, B | SLH-DSA-SHA2-128s | Offline station (separate custodians) | Every bootloader (32 B each) | At fleet setup | Never; replaced only by revocation | KEYREVOKE signed by the other anchor | Firmware forgery until revoked |
| Utility E2E static key | X25519 + ML-KEM-768 | Utility | Devices, through the signed policy | Utility setup | New policy version | New policy | Read **new** sessions of devices that use it (RISK test); **cannot forge commands** |
| Utility command key | ML-DSA-65 | Command service / HSM | Devices, through the signed policy | Utility setup | New policy version | New policy | Forge commands and GRANTs, so it must live in an HSM |
| STEK | 256-bit, ChaCha20-Poly1305 | Utility (HSM in production) | — | Every 24 h | 24 h; retired after the maximum ticket lifetime | Retire kid | Mint tickets and impersonate devices on PASR (RISK test), so HSM |
| Device E2E static key | X25519 + ML-KEM-768 | Device | Utility registry | Provisioning | Re-provisioning | Registry | Impersonate **that** device |
| Device TLS key + certificate | ECDSA P-256 | Device | Broker (through the CA) | Provisioning | CA re-issue | Registry/ACL (+ CRL) | Hop impersonation of that device (TELEMETRY only) |
| Broker TLS key + certificate | ECDSA P-256 | Broker | Devices (through the CA) | Broker setup | Before expiry, with CA overlap | CA | Impersonate the broker at the hop (TELEMETRY only; ALERT/CONTROL remain E2E) |
| CA key | ECDSA P-256 | CA (offline) | Pinned by all | Setup | Roll-over through policy | New CA | Hop impersonation of anyone |
| Zone keys | 256-bit | Utility + zone members | — | Per zone and epoch | Membership change, policy change, weekly | New epoch | Read DR events of that zone; **cannot forge** (events are signed) |
| Session keys | HKDF output | Device + utility, **RAM only** | — | Every handshake/resume | Every resumption; full handshake at least every 7 days | — | That session only |
| Ticket psk | HKDF from K_master | Device flash + sealed in the ticket | — | Every NT | Single-use | — | One resumption, only if the ticket is also held and still unused |

---

# 5. Device Classes

The classes follow RFC 7228 where it applies. Part numbers are real parts [LIT], used as examples only. No
single part's numbers are taken as representative of "all IoT".

## C0/C1 — metrology MCUs (behind a gateway)

| Attribute | Value |
|---|---|
| RAM | 6–16 KB (ATmega4808: 6 KB; MSP430F6765A: 16 KB). RFC 7228: C0 ≪ 10 KiB, C1 ~10 KiB |
| Flash | 48–128 KB |
| CPU | 8/16-bit, ≤ 25 MHz |
| Network | Usually none of its own: PLC or RF to a data concentrator over DLMS/COSEM |
| Energy | Mains (electricity); battery for some gas and water meters |
| Crypto capability | AES in some parts; X25519 takes 13.9 M cycles on AVR [LIT Düll 2015]; Kyber-512 KEM-MQTT takes 31.8 M cycles on AVR [LIT Kim & Seo] |
| Supported profile | **GATEWAY-BEHIND:** data enters the system through a C4 gateway |
| What cannot run | TLS 1.3 (OpenSSL needs ≥ 16 KB stack [LIT Kim & Seo]); hybrid E2E; A/B firmware with PQ verification |
| Why | Peak RAM for the security path is ≥ 16.7 KB even in the constrained profile, before any application (§22.2); the crypto code alone is ~40–45 KB of flash (§22.3) |

## C2 — small cellular comms MCU

| Attribute | Value |
|---|---|
| RAM | ~50–128 KB (RFC 7228 Class 2: ~50 KiB) |
| Flash | 256–512 KB, often plus an external SPI flash |
| CPU | 32-bit Cortex-M0+/M4, 48–120 MHz; often no crypto accelerators |
| Network | NB-IoT or LTE-M modem (AT commands; offloaded TLS is not post-quantum) |
| Energy | Mains (electricity meter comms module) or battery (gas/water) |
| Crypto capability | Cold start ≈ 19.7 M cycles: ~0.31 s at 64 MHz on an M4, ~1.05 s on an M0+ at 125 MHz (lower bounds) [ANALYTICAL from LIT] |
| Supported profile | **CONSTRAINED:** TLS max_fragment_length 512–1,024; stack-optimised PQ code; artifacts streamed to flash; manifest verified from flash; small packet limit (e.g. 4 KiB); batched or persistent reconnect |
| What cannot run | The default profile (16 KB TLS records ×2 plus fast PQ code: peak ≈ 50 KB before the application); a single-packet 16 KB manifest; per-command ML-DSA at 5-s rates |
| Why | RAM (§22.2), packet limit [DOCKER T1], airtime (§22.8) |

## C3 — cellular SiP / metering SoC

| Attribute | Value |
|---|---|
| RAM | 256–304 KB (nRF9160: 256 KB; SAM4CM: up to 304 KB) |
| Flash | 1–2 MB |
| CPU | Cortex-M33 / dual Cortex-M4, 64–120 MHz |
| Network | NB-IoT / LTE-M |
| Energy | Mains or battery |
| Crypto capability | Hardware AES and SHA-256 (CryptoCell 310; SAM4CM AES-GCM + SHA-1/224/256 + ECC accelerator + TRNG + battery-backed RTC) |
| Supported profile | **FULL**, with the class reconnect strategy |
| What cannot run | Nothing in scope; energy per reconnect still needs measurement **[HW]** |
| Why | Comfortable RAM and flash margins (§22) |

## C4 — Linux-class gateways, DER and EV controllers, data concentrators

| Attribute | Value |
|---|---|
| RAM | ≥ 256 MB |
| Flash | GB-class storage |
| CPU | Cortex-A, ≥ 1 GHz |
| Network | LTE / Ethernet |
| Energy | Mains |
| Crypto capability | Everything; the Docker results are representative in *kind* but not in absolute numbers |
| Supported profile | **FULL**; acts as gateway for C0/C1 meters |
| What cannot run | — |
| Why | — |

**The profile is fixed per class in the signed policy (§12), never negotiated on the wire.** A negotiated
profile would be a downgrade surface.

---

# 6. Security Architecture

This section says **what each mechanism does** and with which parameters. Why each was chosen is in §7
(primitives), §8 (TLS) and §20 (decision records).

## 6.1 TLS 1.3

Every MQTT connection, from device or utility to the broker, runs over **TLS 1.3 only**, with mutual
certificate authentication.

It provides:
- confidentiality and integrity of everything on the hop: TELEMETRY, topic names, MQTT framing, and the E2E
  messages as an outer layer;
- hop identity: the broker learns the device ID from the certificate CN.

| Parameter | Value |
|---|---|
| Key exchange | X25519MLKEM768 (SecP256r1MLKEM768 also allowed), **pinned hybrid-only** on broker and devices |
| Cipher suite | One per device class (§6.5): `TLS_AES_256_GCM_SHA384` (the default, and what the utility uses) or `TLS_CHACHA20_POLY1305_SHA256` |
| Authentication | ECDSA P-256 certificates, mutual |
| Resumption | Standard TLS 1.3 tickets (psk_dhe_ke). Hop ticket lifetime 7,200 s [DOCKER T2]; not our contribution |
| Record size | Default 16 KiB; the constrained profile asks for max_fragment_length 512–1,024, which the broker honours [DOCKER T3] |

## 6.2 X25519 + ML-KEM-768

Used in two places:
1. inside TLS, as the `X25519MLKEM768` group (IETF draft-ietf-tls-ecdhe-mlkem): client share 1,216 B, server
   share 1,120 B;
2. inside the E2E handshake, as the **hybrid KEM (HKEM)**:
   - public key = ML-KEM-768 encapsulation key (1,184 B) ‖ X25519 public key (32 B) = 1,216 B;
   - ciphertext = ML-KEM-768 ciphertext (1,088 B) ‖ ephemeral X25519 public key (32 B) = 1,120 B.

Either half alone protects the shared secret. **Security holds as long as either algorithm holds.**

## 6.3 E2E KEM-MQTT

This is the base paper's KEM-MQTT handshake (Kim & Seo, Figure 4), lifted from device ↔ broker to
**device ↔ utility** and made hybrid, with **POLICY_INFO** bound into the key schedule.

Its properties:
- mutual authentication **without signatures**: only the utility can decapsulate `ct_U`, and only the
  device can decapsulate `ct_D`;
- forward secrecy from an ephemeral HKEM;
- policy binding;
- replay safety.

The protocol is in §9.4.

## 6.4 X-Wing Combiner

The hybrid shared secret is computed as:

`ss = SHA3-256(ss_ML-KEM ‖ ss_X25519 ‖ ct_X25519 ‖ pk_X25519 ‖ "\.//^\")`

This is the X-Wing construction (IETF CFRG draft). It binds the X25519 transcript into the secret, so an
attacker cannot mix and match halves. SHA3-256 is available anyway, because ML-KEM uses Keccak.

## 6.5 AEAD

There is **one AEAD per device class**, used at **both** layers (v2.2 change):

| Class situation | TLS cipher suite | E2E AEAD |
|---|---|---|
| AES hardware present (C3 SoCs, gateways, utility) | `TLS_AES_256_GCM_SHA384` | AES-256-GCM |
| No AES hardware (some C2) | `TLS_CHACHA20_POLY1305_SHA256` | ChaCha20-Poly1305 |

The class value is set in the signed policy (`aead`).

**Nonces** are counter-based: `direction(1) ‖ 000 ‖ seq(8)`, with separate keys per tier and direction.
**Session keys and their counters live only in RAM, and die together** (§9.7). STEK-sealed tickets use
ChaCha20-Poly1305 at the utility, with random 96-bit nonces.

## 6.6 HKDF

HKDF-SHA-256 (RFC 5869):
- `K_master = HKDF-Extract(salt = H(transcript), IKM = ss_e ‖ ss_U ‖ ss_D)` for a full handshake, or
  `psk ‖ [ss_e′]` for a resume;
- `K_{name,dir} = HKDF-Expand(K_master, "key|" ‖ name ‖ "|" ‖ dir)`, for ALERT|up, CONTROL|down, ACK|up
  and ACK|down;
- confirmation keys `kc_U` and `kc_D`;
- `sid = HKDF-Expand(K_master, "sid", 8)`;
- resumption secret `psk = HKDF-Expand(K_master, "res|" ‖ ticket_id)`.

Every derived key has its own label (domain separation).

## 6.7 HMAC

HMAC-SHA-256 is used for:
- key-confirmation MACs (MAC_U, MAC_D);
- ACK MACs;
- the PASR binder (`MAC(HKDF(psk, "binder"), H(all RH fields))`).

**All MAC comparisons are constant-time.**

## 6.8 Hashing

| Hash | Uses |
|---|---|
| **SHA-256** | Transcript hash `H(...)` (length-prefixed parts); AAD digests; the RFC 6962 Merkle tree (leaf `SHA-256(0x00 ‖ data)`, node `SHA-256(0x01 ‖ L ‖ R)`); the payload hash in manifests; the SLH-DSA-SHA2-128s internals (**SHA-256 only**, §7.7) |
| **SHA3-256 / SHAKE** | Inside ML-KEM; the X-Wing combiner |
| **SHA-384** | Inside the TLS suite `TLS_AES_256_GCM_SHA384` |

---

# 7. Why Each Cryptographic Primitive Was Chosen

Cycle counts are Cortex-M4 [LIT pqm4, 24 MHz, no wait states] unless stated otherwise. "ms @64 MHz" is a
**lower bound**. Docker numbers are laptop numbers.

## 7.1 X25519 (the classical half of every hybrid KEM)

| Aspect | Content |
|---|---|
| **Chosen** | X25519 (RFC 7748), in the TLS group and in every E2E HKEM |
| **Alternatives considered** | P-256 ECDH (TLS group `SecP256r1MLKEM768`); X448; no classical half (pure ML-KEM) |
| **Why chosen** | Constant-time Montgomery ladder with no special cases; 32-byte keys; it is the half of the most widely deployed hybrid group; the X-Wing combiner is defined for it |
| **Why not P-256** | Also acceptable; it is allowed as a second TLS group, because some MCUs have P-256 accelerators. X25519 stays the default for E2E, because X-Wing specifies X25519 |
| **Why not X448** | Stronger classical security than needed, over a larger field (slower, 56-byte keys), and no benefit against quantum attacks |
| **Why not pure ML-KEM** | Rule P1: recorded traffic must not rest on one young algorithm. ANSSI/BSI recommend hybrid in the transition period (Malina §2.2) |
| **Security trade-off** | Adds nothing once quantum computers exist; protects if ML-KEM is broken classically first |
| **Performance trade-off** | 625,358 cycles per scalar multiplication [LIT Haase-Labrique, M4], about the same as one ML-KEM-768 operation. A cold start needs 7: ~4.4 M cycles, **22%** of device public-key time. M0: 3.59 M cycles; AVR: 13.9 M [LIT Düll 2015]. On the laptop the hybrid adds +122% compute [DOCKER] |
| **Memory/flash trade-off** | Small: < 1 KB stack, a few KB code |
| **Bandwidth trade-off** | +32 B per public key or ciphertext |
| **Migration path** | Drop the classical half (`MLKEM768` TLS group; pure ML-KEM HKEM) once ML-KEM has a longer cryptanalytic record and guidance allows it. One configuration change for TLS; a KEM-identifier change for E2E |

## 7.2 ML-KEM-768

| Aspect | Content |
|---|---|
| **Chosen** | ML-KEM-768 (FIPS 203, Category 3) in TLS and E2E |
| **Alternatives considered** | ML-KEM-512, ML-KEM-1024, HQC, Classic McEliece, BIKE |
| **Why chosen** | NIST's recommended default parameter set; margin against future lattice cryptanalysis for data that must stay secret for 15–20 years; supported natively by OpenSSL 3.5 and Python `cryptography` 50 |
| **Why not ML-KEM-512** | Category 1: smallest margin for long-lived secrets. It would save ~0.3 M cycles per operation and a few hundred bytes per handshake, which is negligible next to ECDSA and radio (§22). Kim & Seo use Kyber-512 because their 8-bit target needed it; ours does not |
| **Why not ML-KEM-1024** | +384 B per key, +480 B per ciphertext and +60% cycles, with no need at our threat level. (CNSA 2.0 mandates it for US national-security systems, which this is not) |
| **Why not HQC** | Selected by NIST in 2025 as a backup; not yet a final standard; much larger (2.2 KB keys, 4.5 KB ciphertexts at level 1) and far slower on an M4 (53–160 M cycles [LIT pqm4]) |
| **Why not McEliece / BIKE** | McEliece public keys are ~1 MB; BIKE needs 27–57 M cycles on an M4 [LIT pqm4] |
| **Security trade-off** | Relies on Module-LWE; the hybrid covers a classical break. Implementations must be free of the **KyberSlash** (2024) timing leaks: use patched, constant-time code |
| **Performance trade-off** | Keygen / enc / dec 0.64 / 0.66 / 0.71 M cycles [LIT pqm4]; M0+ 16.0 / 18.6 / 22.0 ms [LIT RP2040]; measured board energy 1.89 / 1.80 / 1.24 mJ [LIT Tasopoulos 2023]. Laptop: full E2E handshake 0.278 ms on the device side [DOCKER] |
| **Memory/flash trade-off** | Stack 2.8 KB (small-stack) or 6.5 KB (fast); decapsulation key 2,400 B; code ~13.3 KB excluding Keccak [LIT pqm4]; M0+ reference C: 18.9 KB total RAM for decapsulation [LIT RP2040] |
| **Bandwidth trade-off** | 1,184 B public key, 1,088 B ciphertext |
| **Migration path** | ML-KEM-1024 if guidance or cryptanalysis demands it (a parameter change; sizes grow as above). HQC as a diverse backup once standardised |

## 7.3 X25519MLKEM768 (TLS hybrid group)

| Aspect | Content |
|---|---|
| **Chosen** | X25519MLKEM768, pinned hybrid-only; SecP256r1MLKEM768 also allowed |
| **Alternatives considered** | Classical X25519 only; pure `MLKEM768`; accept whatever the client offers (OpenSSL default) |
| **Why chosen** | Rule P1 on the hop; OpenSSL 3.5's default first group (verified); IETF-track codepoint |
| **Why not classical only** | Recorded TELEMETRY and topic names would fall to a future quantum computer |
| **Why not pure MLKEM768** | Rule P1 (hybrid); kept as the E1 benchmark comparison |
| **Why not accept anything** | Verified [DOCKER N3]: with default settings a client offering **only X25519** is silently accepted ("Peer Temp Key: X25519"). Pinning makes it fail ("handshake failure") while normal clients still get X25519MLKEM768 |
| **Security trade-off** | The pin covers **TLS 1.3 only**. A TLS 1.2 listener (e.g. for PSK) negotiates classical FFDHE-3072 regardless of the pin [DOCKER T7], so every listener must be TLS 1.3 (§8.2) |
| **Performance trade-off** | Per full or resumed handshake the device does 1 ML-KEM keygen + 1 decaps + 2 X25519 mults: 2.6 M cycles |
| **Memory/flash trade-off** | The client key share needs ~3.6 KB of transient key material |
| **Bandwidth trade-off** | +2.3 KB per handshake against classical X25519. A full hop handshake with MQTT CONNECT is 6,262 B; a resumed one 4,438 B, because resumption repeats the key shares [DOCKER T5] |
| **Migration path** | Pure `MLKEM768`, with one line of `OPENSSL_CONF` |

## 7.4 X-Wing combiner

| Aspect | Content |
|---|---|
| **Chosen** | `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label)` (CFRG X-Wing) |
| **Alternatives considered** | Concatenate then HKDF; XOR of secrets; the TLS-style "concatenate the two shared secrets" combiner |
| **Why chosen** | A published analysis exists for this exact construction (ML-KEM-768 + X25519); it includes the X25519 ciphertext and public key, so the classical half is transcript-bound; SHA3 is already on the device |
| **Why not XOR** | Not robust if one component is malleable or attacker-influenced |
| **Why not plain concatenation into HKDF** | Works in TLS because the transcript is hashed separately. Our E2E KEMs are also used outside the transcript (for `K_B` and `K1`), so a self-contained combiner is safer |
| **Security trade-off** | Relies on the draft's analysis; the draft is not yet an RFC |
| **Performance trade-off** | One SHA3-256 of ~130 B per encapsulation: negligible |
| **Memory/flash trade-off** | None beyond Keccak, which ML-KEM needs anyway |
| **Bandwidth trade-off** | None |
| **Migration path** | Track the final CFRG document; the label changes with the version |

## 7.5 ECDSA P-256 (hop certificates)

| Aspect | Content |
|---|---|
| **Chosen** | ECDSA P-256 for the CA, broker and device certificates |
| **Alternatives considered** | ML-DSA-44/65 certificates; Ed25519; a per-device TLS PSK; raw public keys |
| **Why chosen** | Rule P3: hop authentication is checked live and can be replaced through the PQ update channel before quantum computers arrive. Smallest handshake: leaf 394–426 B, full handshake 4,695 B vs 23,809 (ML-DSA-44) and 31,702 (ML-DSA-65) [DOCKER]. Broad hardware acceleration (e.g. SAM4CM) |
| **Why not ML-DSA certificates** | 5–7× larger handshakes, and larger resumed handshakes, because OpenSSL embeds the client certificate in tickets (7–9 KB) [DOCKER]. That is the migration path, not the default |
| **Why not a per-device PSK** | Mosquitto 2.0.21 accepts PSK only over **TLS 1.2**, with classical `DHE-PSK` (FFDHE-3072), so it would lose post-quantum key exchange [DOCKER T7]. It also puts per-device secrets on the broker (Rationale B31) |
| **Why not Ed25519** | Viable, but less MCU hardware support and no gain in the quantum dimension |
| **Security trade-off** | Classical: a future quantum computer could forge **future** hop authentication, which is why migration must happen before then. It cannot break past connections. ALERT and CONTROL stay protected E2E even if the hop is impersonated |
| **Performance trade-off** | **The largest device cost:** sign 2.2 M, verify 4.5 M cycles (wolfSSL at 180 MHz [LIT Tasopoulos 2022]); 3 operations per full handshake = **57% of cold-start public-key cycles**. M0+: verify 321 ms [LIT RP2040]. Measured board energy: verify 4.78 mJ [LIT Tasopoulos 2023]. Hardware ECC accelerators help where present **[HW]** |
| **Memory/flash trade-off** | Small keys; the certificate-parsing code is part of the TLS library |
| **Bandwidth trade-off** | ~0.9 KB of certificates per full handshake |
| **Migration path** | ML-DSA-44 certificates, a configuration change measured in E1. **Trigger:** credible CRQC timelines, or a CNSA 2.0/NIST deprecation milestone for the device classes |

## 7.6 ML-DSA-65 (discrete commands and GRANTs; heartbeat)

| Aspect | Content |
|---|---|
| **Chosen** | ML-DSA-65 (FIPS 204, Category 3). The utility signs; the device verifies |
| **Alternatives considered** | ML-DSA-44; ML-DSA-87; FN-DSA-512 (Falcon); SLH-DSA; session AEAD only; per-set-point signatures |
| **Why chosen** | A final standard; fast, constant-time verification; the command key can be rotated through the signed policy (rule P2); widely available (OpenSSL 3.5, Python `cryptography`, pqm4) |
| **Why not ML-DSA-44** | −27% bytes, −41% verify cycles, Category 2. Not enough gain once high-rate traffic moves to GRANTs (§13.3) |
| **Why not ML-DSA-87** | +40% bytes and +73% verify cycles, for no need at our threat level |
| **Why not FN-DSA-512** | **The best future fit:** 666 B signatures and 0.47 M-cycle verification, and the device never signs (Falcon's hard side). But FIPS 206 is **not final**, and there is no vetted library in our stack. Recorded as a trigger (§30) |
| **Why not SLH-DSA** | Signing takes 168–324 ms (laptop), too slow for live commands; signatures are 8–16 KB |
| **Why not session AEAD only** | Anyone holding the session key could forge commands; no non-repudiation; unusable for broadcast |
| **Why not sign every high-rate set-point** | 61 MB/day and 7 h/day of NB-IoT airtime at 5-s set-points (§13.3) |
| **Security trade-off** | Lattice (Module-LWE/SIS) assumption, but the key is rotatable. Adds value over session authentication **only if the signing key is held apart from the E2E key** (§4.4) |
| **Performance trade-off** | Device verify 2.42 M cycles (38 ms @64 MHz) fast, or 5.73 M (90 ms) with a small stack [LIT pqm4]; M0+ 72 ms [LIT RP2040]; measured board energy 2.59 mJ (Dilithium3) [LIT Tasopoulos 2023]. Utility sign 0.556 ms, verify 0.101 ms [DOCKER] |
| **Memory/flash trade-off** | Verify stack 2.7 KB (small) or 9.9 KB (fast); public key 1,952 B (in the policy); code 19–24 KB |
| **Bandwidth trade-off** | 3,309 B per signature: 95% of a CMD envelope (3,466 B [DOCKER, v2.2 code]) |
| **Migration path** | FN-DSA-512 once FIPS 206 is final (trigger §30); ML-DSA-87 if the category must rise |

## 7.7 SLH-DSA-SHA2-128s (firmware, policy, key revocation)

| Aspect | Content |
|---|---|
| **Chosen** | SLH-DSA-SHA2-128s (FIPS 205, Category 1), stateless hash-based, with **two or more anchors** (§15.13) |
| **Alternatives considered** | SLH-DSA-SHA2-192s (the v2.1 choice); 128f/192f; ML-DSA-65; ML-DSA + Ed25519 dual signature; LMS/HSS; XMSS; FN-DSA |
| **Why chosen** | The anchor is burned into the bootloader, so the scheme must be as conservative as possible: security rests on **hash functions only**. 128s is the smallest stateless hash-based option. It needs **only SHA-256**, which is often in hardware. Its signed manifest (8,031 B [DOCKER, v2.2 code]) fits an 8 KiB MQTT packet |
| **Why not 192s** | 16,224 B signature, so a 16,405 B manifest: silently dropped for devices with a packet limit ≤ 16 KiB [DOCKER T1]. Verify needs 13.5 M vs 7.47 M cycles. Categories 3 and 5 **also need SHA-512** (FIPS 205 §11.2), which SHA-256-only engines such as SAM4CM's do not provide. Rationale B10 recorded exactly this trigger for switching (§15.5) |
| **Why not 'f' variants** | Larger signatures (17–36 KB) **and slower verification** (128f: 21.9 M cycles) [LIT pqm4]. They only sign faster, and signing is offline |
| **Why not ML-DSA-65** | A young lattice assumption for a key that can never be replaced |
| **Why not a dual ML-DSA + Ed25519 signature** | After quantum computers arrive it reduces to ML-DSA alone. SLH-DSA is more conservative and simpler |
| **Why not LMS/HSS or XMSS** | Stateful: reusing one internal key even once breaks security. SP 800-208 expects state held in hardware. Right for a **production** station with an HSM (CNSA 2.0's firmware choice); too risky for a student-run station |
| **Why not FN-DSA** | Not final; floating-point signing |
| **Security trade-off** | Category 1 (≥ AES-128 key search), not 3. It is still post-quantum and hash-only; NIST treats Category 1 as adequate. The v2.1 "all Category 3" rule was about uniformity, not a threat requirement |
| **Performance trade-off** | Device verify 7.47 M cycles (117 ms @64 MHz) [LIT pqm4]; board energy for SPHINCS+-128s verify 12.0 mJ, measured [LIT Tasopoulos 2023]; laptop verify 0.164 ms; station sign 168 ms, once per release [DOCKER] |
| **Memory/flash trade-off** | Verify stack 2.0 KB; code 5.3 KB (plus SHA-256); anchors 32 B each |
| **Bandwidth trade-off** | 7,856 B per artifact version (firmware or policy). Negligible per year even on NB-IoT |
| **Migration path** | LMS/HSS with an HSM-backed station (production); higher categories if guidance requires, delivered by KEYREVOKE plus a new anchor only in new hardware |

## 7.8 AES-256-GCM

| Aspect | Content |
|---|---|
| **Chosen** | TLS suite `TLS_AES_256_GCM_SHA384` everywhere AES hardware exists; E2E AEAD for those classes |
| **Alternatives considered** | AES-128-GCM; AES-CCM; ChaCha20-Poly1305; Ascon-AEAD128 |
| **Why chosen** | Negotiated by default (verified); hardware on the target SoCs (SAM4CM AES-GCM; nRF9160 CryptoCell 310 AES); **using the same AEAD at both layers means one implementation on the device** |
| **Why not AES-128** | Also quantum-adequate per NIST. 256-bit is kept for margin and consistency: the cost is negligible with hardware |
| **Why not AES-CCM** | Two passes; no benefit here |
| **Security trade-off** | Catastrophic if a nonce repeats: solved by counter nonces and RAM-only keys (§9.7). Software AES without hardware leaks timing, so classes without AES hardware use ChaCha20 |
| **Performance trade-off** | Fast with hardware; slow and leaky without it |
| **Memory/flash trade-off** | Hardware driver or table-free software |
| **Bandwidth trade-off** | 16-byte tag per record or envelope |
| **Migration path** | None needed; AES remains quantum-adequate |

## 7.9 ChaCha20-Poly1305

| Aspect | Content |
|---|---|
| **Chosen** | E2E AEAD **and** TLS suite `TLS_CHACHA20_POLY1305_SHA256` for classes **without** AES hardware; STEK ticket sealing at the utility |
| **Alternatives considered** | AES-GCM in software; Ascon-AEAD128 |
| **Why chosen** | Fast and constant-time in plain software; 256-bit key; an RFC 8439 standard with a TLS 1.3 suite |
| **Why not software AES** | Slow, and table implementations leak timing |
| **Why not Ascon-AEAD128** | SP 800-232 (final Aug 2025) and very light on 8/16-bit parts, but **no TLS 1.3 suite exists**, so it would be a second AEAD on the device. (The v2.1 reason, "128-bit key", is dropped: 128-bit keys are quantum-adequate per NIST) |
| **Security trade-off** | Same nonce discipline as GCM |
| **Performance trade-off** | Laptop: ALERT seal 0.005 ms [DOCKER] |
| **Memory/flash trade-off** | Small code |
| **Bandwidth trade-off** | 16-byte tag |
| **Migration path** | Ascon only if an 8/16-bit class ever becomes a direct client (it cannot today, §5) |

## 7.10 HKDF-SHA-256

| Aspect | Content |
|---|---|
| **Chosen** | HKDF-SHA-256 (RFC 5869): extract with the transcript hash as salt; expand with distinct labels |
| **Alternatives considered** | HKDF-SHA-384; the TLS 1.3 key-schedule style; SHAKE256 as a KDF |
| **Why chosen** | Standard, analysed, available everywhere; SHA-256 often has hardware |
| **Why not SHA-384 or SHAKE** | No security need; SHA-256 at a 256-bit output keeps ~128-bit strength against quantum search |
| **Security trade-off** | Domain separation depends on unique labels; the label list is fixed in Appendix C |
| **Performance trade-off** | Microseconds |
| **Memory/flash trade-off** | Shares the SHA-256 code |
| **Bandwidth trade-off** | None |
| **Migration path** | None needed |

## 7.11 HMAC-SHA-256

| Aspect | Content |
|---|---|
| **Chosen** | HMAC-SHA-256 for key confirmation, ACKs and the PASR binder |
| **Alternatives considered** | KMAC; Poly1305 as a MAC; AEAD with empty plaintext |
| **Why chosen** | Standard; shares SHA-256; constant-time comparison is simple |
| **Why not the others** | No advantage; KMAC would add a dependency on SHA-3 code paths in more places |
| **Security trade-off** | Comparisons must be constant-time (they are) |
| **Performance, memory, bandwidth** | 32 B per MAC; negligible |
| **Migration path** | None needed |

## 7.12 SHA-256 and the RFC 6962 Merkle tree

| Aspect | Content |
|---|---|
| **Chosen** | SHA-256 for the transcript, AAD, payload hash and Merkle tree (RFC 6962 leaf/node prefixes; RFC 9162 verification) |
| **Alternatives considered** | A flat per-chunk hash list (the report's original); SHA3-256 for the tree |
| **Why the Merkle tree** | Manifest and device memory stay constant (32 B root + one proof) whatever the image size; chunks are verifiable in any order |
| **Why not a flat list** | The hash list grows with the image (8 KB for 1 MiB at 4 KiB chunks; 128 KB for 16 MiB) and must sit in the signed manifest |
| **Security trade-off** | Leaf/node prefixes prevent second-preimage tricks between levels |
| **Performance trade-off** | log₂(n) hashes per chunk |
| **Memory/flash trade-off** | ~300 B of working memory |
| **Bandwidth trade-off** | +log₂(n) × 32 B per chunk (256 B at 256 chunks, i.e. 6% of a 1 MiB image at 4 KiB chunks) [DOCKER]; shrinks with larger chunks |
| **Migration path** | None needed |

## 7.13 Randomness (TRNG + DRBG)

| Aspect | Content |
|---|---|
| **Chosen** | A hardware TRNG seeding an SP 800-90A DRBG, **before the first handshake** (requirement) |
| **Alternatives considered** | Software entropy only; the ring oscillator on parts without a certified TRNG |
| **Why** | ML-KEM keygen/encaps, X25519 keys, TLS randoms, ticket IDs and nonces all need good randomness. Counter nonces remove it only from the AEAD. Cheap devices have shipped with broken RNGs |
| **Target parts** | SAM4CM and nRF9160 CryptoCell 310 have TRNGs; the RP2040 ring oscillator is not certified [LIT RP2040] |
| **Migration path** | — |

---

# 8. TLS Design

## 8.1 Why TLS 1.3

- **One round trip** for a full handshake, and encrypted certificates.
- **The only TLS version with standardised hybrid PQ groups.**
- **Mosquitto and OpenSSL 3.5 support it natively** (verified).

**Why not TLS 1.2:** no hybrid ML-KEM groups. Verified [DOCKER T7]: a TLS 1.2 listener negotiates classical
FFDHE even when the hybrid-only group pin is set.

**Why not DTLS or CoAP:** measured studies show UDP-based protocols doing better than MQTT/TCP on NB-IoT
[LIT Lukic 2020, NB-IoT smart-meter study]. But MQTT is fixed by the project's scope, so this is recorded as
a limitation (§25).

**Where the TLS stack runs.** On the device's **application MCU**, with a library that supports hybrid groups
(wolfSSL 5.8+ class). Cellular modems' offloaded TLS is documented as TLS 1.2/DTLS 1.2 (e.g. nRF91) and has
no ML-KEM. Mbed TLS / TF-PSA-Crypto list ML-KEM as "future" on their roadmap [LIT vendor docs]. The library's
footprint must be measured on the target **[HW]**.

## 8.2 Why Hybrid TLS

Rule P1. TELEMETRY, topic names and MQTT framing can be recorded today and decrypted later. Hybrid means an
attacker must break **both** X25519 and ML-KEM-768.

The pin is essential. Verified [DOCKER N3]:
- by default a classical-only client is accepted (`Peer Temp Key: X25519`);
- with the pin it gets "handshake failure";
- normal clients still negotiate `X25519MLKEM768`.

**v2.2 rule:** every broker listener has `tls_version tlsv1.3`, checked by the configuration validator
(§27.1). The pin does not cover TLS 1.2 [DOCKER T7].

## 8.3 Why X25519MLKEM768

This is the IETF group (draft-ietf-tls-ecdhe-mlkem), and OpenSSL 3.5's default first group (verified).
SecP256r1MLKEM768 is also allowed, for devices with P-256 accelerators. Full trade-offs are in §7.3.

## 8.4 Why TLS Encryption Uses One AEAD per Class

| Situation | Suite | Why |
|---|---|---|
| Utility, gateways, C3 with AES hardware | `TLS_AES_256_GCM_SHA384` | Default (verified); hardware-accelerated; same AEAD as E2E for that class |
| C2 without AES hardware | `TLS_CHACHA20_POLY1305_SHA256` | Constant-time software; same AEAD as E2E for that class |

The device offers only its class suite; the broker accepts both.

**Why:** every device needs the TLS AEAD anyway, so using it end to end as well removes a second
implementation (code, tests, side-channel surface).

## 8.5 Certificate Design

See §4.5. In summary:

| Property | Design |
|---|---|
| Algorithm | ECDSA P-256 throughout |
| Device identity | Device certificate CN = device ID; `use_identity_as_username` |
| Device certificate lifetime | `notAfter = 99991231235959Z` |
| Broker certificate lifetime | Normal |
| Device-side checks | Pinned CA set {current, next}; **no validity-time checks** |
| Broker-side checks | Full validation, including time |
| Revocation | Through the registry and ACL |

**Measured sizes** [DOCKER]:
- leaf certificate 394–426 B (P-256);
- full handshake 4,695 B (handshake only), or 6,262 B with MQTT CONNECT and two NewSessionTickets;
- resumed handshake 3,613 B, or 4,438 B with CONNECT.

## 8.6 Why ECDSA P-256 Currently

**Rule P3.** Hop authentication is checked live, so recorded traffic does not help an attacker forge a past
handshake. The certificates can be replaced through the post-quantum update channel (a signed policy carries
the new CA) before quantum computers arrive.

It is also by far the cheapest in bytes. The cost is device cycles: 57% of cold-start public-key work
(§7.5), which hardware ECC accelerators reduce where present.

## 8.7 Why Not ML-DSA Certificates Yet

| Certificates | Leaf | Full handshake | Resumed handshake |
|---|---|---|---|
| **ECDSA P-256 (chosen)** | 394 B | **4,695 B** | 3,613 B |
| ML-DSA-44 | 3,991 B | 23,809 B | 7,213 B |
| ML-DSA-65 | 5,520 B | 31,702 B | 8,749 B |

All [DOCKER]. OpenSSL embeds the client certificate in session tickets, so even resumption grows. On a
20 kbit/s link, 23.8 KB is ~9.5 s of serialisation alone [ANALYTICAL].

**Migration trigger** (§30): credible quantum-computer timelines, or a deprecation milestone for the device
classes. It is a configuration change, measured by experiment E1.

## 8.8 Certificate-Time Problem

**Observation** [DOCKER T4], with the ECDSA P-256 PKI and a correct broker clock:

| Case | Result |
|---|---|
| a) normal device, correct clock | CONNECTED |
| b) device RTC reset to 1970 (no battery-backed RTC) | `certificate verify failed: certificate is not yet valid` |
| c) same, strict `s_client` | HANDSHAKE FAILED, `verify error:num=9` |
| d) same 1970 clock, `-no_check_time` | **HANDSHAKE OK** |
| e) device clock 3 years ahead | `certificate has expired` |
| f) device certificate expired while offline | the broker refuses it: `alert certificate expired` |
| g) device certificate notAfter 9999-12-31 | **CONNECTED** |

**Why this matters.** v2.1 repaired the device clock from **authenticated utility time inside the E2E
handshake** (B21). But the E2E handshake runs *after* TLS. A device with a bad clock can never reach the
utility that would repair it: **a deadlock.** The v2.1 test "device clock reset to 1970 → still connects"
exercised only the E2E layer, without TLS.

**v2.2 resolution:**
1. **Device TLS skips validity-time checks** (case d). The chain is still verified to the **pinned** CA set,
   and hostname/SAN is still checked.
2. **Device certificates never expire** (`99991231235959Z`, case g), so an offline device is never locked
   out by its own certificate. Revocation is by registry/ACL, which the utility controls.
3. **The broker's own certificate** keeps a normal lifetime and is rotated under CA overlap (OPS-1). Devices
   do not check its dates; they check its chain.
4. **The broker checks device certificates normally.** Its clock is trusted.

**Trade-off:** a CA key compromise is not bounded by expiry on devices. It is mitigated by an offline CA,
pinning, and CA roll-over through signed policy (a PQ-signed channel).

## 8.9 Device Clock Recovery

| Step | Rule |
|---|---|
| Boot | `time = max(RTC, time_floor)`, where `time_floor` is the last **authenticated** utility time, persisted in flash |
| TLS | No time checks (§8.8), so the connection succeeds whatever the clock |
| E2E handshake or resume | SH/RS carry authenticated `utility_time` (inside AEAD and MAC). The device sets `offset = utility_time − clock()` |
| Floor update | Write `time_floor` at most once a day and after the first authenticated time following boot (1 write/day: negligible flash wear, §16) |
| Command expiry | Judged **only** with authenticated time. Commands arrive only inside an established session, so authenticated time is always available |
| Never | Device time never gates a connection. The device's claimed time in CH/RH is informational only |

**Why not NTP or cellular NITZ:** both are unauthenticated, so an attacker could shift time and make expired
commands look fresh. They may serve as a hint for logs only.

---

# 9. End-to-End Security

## 9.1 Why TLS Alone Is Not Enough

TLS protects each **hop**, and the broker **terminates** TLS. It holds the plaintext of everything it relays.
If alert and command keys came from TLS (the report's eq. 3.2, `K_session = KDF(K_TLS, …)`), a curious or
compromised broker could:
- read every alert and command;
- forge commands;
- serve a weaker policy.

Python cannot even export `K_TLS` (stdlib `ssl` has no exporter). The report's end-to-end claim was false
under its own design.

## 9.2 Why E2E Is Required

ALERT and CONTROL need confidentiality and integrity **against the broker** (goal G2), and commands need
authenticity against captured devices (G3). Only a session whose secret is shared by **device and utility
alone** gives that. The broker then relays ciphertext it can neither read nor forge. This was verified: a
curious broker sees no alert plaintext, and a forged command is rejected.

## 9.3 Why KEM-MQTT

| Option | Verdict |
|---|---|
| **KEM-MQTT (base paper, Fig. 4), lifted device ↔ utility** | **Chosen:** mutual authentication without signatures (cheaper than signing on the device); forward secrecy through an ephemeral KEM; the project's base paper |
| Signed Diffie-Hellman (SIGMA-style) | The device would sign with ML-DSA: 50–120 KB RAM for signing in reference C on an M0+ [LIT RP2040]; variable latency (p99 952 ms for ML-DSA-65) |
| Second TLS session through the broker (TLS-in-MQTT) | Heavy: certificates, and a record layer inside MQTT payloads |
| OSCORE/EDHOC-style | Not MQTT-native; would need a classical-to-PQ extension |
| Pre-shared keys only | No forward secrecy; key distribution at scale |

## 9.4 Key Establishment

**Known in advance:** the device knows `pk_U` from its signed policy; the utility knows `pk_D` and the
device class from its registry. HKEM = hybrid KEM (§6.2).

**Full handshake (v2.2)**

```
Device D                                                           Utility U   (the broker only relays)
(pk_e, sk_e) ← HKEM.KeyGen()                      ephemeral → forward secrecy
(ss_U, ct_U) ← HKEM.Encaps(pk_U)                  only U can open → authenticates U
K_B ← HKDF(ss_U, "early" ‖ H(pk_e, ct_U, n_D))
CH:  pk_e, ct_U, n_D, AEAD_KB(id_D ‖ class ‖ POLICY_INFO_D ‖ fw_version ‖ device_time)   ──────────▶
                                   ss_U ← Decaps(ct_U); open; check id = topic id; registered & active;
                                   class matches; POLICY_INFO_D = current (device_time informational)
                                   (ss_e, ct_e) ← Encaps(pk_e); (ss_D, ct_D) ← Encaps(pk_D)   → authenticates D
                                   K1 ← HKDF(ss_e ‖ ss_U, H(CH))
                                   K_master ← HKDF-Extract(H(transcript), ss_e ‖ ss_U ‖ ss_D)
      ◀── SH: ct_e, n_U, AEAD_K1(ct_D ‖ POLICY_INFO_U ‖ resume_mode ‖ chain_expiry ‖ utility_time), MAC_U
ss_e ← Decaps(ct_e); open; check POLICY_INFO_U = installed; ss_D ← Decaps(ct_D); K_master; verify MAC_U
set clock from utility_time; persist time_floor if due
DF:  MAC_D ‖ bundle(envelopes…)        ─────────▶  verify MAC_D → session established; THEN process the
                                                     bundled envelopes in order (e.g. queued alerts)
      ◀── NT: AEAD(ticket) ‖ ACKs   or   FIN: MAC(fin key, sid) ‖ ACKs            (PASR, §14)
```

**Resume (v2.2, one round trip to data)**

```
D: RH: blob, n_D, mode, [pk_e′ if PSK_KEM], id, POLICY_INFO, fw_version, device_time,
       binder = MAC(HKDF(psk, "binder"), H(all fields))                                  ──────────▶
U: 9 checks → persist "ticket used" (SQLite, synchronous) → [ (ss_e′, ct_e′) ← HKEM.Encaps(pk_e′) ]
   K_master′ = HKDF-Extract(H(transcript), psk ‖ [ss_e′])
                                    ◀── RS: n_U, [ct_e′], (utility_time ‖ chain_expiry), MAC_U
D: verify MAC_U, set clock → DF: MAC_D ‖ bundle(envelopes…) ──▶ U: verify → session; process bundle
                                    ◀── NT (new ticket, same chain expiry) ‖ ACKs
```

**DF binds its bundle** (DR-044, decided 2026-09-25):

`MAC_D = HMAC(kc_D, "D-finished" ‖ H(th2, MAC_U, H(bundle)))`

The same rule applies to the resume DF, with its own transcript. DF is atomic, so stripping, truncating or
appending envelopes fails the key confirmation.

**Message sequence vs command sequence** (clarified from §9.7 and §13.6):
- Envelope headers carry `msg_seq`, the per-session, per-direction AEAD counter. The nonce and the AAD use it.
- The **command** sequence (`epoch ‖ counter`) is carried inside the AEAD plaintext and covered by σ.

**v2.2 change: "finished carries data" replaces v2.1's "confirm before use" (D17).**

- **Why it is safe.** When the device sends DF, it has already authenticated the utility (MAC_U over the
  transcript, with keys only U could derive). The utility processes bundled envelopes **only after**
  verifying MAC_D in the same message, so no data is ever accepted from an unauthenticated device. This is
  the TLS 1.3 client pattern: application data right after Finished.
- **Why data goes *inside* DF.** MQTT orders messages only within one topic. A separate ALERT publish could
  overtake DF and hit "unknown session".
- **How much DF carries (final remediation).** The NT/FIN answering DF holds one ALERT ACK (69 B) per alert and
  must fit the device's Maximum Packet Size, so DF carries at most `min(64, (max_packet − 420) ÷ 69)` of the
  oldest outbox entries: **53 for C2 (4 KiB)**, where 53 alerts give a 4,008 B reply. The largest possible C2 DF
  is 6,109 B, sent upstream (the device's limit governs what it receives). The rest of the outbox is sent as live
  ALERTs right after NT/FIN, each ACKed on its own; one whose ACK is lost stays in the outbox and rides in the next
  DF, where the utility flags it as a duplicate by its alert ID. Tested with a full C2 outbox and lost ACKs
  [DOCKER].
- **Why it is reliable.** Every envelope stays in the device's outbox until its end-to-end ACK arrives. If
  DF, NT or the ACKs are lost, the device resends the **identical** DF bytes. The utility's duplicate cache
  answers identically. Envelopes are deduplicated by sequence number and alert ID.
- **Measured effect** [SIM T6]: time to the first protected message on NB-IoT-good falls from 8.25 s to
  6.02 s (−27%) when combined with a persistent MQTT session (§10.4).
- **Status:** implemented in `pqgrid` and tested [DOCKER, SIM]; a session is installed only if its POLICY_INFO is
  still the current policy when DF arrives (§12, remediation M1). Not validated on MCU hardware [HW].

**Measured sizes** [DOCKER, v2.2 code] (pinned by tests; meter-0001/smart_meter for PSK, der-0001/der_ctrl for PSK+KEM; sizes
depend slightly on the lengths of the device ID and class name). The v2.1 bench figures are kept in brackets:

| Exchange | Bytes (CH/RH + SH/RS + DF + NT = total) |
|---|---|
| Full handshake | 2,493 + 2,411 + 46 + 271 = **5,221 B** (v2.1: 5,212 B) |
| PSK resume | 338 + 106 + 46 + 271 = **761 B** (v2.1: 755 B) |
| PSK+KEM resume | 1,555 + 1,226 + 46 + 270 = **3,097 B** (v2.1: 3,103 B) |
| DF with one bundled ALERT | 193 B (DF alone 46 B) |

The differences come from v2.2 fields: the 16-bit ticket key id, the DF bundle field, the ACK field in NT and a flat
RS layout (IMPLEMENTATION-ROADMAP §8.6).

**Laptop compute** [DOCKER, v2.1 bench; not re-measured on the v2.2 code]:

| Exchange | Device | Utility |
|---|---|---|
| Full handshake | 0.278 ms | 0.229 ms |
| PSK resume | 0.021 ms | 0.030 ms |
| PSK+KEM resume | 0.144 ms | 0.103 ms |

For device-class cycles see §22.1.

## 9.5 Key Separation

- **One master secret per session** (`K_master`).
- **Every use has its own HKDF label:**
  - traffic keys: `key|ALERT|up`, `key|CONTROL|down`, `key|ACK|up`, `key|ACK|down`;
  - confirmation keys: `kc_U`, `kc_D`;
  - session identifier: `sid`;
  - pre-handshake keys: `early` (K_B), `k1`;
  - resumption: `res|ticket_id` (psk), `binder`;
  - `new-ticket` and `fin`.
- **Separate keys per tier and direction**, so nonce counters never collide across uses.
- **Signature keys are separate from KEM keys** (command key ≠ E2E key); the ticket-sealing key (STEK) is
  utility-only.

## 9.6 Replay Protection

| Layer | Mechanism | Tested |
|---|---|---|
| Handshake | Fresh nonces n_D, n_U; transcript-bound MACs; one half-open state per device, forgotten after PENDING_TTL | A3, replayed old CH (EDGE), handshake flood |
| Duplicates | Identical reply within DUP_WINDOW for identical CH/DF/RH bytes (QoS 1 reality) | EDGE duplicates |
| Tickets | Single use, consumed after the binder check, persisted **before** RS (§14.5) | P1, P2, consumed after restart |
| Envelopes | Per-direction sequence numbers; **two-phase check**: validate before AEAD, accept after, so a forged envelope never burns a valid number | A8 |
| Commands | epoch ‖ counter sequence; intent log (§13.6) | A9 (+ v2.2 tests) |
| Broadcast | Per-zone sequence + expiry + signature | A11 |
| Artifacts | Monotonic committed version per artifact type in protected storage | F4, F5, F6 |
| Hop | TLS record protection; replayed bytes on a new connection deliver nothing | N1 (16,043 captured bytes replayed → 0 delivered) |

## 9.7 Counter Management

- **Message sequence numbers** (ALERT up, CONTROL down, ACK) are per session, per direction, in **RAM only**.
  Nonce = `direction(1) ‖ 000 ‖ seq(8)`.
- **Session keys and counters live and die together.** A session key is **never** written to flash. After a
  reboot the device resumes and gets new keys, so an old key can never come back with a reset counter
  (nonce reuse).
- **The command sequence is different:** it is a utility-wide, per-device value that survives sessions and
  restarts (§13.6). It lives in the signed command body, not in the nonce.
- **Overflow:** 64-bit counters cannot realistically wrap. The chain-age cap (≤ 7 days) forces fresh keys
  regardless.
- **Chain end on live sessions (remediation M2).** A chain is one full handshake plus the resumptions after it
  (glossary); SH/RS carry `chain_expiry`. A **live** session, full or resumed, ends at `chain_expiry`: from that
  second (utility clock) the utility refuses its ALERTs (with the DR-041 resync hint), status ACKs and new
  CONTROL, removes it, and refuses a DF whose chain ended after RS; the device drops the session and its
  same-chain ticket. Only a full handshake remains, and it starts a **new** chain: a fresh handshake is never
  limited by an old chain. Device time can only end a session early (a full handshake), never block one (§8.8).
  Tested at the boundary (`chain_expiry − 1` accepted, `chain_expiry` refused) [SIM].

## 9.8 Crash Recovery

| Crash / event | Device | Utility | Result |
|---|---|---|---|
| Device reboot (RAM lost) | PASR resume from the flash ticket; outbox resent in DF | Resume | Session back; alerts delivered once (dedup by alert ID) |
| Reboot between RS and NT | No ticket (single-use), so a full handshake next time | — | Graceful |
| Reboot after RH was processed | Resend the **stored identical RH** if it survived; otherwise full handshake | "ticket already used" for a *rebuilt* RH [DOCKER S5] | Graceful; costs one full handshake |
| Utility restart | Next envelope gets a resync hint, then a resume | Sessions lost; STEK, used tickets, command sequences and queue **persisted**, and the rollout state (active and scheduled policy, published artifacts, U-4) [SIM, DOCKER] | Recovers; unacknowledged alerts resent; unacknowledged commands redelivered; a rollout continues under the policy it activated |
| Utility crash mid-write | — | SQLite WAL: a transaction commits entirely or not at all | No torn state (v2.1's JSON files failed here [DOCKER S3]) |
| Crash between command receipt and actuation | Intent log: PENDING without APPLIED → **INTERRUPTED** reported | Re-issues (as a new command) or cancels | No silent loss, no false "OK" (§13.7) |
| Broker restart | Full TLS; persistent MQTT sessions survive with `persistence true` | — | Retained artifacts survive (verified N5) |

---

# 10. MQTT / Broker Security

## 10.1 Topic ACL

| Topic | Tier | Publisher | Subscriber |
|---|---|---|---|
| `grid/{class}/{id}/telemetry` | TELEMETRY | Device | Utility |
| `grid/{class}/{id}/alert` | ALERT | Device | Utility |
| `grid/{class}/{id}/control` | CONTROL (CMD, GRANT, SETPOINT, ZONEKEY) | Utility | Device |
| `grid/dr/{zone}/{group}/event` | CONTROL broadcast, one topic per crypto group (`aes256gcm`, `chacha20poly1305`; §11, DR-047) | Utility | Zone members of that group |
| `pqgrid/hs/{id}/up` · `/down` | Handshake (self-protected) | Device · Utility | Utility · Device |
| `pqgrid/fota/{class}/{type}/{version}/manifest/{part}` · `/chunk/{i}` | Signed artifact (retained) | Utility (relaying the station) | Devices of that class |
| `grid/{class}/{id}/status` | Last Will, informational | Broker (on the device's behalf) | Utility |
| `pqgrid/fota/{class}/request/{id}` | Republish request (v2.2; rate-limited by the utility) | Device | Utility |

**Rules**
- The ACL is **compiled from the signed policy and the registry**. The compiler verifies the policy
  signature, writes one user block per device, and sends SIGHUP (verified: reload without a restart).
- A device may use only topics containing **its own ID**, and never publish on FOTA or policy topics.
- Device IDs must match `^[a-z0-9][a-z0-9-]{0,31}$`. They become topic levels and ACL names, so `+`, `#` and
  `/` would otherwise inject rules (tested).
- **Tests must check delivery, not SUBACK:** Mosquitto answers "Granted" to forbidden subscriptions but never
  delivers (verified).

## 10.2 Maximum Packet Size

| Limit | Value | Why |
|---|---|---|
| Broker `max_packet_size` | 300,000 B | Memory protection. A 400 KB publish disconnects its sender; 256 KB is delivered [DOCKER N6] |
| Device-declared MQTT 5 Maximum Packet Size | Per class (e.g. 4,096 B for C2) | The device's receive buffer |
| **Consequence** | The broker **silently discards** anything larger than the device's limit ([MQTT-3.1.2-25]); the device stays connected and never learns of it [DOCKER T1: 16,405 B manifest never delivered at limits 8,192 and 16,384; delivered at ≥ 16,445] | — |
| **v2.2 rule** | Every artifact, **including the manifest**, travels in parts no larger than the class `max_packet` minus headers. The device reports its maximum in the registry. The utility refuses to publish anything larger to that class. The policy validator checks that `fota_chunk_size` plus proof and header fit `max_packet` | — |

## 10.3 Persistence

- `persistence true` is **mandatory**. Without it, retained firmware and policy artifacts vanish on a broker
  restart (verified N5).
- Retained artifacts are cleaned up only after a **retention window** (e.g. 30 days), so slow or offline
  devices can finish. After it, missing artifacts are republished by the E-4 rule (§15.8).
- Persistent MQTT sessions (§10.4) are stored in the same database.

## 10.4 MQTT Sessions

- **v2.2:** devices connect with `clean_start = false` and a Session Expiry Interval set per class.
  - The broker keeps the subscriptions, so **no SUBSCRIBE round trip on each wake**.
  - The broker also **queues QoS 1 CONTROL messages** for sleeping devices, within its queue limits.
- **Queue overflow** is harmless to correctness: E2E command redelivery (§13) covers dropped messages.
- **One live connection per identity:** a second connection with the same identity kicks off the first
  ("already connected, closing old connection", verified N4). The utility alarms on repeated takeovers
  (clones).
- **Last Will** `status = offline` is informational only.

## 10.5 Reconnection

| Rule | Value | Why |
|---|---|---|
| Strategy per class (`reconnect` in the policy) | **BATCH** (wake every N hours, send accumulated readings) or **PERSISTENT** (stay connected where the radio allows, e.g. LTE-M/eDRX) | For a meter waking every 15 min, handshakes are 97–98% of its bytes (0.44–0.62 MB/day); batching 4×/day cuts that to ~0.03 MB/day [ANALYTICAL] |
| TLS | Resume when the hop ticket is still valid (7,200 s [DOCKER T2]); otherwise full | A resumed hop is 4,438 B vs 6,262 B [DOCKER T5]; wake intervals over 2 h always pay the full handshake |
| E2E | 1-RTT resume (§9.4) within the ticket and chain limits | — |
| **Back-off** | Randomised exponential back-off with full jitter on **every** reconnect: `delay = random(0, min(cap, base × 2^attempt))`, with base and cap per class. `attempt` counts consecutive failures and is kept by the device main loop **across ticks** (the loop never sleeps; it tries again when the delay has passed); a CONNACK resets it to 0. A failed E2E establishment backs off the same way. Tested in the production loop against a stopped broker: windows 2, 4, 8 … 256, 300 s, then 2 s again after a success [DOCKER] | Outage restoration: thousands of devices reconnect at once. v2.1 had jitter only for policy activation |
| Pipelining | The client may send its first PUBLISH/SUBSCRIBE right after CONNECT, without waiting for CONNACK (MQTT allows this) | Saves a round trip on telemetry-only wakes |
| Keep-alive | Per class, shorter than the operator's NAT idle timeout **[HW: operator data]** | A PSM device cannot keep TCP across sleep |
| Main loops (remediation M9) | Device `run()`: flash scrub and intent reclamation; FOTA policy activation at `activate_at` then a re-handshake after `random(0, backoff_cap)`; staged firmware trial boot, commit, then a full handshake (tickets are bound to `fw_version`); cumulative SETPOINT ACK (§13.5); reconnect with the back-off above; (re)establishment whenever there is no confirmed session; a republish request when a verified download stalls (§15.8); a zone sync when a DR event cannot be opened (§11). Utility `run()`: scheduled policy activation (old sessions closed, zone keys rotated, ACL recompiled), weekly zone-key rotation, artifact clean-up, removal of ended chains and expired half-open handshakes | Every behaviour above has a production caller; tested by running both loops over the broker [DOCKER] |

## 10.6 Duplicate Handling

- **MQTT QoS 1 is "at least once", so duplicates are normal.**
- **Every handshake handler is idempotent.** Identical CH, DF or RH bytes within **DUP_WINDOW** get the
  identical stored reply (v2.1 bugs fixed: duplicate CH broke the handshake; duplicate DF crashed the
  utility; duplicate RH gave "ticket already used").
- **v2.2:** DUP_WINDOW and PENDING_TTL are **per class**, at least 2× the worst handshake time on that link.
  At 4 s RTT and 2 kbit/s the E2E exchange alone takes ~30 s [ANALYTICAL], so a 60 s TTL has no margin.
- **Alerts** carry `alert_id(16)`; the utility recognises resends.
- **Commands** are recognised by sequence (DUP / SUPERSEDED, §13.6).

## 10.7 QoS

| Traffic | QoS | Why |
|---|---|---|
| Handshake, ALERT, CONTROL, artifacts | 1 | Delivery matters; duplicates are handled at the E2E layer |
| TELEMETRY | 1, or 0 per class | QoS 0 saves the PUBACK (29 B less on the wire [DOCKER T5]) where occasional loss is acceptable |
| QoS 2 | Not used | 2 extra round trips per message, and it cannot give end-to-end exactly-once through a broker anyway. E2E idempotency does the job |

**Topic aliases** (MQTT 5) cut a 64 B QoS 0 publish from 128 to 94 B on the wire [DOCKER T5]. Recommended
for high-rate TELEMETRY.

---

# 11. Security Tiers

| Tier | Traffic | Protection | Who can read | Who can forge | Per-message cost (64 B payload) |
|---|---|---|---|---|---|
| **TELEMETRY** | Periodic readings | Hybrid TLS hop only | Broker, utility | Broker | +0 B at E2E; 64–93 B MQTT/TLS overhead [DOCKER T5] |
| **ALERT** | Anomaly notifications, device → utility | + E2E AEAD (per-session keys, sequence numbers), end-to-end ACK, flash outbox | Utility only | Only the device | +73 B (137 B envelope) [DOCKER] |
| **CONTROL** | Discrete commands, GRANTs, SETPOINTs, zone keys (utility → device); DR events (broadcast) | + E2E AEAD + ML-DSA-65 on commands, GRANTs and DR events | Target device (or zone members) | Nobody without the command key (SETPOINTs: only within a signed GRANT, by the live session) | CMD 3,466 B; SETPOINT 97 B; ZONEKEY 138 B; DR event 3,488 B for a 64-byte event (hand-derived and measured) [DOCKER, v2.2 code] |

**Firmware and policy artifacts** are public but signed (SLH-DSA-128s). Integrity and authenticity are what
matter for them.

## Telemetry

**Topics:** `grid/{class}/{id}/telemetry`.
**Protection:** the hybrid TLS hop only.
**Why no E2E:** the utility operates the broker and bills from these readings, so E2E would protect them from
their own operator at a per-message cost. Occupancy-sensitive data must go on an ALERT topic.
**Transport:** QoS 1, or QoS 0 per class; topic aliases for high-rate streams (−27% bytes per 64 B message
[DOCKER T5]).

## Alert

**Topics:** `grid/{class}/{id}/alert`.

**Envelope:**

`0x02 ‖ sid(8) ‖ seq(8) ‖ AEAD(K_ALERT|up, nonce = 0x01‖000‖seq, pt = alert_id(16) ‖ payload, AAD = H("ALERT", topic, sid, seq))`

**Handling:**
1. The utility checks ownership (the topic's device owns the session) and the tier, opens the envelope, and
   replies `0x05 ‖ sid ‖ seq ‖ MAC(K_ACK|down, sid ‖ seq)`.
2. The device keeps unacknowledged alerts in the bounded **flash outbox**.
3. After any re-establishment, the device resends them **inside DF**, with the same `alert_id`, so the
   utility deduplicates.

## Control

**Topics:** `grid/{class}/{id}/control` (unicast) and `grid/dr/{zone}/{group}/event` (broadcast, one per crypto
group of the logical zone).

**Sub-types:**

| Sub-type | Authorisation | Section |
|---|---|---|
| CMD (discrete) | ML-DSA-65 | §13.1 |
| GRANT | ML-DSA-65, session-bound | §13.4 |
| SETPOINT | AEAD only, within a GRANT | §13.5 |
| ZONEKEY | AEAD only | §4.7 |
| Broadcast DR event | Crypto-group key + ML-DSA-65 over the **logical** event; a logical zone has one crypto group per AEAD, each with its own ZONEKEY (DR-047 as amended); `bseq` = epoch ‖ counter, the same for every group's publication; the highest accepted `bseq` per **logical** zone kept in device flash (DR-048) | §11 below |

**Broadcast format (clarifications 4–6, remediation M4, M5, M7):**

```
enc[0x04, zone, group, u64 key_epoch, u64 bseq, nonce(12),
    AEAD_group(K_group, nonce, enc[event, u64 expires_at, σ], AAD = H("BCAST", zone, group, key_epoch, bseq))]
σ = ML-DSA-65("pqgrid/v2/bcast" ‖ H(zone, bseq, expires_at, event))          no group, no key epoch
```

- One logical event has one σ and one `bseq`; it is sealed once per crypto group that has members.
- A join rotates the joiner's group key; a removal (including revocation) rotates every group of the zone.
- The utility keeps every still-valid event (durably, before publishing). After a member (re)establishes it
  gets its ZONEKEY and then the still-valid events issued while it was a member, re-encrypted under its group's
  **current** key with the same σ and `bseq`, on its own control topic (one topic, so the key arrives first).
  The device's persisted `bseq` drops what it already accepted. Retention is bounded (64 per zone); overflow
  raises an alarm.
- There is **no RAM early-event buffer** (the former E55 behaviour). An event that cannot be opened (e.g. the
  broker's queued copy delivered at CONNACK, before this session's ZONEKEY) is refused and recorded with its
  reason; the re-send above delivers it. Tested over the broker, including rotation while the device is down
  followed by a reboot [DOCKER].
- **Zone sync (E-2, final remediation): nothing relies on MQTT ordering across topics.** A member online during
  a rotation may receive the next event (group topic) before its new ZONEKEY (control topic). Such an event is
  refused and recorded; if the device has a confirmed session it sends a **ZONESYNC** on its alert topic:
  `enc[0x08, sid, u64 seq, u64 key_epoch_seen, zone, HMAC(K_SYNC|up, sid ‖ seq ‖ epoch ‖ zone)]` (83 B for a
  2-character zone; its own HKDF label `key|SYNC|up` and replay guard). At most one is outstanding per zone
  (cleared when a ZONEKEY for the zone arrives, retried after 10 s). The utility authenticates it under the
  device's current session, refuses non-members and answers at most once per 5 s per (device, zone), on the
  device's control topic: the group's **current ZONEKEY first**, then the zone's still-valid events issued while
  it was a member, re-encrypted under that key with the same σ and `bseq`. Expired events are never
  republished; the device's persisted `bseq` drops duplicates; the device buffers nothing. Tested over the
  broker with the key held back so the event overtakes it (two events → one sync, each accepted once, the
  original copy rejected as a replay; an event expired before the answer is not republished) [DOCKER].

Every unicast CONTROL message gets a status ACK:

`0x06 ‖ sid ‖ msg_seq ‖ cmd_seq ‖ status ‖ MAC(K_ACK|up, sid ‖ msg_seq ‖ cmd_seq ‖ status)`

This is DR-045, decided 2026-09-25. It ties each status to the exact command across redeliveries.
SETPOINTs use a cumulative ACK.

## Why three tiers?

The three tiers match three genuinely different security needs:

| Tier | Needs protection from |
|---|---|
| TELEMETRY | The **network** (the utility runs the broker and bills from these readings) |
| ALERT | The **broker** as well |
| CONTROL | The broker, and from **anyone without the utility's authority** (captured devices, session-key holders) |

Each tier adds exactly one protection layer. Fewer tiers would either over-protect readings or
under-protect commands. More tiers would add policy complexity without a new security property.

## Why not one security level?

- **Everything as CONTROL:** a signature on every reading. At 96 readings/day that is ~+318 KB/day (96 × 3,309 B) for a meter
  whose data is 15 KB/day, for no property the meter needs.
- **Everything as TELEMETRY:** the broker could read and forge commands.

The report's gap 1 ("one fixed configuration for every message") is precisely this.

**Honest note (v2.2):** for meters, **reconnection** costs dominate bytes (97–98%), not the tiers (§22.6).
Tiering is still right: it decides *what* is protected. But it is not the main bandwidth lever. Reconnect
strategy is (§10.5).

## Why strongest-policy-wins?

`tier(topic)` = the **strongest** tier among all matching rules.

- It is **monotone**: adding a rule can never weaken a topic that another rule protects.
- It is **order-independent**: no "first match wins" surprises when rules are reordered.
- A misconfigured broad rule (`grid/#` → TELEMETRY) cannot silently downgrade `grid/+/+/control`. It stays
  CONTROL.

Tested: overlapping rules resolve to the strongest.

## What happens when no policy matches?

**CONTROL.** A forgotten topic gets **maximum** protection (fail-safe, rule P4). The cost of a forgotten
topic is bytes, never exposure.

**Receivers enforce the tier from their *own* installed policy.** A plaintext or wrong-tier message on an
ALERT or CONTROL topic is dropped ("unknown session", tested A6). A device refuses to seal an ALERT on a
TELEMETRY topic (A7).

---

# 12. Policy Engine

## Policy Structure

**v2.2 binary encoding** (the same length-prefixed codec as every message, §12 Binary Encoding):

| Field | Type | Notes |
|---|---|---|
| `magic` | "PQPOL2" | Format version |
| `policy_id`, `version`, `activate_at` | str, u64, u64 | POLICY_INFO = policy_id ‖ "\|" ‖ u32(version) |
| `default_tier` | u8 | Must be CONTROL |
| `rules[]` | (pattern, tier) | MQTT wildcards `+` and `#` |
| `classes[]` | per-class record (below) | — |
| `utility_kem_pk` | 1,216 B | Hybrid E2E public key |
| `utility_cmd_pk` | 1,952 B | ML-DSA-65 command key |
| `ca_set` | 1–2 certificates | Current CA, plus the next one during a roll-over (OPS-1) |

**Per-class record**

| Field | Values | Purpose |
|---|---|---|
| `profile` | FULL / CONSTRAINED | §5 |
| `resume` | NONE / PSK / PSK_KEM | PASR mode |
| `ticket_lifetime_s`, `max_chain_age_s` | ≤ 7 days | PASR limits |
| `unicast_control` | bool | Forces PSK_KEM or NONE |
| `cmd_types` | {CMD, GRANT, SETPOINT} | Allowed CONTROL sub-types |
| `max_setpoint_rate` | per minute | Upper bound any GRANT may give |
| `aead` | AES256GCM / CHACHA20POLY1305 | One AEAD at both layers |
| `tls_max_record` | 512 / 1,024 / 2,048 / 4,096 / none | Asked for with max_fragment_length |
| `max_packet` | bytes | The device's MQTT 5 Maximum Packet Size |
| `fota_chunk_size` | bytes | Must fit `max_packet` with proof and headers |
| `reconnect` | BATCH(interval_s) / PERSISTENT | §10.5 |
| `backoff_base_s`, `backoff_cap_s` | seconds | §10.5 |
| `session_expiry_s`, `keepalive_s` | seconds | §10.4 |
| `dup_window_s`, `pending_ttl_s` | seconds | §10.6 |
| `outbox_cap` | bytes | §16 |

## Signed Policy

The policy is an artifact of type **POLICY**, signed by the offline station with SLH-DSA-SHA2-128s (§15). The
exact signed bytes are what gets installed; **nothing is re-serialised** before verification.

**The validator** refuses to install a policy unless all of these hold:

| # | Rule | Status |
|---|---|---|
| 1 | `default_tier = CONTROL` | v2.1 |
| 2 | Every tier name is valid | v2.1 |
| 3 | `unicast_control ⇒ resume ∈ {PSK_KEM, NONE}` | v2.1 invariant, tested A13 |
| 4 | `0 < ticket_lifetime ≤ max_chain_age ≤ 7 days` | v2.1 |
| 5 | `version > installed` | v2.1 |
| 6 | `SETPOINT ∈ cmd_types ⇒ GRANT ∈ cmd_types` | v2.2 |
| 7 | `fota_chunk_size + proof + headers ≤ max_packet` | v2.2 |
| 8 | `tls_max_record` and `aead` are known values | v2.2 |
| 9 | `dup_window_s ≥ 120` and `pending_ttl_s ≥ 60` (class may raise, never lower) | v2.2 |
| 10 | `ca_set` is non-empty | v2.2 |

## Policy Distribution

Through **PQC-FOTA** as artifact type POLICY (§15), with `activate_at`:
- devices install ahead of activation;
- at `activate_at` the utility refuses old-policy sessions and tickets (P5, P10);
- devices re-handshake with a random delay to avoid a reconnection storm (the class back-off, §10.5);
- **activation race (remediation M1):** a handshake that passed SH/RS under the old policy is refused at DF,
  after the key confirmation: no session is installed, the alerts bundled in DF are not opened (they stay in the
  device outbox) and no ticket is issued. The refusal is not answered (G-1); the device retries under the
  current policy. Every old-policy session is closed at activation, and no command, zone key or status is
  accepted under one. Tested with the activation injected between SH and DF, in process and over the broker.

A device offline across several versions installs the newest directly (tested). The broker's ACL compiler
consumes the same signed policy.

## Policy Binding

POLICY_INFO travels **inside** the authenticated handshake: in CH (AEAD under K_B) and in SH (AEAD under K1).
It is **bound into `K_master`** through the transcript.

`K_tier = KDF(ss_e ‖ ss_U ‖ ss_D, H(transcript ∋ policy_id, policy_version), tier)`

Tickets carry POLICY_INFO and must equal the **current** policy (PASR check 6).

## Downgrade Prevention

| Attack | Result | Test |
|---|---|---|
| Broker changes POLICY_INFO in CH | "client hello failed authentication" | A1 |
| Broker changes POLICY_INFO in SH | "server hello failed authentication" | A2 |
| Device on an old policy | "POLICY_INFO mismatch" | A4 |
| Broker re-serves an old signed policy | "rollback" | F6 |
| Resume-mode downgrade (strip the fresh KEM) | "resume mode does not match policy" | P6 |
| Unsafe policy (PSK-only for a unicast-control class) | Validator rejects | A13 |
| Tier stripping (plaintext on an ALERT topic) | Dropped | A6 |

## Binary Encoding

**Every** protocol object uses the length-prefixed codec: each field is a 4-byte big-endian length plus the
bytes. The codec is strict:
- exact field count;
- known message types only;
- no trailing bytes;
- a 1 MiB cap per field, checked before allocation.

In v2.1 the fuzz test found a lenient type check; it is fixed, and 3,300 corrupted messages across 11
handlers were all rejected cleanly (+16,500 over 5 more seeds).

**v2.2 change:** the policy, which the v2.1 reference encodes as canonical JSON with hex keys, now uses the
same codec. That removes a JSON parser from the device and halves the key bytes (hex doubles them). It also
ends the contradiction with v2.1's own D14.

## Policy Updates

| Change | What happens |
|---|---|
| New policy version | All sessions and tickets are invalid after `activate_at`; devices re-handshake under the new policy |
| Utility key rotation | A new policy carries the new public keys. The utility first **prepares** the matching private keys (held durably in its keyring: an HSM in production, the utility database in the prototype), then schedules the policy; a policy whose private keys it does not hold is refused at scheduling and at activation, before anything changes. The utility always operates with the keys its **active** policy names, so the policy and the keys in use can never disagree, also across a crash or restart. Commands and retained DR events queued before a command-key rotation are re-signed under the new key with the same `cmd_seq` / `bseq`. A device still on the old policy is recognised under the retired E2E key only to be refused and sent the current policy (E-4). DR-051 |
| CA roll-over | A new policy carries {current, next} CA; the broker switches later |
| Class profile change | Takes effect at the next connection. The class values that travel in MQTT CONNECT (Maximum Packet Size, Session Expiry, Keep Alive) take effect at the device's next **MQTT** connection, which the device makes itself when a newly installed policy changes them: once, at its §12 re-handshake time and before it re-establishes (the broker enforces what the live connection declared, and silently drops anything larger). The other class values apply at once. DR-052 |

---

# 13. Control Command Security

## 13.1 Discrete Commands

**What counts as discrete:** curtail, trip or close a breaker, set a schedule, change mode, and firmware
activation windows. They are rare (a few per day at IEEE 2030.5-style rates) and each one matters.

**CMD envelope** (utility → device, on `grid/{class}/{id}/control`):

```
0x03 ‖ sid(8) ‖ seq(8) ‖ AEAD(K_CONTROL|down, nonce = 0x02‖000‖msg_seq,
                              pt  = enc["CMD", command, expires_at, idempotent, σ],
                              aad = H("CONTROL", topic, sid, seq))
σ = ML-DSA-65_Ucmd("pqgrid/v2/cmd" ‖ H(device_id, topic, seq, expires_at, idempotent, command))
```

**Size:** 3,466 B for a 64-byte command [DOCKER, v2.2 code]. The earlier estimate of 3,454 B [ANALYTICAL] omitted `cmd_seq`; v2.1
measured 3,442 B without the `idempotent` field.

**σ does not cover `sid`.** A command can therefore be **redelivered in a later session** with the same
`seq` and the same signature, re-encrypted under the new keys. The one exception is a command-key rotation: a command
queued across it is re-signed under the new key with the same `cmd_seq` before it is sent (DR-051).

**Device order of checks** (clarification 3, 2026-09-29; DR-046 as amended):
1. AEAD open;
2. signature verify;
3. APPLIED → DUP;
4. PENDING (an interrupted intent) → INTERRUPTED, or the §13.7 recovery rule;
5. SUPERSEDED (`cmd_seq` ≤ last applied);
6. EXPIRED (authenticated time), **never before supersession**;
7. body size, then intent-log capacity (`REJECTED:malformed`, `REJECTED:capacity`, both explicit);
8. intent PENDING (§13.7), actuation, APPLIED, then the ACK "OK".

`cmd_seq` (the command sequence, §13.6) is carried inside `pt` and covered by σ (see §9.4); with it the CMD
envelope is 3,466 B.

## 13.2 ML-DSA-65

Full trade-offs are in §7.6.

**Why a signature on top of the session AEAD:**

| Property | What it gives |
|---|---|
| (a) | Only the holder of the **command key** can create a command. That excludes the broker, captured devices, and anyone who has only the E2E key or a session key (tested A10; RISK: a stolen E2E key cannot forge commands) |
| (b) | Non-repudiation and an audit trail per command |
| (c) | Broadcast authenticity, where the zone key is shared among members (A11) |

(a) holds **only with separation of duties** (§4.4).

**Costs:**

| | Cost |
|---|---|
| Bytes | +3,309 B per command |
| Device verification | 2.42–5.73 M cycles (38–90 ms @64 MHz) [LIT pqm4] |
| Utility signing | 0.556 ms [DOCKER] |

## 13.3 Why not sign every high-rate setpoint?

Alghawli's "nominal" DER profile, which the report cites as its traffic source (**SIMULATED**, 802.15.4),
has a set-point every 5 s: **17,280 per day** [ANALYTICAL].

| | Per-set-point ML-DSA-65 (v2.1) | GRANT + SETPOINT (v2.2) |
|---|---|---|
| Control bytes/day | 61.1 MB | 3.30 MB |
| All traffic/day (with telemetry) | 63.0 MB | 5.23 MB |
| Airtime @20 kbit/s | **7.0 h/day** | 35 min/day |
| Device verifies/day | 17,280 (652 s CPU @64 MHz) | 24 (hourly GRANTs) |
| Utility signatures (10k DERs) | 172.8 M/day ≈ 27 CPU-hours; or an HSM bottleneck **[HW]** | 240k/day |
| Device flash writes | 17,280/day: one 4 KiB page lasts ~0.4 years [ANALYTICAL] | none per set-point (session-bound, §13.5) |

The bytes and airtime rows were computed from the pre-implementation sizes (SETPOINT 93 B, CMD 3,454 B). With the
measured 97 B and 3,466 B [DOCKER, v2.2 code], GRANT + SETPOINT control traffic rises by about 2% (3.30 → ~3.37 MB/day) and
the per-set-point signature column by under 1%. No conclusion changes.

At IEEE 2030.5-style rates (DERControl events polled every 10–15 min, a few events a day) per-command
signatures cost ~14 kB/day and are **fine**. The design supports both.

## 13.4 Signed GRANT Design

A GRANT is a signed, **session-bound** authorisation for a stream of set-points within **bounds**.

```
GRANT (CONTROL sub-type, same envelope as CMD):
  pt = enc["GRANT", grant_id(8), sid(8), target, min, max, max_rate, not_before, expires_at, σ]
  σ  = ML-DSA-65_Ucmd("pqgrid/v2/grant" ‖ H(device_id, topic, seq, grant_id, sid, target,
                                          min, max, max_rate, not_before, expires_at))
  size: 3,477 B [DOCKER, v2.2 code], target "P_ACTIVE_W" (estimate 3,461 B)
```

| Rule | Why |
|---|---|
| **Bound to `sid`** (σ covers it) | A GRANT is valid only in the session it was issued for. An attacker who opens a **new** session (e.g. with a stolen utility E2E key) cannot obtain a grant for it without the command key |
| **Bounds**: `min ≤ value ≤ max` for one `target` (e.g. active-power set-point) | Limits what any set-point may do, and gives the device **local safety limits**. That partly answers the out-of-scope "compromised utility" |
| `max_rate` ≤ the class `max_setpoint_rate` | Limits actuation frequency |
| `not_before`, `expires_at` (authenticated time) | Short-lived: e.g. 1 h; renewed while needed |
| A newer GRANT for the same target replaces the older one | Simple state |
| Held in **RAM only** | Dies with the session; a reboot needs a new session and a new GRANT |

## 13.5 AEAD-Protected SETPOINT

```
SETPOINT (CONTROL sub-type): pt = enc["SETPOINT", grant_id(8), value, expires_at]  — no signature
  envelope size: 97 B [DOCKER, v2.2 code] (estimate 93 B)
```

**The device applies a SETPOINT only if all of these hold:**
1. AEAD opens under the **current** session;
2. `grant_id` names a live GRANT whose `sid` = the current `sid`;
3. authenticated time is inside [`not_before`, `expires_at`] of both the GRANT and the SETPOINT;
4. `min ≤ value ≤ max`;
5. the rate is ≤ `max_rate`;
6. the sequence is newer than the last applied SETPOINT of that grant (newest wins).

Otherwise it replies **REJECTED** (with a reason) or **SUPERSEDED**.

**Why this is safe:** only the session's two endpoints can produce a valid SETPOINT, and only inside bounds
the command key signed for that exact session.

**What is given up:**
- Per-set-point non-repudiation becomes per-GRANT.
- A party holding the **live session key** (i.e. inside the utility or the device) can move values **only
  within the signed bounds**. That party could do far worse anyway.

**ACKs (E-3, final remediation):** SETPOINTs are absolute values, so they are idempotent and newest wins. The
device sends one **cumulative ACK**: `OK` for the newest applied SETPOINT, which covers every earlier `msg_seq` of
the session. Rules:
- **Interval: 30 s** (a transport default, not a policy field). It is due when ≥ 30 s have passed since the last
  cumulative ACK: 29.999 s is not due, 30.000 s is (inclusive). The first SETPOINT after 30 s without an ACK is
  acknowledged at the next main-loop tick.
- Several SETPOINTs inside one interval produce **one** ACK, for the newest.
- **GRANT end:** when the GRANT of an unacknowledged SETPOINT ends (it expires on authenticated device time, or
  a newer GRANT replaces it for the same target), its **final cumulative ACK** is sent at the next tick without
  waiting for the interval, once; the interval then applies again to the new GRANT.
- A SETPOINT that arrives after its GRANT expired is refused (`REJECTED:time`, rule 3), never applied and never
  covered by a cumulative ACK.
- When the session ends no ACK is possible (its keys are gone); the utility learns the state under the next GRANT.
**No flash write per SETPOINT**: they are session-bound, and after a reboot the stream restarts under a new GRANT.

**Status:** implemented and tested, including the exact 30 s boundary and the final ACK at expiry and on
replacement [SIM], and through the device main loop over the broker [DOCKER]. Not validated on hardware [HW].

## 13.6 Replay / Ordering

**Command sequence = `epoch(32) ‖ counter(32)`**, allocated by the utility per device.

- **epoch** = the utility start time in seconds, strictly increasing:
  `epoch = max(now_s, last_epoch + 1)`, persisted at start.
- **counter** is persisted per device **in the same SQLite transaction** that stores the command in the
  redelivery queue, **before** it is sent (rule P8).

**Why (the audit's S1 bug)** [DOCKER]: in v2.1 the counter lived in RAM. After a restart, new commands reused
low numbers, the device answered DUP, and the utility deleted them: silent loss. The epoch also survives a
**database restore from backup**, which would otherwise roll the counter back.

**Device classification** (state in flash: `last_applied` plus a 64-bit bitmap of applied sequences just
below it):

| Incoming seq | Status | Action |
|---|---|---|
| > last_applied | — | Run checks, intent log, actuate |
| = an applied seq (in the bitmap) | **DUP** | Re-ACK; never re-apply |
| < last_applied, not applied | **SUPERSEDED** | A newer command already won; ACK, do not apply |
| expired | **EXPIRED** | ACK, do not apply |
| bad signature, out of bounds, no grant | **REJECTED** | ACK with reason |
| found PENDING after reboot | **INTERRUPTED** | Report; the utility decides (§13.7) |

**The utility's alarm rule:** if a **fresh** command (never sent before) comes back DUP or SUPERSEDED, the
utility's sequence has regressed. Raise an alarm and re-issue with a new sequence. **Redelivered** commands
(same seq and σ) answered DUP are normal: the ACK was lost earlier.

**Ordering:** the broker may reorder only across topics; within the control topic QoS 1 delivery is ordered.
The sequence plus newest-wins handles redelivery after reconnects (tested: "commands out of order → newest
wins").

## 13.7 Exactly-once Limitations

**Exactly-once actuation across a power loss is impossible** without actuator feedback. The device cannot
know whether the actuator acted before the power died.

The audit showed what v2.1 did [DOCKER S2]:
- it wrote the counter **before** actuation;
- a crash in between **lost the command**;
- if the ACK had already left, the utility **believed it was applied**.

**Intent log (as implemented, remediation H2):**

```
receive valid command (seq)                       (after the §13.1 checks, including capacity)
  → write intent/<seq> = {PENDING, idempotent, expires_at, body ≤ 1,024 B}     flash write 1
  → actuate; read back actuator state if the hardware allows
  → write state = {last_applied, bitmap}                                       flash write 2 (APPLIED durable)
  → delete intent/<seq>                                                         flash write 3
  → send ACK OK            ← "OK" is sent only after APPLIED is durable
on boot:
  delete any intent whose seq is already applied (a crash between writes 2 and 3)
  for each remaining PENDING:
     if idempotent, unexpired and newer than last_applied: re-apply, then APPLIED, OK
     else: mark INTERRUPTED (the body is dropped) and report INTERRUPTED(seq); the utility decides
reclamation: an INTERRUPTED record is deleted once a newer command is applied, or once
             expires_at + session_expiry + dup_window has passed; at most 32 intents, beyond that REJECTED:capacity
```

Three flash writes per discrete command (the earlier two-write figure assumed a record that was never deleted,
which let the log grow until the command path failed). Tested: 300 interrupted maximum-size commands, page-full
compaction with reboots, and a power cut at every third flash operation during compaction [SIM].

**What the project claims:**
- "applied **at most once**", with honest reporting of **INTERRUPTED**;
- **never** "exactly once".

Commands carry an `idempotent` flag: absolute set-points are idempotent; "trip breaker" is not.

**Status:** implemented and tested in simulation [SIM: FlashSim power-loss model]; not validated on real flash
or actuators [HW].

---

# 14. PASR

## 14.1 Problem

After an outage, a reboot or a key expiry, a device would repeat the full E2E handshake:
- 5,221 B [DOCKER, v2.2 code] (v2.1: 5,212 B);
- ~5.8 M device cycles [ANALYTICAL];
- 2 round trips.

After a feeder-wide outage, **thousands of devices** do this at once. Existing PQ-MQTT work repeats the full
handshake on every reconnection (report gap 2). Standard TLS 1.3 resumption exists on the hop, but it:
- is not policy-aware;
- is not bound to firmware;
- does not check revocation;
- protects only the hop, not the E2E session.

## 14.2 Original Design

The report (§3.5) specified:
- a **broker-held** ticket key;
- `K = KDF(K_ticket, nonces)` (eq. 3.8), with no forward-secrecy option;
- "control-tier topics excluded from resumption".

That last rule cannot be implemented, because one MQTT connection carries all tiers. v2 moved the ticket
issuer to the **utility**, because a ticket resumes a session and must be issued by whoever holds that
session's secret. v2 also added a binder, single use, modes and invalidation.

## 14.3 Why Stateless Tickets

| Option | Verdict |
|---|---|
| **Stateless sealed tickets (STEK)** | **Chosen.** The utility stores only the used-ticket set, with no per-device session state. Scales, and survives utility restarts when the STEK is persisted |
| Stateful session cache at the utility | Memory grows with the fleet; lost on restart unless persisted anyway |
| Device-side resumption secret only (no ticket) | The utility would need the per-device psk: stateful again |
| TLS 1.3 resumption on the hop only | Does not cover the E2E session; not policy- or firmware-bound (still used on the hop as standard behaviour) |

**Ticket (sealed; about 250 B):**

`0x01 ‖ kid ‖ nonce(12) ‖ ChaCha20-Poly1305(STEK[kid], pt, AAD = 0x01 ‖ kid)`

where the plaintext `pt` is:

`ticket_id(16) ‖ device_id ‖ class ‖ POLICY_INFO ‖ fw_version ‖ resume_mode ‖ issued_at ‖ expires_at ‖ chain_expires_at ‖ psk(32)`

**v2.2:** `kid` is 16 bits (v2.1: 8 bits, with wrap-around after 256 rotations).

## 14.4 STEK

| Rule | Value |
|---|---|
| Rotation | Every 24 h |
| Retirement | **Automatic**, once every ticket it sealed has expired: rotation time + maximum ticket lifetime (≤ 7 days) |
| Storage | **HSM in production.** In the prototype: SQLite (§16), written before any ticket is sealed under it |
| Loss | A lost STEK invalidates every ticket in the fleet at once, so all devices do full handshakes together (tested counterfactual) |
| Theft | A stolen STEK lets an attacker mint tickets (RISK test, shown succeeding on purpose). Hence the HSM. Revocation is still checked on every resume |

## 14.5 Single-use Enforcement

**The 9 checks, in order.** Any failure means a full handshake, never a weaker session:
1. `kid` is live;
2. the ticket decrypts and authenticates;
3. device ID in the ticket = the topic's = the claimed one;
4. registered and **not revoked**;
5. the ticket and its chain are unexpired (utility clock);
6. POLICY_INFO = the **current** policy;
7. firmware version matches;
8. mode = the requested mode = the current policy's mode for the class (and PSK_KEM carries a fresh key);
9. the **binder** is valid (proves possession of the psk); **then** the ticket is unused, and it is
   consumed.

**Consumption rules**

| Rule | Why | Evidence |
|---|---|---|
| Consume **after** the binder | A stolen blob cannot burn the genuine device's ticket | P2 |
| **Persist "used", then respond** (v2.2) | A crash after RS but before persisting would otherwise forget the consumption and reopen replay | **S3/S4 [DOCKER]** |
| Duplicate RH within DUP_WINDOW gets the **identical** RS | QoS 1 duplicates | v2.1 fix |
| Device keeps and **resends the identical RH** (+ its ephemeral key for PSK_KEM) until RS or a timeout | A *rebuilt* RH after the first was processed gets "ticket already used", then a full handshake | **S5 [DOCKER]** |
| Used records expire with the ticket | Bounded storage | — |

## 14.6 Ticket Binding

| A ticket is bound to | Invalidated when |
|---|---|
| Device (checks 3, 4) | Revocation |
| POLICY_INFO (check 6) | A new policy is activated |
| Firmware version (check 7) | New firmware is committed |
| Resume mode (check 8) | The policy mode changes |
| STEK kid (check 1) | The STEK retires |
| Expiry and chain expiry (check 5) | Ticket lifetime; chain age ≤ 7 days forces a full handshake |

**Modes and the invariant:**
- PSK is cheapest, with no forward secrecy.
- PSK_KEM adds a fresh hybrid KEM, so it has forward secrecy.
- **Classes that receive unicast control resume only with PSK_KEM, or not at all** (validator; A13).

There is **no 0-RTT data**: a resume carries data only after both key confirmations (v2.2: data rides
*inside* DF, after MAC_D is verified), so resumption can never replay a command.

## 14.7 Persistence

**Utility (SQLite WAL, `synchronous = FULL`):**
- `used_tickets(ticket_id PK, expires_at)`, pruned by expiry;
- `stek(kid PK, key, created_at, retire_at)`, or an HSM.

**Device (flash record store, §16):** the ticket, its psk, the expiry and the mode. Written on NT. It is
single-use, so it is cleared from RAM on RS and replaced on NT.

**v2.1 → v2.2** [DOCKER S3, S4]:
- v2.1 wrote JSON files with `open(path, "w")` (truncate, then write, with no fsync), and rewrote the
  **whole used set on every resume**.
- A torn write stopped the utility restarting.
- At 100,000 outstanding tickets each rewrite was 4.8 MB and 41.9 ms (in the container), i.e. ~480 GB/day
  if each device resumes daily.
- SQLite with an index keyed by ticket makes it **one small insert per resume**.

## 14.8 Reconnection Measurements

**Compute and bytes** (laptop container). Compute: [DOCKER, v2.1 bench]. Bytes: [DOCKER, v2.2 code]:

| Mode | Device | Utility | Bytes | vs full |
|---|---|---|---|---|
| Full handshake | 0.278 ms | 0.229 ms | 5,221 | — |
| PSK | 0.021 ms | 0.030 ms | 761 | −92% / −87% / −85% |
| PSK+KEM | 0.144 ms | 0.103 ms | 3,097 | −47% / −54% / −41% |

**Time to the first protected message over modelled links** [SIM T6]. One-way delay plus serialisation plus
the TCP handshake RTT; the proxy terminates TCP; no radio scheduling or loss; parameters **assumed**. n = 3,
and n = 1 for the poor link.

| Scenario | LTE-M-like (0.2 s, 200 kbit/s) | NB-IoT-good (1 s, 20 kbit/s) | NB-IoT-poor (4 s, 2 kbit/s) | Bytes |
|---|---|---|---|---|
| A · cold: full TLS + SUBSCRIBE + full E2E | 1.72 s | 10.77 s | 71.2 s | 11,870 |
| B · reboot (v2.1): full TLS + SUBSCRIBE + PSK | 1.53 s | 8.98 s | 53.4 s | 7,414 |
| C · wake (v2.1): TLS resumed + SUBSCRIBE + PSK | 1.46 s | 8.25 s | 46.1 s | 5,590 |
| C′ · wake (v2.1): TLS resumed + SUBSCRIBE + PSK+KEM | 1.55 s | 9.18 s | 55.5 s | 7,933 |
| **D · v2.2**: TLS resumed + persistent session + 1-RTT PSK | **1.02 s** | **6.02 s** | **35.9 s** | 5,866 (includes the first alert and its ACK) |
| E · floor: telemetry-only wake | 1.00 s | 5.84 s | 34.2 s | 4,579 |

**Reading:**
- PASR cuts bytes 37–53% and device public-key work to zero (PSK).
- On high-latency links, **time** falls only 17–23% (B/C vs A), because round trips dominate: both full and
  resumed E2E take 2 of them.
- v2.2's D removes two round trips: −27% (NB-IoT-good) and −22% (poor) against C, and −44% / −50% against a
  cold start.
- D lands within 3–5% of the floor E.

## 14.9 Why the Original "60–70%" Claim Was Removed

The report (§4.2.3) *expected* "reconnection latency reduced by 60–70%". The evidence says:

1. On the laptop, **compute** fell 92% and **bytes** 85% (PSK). Those are real, but they are not latency.
2. On simulated NB-IoT, **latency** fell only **17–23%** from PASR alone, because latency is dominated by
   round trips, which PASR does not remove.
3. With v2.2's persistent session and 1-RTT resume, latency fell **44–50%** against a cold start. That is
   still below 60–70%, and it depends on assumed link parameters.

So no single latency percentage is claimed. The project reports **measured** E2/E4/T6 values, each with its
environment label and link parameters (§26).

## 14.10 Persistent MQTT + 1-RTT Resume

The three v2.2 mechanisms, measured together as scenario D:
1. **Persistent MQTT session** (`clean_start = false`, Session Expiry per class): no SUBSCRIBE per wake; the
   broker queues commands for sleeping devices (§10.4).
2. **1-RTT resume:** DF carries the first envelopes (§9.4).
3. **Pipelining** CONNECT and the first publish (telemetry-only wakes).

**Status:** (1) and (3) are standard MQTT behaviour, used in T6. (2) was simulated **size-equivalently** in T6
(it measures link time, not the protocol code). The reference implementation of (2) is **not yet
validated**.

## 14.11 Trade-offs

| Choice | Gain | Cost / risk |
|---|---|---|
| PSK mode | −92% compute, −85% bytes | No forward secrecy within a chain; capped at 7 days; forbidden for unicast-control classes |
| PSK_KEM mode | Forward secrecy per resume | 3,097 B and 2.6 M device cycles |
| Stateless tickets | Scales; survives restarts | STEK theft → ticket minting (HSM) |
| Single use | Clone detection ("already used" alarm) | A rebuilt RH after a crash costs a full handshake |
| Persist before respond | No replay after a crash | ~ms fsync per resume at the utility |
| Persistent MQTT sessions | −1 RTT per wake; command queuing | Broker per-device state; queue limits |
| Finished carries data | −1 RTT | A lost DF means resent alerts (the outbox covers it) |

---

# 15. Firmware / FOTA

## 15.1 Firmware Threat Model

| Attacker | Goal | Stopped by |
|---|---|---|
| Network / broker | Install modified or foreign firmware | SLH-DSA signature from an offline anchor (F2, F3); Merkle-authenticated chunks (F1) |
| Network / broker | Roll back to an old, vulnerable, validly signed version | Monotonic committed version in protected storage (F4, F5; the policy too: F6) |
| Network / broker | Cross-class firmware | Class field in the signed manifest (F7) |
| Broker | Withhold updates | Not preventable (DoS). The stretch goal, a freshness heartbeat signed with ML-DSA-65, lets devices detect it |
| Attacker with access to external flash | Modify a staged image after the download checks | **v2.2:** the bootloader re-verifies the payload hash before booting or swapping from an external slot; a policy is re-checked against its signed SHA-256 whenever it is read back from flash (activation, boot) [SIM] |
| Thief of a station key | Sign malicious firmware | **v2.2:** anchor revocation by the other anchor (§15.14) |
| A future quantum computer or lattice break | Forge signatures | Hash-based SLH-DSA (hash assumptions only) |

## 15.2 Manifest

**v2.2 manifest fields** (binary codec):

| Field | Purpose |
|---|---|
| `"PQFW2"` | Format version |
| `type` | FIRMWARE / POLICY / KEYREVOKE |
| `device_class` | Target class |
| `version` (u64) | Anti-rollback |
| `payload_length`, `SHA-256(payload)` | Final check |
| `chunk_size`, `chunk_count`, `merkle_root` | Per-chunk verification |
| `activate_at`, `issued_at` | Activation timing |
| `signer_anchor_id` (u8) | Which anchor signed it (§15.13) |

**Signed form:** `enc[manifest, SLH-DSA-SHA2-128s signature]`, **8,031 B** [DOCKER, v2.2 code] (estimate 8,042 B; v2.1 measured 16,405 B
with 192s].

**Delivery:** in **parts** no larger than the class `max_packet` minus headers:
`part = enc["MP", type, version, index, total, bytes]`, retained. At `max_packet = 4,096` that is 3 parts
[DOCKER, v2.2 code]; at 8,192 it is 1. The device reassembles the parts into a **flash staging area** and verifies from flash, so the
signature never has to fit in RAM.

## 15.3 Firmware Signature

- An offline station signs every FIRMWARE, POLICY and KEYREVOKE manifest with **SLH-DSA-SHA2-128s**.
- Signing takes 168 ms per artifact on the laptop [DOCKER]: offline, once per release.
- The device verifies against `anchor[signer_anchor_id]` if that anchor is not revoked.
- Laptop verification takes 0.164 ms [DOCKER]; Cortex-M4 about 7.47 M cycles (117 ms @64 MHz) [LIT pqm4].

## 15.4 SLH-DSA-128s

**Chosen** (full trade-offs in §7.7):
- **Hash-only security** for a key that is burned into bootloaders;
- **stateless**, so there is no state to mismanage;
- **SHA-256 only**, often in hardware;
- the smallest stateless hash-based signature: 7,856 B;
- the signed manifest fits an 8 KiB packet.

**Category 1 is the conscious trade-off.** It is post-quantum and rests on hash functions alone.

## 15.5 Why not SLH-DSA-192s

192s was the v2.1 choice (D6). The audit's evidence meets the change trigger recorded in Rationale B10
("change it if manifest bandwidth matters more than keeping one security category; then 128s"):

| Evidence | 192s | 128s |
|---|---|---|
| Signed manifest | 16,405 B: **silently dropped** for devices with a packet limit ≤ 16,384 [DOCKER T1] | 8,031 B |
| Verify cycles (M4) [LIT pqm4] | 13.5 M | 7.47 M |
| Verify stack | 3.7 KB | 2.0 KB |
| Hash functions in the bootloader | SHA-256 **and SHA-512** (FIPS 205 §11.2) | SHA-256 only (e.g. the SAM4CM hash engine: SHA-1/224/256) |
| Category | 3 | 1 |

**What it costs to switch:** Category 3 → 1, and giving up v2.1's "all Category 3" uniformity. That was a
consistency preference, not a threat requirement.

## 15.6 Why not ML-DSA

ML-DSA-65 (the report's original) rests on a young lattice assumption, for a key that can never be replaced.
One cryptanalytic advance would be permanent for the fleet. Its speed advantage does not matter for a
once-a-year verification. ML-DSA stays where keys *can* rotate: commands (§7.6).

## 15.7 Merkle Tree

The tree is RFC 6962 (leaf `SHA-256(0x00 ‖ data)`, node `SHA-256(0x01 ‖ L ‖ R)`), verified per RFC 9162
§2.1.3.2.

| 1 MiB image, 4 KiB chunks [DOCKER] | Flat hash list (report) | Merkle (design) |
|---|---|---|
| Hash data in the signed manifest | 8,192 B, growing with the image | 32 B (the root), always |
| Hash data held while installing | 8,192 B | 32 B + one 256 B proof |
| Extra bytes per chunk | 0 | 256 B |
| Total integrity bytes on the wire | 8 KB | 64 KB (6% of the image) |

**Merkle costs more bandwidth and saves device memory**, and the saving grows with image size. The knob is
chunk size: at 64 KiB chunks a 1 MiB image needs 128 B of proof per chunk.

**Measured:** 1 MiB installed as 256 shuffled chunks in 3 ms on the laptop.

## 15.8 Chunking

| Rule | Why |
|---|---|
| `chunk = enc[type, version, index, data, merkle_path]`, retained at `…/chunk/{i}` | Any order; duplicates harmless; chunks from another artifact or version refused (tested) |
| Chunk size per class (policy), with chunk + proof + headers ≤ `max_packet` | §10.2 |
| Received-chunk bitmap in flash (`chunk_count` / 8 bytes) | Resume after a power loss (tested) |
| Device limit = **its own slot size** (v2.1's generic 64 MiB / 65,536 chunks is only an outer cap) | Refuse before downloading |
| Retention window (e.g. 30 days), then clean up | Slow devices finish |
| **Republish (E-4, final remediation)** | Triggers, none of which uses the time floor: (1) the **device** asks on `pqgrid/fota/{class}/request/{id}` (ACL-scoped to its own ID) when a verified download has gained no chunk for 600 s while connected, at most once per such period; (2) the **utility** republishes its newest POLICY when a device's CH is refused for an older POLICY_INFO; (3) the **utility** republishes its newest FIRMWARE when an established device reports an older `fw_version` and that artifact is no longer retained. Rules for every republish: at most once an hour per device (an offer that republishes nothing costs nothing); only the newest artifact per (class, type); only if still valid now (signer not revoked and in its DR-050 role; a POLICY not older than the active one), so nothing revoked, superseded or stale is resurrected. Expired DR events are never republished (§11). Tested: missing valid artifact, stale policy, revoked signer, superseded version, rate limit, and the three triggers over the broker [SIM, DOCKER] |

## 15.9 Maximum MQTT Packet Size

See §10.2 and the evidence in [DOCKER T1]: a device declaring a limit of 8,192 or 16,384 B never received the
16,405 B manifest. The broker dropped it silently and the device stayed connected. v2.2 guarantees
**every** FOTA message (manifest part or chunk) fits the target class's declared maximum, and the validator
and publisher check it. A device declares the class maximum of the policy it has **installed**, so a POLICY or
KEYREVOKE (which must also reach devices still on an older policy) is sized to the smallest maximum the class has had
under any policy the utility activated; FIRMWARE follows the current policy, and a device re-subscribes to the retained
artifacts after a CONNECT that raised its maximum (DR-052).

## 15.10 A/B Slots

**Minimum flash:**

`bootloader + 2 × max_image + manifest staging + persistent data (+ one scratch sector for swap-based schemes)`

An overwrite-only bootloader cannot revert, so two slots are needed.

| Class | Two in-chip slots? |
|---|---|
| C0/C1 (48–128 KB) | No: the crypto code alone is ~40–45 KB before TLS (§22.3). Behind a gateway |
| C2 (256–512 KB) | Only for small images. Usually slot B lives on **external SPI flash**, which is outside the trust boundary, so the bootloader **re-verifies the payload hash** from the committed/staged manifest before swapping or booting |
| C3 (1–2 MB) and C4 | Yes |

**Procedure:**
1. collect the manifest parts → verify the signature (from flash) → check magic, class and limits →
   `version > committed[type]`;
2. write verified chunks into the inactive slot;
3. check the length and SHA-256: **staged**;
4. by artifact type:
   - **FIRMWARE:** reboot into the new slot; self-test passes → **commit** (the counter moves forward);
     it fails → **revert** (the counter is unchanged, so the same version can be retried);
   - **POLICY:** re-hash, validate (including that it defines the device's own class) → activate at `activate_at` →
     commit; the device keeps the installed policy in flash (§4.1) and boots with it (§15.11);
   - **KEYREVOKE:** §15.14.

## 15.11 Anti-Rollback

- `committed[type]` lives in **protected storage** that a factory reset cannot erase: OTP, a secure element,
  or a protected flash region.
- It moves forward **only after a successful boot**. Moving it before would strand a device whose new image
  fails (it would refuse the old version, and the new one would not work).
- The same protected record holds the installed policy's area, length and SHA-256. A new policy is staged in the
  other of two policy areas (like the firmware slots) and replaces the installed one in the commit's single write;
  the device boots with it, re-checked against that digest. Without it a reboot after a policy update left the
  device on its factory policy, which the utility refuses, while anti-rollback refused the current one: a lock-out
  (found and fixed in the continuous audit, IMPLEMENTATION-ROADMAP §14, C1-8) [SIM, DOCKER].
- Tested: firmware rollback and replay (F4, F5), policy rollback (F6), failed boot → revert with the counter
  unchanged, rollback still blocked.

## 15.12 Power Failure

| When | Result |
|---|---|
| During download | Resume from retained chunks using the bitmap (tested) |
| While writing a chunk | That chunk is re-verified and rewritten; the bitmap is set only after its record is durable |
| During swap | The bootloader's swap must be **power-fail-safe** (swap with scratch or swap-move). Must be tested on hardware **[HW]** |
| While committing | The counter is a single atomic record (CRC + sequence, §16). Either old or new, never torn |
| Watchdog during verification | Verification takes ~117 ms @64 MHz, up to ~0.31 s at 24 MHz (lower bounds). The watchdog budget must exceed the worst per-class time, or verification must yield and kick it **[HW]** |

## 15.13 Firmware Trust Anchors

| Rule | Why |
|---|---|
| ≥ 2 anchors, **A** and **B**: independent SLH-DSA-SHA2-128s key pairs with separate custodians. Both public keys (32 B each) are burned in | v2.1 had one anchor. Losing or leaking its key would leave the fleet un-updatable or permanently forgeable, and that is **far more likely than SLH-DSA being broken** |
| Every manifest names `signer_anchor_id` | Verification selects the key |
| While A is active, **only A** signs releases (firmware, policy); a B-signed release is refused by the device and by the utility/ACL policy verifier. After A is revoked, B is the release anchor (clarification 8, DR-050) | Minimises B's exposure; a stolen A stays recoverable |

## 15.14 Revocation

- **A KEYREVOKE manifest** revokes anchor X. **Only the recovery anchor B may revoke the release anchor A; A
  can never revoke B** (DR-050, decided 2026-09-29). Under the earlier rule, "signed by a different, non-revoked
  anchor", a thief of A (the most exposed key) could revoke B first and leave the fleet unrecoverable.
- **Its version number is a revocation counter** in protected storage, so it cannot be rolled back.
- **The device refuses to revoke its last active anchor.**
- **After revoking A**, B signs every subsequent release and A is refused for everything, permanently. A new
  anchor can be added only in new hardware (bootloader ROM).
- **Roles are re-checked** at firmware boot and policy activation (an artifact staged before a revocation).
- **Trade-off:** a second custodied key, and one more artifact type to test.

**Status:** implemented (`check_signer`) and tested: A releases while active; B release refused while A is
active; B revokes A; A cannot revoke B, itself or anything; B releases after the revocation; power loss during
KEYREVOKE leaves the old or the new state [SIM]; revoked anchor over the broker [DOCKER].

---

# 16. Persistence / Crash Safety

**Rule P8, persist then respond:** any promise (a consumed ticket, an allocated command sequence, an applied
command, a committed version) is **durable before it is communicated**.

## Utility Command Sequence

- `utility_epoch(last_epoch)`, written once at each start: `epoch = max(now_s, last_epoch + 1)`.
- `device_seq(device_id PK, counter)` and `commands(device_id, seq, topic, body, sig, expires_at, status)`
  are updated **in one transaction** before a command is sent.
- The redelivery queue **is** the `commands` table (status PENDING until acknowledged).
- Evidence for the need: **S1** [DOCKER] (sequence reset → silent DUP loss).

## Device Command State

`last_applied` (u64 = epoch ‖ counter), plus a 64-bit bitmap of applied sequences just below it, plus the
intent log.

Updated with log records (below). SETPOINTs are **not** persisted: they are session-bound (§13.5).

## Intent Log

The records are `INTENT{seq, PENDING, idempotent}` and `INTENT{seq, APPLIED}`. The algorithm is in §13.7.

The log is compacted when a page fills: live records are copied to a fresh page, then the old page is
erased. Evidence for the need: **S2** [DOCKER] (counter written before actuation → lost command with a false
OK).

## Used PASR Tickets

`used_tickets(ticket_id PK, expires_at)` in SQLite:
- one insert per resume, **committed before RS is sent**;
- pruned by expiry.

v2.1 rewrote the whole JSON set per resume: 4.8 MB and 41.9 ms per rewrite at 100k tickets [DOCKER S4].

## STEK Persistence

- **Production:** an HSM.
- **Prototype:** an SQLite table `stek(kid, key, created_at, retire_at)`. A new key is committed **before**
  the first ticket is sealed under it. Retirement is automatic.
- v2.1's `json.dump(open(path, "w"))` pattern produced a file that would not load after a torn write
  [DOCKER S3].

## Outbox

| Property | Design |
|---|---|
| Contents | Unacknowledged ALERT plaintexts (topic, payload, alert_id) as flash records |
| Removal | On the end-to-end ACK |
| Bound (v2.2) | `outbox_cap` per class (e.g. 4 KiB), counted in **real flash bytes**: payload + kind + 40 B per entry (record header, alert ID, framing). One alert ≤ 1,024 B payload and ≤ 16 B kind; larger is refused, never truncated |
| When full | Merge repeats of the same alert type; drop the oldest; keep a "dropped N" counter, itself sent as an alert |
| Why | A device offline for days must not fill its flash |

## SQLite WAL

The utility's state lives in SQLite with `journal_mode = WAL` and `synchronous = FULL`.

**What it gives:**
- a transaction commits entirely or not at all (no torn files);
- one indexed insert per event instead of a whole-file rewrite;
- concurrent readers.

**Cost:** an fsync per commit (≈ ms) and one dependency.

High availability with several utility servers (Rationale OPS-7) would replace this with a replicated
database and an HSM; that is out of prototype scope.

## Flash Wear

Device state is written as **log-structured records** `{type, seq, len, payload, CRC32}` across ≥ 2 erase
pages. The latest valid record per key wins; a torn record fails its CRC and is ignored. Superseded records that
hold a secret (the ticket's `psk`) are erased by software within 7 days of device time (DR-049, clarification 7):
checked at boot, after every authenticated time update, by the device main loop and after every ticket write;
a resume does not erase a bank. Nothing is claimed about flash contents while the device is powered off, nor
about physical remanence after an erase. A PSK_KEM ephemeral private key is never written (§9.7).

**Analytical budget:** 10,000 erase cycles (typical embedded NOR flash, **use the actual part's
datasheet**), 4 KiB pages, 16-byte records.

| Writer | Writes/day | One page lasts | Pages for 15 years |
|---|---|---|---|
| Meter: tickets, outbox, counters | ~100 | ~70 years | 1 |
| DER, discrete commands | ~60 | ~117 years | 1 |
| DER with a flash counter per 5-s set-point (**not done in v2.2**) | 17,280 | ~0.4 years | 37 (148 KiB) |
| Time floor | 1 | — | negligible |

**Correction to Rationale OPS-5.** "Reserve counters every 100" is valid on the **utility** side, which can
skip ahead after a restart. On the **device** it would refuse the next 100 commands after a reboot. Devices
use the append log instead.

## Device Storage Capacity (final remediation)

Every record that can legitimately coexist, each at its largest (IDs ≤ 32 B), must fit one bank of the record
store, plus one record in flight while it replaces another. A record never spans pages, so a page can end with up
to (largest record − 1) unusable bytes. Default classes (4 KiB outbox), 4 KiB pages:

| Item | Bytes |
|---|---|
| Outbox (cap) + drop counter | 4,096 + 43 |
| Intents: 31 interrupted + 1 pending body (1,024 B) — at most one body: an older PENDING becomes INTERRUPTED when a new command is accepted (E37) | 2,624 |
| FOTA: FIRMWARE, POLICY, KEYREVOKE, one download or staged record each (≤ 1,024 chunks) | 1,032 |
| Zone `bseq` records (≤ 16 zones per device, refused beyond on both sides) | 896 |
| Resume hello (PSK) · ticket | 473 · 411 |
| Command state · time floor · bank markers | 45 · 24 · 34 |
| **Worst case** (+ largest record, 1,080 B, in flight) | **9,678 + 1,080 = 10,758** |
| One bank of 4 pages holds at least 4 × (4,096 − 1,079) | **12,068** |

**Configured store: 2 banks × 4 pages × 4 KiB = 32 KiB.** The device checks this at start-up and before adopting
a new policy (CapacityError: an impossible configuration is refused, never run); two 8 KiB banks (6,034 B) are
refused. The worst case built from real records (all states at once, 32-character device ID) measured 7,927 B
live, and survived a power cut at every step of compacting it [SIM].

## fsync / atomic rename

Any state kept in plain files follows one pattern:
1. write to a temporary file in the same directory;
2. `fsync(file)`;
3. `rename(tmp, final)`;
4. `fsync(directory)`.

**Never** `open(path, "w")` on the live file. Applies to utility artifact storage, configuration outputs such
as the generated ACL, and any prototype file store.

---

# 17. Constrained-IoT Audit

## 17.1 Audit Methodology

The audit ([BalaMP-Audit.md](BalaMP-Audit.md)) asked a question the 80/80 validation could not answer:
**can the target devices afford v2.1, and does it behave correctly under real device conditions?**

It had five steps:

1. **Evidence gathering.** Re-read the six reference papers for their *actual* hardware, then added the
   literature: pqm4 (Cortex-M4), RP2040 (Cortex-M0+), Tasopoulos (PQ TLS time and measured energy on an M4),
   Lukic (live NB-IoT energy), Düll and Haase (X25519 on MCUs), and the standards (FIPS 203/204/205/206
   status, SP 800-232, SP 800-208, RFC 7228, MQTT 5, RFC 6066/5280, CNSA 2.0).
2. **Code review** of the reference implementation for persistent state, crash windows and ordering.
3. **New Docker experiments:** S1–S5 (state), T1–T7 (transport, TLS, time, PSK).
4. **Analytical budgets** built only from cited inputs (`analysis.py`): cycles, RAM peaks, flash, bytes per
   day, airtime, flash wear.
5. **Classification** of every decision as GREEN / YELLOW / ORANGE / RED, with a proposed change for each
   non-GREEN.

## 17.2 Docker vs Real Hardware

| Docker **can** show | Docker **cannot** show |
|---|---|
| Protocol logic, attack rejection, crash and restart behaviour of the code | Cycle counts, flash wait states, stack peaks on an MCU |
| Broker behaviour (packet limits, TLS tickets, max_fragment_length, clocks via libfaketime) | TLS library footprint on the device |
| Bytes on the wire (TCP payload) | Radio energy, NB-IoT scheduling, repetitions, operator NAT timeouts |
| Relative costs in one environment | Absolute device performance ("the same code ran ~5× slower in a macOS venv": environments are never mixed) |
| Link effects under a **model** (delay + rate) [SIM] | Real link behaviour |

`--cpus` and `--memory` limits only keep resource use tidy. **They never model an MCU.**

## 17.3 Evidence Labels

| Label | Meaning |
|---|---|
| **[DOCKER]** | Measured in the project container (Debian trixie, OpenSSL 3.5.7, Mosquitto 2.0.21, Python 3.13.5, `cryptography` 50.0.1, paho-mqtt 2.1.0) on an Apple-silicon laptop. **Not** a device measurement |
| **[SIM]** | Docker plus a modelled link (one-way delay, serialisation rate, TCP handshake RTT). Not NB-IoT, not an MCU |
| **[LIT]** | From a named paper, standard or datasheet; the source's hardware is always stated (§32) |
| **[ANALYTICAL]** | Calculated from [LIT]/[DOCKER] inputs in `constrained-audit/analysis.py`; lower bounds where stated |
| **[HW]** | Needs real hardware; stated as an open question, never as a number (§29) |

---

# 18. Audit Findings

## RED Findings

### R1 — Clock and certificate validity deadlock on the TLS hop

| Aspect | Content |
|---|---|
| **Observation** | A device whose RTC resets to 1970, or runs years ahead, is refused by TLS. So is a device whose certificate expired while it was offline. The E2E clock repair (B21) never runs |
| **Why it happens** | TLS runs before the E2E handshake, and standard validation checks certificate notBefore/notAfter against the device clock. v2.1's clock test exercised only the E2E layer |
| **Security impact** | Availability of the whole device (no alerts, no commands, no updates). Also an attacker lever: cutting power resets the clock |
| **Resource impact** | Endless reconnect attempts: radio energy, and possibly a truck roll |
| **Evidence** | [DOCKER T4] cases a–g (§8.8) |
| **Decision** | Adopted |
| **Fix** | Device TLS verifies the chain with no time checks; device certificates notAfter 9999; persisted time floor; command expiry only on authenticated time; broker validates device certificates normally (§8.8–§8.9) |
| **Trade-off** | A compromised CA key is not bounded by expiry on devices. Mitigated by an offline CA, pinning, and roll-over through PQ-signed policy |
| **Test required** | T4 re-run expecting "CONNECTED" for b, e, f′ (long-lived certificate); "1970 device completes TLS + E2E and corrects its clock"; "clock 3 years ahead completes and rejects nothing fresh" |

### R2 — Utility command sequence not persisted

| Aspect | Content |
|---|---|
| **Observation** | After a utility restart, new commands get low sequence numbers. The device answers DUP; the utility deletes them |
| **Why it happens** | `cmd_seq` and `pending_cmds` live in utility RAM (reference `e2e.py`) |
| **Security impact** | **Silent loss of grid commands:** a CONTROL integrity/availability failure without any attacker |
| **Resource impact** | None until it happens; then operations cost |
| **Evidence** | [DOCKER S1]: 3 commands applied; restart; new command got seq = 1 with device last = 3, answered DUP, applied = None, and the utility kept nothing for redelivery |
| **Decision** | Adopted |
| **Fix** | seq = epoch ‖ counter; counter and queue persisted in one SQLite transaction before sending; the utility alarms when a fresh command is answered DUP or SUPERSEDED (§13.6) |
| **Trade-off** | One small database write per command |
| **Test required** | S1 must end with the command applied after the restart; a "DB restored from backup" variant; an alarm test |

### R3 — Apply-at-most-once became "possibly never", with a false OK

| Aspect | Content |
|---|---|
| **Observation** | The device writes `last_cmd_seq` before actuation. A power cut in between loses the command; if the ACK already left, the utility believes it was applied |
| **Why it happens** | Commit order in `open_control` (the counter is written, then the command is returned for application) |
| **Security impact** | Grid state differs from what the utility believes. The operator is misled |
| **Resource impact** | Negligible |
| **Evidence** | [DOCKER S2a] (redelivery answered DUP → never applied, dropped); [S2b] (OK recorded, nothing to redeliver) |
| **Decision** | Adopted |
| **Fix** | Intent log PENDING → actuate → APPLIED → ACK "OK"; INTERRUPTED after reboot; `idempotent` flag (§13.7) |
| **Trade-off** | Two flash records per discrete command as first specified; **three writes since remediation H2** (PENDING, APPLIED, the intent deleted: §13.7); honest "at most once", never "exactly once" |
| **Test required** | S2 variants: crash before PENDING, between PENDING and actuation, between actuation and APPLIED, after the ACK. Each must end in a correct status |

### R4 — Utility persistence not crash-safe; O(n) per resume

| Aspect | Content |
|---|---|
| **Observation** | A torn write of used.json or stek.json stops the utility restarting. The whole used set is rewritten per resume |
| **Why it happens** | `json.dump(…, open(path, "w"))`: truncate first, no fsync, no rename, whole-file rewrite |
| **Security impact** | Availability (no restart); **replay** (a consumed ticket forgotten without fsync); fleet-wide full handshakes if the STEK is lost |
| **Resource impact** | 100k tickets → 4.8 MB and 41.9 ms per rewrite → ~480 GB/day of writes and ~1.2 h/day of blocking I/O (container) |
| **Evidence** | [DOCKER S3, S4] |
| **Decision** | Adopted |
| **Fix** | SQLite WAL (`synchronous = FULL`), persist then respond; STEK in an HSM (production) or SQLite; atomic temp + fsync + rename for any file (§16) |
| **Trade-off** | One dependency; an fsync (≈ ms) per resume |
| **Test required** | S3 (kill during a write → restart OK, no consumed ticket forgotten); S4 (constant per-resume cost at 10k/100k) |

### R5 — Manifest larger than the device's packet limit: silent non-delivery

| Aspect | Content |
|---|---|
| **Observation** | A device declaring an MQTT 5 Maximum Packet Size ≤ 16,384 B never receives the 16,405 B manifest, and gets no error |
| **Why it happens** | MQTT 5 requires the broker to discard over-size packets silently ([MQTT-3.1.2-25]). v2.1 sized only data chunks per class, not the manifest |
| **Security impact** | Security updates never arrive, so devices stay vulnerable, with no alarm |
| **Resource impact** | Devices wait forever |
| **Evidence** | [DOCKER T1]: received at limits ≥ 16,445; never at 8,192 or 16,384; still connected |
| **Decision** | Adopted |
| **Fix** | Manifest delivered in parts ≤ class `max_packet`; the device's maximum recorded in the registry; the publisher and validator check it; SLH-DSA-128s halves the manifest (§15) |
| **Trade-off** | A few more messages; reassembly into flash |
| **Test required** | T1 re-run with a parted manifest at max 4,096 and 8,192 → installed |

### R6 — Scope: "hardware-independent" is false

| Aspect | Content |
|---|---|
| **Observation** | C0/C1 devices (6–16 KB RAM) cannot run TLS 1.3, let alone the E2E layer. C2 fits only with a constrained profile |
| **Why it happens** | TLS buffers (2 × 16 KiB by default) plus PQ working sets plus library code |
| **Security impact** | Overclaiming; a deployment could promise protection that the device cannot run |
| **Resource impact** | Peak ≈ 50 KB (default) or 16.7 KB (constrained) before the application; crypto code ~40–45 KB of flash [ANALYTICAL] |
| **Evidence** | §22; [LIT Kim & Seo, RP2040, pqm4, RFC 7228] |
| **Decision** | Adopted |
| **Fix** | Device classes (§5); C0/C1 behind C4 gateways; constrained profile for C2; claims stated per class |
| **Trade-off** | For C0/C1 meters, E2E ends at the gateway |
| **Test required** | Hardware validation (§29) |

### R7 — Per-command ML-DSA-65 at 5-s set-point rates

| Aspect | Content |
|---|---|
| **Observation** | At the report's cited traffic source (a set-point every 5 s): 61 MB/day of signatures, ~7 h/day of airtime at 20 kbit/s, and 17,280 verifications a day |
| **Why it happens** | Every command carries a 3,309 B signature |
| **Security impact** | None directly; the design is infeasible for that profile |
| **Resource impact** | See §13.3 |
| **Evidence** | [ANALYTICAL] from FIPS sizes, [DOCKER T5] overheads, [LIT pqm4] |
| **Decision** | Adopted |
| **Fix** | GRANT (signed, session-bound, bounded) + SETPOINT (AEAD) for high-rate streams; per-command signatures kept for discrete commands (§13.4–§13.5) |
| **Trade-off** | Per-grant rather than per-set-point non-repudiation; a live-session-key holder can act within the bounds |
| **Test required** | GRANT forgery, SETPOINT without a grant, out of bounds, too fast, on another session, after the grant expires, replayed SETPOINT (§28) |

## ORANGE Findings

| # | Observation | Evidence | Decision / fix | Trade-off | Test |
|---|---|---|---|---|---|
| O1 | Meters reconnecting every 15 min spend 97–98% of their bytes on handshakes; the hop ticket lasts 2 h | T2, T5 [DOCKER]; §22.6 | `reconnect` per class: BATCH or PERSISTENT (§10.5) | Batching delays data; persistent connections need a non-PSM radio | E3/E4 bytes per day per strategy |
| O2 | 6 round trips before the first protected message; "confirm before use" costs one | T6 [SIM] | Persistent MQTT session + finished-carries-data + pipelining (§9.4, §14.10) | Broker session state; a lost DF means resent alerts | T6-D on the real protocol code; lost-DF, duplicate-DF, reordered-envelope tests |
| O3 | Peak RAM 45–52 KB with default TLS buffers | T3 [DOCKER]; §22.2 | Constrained profile: max_fragment_length 512–1,024, small-stack PQ code, streaming to flash | +17 B per small record | C2 hardware RAM measurement **[HW]** |
| O4 | 16.2 KB signature: packet limits, RAM, SHA-512 | T1; pqm4; FIPS 205 | **SLH-DSA-SHA2-128s** (§15.4–§15.5) | Category 3 → 1 | F1–F7 re-run with 128s |
| O5 | OPS-5 "reserve counters" is wrong on the device; flash wear at high rates | §16 [ANALYTICAL] | Log-structured device records; no per-SETPOINT persistence | A few KiB of flash | Record-store torn-write and wear tests **[HW]** |
| O6 | Jitter existed only for policy activation | Audit Part 12 #14 | Exponential back-off with full jitter on every reconnect (§10.5) | Slower recovery for some devices | E4 outage restoration |
| O7 | One burned-in anchor | Audit Part 4 | ≥ 2 anchors + KEYREVOKE (§15.13–§15.14) | A second custodied key | Revoke A → B-signed update installs; A-signed refused; last-anchor revoke refused |

## YELLOW Findings

| # | Observation | Decision / fix (section) |
|---|---|---|
| Y1 | Two AEADs on one device (AES-GCM in TLS, ChaCha20 E2E) | One AEAD per class at both layers (§6.5, §8.4) |
| Y2 | Ascon rejected for a "128-bit key" | Real reason: no TLS suite, so it would be an extra AEAD. 128-bit keys are quantum-adequate (§7.9) |
| Y3 | The policy is canonical JSON with hex keys, contradicting D14 | Binary codec (§12) |
| Y4 | Zone keys delivered as *signed* CONTROL (3.4 KB per member per rotation) | ZONEKEY under the session AEAD (138 B); rotate on membership change + weekly (§4.7, §13) |
| Y5 | Command key and E2E key both "utility", with no separation stated | Separation of duties: HSM or separate service (§4.4) |
| Y6 | FN-DSA dismissed without a trigger | Trigger recorded: FIPS 206 final + a vetted library (§30) |
| Y7 | The hybrid pin does not cover TLS 1.2 listeners | Validator: every listener TLS 1.3 (§8.2) [DOCKER T7] |
| Y8 | Fixed 120 s DUP_WINDOW and 60 s PENDING_TTL | Per class, ≥ 2× the worst handshake time (§10.6) |
| Y9 | Unbounded outbox | Cap, merge, "dropped N" (§16) |
| Y10 | RNG unstated | TRNG + SP 800-90A DRBG required (§7.13) |
| Y11 | Watchdog vs long crypto | Per-class budget; crypto yields (§15.12, §27.2) |
| Y12 | Modem-offloaded TLS is not PQ | TLS on the application MCU with a hybrid-capable library (§8.1) |
| Y13 | Generic FOTA limits; external slot B unverified at boot | Limit = own slot size; re-verify the external slot (§15.8, §15.10) |
| Y14 | 8-bit STEK key id; manual retirement | 16-bit kid; automatic retirement (§14.4) |

---

# 19. Design Changes Resulting From the Audit

| Area | Before (v2.1) | Problem | After (v2.2) | Reason / evidence |
|---|---|---|---|---|
| Device TLS time checks | Standard validity checks | Deadlock after a clock reset or skew (R1) | No time checks on the device; chain to the pinned CA set | T4 |
| Device certificate lifetime | Normal lifetime | Offline expiry locks the device out | notAfter 99991231235959Z; revocation through registry/ACL | T4-f, T4-g |
| Device clock | Utility time from the E2E handshake | Unreachable if TLS fails | + persisted time floor; `max(RTC, floor)` | §8.9 |
| Command sequence | RAM counter per device | Reset → silent DUP loss (R2) | epoch ‖ counter, persisted with the queue in one transaction | S1 |
| Command statuses | OK / DUP / EXPIRED | Cannot tell a lost command from a real duplicate | OK / DUP / SUPERSEDED / EXPIRED / REJECTED / INTERRUPTED + utility regression alarm | S1, S2 |
| Command apply | Counter written, then applied, then OK | Lost command, false OK (R3) | Intent log PENDING → APPLIED → OK; INTERRUPTED; `idempotent` flag | S2 |
| High-rate control | Per-command ML-DSA-65 | 61 MB/day at 5-s set-points (R7) | GRANT (signed, session-bound, bounded) + SETPOINT (AEAD) | §13.3 |
| Zone-key delivery | Signed unicast CONTROL, daily rotation | 3.4 KB per member per day for no needed property | ZONEKEY under session AEAD (138 B); rotate on membership change + weekly | Y4 |
| Utility persistence | JSON files, whole rewrite, no fsync | Torn restart; replay window; O(n) (R4) | SQLite WAL, persist then respond | S3, S4 |
| STEK | 8-bit kid; file; manual retire | Wrap; torn file | 16-bit kid; HSM/SQLite; automatic retire | Y14, S3 |
| Firmware signature | SLH-DSA-SHA2-192s (16,405 B manifest) | Packet limit, RAM, SHA-512 (O4) | **SLH-DSA-SHA2-128s** (8,031 B) | T1, pqm4, FIPS 205 |
| Manifest delivery | One retained message | Silently dropped at small limits (R5) | Parts ≤ class `max_packet`, staged and verified in flash | T1 |
| Trust anchors | One | Key loss or compromise unrecoverable (O7) | ≥ 2 anchors + KEYREVOKE | §15.13 |
| External slot B | Verified at download only | Physical tampering after the check | Re-verify the hash before boot or swap | Y13 |
| FOTA limits | 64 MiB / 65,536 chunks | Not device-specific | The device's own slot size | Y13 |
| Establishment | Confirm before use: wait for NT/FIN before sending data | +1 RTT (O2) | Finished carries data (inside DF) | T6 |
| MQTT sessions | Clean session, SUBSCRIBE each time | +1 RTT per wake | `clean_start = false` + Session Expiry per class | T6 |
| Reconnect | Unspecified; jitter only for policy activation | Handshakes dominate meter bytes; outage storms (O1, O6) | BATCH/PERSISTENT per class; exponential back-off with full jitter | T2, T5, §22.6 |
| Resume retransmission | Rebuilt RH on retry | "already used" → full handshake | Resend the identical stored RH | S5 |
| Duplicate windows | Fixed 120 s / 60 s | Too short on poor NB-IoT | Per class, ≥ 2× the worst handshake time | Y8 |
| AEAD | ChaCha20 E2E + AES-GCM in TLS | Two implementations | One per class at both layers | Y1 |
| Policy encoding | Canonical JSON with hex keys | Contradicts D14; parser and size | Binary codec; new class fields | Y3 |
| Listeners | "tls_version tlsv1.3" in the example config | TLS 1.2 bypasses the hybrid pin | Validator: every listener TLS 1.3 | T7 |
| TLS placement | Unspecified | Modem TLS is not PQ | Application-MCU TLS with a hybrid-capable library | Y12 |
| Device scope | Unspecified classes; report says "hardware-independent" | Overclaim (R6) | C0/C1 behind gateways; C2 constrained profile; C3/C4 full | §5, §22 |
| Outbox | Unbounded | Flash exhaustion | Bounded + merge + "dropped N" | Y9 |
| Randomness, watchdog | Unstated | Weak keys; reset loops | Requirements (§27.2) | Y10, Y11 |
| Separation of duties | Unstated | Command signature adds little without it | Required (§4.4) | Y5 |

---

# 20. Decision Records

**How to use this section.**
- Each record is **frozen**. Changing one means writing a new record (DR-0xx-v2) that states the evidence,
  then re-running the tests in §28.
- "v2.1 → v2.2" marks records the audit changed.
- Evidence labels follow §17.3.

## DR-001: Hop key exchange

| Field | Content |
|---|---|
| **Question** | Which key exchange protects each device/utility ↔ broker hop? |
| **Options** | 1. Classical X25519. 2. Pure ML-KEM-768 (`MLKEM768`). 3. Hybrid X25519MLKEM768 |
| **Decision** | **3. Hybrid X25519MLKEM768** (SecP256r1MLKEM768 also allowed) |
| **Why** | Record-now rule (P1): recorded hop traffic, including TELEMETRY and topic names, must survive a future quantum computer, and must not rest on one young algorithm. OpenSSL 3.5 default; IETF track; matches the report |
| **Rejected** | 1: breaks under a future quantum computer. 2: single-algorithm risk; kept as the E1 benchmark |
| **Trade-offs** | +2.3 KB per handshake; +1.25 M device cycles for the X25519 half (~20 ms @64 MHz) |
| **Evidence** | [DOCKER] negotiated by default; X25519 vs ML-KEM compute +122% on the laptop; [LIT] pqm4, Haase-Labrique |
| **Future trigger** | Guidance allowing pure ML-KEM, and a longer ML-KEM cryptanalytic record → pure `MLKEM768` (one config line) |

## DR-002: Hybrid-only pinning and TLS 1.3-only listeners

| Field | Content |
|---|---|
| **Question** | Accept any group the client offers, or enforce hybrid? |
| **Options** | 1. OpenSSL defaults. 2. Pin `Groups = X25519MLKEM768:SecP256r1MLKEM768` on broker and devices. 3. Option 2 + every listener `tls_version tlsv1.3` |
| **Decision** | **3** (v2.1 had 2; v2.2 adds the listener rule) |
| **Why** | Defaults silently accept classical-only clients. The pin does not cover TLS 1.2, where FFDHE is negotiated regardless |
| **Rejected** | 1: silent downgrade. 2 alone: bypassed by any TLS 1.2 listener |
| **Trade-offs** | Legacy TLS 1.2 clients cannot connect (intended). Mosquitto has no groups setting, so `OPENSSL_CONF` is the only mechanism |
| **Evidence** | [DOCKER N3] (accepted by default, refused when pinned); [DOCKER T7] (TLS 1.2 PSK → `DHE-PSK`, FFDHE-3072, despite the pin) |
| **Future trigger** | Mosquitto adding a native groups option → use it |

## DR-003: One AEAD per device class

| Field | Content |
|---|---|
| **Question** | Which AEAD protects TLS records and E2E envelopes? |
| **Options** | 1. ChaCha20 E2E + AES-GCM in TLS (v2.1). 2. AES-256-GCM everywhere. 3. ChaCha20 everywhere. 4. One per class: AES-256-GCM where AES hardware exists, ChaCha20-Poly1305 otherwise, the same at both layers. 5. Ascon-AEAD128 |
| **Decision** | **4** (v2.1 → v2.2) |
| **Why** | The device must implement the TLS AEAD anyway. Using it E2E removes a second implementation. AES hardware is common on C3 SoCs; ChaCha20 is constant-time in software where it is not |
| **Rejected** | 1: two AEADs per device. 2: slow and leaky without AES hardware. 3: wastes the hardware. 5: no TLS suite, so it would be a second AEAD |
| **Trade-offs** | The policy carries an `aead` field; the broker accepts both suites |
| **Evidence** | [DOCKER] `TLS_AES_256_GCM_SHA384` negotiated by default; [LIT] SAM4CM and nRF9160 datasheets |
| **Future trigger** | An 8/16-bit class becoming a direct client → reconsider Ascon |

## DR-004: Hop certificates

| Field | Content |
|---|---|
| **Question** | How do devices and the broker authenticate each other on the hop? |
| **Options** | 1. ECDSA P-256 certificates. 2. ML-DSA-44/65 certificates. 3. Per-device TLS PSK. 4. Username/password. 5. Ed25519 |
| **Decision** | **1. ECDSA P-256**, private CA, CN = device ID |
| **Why** | Rule P3: hop authentication is checked live and can be replaced through the PQ channel. Smallest handshake. Hardware-accelerated on many SoCs |
| **Rejected** | 2: 5–7× larger handshakes (23.8–31.7 KB); resumption grows too. 3: Mosquitto supports it only on TLS 1.2 with classical DHE, and it puts secrets on the broker. 4: phishable and stored at the broker. 5: less MCU acceleration, no quantum gain |
| **Trade-offs** | 57% of the device's cold-start public-key cycles; a classical assumption for *future* handshakes |
| **Evidence** | [DOCKER] handshake bytes per certificate type; [DOCKER T7]; [LIT Tasopoulos 2022] ECDSA cycles |
| **Future trigger** | Credible CRQC timeline or deprecation milestone → ML-DSA-44 certificates (E1 measures the cost) |

## DR-005: Certificate time handling

| Field | Content |
|---|---|
| **Question** | How can a device with a wrong or reset clock still connect? |
| **Options** | 1. Standard validity checks (v2.1). 2. Battery-backed RTC. 3. NTP or cellular NITZ. 4. No time checks on the device + device certificates notAfter 9999 + persisted time floor |
| **Decision** | **4** (v2.1 → v2.2) |
| **Why** | TLS runs before the E2E time repair, so option 1 deadlocks. A pinned private CA plus revocation by registry makes validity dates unnecessary on the device |
| **Rejected** | 1: deadlock. 2: hardware cost, not universal. 3: unauthenticated, shiftable |
| **Trade-offs** | A CA compromise is unbounded in time on devices (mitigated by an offline CA, pinning, PQ-signed roll-over) |
| **Evidence** | [DOCKER T4] a–g |
| **Future trigger** | Authenticated network time becoming available on target modems → it may feed the floor |

## DR-006: Where the protected session lives

| Field | Content |
|---|---|
| **Question** | Between which parties do ALERT and CONTROL get their keys? |
| **Options** | 1. From TLS (`K_session = KDF(K_TLS, …)`, report eq. 3.2). 2. Device ↔ broker application session. 3. **Device ↔ utility** |
| **Decision** | **3** |
| **Why** | The only placement where "the broker cannot read or forge alerts and commands" is true |
| **Rejected** | 1: the broker holds K_TLS, and Python cannot export it. 2: the broker still sees plaintext |
| **Trade-offs** | Handshake messages travel through the broker (2 round trips); the utility holds sessions |
| **Evidence** | [DOCKER] curious broker sees no plaintext (A5); forged commands rejected (A10) |
| **Future trigger** | None; this is the project's central claim |

## DR-007: E2E protocol

| Field | Content |
|---|---|
| **Question** | How are device and utility mutually authenticated and keyed? |
| **Options** | 1. KEM-MQTT (base paper, Fig. 4). 2. Signed DH (SIGMA). 3. TLS inside MQTT. 4. PSK only |
| **Decision** | **1. KEM-MQTT, lifted end to end, with POLICY_INFO** |
| **Why** | Signature-free mutual authentication (the device never signs); forward secrecy; the base paper |
| **Rejected** | 2: device-side ML-DSA signing (50–120 KB RAM in reference C on an M0+; variable latency). 3: heavy. 4: no forward secrecy; distribution at scale |
| **Trade-offs** | 3 KEMs (5.2 KB, 5.8 M device cycles) per full handshake |
| **Evidence** | [DOCKER] 47 CORE scenarios; [LIT RP2040] ML-DSA signing RAM |
| **Future trigger** | A formal model (ProVerif/Tamarin) finding an issue → revise |

## DR-008: Hybrid KEM in E2E, X-Wing combiner

| Field | Content |
|---|---|
| **Question** | Pure ML-KEM or hybrid inside E2E, and how are the secrets combined? |
| **Options** | 1. Pure ML-KEM-768. 2. Hybrid + concatenation into HKDF. 3. Hybrid + XOR. 4. Hybrid + X-Wing (SHA3-256 with the X25519 transcript) |
| **Decision** | **4** |
| **Why** | The broker can record E2E traffic, so rule P1 applies. X-Wing binds the classical transcript and has published analysis |
| **Rejected** | 1: single-algorithm risk. 2: weaker when used outside a transcript (K_B, K1). 3: not robust |
| **Trade-offs** | +5 X25519 multiplications per full handshake (3.1 M cycles, ~49 ms @64 MHz) |
| **Evidence** | [LIT Haase-Labrique]; [ANALYTICAL] §22.1 |
| **Future trigger** | Same as DR-001, and the final CFRG X-Wing RFC |

## DR-009: ML-KEM parameter set

| Field | Content |
|---|---|
| **Question** | Which ML-KEM security category? |
| **Options** | 1. ML-KEM-512. 2. ML-KEM-768. 3. ML-KEM-1024 |
| **Decision** | **2** |
| **Why** | NIST's default; margin for 15–20-year secrets; tiny cost difference on an MCU |
| **Rejected** | 1: minimum margin for a negligible saving. 3: +60% cycles, +384/480 B, no need |
| **Trade-offs** | See §7.2 |
| **Evidence** | [LIT pqm4, RP2040, FIPS 203] |
| **Future trigger** | Lattice cryptanalysis reducing the Category 3 margin → 1024 |

## DR-010: KDF, MAC and hash suite

| Field | Content |
|---|---|
| **Question** | Which KDF, MAC and hash? |
| **Options** | SHA-256 family; SHA-384; SHA-3/SHAKE/KMAC |
| **Decision** | **HKDF-SHA-256, HMAC-SHA-256, SHA-256**; SHA3-256 only in X-Wing (and inside ML-KEM) |
| **Why** | Standard; SHA-256 hardware is common; SLH-DSA-128s also needs only SHA-256 |
| **Rejected** | SHA-384/KMAC: no security need; more code paths |
| **Trade-offs** | None material |
| **Evidence** | [LIT] RFC 5869/2104, FIPS 180-4, FIPS 205 §11.2 |
| **Future trigger** | None expected |

## DR-011: Nonces and key lifetime

| Field | Content |
|---|---|
| **Question** | Where do AEAD nonces come from? |
| **Options** | 1. Random 96-bit. 2. Counters (direction ‖ seq) with keys in RAM only |
| **Decision** | **2** |
| **Why** | No dependence on RNG quality per message; counters cannot collide while the key is fresh |
| **Rejected** | 1: cheap devices have had broken RNGs |
| **Trade-offs** | Session keys are never persisted, so every reboot needs a resume |
| **Evidence** | Design rule (Rationale B8); A8 |
| **Future trigger** | None |

## DR-012: Tiers

| Field | Content |
|---|---|
| **Question** | How many protection levels, and is TELEMETRY end to end? |
| **Options** | 1. One level for everything. 2. Two. 3. **Three** (TELEMETRY hop-only; ALERT + E2E; CONTROL + E2E + signature) |
| **Decision** | **3** |
| **Why** | Three distinct adversary needs (§11) |
| **Rejected** | 1: over- or under-protection. 2: merges alerts with telemetry or commands |
| **Trade-offs** | The broker reads TELEMETRY (deliberate: the utility runs the broker; occupancy-sensitive data belongs on ALERT) |
| **Evidence** | A5–A11 |
| **Future trigger** | A regulator requiring E2E for meter readings → a fourth tier or TELEMETRY → ALERT |

## DR-013: Tier resolution

| Field | Content |
|---|---|
| **Question** | Several rules match a topic, or none does: what tier? |
| **Options** | 1. First match. 2. Most specific. 3. **Strongest wins; no match → CONTROL** |
| **Decision** | **3** |
| **Why** | Monotone, order-independent, fail-safe |
| **Rejected** | 1 and 2: a broad weak rule can downgrade |
| **Trade-offs** | A mistakenly strong rule costs bytes, never exposure |
| **Evidence** | CORE tier-engine tests |
| **Future trigger** | None |

## DR-014: Policy form and distribution

| Field | Content |
|---|---|
| **Question** | How is the policy encoded, protected and delivered? |
| **Options** | 1. Broker-hosted, unsigned. 2. Signed JSON (v2.1 reference). 3. **Signed binary codec, delivered as a FOTA artifact with `activate_at`, including class profiles** |
| **Decision** | **3** (v2.1 → v2.2: binary encoding, class profile fields, validator rules 6–10) |
| **Why** | One PQ-signed pipeline; no re-serialisation; no JSON parser on the device; profiles are fixed, not negotiated |
| **Rejected** | 1: the broker could weaken it. 2: parser and size costs; contradicted D14 |
| **Trade-offs** | Every policy change is a signed release |
| **Evidence** | F6 (rollback), A13 (validator); Audit Y3 |
| **Future trigger** | None |

## DR-015: Policy binding

| Field | Content |
|---|---|
| **Question** | How is the policy made tamper-evident in sessions? |
| **Options** | 1. Send it in the clear. 2. MQTT 5 enhanced auth (report). 3. **Inside the authenticated handshake, bound into `K_master` and into tickets** |
| **Decision** | **3** |
| **Why** | Any change to POLICY_INFO in either direction aborts the handshake |
| **Rejected** | 1: silent downgrade. 2: the broker is a party, and Mosquitto needs a C plugin |
| **Trade-offs** | A policy change forces re-handshakes (jittered) |
| **Evidence** | A1, A2, A4, P5, P10 |
| **Future trigger** | None |

## DR-016: Discrete command authenticity

| Field | Content |
|---|---|
| **Question** | How does a device know a discrete command came from the utility's authority? |
| **Options** | 1. Session AEAD only. 2. **ML-DSA-65 per command + AEAD**. 3. ML-DSA-44. 4. FN-DSA-512 |
| **Decision** | **2**, with the signing key held apart from the E2E key (v2.2 requirement) |
| **Why** | Excludes session-key holders and captured devices; non-repudiation; rotatable key |
| **Rejected** | 1: forgeable by session-key holders. 3: marginal gain. 4: not final |
| **Trade-offs** | +3.3 KB per command; 38–90 ms verification @64 MHz |
| **Evidence** | A10; RISK (stolen E2E key cannot forge); [LIT pqm4] |
| **Future trigger** | FIPS 206 final + a vetted library → FN-DSA-512 |

## DR-017: High-rate control

| Field | Content |
|---|---|
| **Question** | How are frequent set-points authorised? |
| **Options** | 1. Sign each (v2.1). 2. AEAD only. 3. **Signed session-bound GRANT with bounds, rate and expiry + AEAD SETPOINTs** |
| **Decision** | **3** (new in v2.2) |
| **Why** | Keeps "no forgery without the command key" (a GRANT is needed per session) while cutting bytes ~18× at 5-s rates; gives the device local safety limits |
| **Rejected** | 1: 61 MB/day and 7 h airtime at 5-s rates. 2: no command-key authority at all |
| **Trade-offs** | Per-grant non-repudiation; live-session-key holders act within the bounds |
| **Evidence** | [ANALYTICAL] §13.3 |
| **Future trigger** | Real DER traffic data showing different rates → adjust GRANT lifetime or rate |

## DR-018: Command sequence and statuses

| Field | Content |
|---|---|
| **Question** | How are commands ordered and deduplicated across sessions and restarts? |
| **Options** | 1. RAM counter (v2.1). 2. Persisted counter. 3. **epoch ‖ counter, persisted with the queue in one transaction** |
| **Decision** | **3** (v2.1 → v2.2), with statuses OK / DUP / SUPERSEDED / EXPIRED / REJECTED / INTERRUPTED and a utility regression alarm |
| **Why** | Survives restarts **and** database restores; lets the utility detect a regression |
| **Rejected** | 1: silent loss after a restart. 2: a database restore rolls it back |
| **Trade-offs** | One database write per command (needed anyway for the queue) |
| **Evidence** | [DOCKER S1] |
| **Future trigger** | None |

## DR-019: Apply semantics

| Field | Content |
|---|---|
| **Question** | What does "applied" mean across a power loss? |
| **Options** | 1. Write the counter, then apply (v2.1). 2. Apply, then write (at least once). 3. **Intent log with INTERRUPTED + `idempotent` flag** |
| **Decision** | **3** (v2.1 → v2.2) |
| **Why** | Exactly-once is impossible without actuator feedback; honesty about the uncertain case |
| **Rejected** | 1: silent loss and a false OK. 2: duplicate actuation of non-idempotent commands |
| **Trade-offs** | Two flash records per discrete command as first specified; three writes since remediation H2 (§13.7) |
| **Evidence** | [DOCKER S2a/b] |
| **Future trigger** | Actuators with readable state → resolve INTERRUPTED automatically |

## DR-020: Broadcast demand-response

| Field | Content |
|---|---|
| **Question** | How are DR events delivered to a zone? |
| **Options** | 1. Unicast to each member. 2. Signed only (no confidentiality). 3. **Zone key (delivered as ZONEKEY under each member's session AEAD) + ML-DSA-65-signed events** |
| **Decision** | **3** (v2.1 → v2.2: ZONEKEY unsigned under the session; rotation on membership change + weekly) |
| **Why** | Scales; a captured member cannot forge events (they are signed); the session already authenticates key delivery |
| **Rejected** | 1: does not scale. 2: DR plans can be market-sensitive. v2.1's signed key delivery cost 3.4 KB per member per rotation for no needed property |
| **Trade-offs** | A captured member reads its zone's events until the next rotation |
| **Evidence** | A11; zone re-key EDGE test |
| **Future trigger** | Regulators classifying DR events as public → option 2 |

## DR-021: Resumption tickets

| Field | Content |
|---|---|
| **Question** | Who issues resumption state, and in what form? |
| **Options** | 1. Broker-held ticket key (report). 2. Stateful utility cache. 3. **Utility-issued, STEK-sealed, single-use stateless tickets with a binder** |
| **Decision** | **3** (v2.2 adds a 16-bit kid and automatic retirement) |
| **Why** | The issuer must hold the session secret; scales; clone detection through single use |
| **Rejected** | 1: the broker is not a party to the E2E session. 2: state grows and is lost on restart |
| **Trade-offs** | STEK theft → ticket minting (HSM) |
| **Evidence** | P1–P10; RISK (stolen STEK) |
| **Future trigger** | Multi-utility high availability → shared HSM and a replicated used-ticket store |

## DR-022: Resume modes and invariant

| Field | Content |
|---|---|
| **Question** | May resumption skip the fresh KEM? |
| **Options** | 1. Always PSK. 2. Always PSK+KEM. 3. **Per class: PSK or PSK_KEM; unicast-control classes PSK_KEM or NONE; chain ≤ 7 days** |
| **Decision** | **3** |
| **Why** | A policy-controlled trade-off between forward secrecy and cost; the invariant protects command channels |
| **Rejected** | 1: no forward secrecy for command channels. 2: wastes 2.6 M cycles and 2.3 KB on telemetry-only meters |
| **Trade-offs** | PSK chains lack forward secrecy for ≤ 7 days |
| **Evidence** | P6, A13; [DOCKER bench] |
| **Future trigger** | None |

## DR-023: Establishment completion

| Field | Content |
|---|---|
| **Question** | When may the device send protected data after SH/RS? |
| **Options** | 1. After NT/FIN ("confirm before use", v2.1). 2. **Inside DF ("finished carries data")**. 3. 0-RTT inside RH |
| **Decision** | **2** (v2.1 → v2.2) |
| **Why** | Saves a round trip; the utility processes data only after verifying MAC_D in the same message; outbox + ACKs keep it reliable |
| **Rejected** | 1: +1 RTT for protection that ACK + outbox already give. 3: replayable early data |
| **Trade-offs** | A lost DF means resent alerts |
| **Evidence** | [SIM T6] scenario D |
| **Future trigger** | None |

## DR-024: MQTT sessions and reconnect strategy

| Field | Content |
|---|---|
| **Question** | How do devices reconnect, and how often? |
| **Options** | 1. Clean session, reconnect on demand (v2.1). 2. **Persistent MQTT session; per-class BATCH or PERSISTENT; exponential back-off with full jitter; pipelined CONNECT** |
| **Decision** | **2** (new in v2.2) |
| **Why** | Handshakes are 97–98% of meter bytes at 15-min wakes; SUBSCRIBE costs a round trip; outages cause storms |
| **Rejected** | 1: wasteful and storm-prone |
| **Trade-offs** | Broker per-device state and queues; batching delays data |
| **Evidence** | [DOCKER T2, T5]; [SIM T6]; [ANALYTICAL] §22.6 |
| **Future trigger** | Operator NAT timeouts measured **[HW]** → keep-alive settings |

## DR-025: Firmware and policy signature

| Field | Content |
|---|---|
| **Question** | Which scheme signs artifacts verified against the burned-in anchor? |
| **Options** | 1. ML-DSA-65 (report). 2. ML-DSA + Ed25519. 3. SLH-DSA-SHA2-192s (v2.1). 4. **SLH-DSA-SHA2-128s**. 5. SLH-DSA 'f' variants. 6. LMS/HSS or XMSS |
| **Decision** | **4** (v2.1 → v2.2) |
| **Why** | Hash-only; stateless; SHA-256 only; 8,031 B manifest; 7.47 M-cycle verify. The trigger recorded in Rationale B10 is met |
| **Rejected** | 1: lattice risk for an irreplaceable key. 2: reduces to ML-DSA. 3: 16.4 KB packet problem and SHA-512. 5: bigger **and** slower to verify. 6: stateful; needs an HSM-backed station |
| **Trade-offs** | Category 1 instead of 3 |
| **Evidence** | [DOCKER T1, signature_speed]; [LIT pqm4, FIPS 205] |
| **Future trigger** | HSM-backed production station → LMS/HSS; a guidance change requiring Category 3+ → 192s with parted delivery |

## DR-026: Trust anchors

| Field | Content |
|---|---|
| **Question** | How many anchors, and can they be revoked? |
| **Options** | 1. One, never replaceable (v2.1). 2. **≥ 2 with KEYREVOKE signed by another anchor** |
| **Decision** | **2** (new in v2.2) |
| **Why** | Key loss or compromise is likelier than an algorithm break |
| **Rejected** | 1: a single point of failure for the fleet |
| **Trade-offs** | A second custodied key; an extra artifact type |
| **Evidence** | Audit Part 4 |
| **Future trigger** | None |

## DR-027: Chunk integrity and artifact sizing

| Field | Content |
|---|---|
| **Question** | How are large artifacts verified and delivered? |
| **Options** | 1. Flat hash list in the manifest. 2. **Merkle root + per-chunk path; every message (manifest parts and chunks) ≤ class `max_packet`** |
| **Decision** | **2** (v2.2 adds manifest parts) |
| **Why** | Constant memory; any order; no silent drop at packet limits |
| **Rejected** | 1: the manifest grows with the image |
| **Trade-offs** | +256 B per 4 KiB chunk (6%) |
| **Evidence** | [DOCKER] Merkle benchmarks; [DOCKER T1] |
| **Future trigger** | None |

## DR-028: A/B slots and commit timing

| Field | Content |
|---|---|
| **Question** | How are updates installed without bricking or rollback? |
| **Options** | 1. Overwrite in place. 2. **A/B with commit after a successful boot; revert on failure; re-verify an external slot** |
| **Decision** | **2** (v2.2 adds external-slot re-verification and device-specific limits) |
| **Why** | Commit before boot would strand the device; an external slot is outside the trust boundary |
| **Rejected** | 1: bricking; no revert |
| **Trade-offs** | 2× image flash (external flash on C2) |
| **Evidence** | EDGE failed-boot test; F4/F5 |
| **Future trigger** | None |

## DR-029: Utility persistence

| Field | Content |
|---|---|
| **Question** | How does the utility store promises durably? |
| **Options** | 1. JSON files rewritten (v2.1). 2. Append-only log + compaction. 3. **SQLite WAL, `synchronous = FULL`, persist then respond** |
| **Decision** | **3** (v2.1 → v2.2) |
| **Why** | Atomic transactions; indexed inserts; standard; available in Python |
| **Rejected** | 1: torn files, replay window, O(n). 2: correct, but more custom code |
| **Trade-offs** | One dependency; ms-level fsync |
| **Evidence** | [DOCKER S3, S4] |
| **Future trigger** | High availability → replicated DB + HSM |

## DR-030: Device persistence

| Field | Content |
|---|---|
| **Question** | How does the device store state across power loss without wearing flash out? |
| **Options** | 1. Overwrite fixed locations. 2. **Log-structured records with CRC and sequence across ≥ 2 pages; bounded outbox** |
| **Decision** | **2** |
| **Why** | Torn writes are detected; wear is spread |
| **Rejected** | 1: torn writes and hot spots |
| **Trade-offs** | A few KiB of flash; compaction code |
| **Evidence** | [ANALYTICAL] §16 flash wear |
| **Future trigger** | Target part endurance ≠ 10k cycles **[HW]** → re-size |

## DR-031: Device scope

| Field | Content |
|---|---|
| **Question** | Which devices run the design directly? |
| **Options** | 1. All ("hardware-independent"). 2. **C2 (constrained profile), C3, C4 directly; C0/C1 through C4 gateways** |
| **Decision** | **2** (new in v2.2) |
| **Why** | C0/C1 cannot run TLS 1.3 |
| **Rejected** | 1: false |
| **Trade-offs** | For C0/C1 meters, E2E ends at the gateway |
| **Evidence** | §5, §22; [LIT Kim & Seo, RP2040, RFC 7228] |
| **Future trigger** | A KEM-MQTT-only profile for 8-bit devices, as a separate research track |

## DR-032: Constrained profile

| Field | Content |
|---|---|
| **Question** | How does a C2 device fit? |
| **Options** | 1. A bigger MCU only. 2. **Profile: max_fragment_length 512–1,024; small-stack PQ implementations; stream artifacts to flash; small `max_packet`** |
| **Decision** | **2** |
| **Why** | Peak RAM falls from ~50 KB to ~17 KB before the application |
| **Rejected** | 1: excludes a real market segment |
| **Trade-offs** | +17 B per small record; small-stack code is slower (e.g. ML-DSA verify 5.73 M vs 2.42 M cycles) |
| **Evidence** | [DOCKER T3]; [LIT pqm4] |
| **Future trigger** | Hardware RAM measurement **[HW]** |

## DR-033: Broker

| Field | Content |
|---|---|
| **Question** | Which broker, and configured how? |
| **Options** | Mosquitto; EMQX; HiveMQ; VerneMQ |
| **Decision** | **Mosquitto 2.0** with the §27.1 configuration |
| **Why** | Lightweight, C/OpenSSL, native hybrid groups through OpenSSL 3.5; everything verified in Docker |
| **Rejected** | Others: not verified in this project; heavier |
| **Trade-offs** | No native groups option; TLS 1.3 PSK unavailable (T7) |
| **Evidence** | [DOCKER] broker and network results |
| **Future trigger** | A broker change requires re-running `run_all.sh` and `run_audit.sh` |

## DR-034: Duplicate handling

| Field | Content |
|---|---|
| **Question** | How are MQTT QoS 1 duplicates handled? |
| **Options** | 1. Treat as new. 2. **Identical stored reply within DUP_WINDOW; windows per class** |
| **Decision** | **2** (v2.2: per-class windows) |
| **Why** | v1 broke on duplicate CH, DF and RH |
| **Rejected** | 1: broken handshakes, crashes, killed tickets |
| **Trade-offs** | Utility memory for cached replies |
| **Evidence** | EDGE duplicate tests; §10.6 |
| **Future trigger** | None |

## DR-035: Time source for E2E decisions

| Field | Content |
|---|---|
| **Question** | Which clock judges command expiry? |
| **Options** | Device RTC; NTP/NITZ; **utility time inside the authenticated handshake** |
| **Decision** | **Utility-authenticated time** (+ time floor, DR-005) |
| **Why** | Authenticated, free, and available on every handshake and resume |
| **Rejected** | RTC resets; NTP/NITZ unauthenticated |
| **Trade-offs** | Accurate only to network delay (seconds) |
| **Evidence** | EDGE clock tests (E2E layer) + T4 (TLS layer) |
| **Future trigger** | None |

## DR-036: Sessions per device

| Field | Content |
|---|---|
| **Question** | How many live E2E sessions may a device have? |
| **Options** | **One (a new session replaces the old)**; many |
| **Decision** | **One** |
| **Why** | Simple replay tracking; clones become visible |
| **Rejected** | Many: harder replay tracking; hides clones |
| **Trade-offs** | A clone can evict the genuine session (and triggers an alarm) |
| **Evidence** | Clone EDGE test; N4 |
| **Future trigger** | None |

## DR-037: Identifiers and parsing

| Field | Content |
|---|---|
| **Question** | How are inputs constrained? |
| **Options** | Lenient; **strict** |
| **Decision** | **Strict:** device IDs `^[a-z0-9][a-z0-9-]{0,31}$`; exact field counts; known types; 1 MiB field cap; one half-open handshake per device |
| **Why** | Topic/ACL injection; memory exhaustion; the v1 fuzz finding |
| **Rejected** | Lenient: exploitable |
| **Trade-offs** | None |
| **Evidence** | Fuzz (3,300 + 16,500 messages rejected); ID-injection EDGE test |
| **Future trigger** | None |

## DR-038: End-to-end delivery

| Field | Content |
|---|---|
| **Question** | How do we know an alert or command arrived? |
| **Options** | Broker PUBACK; **E2E ACKs + alert IDs + flash outbox + command redelivery** |
| **Decision** | **E2E**, with the outbox bounded in v2.2 |
| **Why** | A PUBACK only proves the broker received it; utility restarts lost alerts in testing |
| **Rejected** | PUBACK: not end to end |
| **Trade-offs** | +73 B per alert (ID + framing); flash writes |
| **Evidence** | EDGE: lost ACK, utility restart, device reboot |
| **Future trigger** | None |

## DR-039: TLS placement on the device

| Field | Content |
|---|---|
| **Question** | Where does the device's TLS run? |
| **Options** | Modem offload; **application MCU with a hybrid-capable library** |
| **Decision** | **Application MCU** (new in v2.2) |
| **Why** | Modem TLS is TLS 1.2 / not PQ (e.g. nRF91) |
| **Rejected** | Modem offload: no ML-KEM |
| **Trade-offs** | Library footprint on the MCU **[HW]**; Mbed TLS lacks ML-KEM (roadmap "future"), so a wolfSSL-class library is used |
| **Evidence** | [LIT vendor docs] |
| **Future trigger** | Modem firmware adding hybrid groups → re-evaluate |

## DR-040: Randomness

| Field | Content |
|---|---|
| **Question** | Where does device randomness come from? |
| **Options** | Software only; **TRNG + SP 800-90A DRBG** |
| **Decision** | **TRNG + DRBG, seeded before the first handshake** (new requirement) |
| **Why** | ML-KEM and X25519 keys, TLS randoms and ticket IDs depend on it |
| **Rejected** | Software only: predictable on cheap parts |
| **Trade-offs** | Excludes parts without a usable entropy source |
| **Evidence** | [LIT] datasheets; RP2040 ring oscillator not certified |
| **Future trigger** | None |

## DR-041: Resync hint

| Field | Content |
|---|---|
| **Question** | How does a device learn that the utility lost its session? |
| **Options** | Wait for a timeout; **unauthenticated hint `0x07 ‖ sid`, rate-limited to 1 per 30 s, triggering an authenticated resume** |
| **Decision** | **The hint** |
| **Why** | Fast recovery; forging it costs only one cheap resume |
| **Rejected** | Timeout: slow |
| **Trade-offs** | A DoS amplification of at most one resume per 30 s |
| **Evidence** | Forged-resync EDGE test |
| **Future trigger** | None |

## DR-042: Encoding

| Field | Content |
|---|---|
| **Question** | How are protocol objects encoded? |
| **Options** | Canonical JSON; CBOR; **length-prefixed binary** |
| **Decision** | **Length-prefixed binary everywhere**, now including the policy (v2.2) |
| **Why** | Deterministic; portable; small; strict parsing |
| **Rejected** | JSON: parser, size, canonicalisation. CBOR: viable, but a second codec |
| **Trade-offs** | A custom codec; its specification is in §12 |
| **Evidence** | Fuzz results |
| **Future trigger** | Interoperability with SUIT/COSE ecosystems → consider CBOR/COSE for manifests |

## DR-043: Development and evidence

| Field | Content |
|---|---|
| **Question** | Where is the system built and measured, and how are results reported? |
| **Options** | Host machine; **Docker only, with evidence labels** |
| **Decision** | **Docker only** (no host installs, no bind mounts, no `--privileged`, no host network); labels [DOCKER]/[SIM]/[LIT]/[ANALYTICAL]/[HW] |
| **Why** | Reproducibility; the host stays untouched; honest reporting |
| **Rejected** | Host: pollution; environment drift (macOS venv ~5× slower) |
| **Trade-offs** | Docker cannot answer the hardware questions (§29) |
| **Evidence** | `run_all.sh`, `run_audit.sh` |
| **Future trigger** | Hardware available → §29 plan |

## DR-044: DF binds its bundle

| Field | Content |
|---|---|
| **Question** | Does the device's key confirmation MAC_D cover the envelopes piggybacked inside DF? |
| **Options** | 1. MAC_D over the transcript only (v2.1 formula). 2. **MAC_D over the transcript and H(bundle)** |
| **Decision** | **2**: `MAC_D = HMAC(kc_D, "D-finished" ‖ H(th2, MAC_U, H(bundle)))`. The same rule applies to the resume DF |
| **Why** | Makes DF atomic: a relay cannot strip, truncate or append envelopes inside a valid DF |
| **Rejected** | 1: each envelope would still be AEAD- and replay-protected, but the bundle's composition would not be bound to the device's key confirmation |
| **Trade-offs** | One extra hash; the device must build the bundle before computing MAC_D |
| **Evidence** | Raised as OPEN-1 in IMPLEMENTATION-ROADMAP.md; decided by the team 2026-09-25 |
| **Future trigger** | None |

## DR-045: CONTROL status ACK binding

| Field | Content |
|---|---|
| **Question** | What does the MAC of a CONTROL status ACK cover? |
| **Options** | 1. `sid ‖ msg_seq ‖ status`. 2. **`sid ‖ msg_seq ‖ cmd_seq ‖ status`, with `cmd_seq` carried in the ACK body** |
| **Decision** | **2** |
| **Why** | The utility must tie a status to the exact **command** across sessions and redeliveries (the S1/S2 class of bugs) |
| **Rejected** | 1: after a cross-session redelivery, a status could be attributed to the wrong command |
| **Trade-offs** | +8 bytes per ACK |
| **Evidence** | Raised as OPEN-2 in IMPLEMENTATION-ROADMAP.md; decided by the team 2026-09-25 |
| **Future trigger** | None |

## DR-046: DUP and INTERRUPTED take precedence over EXPIRED

| Field | Content |
|---|---|
| **Question** | In which order does a device classify an authentic command? |
| **Options** | 1. As §13.1 was written: expiry, then sequence classification. 2. **"Already seen" first (DUP for applied, INTERRUPTED for interrupted), then expiry, then SUPERSEDED / new** |
| **Decision** | **2** |
| **Why** | A command that was applied, whose OK was lost and whose redelivery arrives after `expires_at`, must be reported as applied (DUP), not EXPIRED; otherwise a re-issue can actuate twice |
| **Rejected** | 1: the status could say "not applied" for an applied command |
| **Trade-offs** | None measurable (one lookup before the time check) |
| **Evidence** | Raised as OPEN-5 in IMPLEMENTATION-ROADMAP.md; decided by the team 2026-09-25 |
| **Amended 2026-09-29** | Clarification 3 fixes the full order: DUP (applied) → INTERRUPTED/recovery (pending) → SUPERSEDED → EXPIRED → execute. Expiry is never checked before supersession (§13.1) |
| **Future trigger** | None |

## DR-047: One AEAD per zone (amended: logical zone, crypto groups)

| Field | Content |
|---|---|
| **Question** | Which AEAD protects a DR broadcast when a feeder holds devices of different class AEADs? |
| **Options** | 1. **One AEAD per zone: the zone manager groups members by AEAD, so a mixed feeder is two zones**. 2. ChaCha20-Poly1305 for every zone. 3. AES-256-GCM for every zone |
| **Decision** | **1** |
| **Why** | Keeps DR-003 (one AEAD implementation per device). The ZONEKEY names the zone's AEAD, and a device refuses a zone whose AEAD is not its own |
| **Rejected** | 2: a second AEAD on AES-class devices. 3: slow, timing-leaky software AES on classes without AES hardware |
| **Trade-offs** | An event for a mixed feeder is published once per AEAD group (at most 2×) |
| **Evidence** | Raised as OPEN-3 in IMPLEMENTATION-ROADMAP.md; decided by the team 2026-09-25 |
| **Amended 2026-09-29** | Clarification 4: a feeder stays **one logical zone** (membership, event identity and `bseq` are logical); it has one crypto group per AEAD (zone+AES, zone+ChaCha), each with its own ZONEKEY, key epoch and topic. The same logical event keeps one σ and one `bseq` in both groups' publications. DR-003 still holds: a device receives and accepts only its own class AEAD's key |
| **Future trigger** | A class able to run both AEADs cheaply |

## DR-048: Broadcast sequence

| Field | Content |
|---|---|
| **Question** | How does the per-zone broadcast sequence survive a utility restart and a device reboot? |
| **Options** | Utility side: `bseq = utility epoch(32) ‖ per-zone counter(32)` (as §13.6) vs a counter persisted before each event. Device side: 1. a floor carried in ZONEKEY; 2. **the device keeps the last accepted `bseq` per zone in its flash record store**; 3. a floor set at the device's last contact |
| **Decision** | **epoch ‖ counter, and device option 2** (option 1 was chosen first, then replaced the same day, see below) |
| **Why** | A restart can never move the sequence backwards (the S1 bug for broadcasts), with no utility write per event. A device that reboots still refuses replays, because its last accepted `bseq` survives in flash, and it still accepts events the broker queued while it was down. A new member needs no floor: the zone key rotates when membership changes, so it cannot open older events |
| **Rejected** | A counter persisted per event: a write per event at the utility. Device option 1: a rebooted device would refuse **every** event issued before its new ZONEKEY, including unexpired restoration and cold-load-pickup events queued during an outage. This was found while planning the code, and the team switched to option 2. Option 3: an event delivered between the last contact and the reboot could be replayed once |
| **Trade-offs** | One small flash record per accepted DR event (a few per day, negligible wear) |
| **Evidence** | Raised as OPEN-4 in IMPLEMENTATION-ROADMAP.md; decided by the team 2026-09-25 |
| **Amended 2026-09-29** | Clarifications 5–6: `bseq = utility_epoch(32) ‖ per_zone_counter(32)`; **no** ZONEKEY floor; the device persists the highest accepted `bseq` per **logical** zone (stored 100, reboot: queued 101 accepted, retried 100 refused; reboot again: retried 101 refused). Still-valid events are re-sent under the current group key after re-establishment (§11), so a rotation while a device is away does not lose them |
| **Future trigger** | None |

## DR-049: Superseded secrets in device flash

| Field | Content |
|---|---|
| **Question** | The log-structured record store never overwrites in place, so an old ticket's `psk` stays in flash until its page is erased. How long may it stay? |
| **Options** | 1. **At most the 7-day chain cap: compact whenever a superseded secret record is older than 7 days (and at boot)**. 2. Compact after every resume. 3. Accept residue until the bank fills |
| **Decision** | **1** |
| **Why** | A captured device (in scope, §2.1) must not reveal PSK sessions older than the window PSK mode already accepts (§14.11). Wear: about one extra bank erase a week |
| **Rejected** | 2: about one bank erase per resume (≈14 years of life on 10,000-cycle flash at 4 resumes/day). 3: residue with no upper bound |
| **Trade-offs** | Needs a clock; after a reboot the age is unknown, so the store compacts at boot if any superseded secret is present |
| **Evidence** | Raised as OPEN-6 in IMPLEMENTATION-ROADMAP.md; decided by the team 2026-09-29 |
| **Amended 2026-09-29** | Clarification 7: residue may stay physically in flash for a while, but software enforces the 7-day maximum on device time (RTC + authenticated offset). Production paths: boot, every authenticated time update, the device main loop, every ticket write. A bank is not erased on every resume. No claim of erasure while powered off |
| **Future trigger** | A secure element that stores the ticket outside the log |

## DR-050: Anchor revocation authority

| Field | Content |
|---|---|
| **Question** | Which anchor may sign a KEYREVOKE for which? |
| **Options** | 1. Any different, non-revoked anchor (symmetric; §15.14 as first written). 2. **Asymmetric: only the offline recovery anchor B may revoke the release anchor A; A can never revoke B**. 3. Either, but only after a veto delay |
| **Decision** | **2** |
| **Why** | A signs every release, so it is the key most likely to be stolen. Under 1, a thief of A can revoke B first and leave only the stolen key, which can never be revoked. Under 2 a stolen A is always recoverable |
| **Rejected** | 1: whoever acts first wins, and the likelier theft (A) is fatal. 3: new protocol state and a timing rule |
| **Trade-offs** | A stolen B is fatal (as under 1). B is the least exposed key: offline, separate custodian, used only for recovery |
| **Evidence** | Raised as OPEN-7 in IMPLEMENTATION-ROADMAP.md; decided by the team 2026-09-29 |
| **Amended 2026-09-29** | Clarification 8, the full lifecycle: while A is active, A signs ordinary releases, B must **not** sign them, B may sign KEYREVOKE(A), A may never revoke B. After A is revoked, B is the active recovery/release anchor and signs subsequent releases; A is permanently unauthorised |
| **Amended 2026-09-30 (audit M-1)** | **Where the utility's revocation state lives and when it is checked.** The utility has **one** authoritative set of revoked anchors: those its published KEYREVOKEs revoked, durable in its database before the broker is told. A policy that is not yet in force is checked against the set of *now* when it is scheduled, when it is activated (a scheduled policy is re-checked at every activation attempt, not with the snapshot taken when it was scheduled), after a restart, when an ACL is compiled for it and when it would be republished. The policy **already in force** is not re-judged by a later revocation: like a device's installed policy it stays until a newer one, signed by the release anchor of the day, replaces it (so the utility and the fleet never end on different policies). Before this, an A-signed policy scheduled before KEYREVOKE(A) was still activated by the utility and refused by every device. Tested in `tests/security/test_revocation_authority.py` [SIM] |
| **Future trigger** | More than two anchors in new hardware (a quorum rule becomes possible) |

## DR-051: Utility key rotation

| Field | Content |
|---|---|
| **Question** | How does the utility move to new E2E and command keys that a new policy names (§12 Policy Updates, §4.7, §23.7)? |
| **Options** | 1. **Prepared keys, selected by the active policy**: the utility holds a keyring of private keys (current and prepared), and uses the pair whose public keys its active policy names. 2. A separate "active key" record switched at activation. 3. Private keys delivered inside the policy |
| **Decision** | **1**. A policy whose private keys the utility does not hold is refused when scheduled and when activated (before any state changes); a utility is never started on a policy whose keys it does not hold. Commands and retained DR events signed before a command-key rotation are re-signed under the active key with the same `cmd_seq` / `bseq` before they are sent (the device classifies by sequence, and verifies with the key of its installed policy). The E2E endpoint keeps the two most recent retired E2E keys only to **recognise** a client hello from a device still on an older policy, refuse it as such and republish the current policy (E-4 trigger 2); a hello under a retired key never establishes a session |
| **Why** | The persisted active policy is the single record of which keys are in use, so a crash or restart can never leave the policy naming one key while the utility uses another. Found by the independent release audit (H-1): activating a policy with new keys used to succeed while the utility kept its old keys, which refused every device's handshake |
| **Rejected** | 2: a second record that a crash can leave inconsistent with the policy. 3: private keys must never travel in a broadcast artifact |
| **Trade-offs** | The keyring holds old private keys (prototype: the utility database, L16); a re-signed command carries a new σ over the same fields |
| **Evidence** | `tests/security/test_key_rotation.py` (KEM, command and both keys; missing and mismatched keys; crash before and after the activation write; restarts; queued commands and DR events; duplicate and older policies; retired-key hellos) [SIM]; rollout through both main loops over the broker, then a device power cycle and a utility restart [DOCKER] |
| **Future trigger** | HSM integration (§30) |

## DR-052: CONNECT properties after a policy change

| Field | Content |
|---|---|
| **Question** | When does a class's Maximum Packet Size, Session Expiry or Keep Alive change for a device that is connected when a new policy is activated (§12 "takes effect at the next connection")? |
| **Options** | 1. **The device reconnects once when a newly installed policy changes a CONNECT value**, at its §12 re-handshake time and before it re-establishes. 2. Wait for the next natural reconnect. 3. The utility tracks each device's declared values |
| **Decision** | **1**, plus two sizing rules at the utility: unicast messages follow the current policy (they go only to devices established under it, which reconnected first); POLICY and KEYREVOKE artifacts fit the class **delivery floor**, the smallest max_packet any policy the utility activated gave the class (a device still on an older policy must still receive the policy that updates it), persisted; FIRMWARE follows the current policy, and a device re-subscribes to retained artifacts after a CONNECT that raised its maximum. A policy that changes no CONNECT value causes no reconnect |
| **Why** | The broker enforces what the live connection declared and drops anything larger silently [DOCKER T1]. Found by the independent release audit (H-2): after a policy raised c2_meter from 4,096 to 16,384 B, the NT answering a DF with an alert backlog was dropped and the device could not re-establish while its (healthy) connection lasted |
| **Rejected** | 2: silent loss for as long as the connection lasts (indefinitely for PERSISTENT classes). 3: the declared values are not visible to the utility |
| **Trade-offs** | One extra TCP + TLS + CONNECT per device per policy that changes a CONNECT value (spread by the §12 random delay); a raised max_packet benefits POLICY/KEYREVOKE artifacts only when every earlier policy allowed it |
| **Evidence** | `tests/integration/test_connect_properties.py` [DOCKER, real Mosquitto]: the broker's own CONNECT log and forwarding behaviour — raise (backlog of 60 alerts, one reconnect, new Keep Alive, 10 kB forwarded afterwards, no reconnect storm), lower (10 kB dropped, 3 s session expiry applied), broker outage across the activation, device reboot, a policy with no CONNECT change (no reconnect), FIRMWARE and a DR event above the old limit delivered, a POLICY above the floor refused, floor kept across a utility restart |
| **Future trigger** | An MQTT client stack that can update these values without a reconnect |

---

# 21. Alternatives Considered

Everything the project deliberately does **not** use, with the reason and what would reopen it.

| Alternative | Where it would go | Why not (evidence) | Revisit when |
|---|---|---|---|
| ML-KEM-512 | TLS, E2E | Category 1 margin for 15–20-year secrets; the saving is negligible next to ECDSA and radio [LIT pqm4] | Never, for this threat model |
| ML-KEM-1024 | TLS, E2E | +60% cycles, +384/480 B, no need [LIT pqm4] | Lattice cryptanalysis erodes Category 3 |
| Pure ML-KEM (no X25519) | TLS, E2E | Single-algorithm risk for recorded traffic (P1) | Guidance allows it (one config line) |
| HQC, BIKE, McEliece | KEM | Not final (HQC); huge keys (McEliece); slow on an M4 (BIKE, HQC) [LIT pqm4] | HQC final, as a diverse backup |
| ML-DSA-44 | Commands | Marginal gain once high-rate traffic uses GRANTs | Bandwidth becomes critical at discrete rates |
| ML-DSA-87 | Commands | +40% bytes, +73% verify, no need | Guidance requires Category 5 |
| **ML-DSA-65 for firmware** | Anchor | Lattice risk for an irreplaceable key | Never, for anchors |
| **SLH-DSA-SHA2-192s** | Firmware (v2.1) | 16.4 KB manifest dropped at ≤ 16 KiB limits [DOCKER T1]; SHA-512; 1.8× verify cycles | Guidance requires Category 3+ (use parted delivery) |
| SLH-DSA 'f' variants | Firmware | Bigger **and** slower to verify [LIT pqm4] | Never |
| LMS/HSS, XMSS | Firmware | Stateful: a reused state breaks security; needs an HSM-backed station | Production station with HSM state management |
| ML-DSA + Ed25519 dual signature | Firmware | Reduces to ML-DSA after quantum computers | Never |
| **FN-DSA (Falcon)** | Commands | FIPS 206 not final; no vetted library in the stack (it is the best technical fit: the device only verifies) | FIPS 206 final + vetted library |
| **Ascon-AEAD128** | AEAD | No TLS suite, so an extra AEAD (not the key size) | An 8/16-bit direct-client class |
| AES-GCM only / ChaCha20 only | AEAD | One size does not fit hardware-AES and no-AES classes | — (per-class choice, DR-003) |
| ML-DSA certificates | Hop | 23.8–31.7 KB handshakes [DOCKER] | CRQC timeline / deprecation milestone |
| Per-device TLS PSK | Hop | Mosquitto 2.0 supports it only on TLS 1.2 with classical DHE [DOCKER T7]; secrets on the broker | A broker supporting TLS 1.3 external PSK with psk_dhe_ke |
| Username/password | Hop | Phishable; stored at the broker | Never |
| **TLS-only security** (keys from `K_TLS`) | Alerts, commands | The broker reads and forges; K_TLS is not exportable in Python | Never |
| **E2E-only security** (no TLS) | Everything | TELEMETRY, topic names and MQTT framing exposed to the network; no hop identity for the ACL | Never, for MQTT through a shared broker |
| Malina-style broker re-encryption | E2E | The broker sees plaintext | Never |
| **Sign every set-point** | High-rate control | 61 MB/day, 7 h airtime at 5-s rates [ANALYTICAL] | Never at those rates |
| **Unsigned set-points** (session AEAD only, no GRANT) | High-rate control | Loses command-key authority; no local bounds | Never |
| Signed zone-key delivery | DR | Session AEAD already authenticates; +3.4 KB per member per rotation | Never |
| **Clean MQTT sessions + reconnect per message** | Transport | +1 RTT per wake; handshakes dominate bytes [SIM T6, ANALYTICAL] | — (per-class choice) |
| MQTT QoS 2 | Transport | +2 RTT per message; cannot give E2E exactly-once through a broker | Never |
| 0-RTT (early data) | Resume, TLS | Replayable | Never for CONTROL |
| `psk_ke` TLS resumption | Hop | Saves ~2.3 KB but loses hop forward secrecy against broker ticket-key theft | Bytes become critical and the hop FS risk is accepted |
| Confirm before use (v2.1 D17) | Establishment | +1 RTT that ACK + outbox already cover | — |
| Broker-held ticket key | PASR | The broker is not a party to the E2E session | Never |
| Stateful utility session cache | PASR | Grows with the fleet; lost on restart | Never |
| JSON persistence | Utility | Torn writes, O(n) [DOCKER S3, S4] | Never |
| Canonical JSON encoding | Protocol, policy | Parser, size, canonicalisation | Never |
| Standard TLS certificate time checks on devices | Hop | Clock-reset deadlock [DOCKER T4] | Devices gain authenticated time before TLS |
| NTP / NITZ as the time source | Device | Unauthenticated | Authenticated network time on target modems |
| Battery-backed RTC as a requirement | Device | Not universal; hardware cost (useful where present) | — |
| A single firmware anchor | Bootloader | Unrecoverable key loss or compromise | Never |
| Modem-offloaded TLS | Device | Not PQ (e.g. nRF91 modem TLS 1.2) | Modem firmware adds hybrid groups |
| Mbed TLS | Device TLS | No ML-KEM yet (roadmap "future") | ML-KEM released in TF-PSA-Crypto |
| CoAP/DTLS, MQTT-SN | Transport | Out of project scope (MQTT fixed); literature favours UDP on NB-IoT | Future work (§30) |
| Hardware independence | Claim | False (§5) | Never |

---

# 22. Performance / Resource Analysis

**Environment reminder:**
- **[DOCKER]** numbers are laptop numbers;
- MCU numbers are **[LIT]** or **[ANALYTICAL]** lower bounds;
- nothing here is a smart-meter measurement.

## 22.1 CPU

**Device public-key work per event** [ANALYTICAL from LIT: pqm4, Haase-Labrique, Tasopoulos 2022, RP2040,
Düll 2015]:

| Event | ML-KEM-768 ops (kg/enc/dec) | X25519 mults | ECDSA (sign/verify) | M4 M cycles | @64 MHz | @24 MHz | M0+ @125 MHz |
|---|---|---|---|---|---|---|---|
| TLS full (hybrid, mutual ECDSA) | 1/0/1 | 2 | 1/2 | 13.9 | 217 ms | 579 ms | 831 ms |
| TLS resumed | 1/0/1 | 2 | 0 | 2.6 | 41 ms | 108 ms | 95 ms |
| E2E full | 1/1/2 | 5 | 0 | 5.8 | 91 ms | 243 ms | 222 ms |
| E2E PSK+KEM | 1/0/1 | 2 | 0 | 2.6 | 41 ms | 108 ms | 95 ms |
| E2E PSK | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| **Cold start** (TLS full + E2E full) | 2/1/3 | 7 | 1/2 | **19.7** | **308 ms** | **821 ms** | **1,053 ms** |
| CMD or GRANT verify (ML-DSA-65) | — | — | — | 2.42 (fast) / 5.73 (small stack) | 38 / 90 ms | 101 / 239 ms | 72 ms |
| SETPOINT | AEAD only | — | — | ~0 | — | — | — |
| Firmware or policy manifest verify (SLH-128s) | — | — | — | 7.47 | 117 ms | 311 ms | **[HW]** |

**Cold-start shares:** ML-KEM 21%, X25519 22%, **ECDSA 57%**.

**Laptop** [DOCKER]:

| Operation | Time |
|---|---|
| E2E full, device / utility | 0.278 / 0.229 ms |
| E2E PSK, device / utility | 0.021 / 0.030 ms |
| CONTROL open + verify | 0.118 ms |
| ML-DSA-65 sign / verify | 0.556 / 0.101 ms |
| SLH-128s sign / verify | 167.5 / 0.164 ms |
| Hybrid X25519 vs ML-KEM | +122% compute |

## 22.2 RAM

**Peak simultaneous RAM of the security path** [ANALYTICAL]. Application, RTOS, IP stack and modem driver
are **excluded [HW]**.

| Moment | Default | Constrained profile |
|---|---|---|
| Full connection (TLS buffers + E2E handshake) | 50.2 KB | 16.7 KB |
| Manifest receive + verify | 51.8 KB (192s, in RAM) | ~8–10 KB (128s, streamed, verified from flash) |
| CONTROL receive + ML-DSA-65 verify | 45.1 KB | 8.1 KB |

**The TLS record buffers dominate:** 2 × 16 KiB by default. The broker sends 16,401 B records unless asked
for max_fragment_length (512 → ≤ 529 B records; 1,024 → ≤ 1,041 B) [DOCKER T3].

## 22.3 Flash

| Item | Size |
|---|---|
| Crypto code (excluding hashing and TLS) [LIT pqm4]: ML-KEM-768 | 13.3 KB |
| ML-DSA-65 | 19.3–24.1 KB |
| SLH-DSA-128s verify | 5.3 KB |
| TLS library, MQTT client, RTOS | **[HW]** |
| Persistent data (§16): keys | ~2.5 KB |
| Certificates | ~0.9–1.3 KB |
| Policy (binary) | ~3.5 KB |
| Ticket | ~0.3 KB |
| Device record store (outbox, intents, ticket, RH, FOTA records, zones, time floor) | 32 KiB: 2 banks × 4 × 4 KiB (§16 Device Storage Capacity) |
| A/B | 2 × image (§15.10) |

## 22.4 Stack

| Operation | Stack [LIT pqm4] (excluding buffers) |
|---|---|
| ML-KEM-768 | 2.8 KB (small) / 6.5 KB (fast) |
| ML-DSA-65 verify | 2.7 KB / 9.9 KB |
| SLH-DSA-128s verify | 2.0 KB |
| Falcon-512 verify | 0.4 KB |
| M0+ reference C: ML-KEM-768 decaps | 14.2 KB (18.9 KB total) [LIT RP2040] |
| M0+ reference C: ML-DSA-65 *sign* | 77.6 KB (never done on the device) [LIT RP2040] |

## 22.5 Code Size

See Flash. Hashing (Keccak, SHA-256) is shared. **One AEAD per device** (DR-003) avoids a second AEAD
implementation.

## 22.6 Bandwidth

**Per message** [DOCKER T5]:
- TELEMETRY 64 B: 128 B (QoS 0), 157 B (QoS 1), 94 B (QoS 0 with a topic alias);
- ALERT: 231 B;
- CMD: ~3.55 KB on the wire;
- SETPOINT: 97 B envelope [DOCKER, v2.2 code].

**Handshakes:**

| Handshake | Bytes |
|---|---|
| TLS full + CONNECT | 6,262 B [DOCKER T5] |
| TLS resumed + CONNECT | 4,438 B [DOCKER T5] |
| E2E full | 5,221 B [DOCKER, v2.2 code] |
| E2E PSK | 761 B [DOCKER, v2.2 code] |
| E2E PSK+KEM | 3,097 B [DOCKER, v2.2 code] |

**Per day** [ANALYTICAL]:

| Profile | Bytes/day | Security share |
|---|---|---|
| P1 meter, 15-min wakes, full / resumed TLS | 0.62 / 0.44 MB | 98% / 97% |
| P1 meter, batched 4×/day | ~0.03 MB | — |
| P2 DER, 2030.5-style | 0.10 MB | 21% |
| P3 stress, v2.1 | 63.0 MB | — |
| P3 stress, v2.2 GRANT | 5.23 MB | — |

These per-day figures were computed from the pre-implementation sizes. With the measured v2.2 sizes they move by
under 1%, except P3 GRANT (+1.3%, because SETPOINT is 97 B rather than 93 B).

**Not counted above** [ANALYTICAL, continuous audit C3]: for a device in DR zones, every (re)establishment also brings
the still-valid events of its zones again (M4, §11: ~3.5 KB each for a 64-byte event, at most 64 retained per
zone), which the device drops by `bseq` if it already accepted them. With few short-lived events this is small; a
device that wakes often while long-lived events are valid pays it at every wake. Sending only events newer than the
device's last accepted `bseq` would need a protocol change (a decision record), so it is recorded, not changed.

## 22.7 MQTT Packet Size

| Item | Size |
|---|---|
| Broker limit | 300,000 B |
| Device limit | per class |
| v2.1 manifest (192s) | 16,405 B: silently dropped at limits ≤ 16,384 [DOCKER T1] |
| v2.2 manifest (128s) | 8,031 B, delivered in parts (3 parts at a 4 KiB limit, 1 at 8 KiB) [DOCKER, v2.2 code] |
| Chunk | 4 KiB + 256 B proof + ~50 B header |

## 22.8 Radio Airtime

At 20 kbit/s (NB-IoT-good assumption) [ANALYTICAL]:

| Traffic | Airtime |
|---|---|
| P1 meter, 15-min wakes | 2.9–4.1 min/day |
| P1 meter, batched | ~0.2 min/day |
| P2 DER | 0.7 min/day |
| P3 stress, v2.1 | 7.0 h/day |
| P3 stress, v2.2 | 35 min/day |
| One 8,031 B manifest | ~3.2 s |
| 1 MiB firmware | ~7.4 min (4 KiB chunks + proofs) |

## 22.9 Energy

**Only measured sources are used.** No value is invented.

| Source | Value | Measured? |
|---|---|---|
| Tasopoulos 2023, whole board at 180 MHz, 3.3 V, including ~100 mW idle | Kyber-768 keygen/enc/dec 1.89/1.80/1.24 mJ; ECDSA verify 4.78 mJ; Dilithium3 verify 2.59 mJ; SPHINCS+-128s verify 12.0 mJ; PQ TLS client handshake 15.0–25.4 mJ; ECDSA+ECDHE 18.2 mJ | **Measured** |
| Lukic 2020, Quectel BC68, live network | NB-IoT UDP echo ≈ 275–415 mAs (16–1,024 B); ~64% is the 5-s inactivity timer | **Measured** |
| Kim & Seo 71.75 mJ | — | **Calculated** |
| RP2040 | — | **Estimated** from a datasheet |
| Alghawli radio | — | **Simulated** |

**The ratio** [ANALYTICAL]:
- a cold start's crypto is ~39 mJ on that board (P-256 used as a proxy, so over-estimated);
- **one** 64-byte NB-IoT exchange costs ~282 mAs, i.e. 0.85–1.0 J at 3.0–3.6 V (voltage not stated);
- so the radio costs **≥ ~20–25×** the crypto per reconnect.

**Conclusion:** reduce wake-ups, round trips and active-waiting time; algorithm choice barely moves energy. A
per-day energy figure for the design needs hardware **[HW]**. Energy matters most for battery gas and water
meters; electricity meters, DER and chargers are mains-powered.

## 22.10 Storage Writes

**Device** [ANALYTICAL]:
- meter ~100 writes/day, so one 4 KiB page lasts ~70 years;
- no per-SETPOINT writes;
- discrete commands: 2 records each.

**Utility:**
- v2.1 rewrote 4.8 MB per resume at 100k tickets (~480 GB/day) [DOCKER S4];
- v2.2 does one indexed insert per resume.

## 22.11 FOTA Storage

`bootloader + 2 × image + ~8 KB manifest staging + persistent data (+ scratch)` (§15.10):
- C2 usually needs external flash for slot B, re-verified at boot;
- C3 fits in-chip.

## 22.12 Latency

Time to the first E2E-protected message [SIM T6]:

| Link | v2.1 wake | v2.2 (scenario D) | Cold start |
|---|---|---|---|
| LTE-M-like | 1.46 s | **1.02 s** | 1.72 s |
| NB-IoT-good | 8.25 s | **6.02 s** | 10.77 s |
| NB-IoT-poor | 46.1 s | **35.9 s** | 71.2 s |

**Round trips:** a cold start takes 6 RTT; the v2.2 wake takes 4 (TCP, TLS, CONNECT, 1-RTT PSK).

## 22.13 Reconnection Cost

| Reconnect | Bytes | Device public-key cycles | Round trips | Notes |
|---|---|---|---|---|
| Cold (full TLS + full E2E) | 11,870 | 19.7 M | 6 | [DOCKER/SIM] |
| Reboot (full TLS + PSK) | 7,414 | 13.9 M | 6 → 5 with a persistent session | — |
| Wake within 2 h (TLS resumed + PSK), v2.1 | 5,590 | 2.6 M | 6 | — |
| **Wake, v2.2 (D)** | 5,866 (with the first alert and ACK) | 2.6 M | 4 | — |
| Telemetry-only wake (no E2E) | 4,579 | 2.6 M | 4 → 3 with pipelining | — |

---

# 23. Security Analysis

## 23.1 Confidentiality

| Data | Against the network (incl. a quantum recorder) | Against the broker | Residual |
|---|---|---|---|
| TELEMETRY | Hybrid TLS | **Readable by design** | Occupancy inference by the utility-run broker; sensitive data belongs on ALERT |
| ALERT, CONTROL | Hybrid TLS + E2E hybrid | E2E hybrid | Holds while either X25519 or ML-KEM holds (hop and E2E) |
| DR events | Hybrid TLS + zone key | Zone key | Captured members read their zone until rotation |
| Firmware, policy | Public by design | Public | — |

## 23.2 Integrity

| Mechanism | Scope |
|---|---|
| AEAD | Every E2E envelope and TLS record |
| Merkle + SLH-DSA | Artifacts |
| Transcript MACs | Handshake integrity |

Tested:
- one flipped bit on the wire → not delivered, connection dropped (N2);
- tampered chunk (F1) and manifest (F2) rejected;
- 3,300 + 16,500 fuzzed messages rejected cleanly.

## 23.3 Authentication

| Party | How it is authenticated |
|---|---|
| Hop | ECDSA mutual certificates (classical; live-only; replaceable, DR-004) |
| E2E | KEM-based mutual: only U can open `ct_U`; only D can open `ct_D` |
| Commands and GRANTs | ML-DSA-65 under the command key |
| SETPOINTs | Session AEAD **within a signed GRANT bound to that session** |
| Artifacts | SLH-DSA-128s under a non-revoked anchor |

## 23.4 Replay

See §9.6. The v2.2 additions:
- the epoch-based command sequence (restart- and restore-safe);
- persist-before-respond for tickets;
- SETPOINT newest-wins per grant;
- the identical-RH retransmission rule.

## 23.5 Downgrade

| Downgrade | Defence |
|---|---|
| Classical TLS | Hybrid pin + TLS 1.3-only listeners |
| Policy or tier | Binding and validator (A1–A4, A6, A13) |
| Resume mode | Check 8 (P6) |
| Firmware or policy rollback | Monotonic counters (F4–F6) |
| Profile | Fixed in the signed policy, never negotiated |

## 23.6 Forward Secrecy

| Where | Forward secrecy? |
|---|---|
| Full E2E handshake; PSK+KEM resume | Yes (ephemeral hybrid KEM) |
| PSK chains | No; capped at 7 days, and forbidden for unicast-control classes |
| TLS hop | Via (EC)DHE in full and psk_dhe_ke resumed handshakes |
| Long-term static E2E keys | A stolen utility static key reads **new** sessions of devices that use it, not past full-handshake sessions (ephemeral key) (RISK test) |

## 23.7 Key Compromise

| Stolen key | Consequence | Containment |
|---|---|---|
| Device E2E or TLS key | Impersonate **that** device | Revoke in the registry (P9) |
| Utility E2E key | Read new sessions; **no command forgery** | New policy naming a new key (key rotation, DR-051) |
| Command key | Forge commands and GRANTs | HSM, separation of duties, rotation through policy (DR-051) |
| STEK | Mint tickets (RISK) | HSM; revocation still checked |
| Anchor | Forge firmware | KEYREVOKE by the other anchor |
| CA | Hop impersonation | ALERT/CONTROL still E2E-protected; CA roll-over through policy |

## 23.8 Broker Compromise

The broker can:
- read TELEMETRY;
- drop, delay or reorder (DoS);
- serve stale retained artifacts (refused: rollback);
- attempt downgrades (fail closed);
- impersonate devices only at the hop (it cannot forge E2E envelopes or signatures).

It **cannot** read or forge ALERT/CONTROL, or forge firmware or policy.

## 23.9 Device Compromise

A captured device holds only its own keys. It cannot:
- use other devices' topics (ACL: A12);
- replay other devices' envelopes (ownership check);
- forge commands or DR events (A10, A11).

It **can** read its zone's DR events until rotation, and act as itself.

## 23.10 Firmware Compromise

- Malicious firmware needs an anchor signature.
- A compromised anchor is revoked with the other one.
- Rollback is blocked by the committed counters.
- A tampered external slot B is caught by boot-time re-verification.

## 23.11 Clone / Stolen Credential

| Layer | What happens |
|---|---|
| Hop | A clone evicts the genuine connection (N4) |
| E2E | Whoever resumes second gets "ticket already used", which raises an **alarm**; the full handshake evicts the other session (one live session per device) |

Response: revoke and re-provision.

## 23.12 Crash / Power Loss

§9.8 and §16. After v2.2:
- the utility is crash-safe (WAL);
- device actuation is honestly reported (intent log);
- FOTA is safe at every step, with the swap power-safety left for **[HW]**.

## 23.13 Duplicate / Reordering

- Idempotent handlers and identical-reply caches (per-class windows).
- Sequence numbers with a two-phase check.
- Commands resolved newest-wins, with DUP/SUPERSEDED.
- Envelopes ride inside DF, so they cannot overtake it.

## 23.14 DoS — explicitly out of scope

Flooding, jamming and a broker dropping traffic can be **detected** (the heartbeat stretch goal; ACK
timeouts) but not prevented.

Bounded costs:
- one half-open handshake per device;
- rate-limited resync hints;
- field caps;
- queue limits.

---

# 24. Attack Validation

**Status codes**

| Code | Meaning |
|---|---|
| **PASS-v2.1** | Passed in `design-validation` (80/80, network N1–N7); the behaviour is unchanged in v2.2, and it will be re-run on the v2.2 code |
| **PASS-v2.1 → UPDATE** | Passed in v2.1, but v2.2 changes the expected behaviour; the test must be rewritten |
| **FAIL-v2.1 → FIX SPECIFIED** | The audit demonstrated a failure in v2.1; the v2.2 fix is specified, **not yet validated** |
| **NEW** | A v2.2 test, **not yet run** (none remain: see PASS-v2.2) |
| **PASS-v2.2** | Implemented and passing in the v2.2 reference (`pqgrid`) [SIM, DOCKER] (IMPLEMENTATION-ROADMAP §7–§13); never [HW] |

"Actual result" quotes the v2.1 run.

## 24.1 PCHC (policy, tiers, E2E, commands)

| ID | Attack / scenario | Expected | Actual (v2.1) | Property | Status |
|---|---|---|---|---|---|
| A1 | Broker changes POLICY_INFO in CH | Reject | "client hello failed authentication" | Downgrade | PASS-v2.1 |
| A2 | Broker changes POLICY_INFO in SH | Reject | "server hello failed authentication" | Downgrade | PASS-v2.1 |
| A3 | CH replayed onto another device's topic | Reject | "identity does not match the device's topic" | Authentication | PASS-v2.1 |
| A4 | Device on an old policy connects | Reject | "POLICY_INFO mismatch: device must install current policy" | Downgrade | PASS-v2.1 |
| A5 | Curious broker reads an alert | Only ciphertext | No plaintext seen | Confidentiality vs broker | PASS-v2.1 (live test in Phase 1) |
| A6 | Tier stripping: plaintext on an ALERT topic | Drop | "unknown session" | Downgrade | PASS-v2.1 |
| A7 | Seal an alert on a TELEMETRY topic | Refused by the sender | "topic is not ALERT tier under installed policy" | Tier enforcement | PASS-v2.1 |
| A8 | Alert replay; forged alert must not burn the sequence | Replay rejected; next genuine accepted | "seq 1 <= 1"; forged tag did not consume | Replay | PASS-v2.1 |
| A9 | Command replay or redelivery, including after a reboot | DUP, never re-applied | DUP, not re-applied | Replay | PASS-v2.1 → UPDATE (v2.2 statuses, epoch seq, intent log) → PASS-v2.2 |
| A10 | Forged command by a holder of the session key but not the command key | Reject | "command signature invalid" | Command authenticity | PASS-v2.1 |
| A11 | Captured meter forges a DR event; event replay | Reject | "broadcast signature invalid"; "broadcast replay" | Authenticity; replay | PASS-v2.1 |
| A12 | Publish or subscribe to another device's topics | Not authorised / not delivered | PUBACK "Not authorized"; nothing delivered | Least privilege | PASS-v2.1 (broker) |
| A13 | Unsafe policy (unicast control + PSK) | Validator rejects | "…PSK-only resumption (no forward secrecy) is forbidden" | Downgrade | PASS-v2.1 |
| C-T1 | Tier engine: telemetry/alert/control/unknown | 1/2/3/3 | ok | Fail-safe default | PASS-v2.1 |
| C-T2 | Overlapping rules | Strongest wins | ok | Monotonicity | PASS-v2.1 |
| C-E1 | Full E2E handshake (meter, DER); keys equal | Success | ok | Key agreement | PASS-v2.1 → UPDATE (DF carries data) → PASS-v2.2 |
| C-E2 | Alert E2E + ACK | Delivered, ACKed | ok | Delivery | PASS-v2.1 |
| C-E3 | Command: AEAD + ML-DSA-65 verified, applied, ACK clears the queue | Success | ok | Command path | PASS-v2.1 → UPDATE (intent log; CMD format) → PASS-v2.2 |
| E-CMD1 | Command sent while the device is offline → redelivered next session, applied once | Applied once | ok | Delivery | PASS-v2.1 → UPDATE → PASS-v2.2 |
| E-CMD2 | ACK lost → redelivery answered DUP, never applied twice | DUP | ok | At most once | PASS-v2.1 |
| E-CMD3 | Applied, ACK lost, device reboots → redelivery DUP | DUP | ok | At most once | PASS-v2.1 → UPDATE (intent log) → PASS-v2.2 |
| E-CMD4 | Expired command not redelivered; refused if late | EXPIRED | ok | Freshness | PASS-v2.1 |
| E-CMD5 | Commands out of order → newest wins | Older not applied | ok | Ordering | PASS-v2.1 → UPDATE (status SUPERSEDED) → PASS-v2.2 |
| E-X1 | Captured meter re-publishes another meter's alert envelope on its own topic | Reject | "envelope belongs to another device's session" | Ownership | PASS-v2.1 |
| E-X2 | Device IDs with `+ # /`, uppercase, unicode, > 32 chars | Reject | ok | Injection | PASS-v2.1 |
| E-X3 | Oversized length field | Reject before allocation | "field too large" | Parser safety | PASS-v2.1 |
| E-X4 | Fuzz: 3,300 corrupted messages into 11 handlers (+16,500) | All rejected cleanly | ok | Robustness | PASS-v2.1 |
| E-X5 | Handshake flood from one device | ≤ 1 half-open state | ok | Resource bound | PASS-v2.1 |
| E-X6 | Old CH replayed while a session is live | Live session unaffected | ok | Replay | PASS-v2.1 |
| E-Z1 | Member removed from a zone (holds the old epoch key) | Cannot read the new epoch | "no key for zone/epoch" | Backward secrecy | PASS-v2.1 |
| **S1** | Utility restart, then a new command | Applied | **Answered DUP, silently dropped** | Command liveness | **FAIL-v2.1 → FIX SPECIFIED** (epoch ‖ counter, persisted) |
| **S2a** | Crash after the counter write, before actuation (ACK not sent) | INTERRUPTED reported | **Never applied; utility dropped it** | Honest apply | **FAIL-v2.1 → FIX SPECIFIED** (intent log) |
| **S2b** | Crash after an OK ACK, before actuation | Cannot happen (OK only after APPLIED) | **False OK; nothing to redeliver** | Honest apply | **FAIL-v2.1 → FIX SPECIFIED** |
| V-G1 | Forged GRANT (no command key) | Reject: signature | — | Command authority | PASS-v2.2 |
| V-G2 | GRANT from session X used in session Y | Reject: sid | — | Session binding | PASS-v2.2 |
| V-G3 | SETPOINT without a live GRANT | REJECTED (no grant) | — | Command authority | PASS-v2.2 |
| V-G4 | SETPOINT out of bounds / too fast / after expiry | REJECTED (bounds / rate / expired) | — | Safety limits | PASS-v2.2 |
| V-G5 | Replayed or older SETPOINT | SUPERSEDED, not applied | — | Replay, ordering | PASS-v2.2 |
| V-G6 | SETPOINT forged by the broker (no session key) | AEAD fails | — | Integrity | PASS-v2.2 |
| V-S1 | Utility restart and DB restore from an old backup, then a new command | Applied (epoch newer) | — | Liveness | PASS-v2.2 |
| V-S2 | Fresh command answered DUP/SUPERSEDED | Utility regression alarm | — | Detectability | PASS-v2.2 |
| V-S3 | Crash at each intent-log step | Correct final status (OK / INTERRUPTED / re-applied if idempotent) | — | Honest apply | PASS-v2.2 |
| V-Z1 | ZONEKEY delivered under the session (unsigned) cannot be forged by the broker | AEAD fails | — | Integrity | PASS-v2.2 |
| V-D1 | DF with bundled alerts; utility processes them after MAC_D | Delivered once | — | 1-RTT correctness | PASS-v2.2 |
| V-D2 | DF with a bad MAC_D and bundled alerts | Nothing processed | — | Authentication | PASS-v2.2 |
| V-D3 | Lost DF → identical DF resent → identical NT; alerts not duplicated | One delivery | — | Idempotency | NEW (replaces "confirm before use" EDGE) |

## 24.2 PASR

| ID | Attack / scenario | Expected | Actual (v2.1) | Property | Status |
|---|---|---|---|---|---|
| P1 | RH replayed after the duplicate window; same ticket with a fresh RH (clone) | "already used" | "ticket already used" | Single use | PASS-v2.1 |
| P2 | Stolen blob without the psk | "binder invalid"; genuine ticket survives | as expected | Possession | PASS-v2.1 |
| P3 | Ticket on another device's channel | Reject | "ticket/device identity mismatch" | Binding | PASS-v2.1 |
| P4 | Expired ticket or chain | Reject | "ticket expired" | Freshness | PASS-v2.1 |
| P5 | Ticket after a policy change | Reject | "ticket issued under a different policy" | Binding | PASS-v2.1 |
| P6 | Mode downgrade (strip the fresh KEM) | Reject | "resume mode does not match policy" | Downgrade | PASS-v2.1 |
| P7 | Ticket after a firmware update | Reject | "ticket issued for different firmware" | Binding | PASS-v2.1 |
| P8 | Ticket under a retired STEK | Reject | "ticket key retired" | Key lifecycle | PASS-v2.1 → UPDATE (16-bit kid, automatic retire) → PASS-v2.2 |
| P9 | Revoked device (resume and full handshake) | Reject | "device unknown or revoked" / "unknown or revoked device" | Revocation | PASS-v2.1 |
| P10 | Alerts on an old-policy session after activation | Reject | "session belongs to an old policy" | Binding | PASS-v2.1 |
| E-P1 | Duplicate RH within the window | Identical RS | ok | Idempotency | PASS-v2.1 |
| E-P2 | Utility restart → resync → PSK resume → unACKed alert resent | Delivered | ok | Recovery | PASS-v2.1 → UPDATE (SQLite store; alert inside DF) → PASS-v2.2 |
| E-P3 | Counterfactual: restart without a persisted STEK | Every ticket dies | "ticket not authentic" | Why the STEK is persisted | PASS-v2.1 |
| E-P4 | Consumed ticket replayed after a restart | Reject | "ticket already used" | Single use | PASS-v2.1 |
| E-P5 | Clone uses the ticket first | Genuine device sees "already used" (alarm); full handshake evicts the clone | ok | Clone detection | PASS-v2.1 |
| **S3** | Torn write of used.json / stek.json | Restart OK; no ticket forgotten | **Restart fails (JSONDecodeError)** | Availability, replay | **FAIL-v2.1 → FIX SPECIFIED** (SQLite WAL) |
| **S4** | 100k outstanding tickets | Constant cost per resume | **4.8 MB / 41.9 ms rewrite per resume** | Scalability | **FAIL-v2.1 → FIX SPECIFIED** |
| **S5** | Rebuilt RH after the first was processed | (by design) full handshake; **v2.2:** the identical RH is resent and gets the same RS | "ticket already used" | Single use vs recovery | Behaviour confirmed; v2.2 retransmission rule **NEW** |
| RISK-1 | Stolen STEK | Attacker mints tickets (shown **succeeding** on purpose) | ok | Why an HSM | PASS-v2.1 (documented risk) |
| RISK-2 | Stolen utility E2E key | Reads new sessions, **cannot forge commands** | ok | Separation of keys | PASS-v2.1 (documented risk) |

## 24.3 PQC-FOTA

| ID | Attack / scenario | Expected | Actual (v2.1) | Property | Status |
|---|---|---|---|---|---|
| F1 | Tampered chunk | Reject | "chunk 17 failed Merkle verification" | Integrity | PASS-v2.1 → re-run with 128s |
| F2 | Tampered manifest | Reject | "manifest signature invalid" | Authenticity | PASS-v2.1 → re-run with 128s |
| F3 | Artifact signed by a non-station key | Reject | "manifest signature invalid" | Authenticity | PASS-v2.1 → re-run |
| F4 | Rollback to a validly signed older version | Reject | "rollback: version not newer than installed" | Anti-rollback | PASS-v2.1 |
| F5 | Replay of the installed version | Reject | same | Anti-rollback | PASS-v2.1 |
| F6 | Broker re-serves an old signed policy | Reject | same | Anti-rollback | PASS-v2.1 |
| F7 | Firmware for another class | Reject | "manifest targets another device class" | Targeting | PASS-v2.1 |
| E-F1 | Power loss mid-download | Resume, install | ok | Robustness | PASS-v2.1 |
| E-F2 | New firmware fails to boot | Revert; counter unchanged; rollback still blocked | ok | No bricking | PASS-v2.1 |
| E-F3 | Chunk from another version mixed in | Reject | "chunk from another artifact" | Integrity | PASS-v2.1 |
| E-F4 | Offline across policy v1 → v4 | Installs v4; v3 refused | ok | Currency | PASS-v2.1 |
| **T1** | Manifest larger than the device's max packet | Delivered (parted) | **Never delivered at 8,192 / 16,384** | Update availability | **FAIL-v2.1 → FIX SPECIFIED** (parts; 128s) |
| V-F1 | Parted 128s manifest at max 4,096 / 8,192 → installs | Installed | — | Availability | PASS-v2.2 |
| V-F2 | KEYREVOKE(A) signed by B → A-signed artifacts refused; B-signed accepted | as stated | — | Revocation | PASS-v2.2 |
| V-F3 | KEYREVOKE(A) signed by A, or revoking the last anchor | Refused | — | Revocation safety | PASS-v2.2 |
| V-F4 | External slot B modified after staging | Boot refuses (hash mismatch) | — | Integrity | NEW **[HW]** |
| V-F5 | Manifest with payload length > own slot | Refused before download | — | Resource safety | PASS-v2.2 |

## 24.4 Network and broker (real Mosquitto, interception proxy)

| ID | Attack / scenario | Expected | Actual | Property | Status |
|---|---|---|---|---|---|
| N1 | Replay all 16,043 captured bytes on a new connection | Nothing delivered | 0 delivered; "record layer failure" | Replay (hop) | PASS-v2.1 |
| N2 | One bit flipped in the encrypted PUBLISH | Not delivered | 0 delivered; connection dropped | Integrity (hop) | PASS-v2.1 |
| N3 | Classical-only client | Refused when pinned | Default: **accepted** (X25519); pinned: handshake failure; normal: X25519MLKEM768 | Downgrade | PASS-v2.1 (with the pin) |
| N4 | Clone connects with the same identity | Genuine kicked off (alarm) | "already connected, closing old connection" | Clone visibility | PASS-v2.1 |
| N5 | Broker restart with a retained manifest | Survives only with persistence | persistence on: kept; off: lost | Availability | PASS-v2.1 |
| N6 | 400 KB publish vs `max_packet_size 300000` | Sender disconnected; 256 KB delivered | as expected | Resource bound | PASS-v2.1 |
| N7 | TLS resumption after an IP change | Resumed | resumed | Mobility | PASS-v2.1 |
| **T4** | Device clock 1970 / +3 years; expired device certificate | Connects (v2.2) | **Refused ("not yet valid" / "expired")** | Availability | **FAIL-v2.1 → FIX SPECIFIED** (T4-d and T4-g show the fix works) |
| T7 | Per-device PSK on the hop | (evaluated as an alternative) | TLS 1.2 only, classical DHE; the pin bypassed | Downgrade | Alternative **rejected**; validator rule added |
| V-N1 | Configuration validator refuses any TLS 1.2 listener | Refused | — | Downgrade | PASS-v2.2 |
| I1 | Integrated: tampered chunk + replayed command + policy downgrade during a rollout | Each rejected by its own mechanism | — | Composition | Planned (Phase 4) |

**Totals.** 80/80 v2.1 scenarios behaved as expected, and N1–N7 passed.

The audit **demonstrated** failures in v2.1 in:
- S1, S2a, S2b, S3, S4 (state and persistence);
- T1, T4 (transport and TLS time).

Their fixes are specified here. The v2.2 tests (V-*) are **not yet run**.

---

# 25. Known Limitations

| # | Limitation | Consequence | Where addressed |
|---|---|---|---|
| L1 | **No real hardware measurement.** All MCU numbers are literature or analytical lower bounds | Feasibility per class is argued, not demonstrated | §29 |
| L2 | **v2.2 mechanisms are implemented in `pqgrid` and tested in simulation and Docker only** (GRANT/SETPOINT, intent log, epoch sequence, SQLite store, finished-carries-data, parted manifests, anchors and revocation, the time floor, logical zones): no MCU, real flash, actuator or radio validation | Claims are [SIM]/[DOCKER], never [HW] | §28, IMPLEMENTATION-ROADMAP §13 |
| L3 | T6 link results are a **model**: delay + rate + TCP handshake RTT, TCP terminated at the proxy, no radio scheduling, repetitions or loss; parameters assumed | Relative comparisons only | §22 |
| L4 | MQTT over TCP on NB-IoT is costlier than UDP options (literature). MQTT is fixed by scope | Every wake pays TCP + TLS + CONNECT | §30 |
| L5 | TELEMETRY is readable by the broker (by design) | Occupancy inference by the utility operator | §11 |
| L6 | For C0/C1 meters behind gateways, E2E ends at the gateway; the meter link is classical DLMS/COSEM | Not end to end from the meter | §4.2 |
| L7 | The hop certificates are classical (ECDSA) | Future forgery once a quantum computer exists, until migration | §30 |
| L8 | Device TLS ignores certificate validity dates | A CA compromise is time-unbounded on devices | §8.8 |
| L9 | Exactly-once actuation is impossible across a power loss | INTERRUPTED must be handled by operators | §13.7 |
| L10 | PSK-mode chains lack forward secrecy for ≤ 7 days | Accepted for classes without unicast control | §14.6 |
| L11 | No formal proof (ProVerif/Tamarin) | Security argued and tested, not proved | §30 |
| L12 | Side channels are not evaluated | Per-device keys limit the damage | §23 |
| L13 | DoS is out of scope | Detectable only | §2.4 |
| L14 | Mosquitto specifics: no native groups option; no TLS 1.3 PSK; the private `_ssl_wrap_socket` override in paho (pinned `paho-mqtt==2.1.0`) | Configuration fragility | §27 |
| L15 | Traffic profiles: P1/P2 are derived from standards and practice, P3 from a simulated 802.15.4 study; no utility trace data | Estimates, labelled | §22 |
| L16 | The HSM is only stated as a requirement; the prototype stores the STEK and command key in SQLite or files | Prototype key theft = RISK tests | §27.3 |

---

# 26. Explicitly Rejected Claims

The project **must not** claim:

| # | Claim | Why not |
|---|---|---|
| X1 | "Hardware-independent" | C0/C1 cannot run it; C2 needs a constrained profile (§5) |
| X2 | Any smart-meter or MCU performance number as *measured* | Only literature and analytical values exist (§22) |
| X3 | Universal performance ("PQC costs X% everywhere") | Ratios differ by platform: +122% hybrid compute in Docker vs +67% in the macOS venv; on an M4, ECDSA dominates |
| X4 | "60–70% faster reconnection" | Latency fell 17–23% from PASR alone on simulated NB-IoT, 44–50% with v2.2 against a cold start; compute and bytes are not latency (§14.9) |
| X5 | Exactly-once command execution | Impossible without actuator feedback (§13.7) |
| X6 | Docker, laptop or `--cpus`-limited measurements = MCU measurements | §17.2 |
| X7 | "Formally verified" | No proof exists |
| X8 | "Production-ready" | Prototype; HSM, high availability and hardware not done |
| X9 | End-to-end encryption of TELEMETRY | By design it is hop-only |
| X10 | Forward secrecy for PSK-mode sessions | Not provided |
| X11 | Protection against a compromised utility | Out of scope (GRANT bounds only limit it) |
| X12 | Resistance to DoS | Out of scope |
| X13 | "Hybrid is twice as secure" | Hybrid is secure while **either** algorithm holds |
| X14 | Setyowati et al. evaluated TLS 1.3 hybrid groups | They used TLS 1.2 + app-layer ML-KEM over HTTP |
| X15 | Kim & Seo's handshake used "only 3 KB stack" | 3 KB is their Kyber code; handshake phases used ~5.7 KB, simulated without transmission |
| X16 | Domingo et al. measured "sub-millisecond ML-DSA on reference platforms" relevant to meters | 2012 laptop; the authors warn; firmware updates are ~yearly |
| X17 | Alghawli's traffic model is "realistic AMI" | Simulated 802.15.4 with 15-**second** meter reads (stress case only) |
| X18 | Energy values from Kim & Seo (71.75 mJ) or RP2040 as measured | Calculated / estimated |
| X19 | The v2.1 "device clock reset to 1970 still connects" as a system result | It tested only the E2E layer; TLS refused the device [DOCKER T4] |

---

# 27. Implementation Requirements

## 27.1 Broker

| # | Requirement |
|---|---|
| B-1 | Mosquitto 2.0.x on OpenSSL ≥ 3.5, running as the `mosquitto` user (test configs with `user root` are test-only) |
| B-2 | Every listener: `tls_version tlsv1.3`, `require_certificate true`, `use_identity_as_username true`, `allow_anonymous false`. **A validator refuses any TLS 1.2 or plaintext listener** |
| B-3 | Start with `OPENSSL_CONF` → `Groups = X25519MLKEM768:SecP256r1MLKEM768` |
| B-4 | `acl_file` generated by the ACL compiler from the signed policy + registry; SIGHUP reload |
| B-5 | `persistence true`; persistence location on durable storage |
| B-6 | `max_packet_size 300000`; queue limits (`max_queued_messages`) sized for class command queues |
| B-7 | `set_tcp_nodelay true` (without it every handshake stalls ~40–90 ms, measured) |
| B-8 | Allow the Session Expiry Intervals the class policies request |
| B-9 | Logging of connection failures, takeovers ("already connected") and TLS errors, feeding monitoring (§27.8) |

## 27.2 Device

| # | Requirement |
|---|---|
| D-1 | TLS 1.3 client on the application MCU with hybrid groups (wolfSSL-class). Offers only its class suite. Asks for max_fragment_length per the class profile. Verifies the chain to the pinned CA set **without time checks**. Checks hostname/SAN. **TCP_NODELAY on** |
| D-2 | MQTT 5 client: `clean_start = false`, Session Expiry, declared Maximum Packet Size = class `max_packet`, pipelining, topic aliases for high-rate TELEMETRY, back-off with full jitter |
| D-3 | E2E state machine per §9.4 (finished carries data), with identical retransmission of CH/DF/RH, and per-class DUP/PENDING timers |
| D-4 | Command handling per §13: statuses, intent log, GRANT/SETPOINT checks, `idempotent` handling |
| D-5 | Policy engine: binary parser (strict), strongest rule wins, CONTROL default, validator rules 1–10 |
| D-6 | FOTA installer per §15: parts → flash staging → verify from flash; Merkle chunks; A/B; commit after boot; KEYREVOKE; limits = own slot |
| D-7 | Persistence per §16: log-structured records with CRC; bounded outbox; time floor; never persist session keys |
| D-8 | TRNG + SP 800-90A DRBG seeded before the first handshake |
| D-9 | Watchdog budget above the worst crypto operation per class, or crypto yielding with watchdog kicks **[HW]** |
| D-10 | Constant-time MAC comparisons; KyberSlash-patched ML-KEM; constant-time ML-DSA verification |

## 27.3 Utility

| # | Requirement |
|---|---|
| U-1 | E2E endpoint and PASR per §9 and §14, persist then respond |
| U-2 | Command service **separated** from the E2E key holder; ML-DSA-65 key in an HSM (production) |
| U-3 | epoch ‖ counter sequences; the commands table as the redelivery queue; regression alarm |
| U-4 | SQLite WAL, `synchronous = FULL`: registry, used tickets, STEK (or HSM), sequences, commands, zone keys, rollout state |
| U-5 | Zone manager: ZONEKEY per member session; rotation on membership change + weekly |
| U-6 | Resync hint rate limit (1 per 30 s per device) |
| U-7 | Artifact publisher: parts and chunks ≤ class `max_packet`; retention window; republish requests rate-limited |
| U-8 | ACL compiler: verify the policy signature, compile, SIGHUP; config validator (B-2) |

## 27.4 FOTA

| # | Requirement |
|---|---|
| F-1 | Offline station (`network_mode: none`); SLH-DSA-SHA2-128s anchors A and B with separate custodians |
| F-2 | Manifest v2.2 fields (§15.2); `signer_anchor_id`; KEYREVOKE support |
| F-3 | Chunk size per class; the validator checks the fit within `max_packet` |
| F-4 | Bootloader: anchors in ROM/OTP; revocation state and committed versions in protected storage; power-safe swap; re-verification of an external slot |

## 27.5 PKI

| # | Requirement |
|---|---|
| K-1 | Offline ECDSA P-256 CA with `basicConstraints` and `keyUsage` (needed by Python 3.13) |
| K-2 | Device certificates: CN = device ID (regex), EKU clientAuth, `notAfter 99991231235959Z` |
| K-3 | Broker certificate: SAN, EKU serverAuth, rotation under CA overlap |
| K-4 | CA roll-over through signed policy (`ca_set`) before any switch |
| K-5 | Revocation: registry → ACL (+ optional CRL) |

## 27.6 Persistence

The rules are in §16. Every write that backs a promise is committed before the promise is sent. File writes
use temp + fsync + rename + fsync(dir).

## 27.7 Logging

| # | Requirement |
|---|---|
| G-1 | The utility logs every handshake outcome, check failure reason (internally; externally only "refused" or a resync hint: Rationale OPS-6), command status, ticket consumption, and regression alarm |
| G-2 | **Never** log key material, psk, plaintext alerts or commands beyond an audit digest |
| G-3 | Devices keep a bounded local error log (flash-wear aware) |

## 27.8 Monitoring

| # | Alarm |
|---|---|
| M-1 | Repeated "already connected" takeovers and "ticket already used" (clone indicators) |
| M-2 | Command regression alarm (fresh command → DUP/SUPERSEDED); INTERRUPTED counts |
| M-3 | Devices on old policy/firmware after the rollout window; republish requests |
| M-4 | Heartbeat staleness (stretch): the device detects withheld updates |
| M-5 | Broker TLS failure rates (classical-only attempts; certificate errors) |

---

# 28. Required Tests

All tests run in Docker unless marked **[HW]**. The existing 80 scenarios and N1–N7 are regression tests.

| Category | Tests |
|---|---|
| **Unit** | Codec (strict parsing, caps, trailing bytes); policy validator rules 1–10; tier engine; X-Wing; HKDF labels; Merkle paths (all sizes, including non-powers of two); sequence classification (DUP / SUPERSEDED) and the utility regression alarm; GRANT bounds and rate; the device record store (CRC, latest-wins, compaction) |
| **Integration** | Full lifecycle over real Mosquitto: provisioning → full handshake → alerts, commands, GRANT/SETPOINT → PASR → policy change → firmware update → ticket invalidation (I1); persistent sessions; parted manifest delivery |
| **Security** | A1–A13, P1–P10, F1–F7, N1–N7, RISK-1/2; V-G1…G6, V-Z1, V-D2, V-F2, V-F3, V-F5, V-N1 |
| **Crash** | S1 (utility restart), V-S1 (DB restore), S2 variants and V-S3 (every intent-log step), S3 (kill during every SQLite write → restart consistent), device crash at every record write, crash mid-KEYREVOKE |
| **Reboot** | Reboot between RH/RS/DF/NT; after PENDING; mid-download; during swap **[HW]**; RTC 1970 and +3 years (T4) through **both** TLS and E2E |
| **Network loss** | Lost CH/SH/DF/NT/RS/ACK; the identical-retransmission rules; loss of manifest parts or chunks; broker restart; utility restart with resync |
| **Duplicate** | QoS 1 duplicates of every message type within and beyond the per-class windows |
| **Reordering** | Envelopes vs DF (bundled); commands out of order; SETPOINTs out of order; manifest parts out of order |
| **FOTA** | 128s manifests (F1–F7 re-run); parts at max 4,096/8,192; limits = slot size; revert; KEYREVOKE (V-F2/3); external-slot tamper **[HW]** |
| **Resource** | T2/T3/T5/T6 re-run on v2.2 code; S4 at 10k/100k (constant per resume); bytes per day per reconnect strategy (E3); outage restoration at N = 100/500/1,000 (E4); policy rollout (E6); reliability under injected loss, duplication and restarts (E8, **SIMULATED** impairments) |
| **Hardware** | §29 |

**Experiment plan carried from v2.1** (all labelled; SIMULATED where modelled):

| ID | Experiment |
|---|---|
| E1 | Hop: full vs resumed; hybrid vs pure; ECDSA vs ML-DSA certificates |
| E2 | E2E: full vs PSK vs PSK+KEM |
| E3 | Tier overhead and bytes per day (P1/P2 realistic; P3 stress) |
| E4 | Outage restoration |
| E5 | FOTA costs vs chunk size, with loss |
| E6 | Policy rollout |
| E7 | Security pass/fail |
| E8 | Reliability |

---

# 29. Hardware Validation Plan

What Docker cannot prove, and how to settle it. Instruments are named as examples of *method*, not as a
source of numbers.

| Target | Board (example) | What to measure | Method | Settles |
|---|---|---|---|---|
| **C3** | nRF9160 DK (Cortex-M33, 256 KB RAM, LTE-M/NB-IoT) | Cold start, wake and resume times; stack peaks; the TLS library footprint (wolfSSL build with hybrid groups); energy per wake | DWT cycle counter; stack painting; build-size reports; a power profiler on the SiP supply; a live operator SIM | C3 feasibility; energy per reconnect **[HW]** |
| **C2** | A Cortex-M4 or M0+ board with ~64–128 KB RAM + external NB-IoT modem (AT) | Peak RAM with max_fragment_length 512/1,024 and small-stack PQ code; ML-KEM/ML-DSA/SLH-DSA cycles with flash wait states; watchdog budget | As above | The constrained profile's real peak (vs the analytical 16.7 KB) |
| **C4** | Raspberry Pi-class gateway | Throughput of gateway ↔ utility sessions for N meters; DLMS/COSEM bridging | Standard profiling | Gateway sizing |
| **Cellular** | Operator network (NB-IoT and LTE-M) | RTT distributions; NAT idle timeouts; energy per TCP+TLS+MQTT wake (full vs resumed; batch vs persistent) | Modem logs; current trace | Keep-alive and batch intervals; replaces [SIM] link parameters |
| **MCU crypto** | C2/C3 boards | Verify SLH-DSA-128s with SHA-256 hardware vs software; hardware ECC for ECDSA | Cycle counter | The real share of ECDSA; the hardware speed-up |
| **RAM** | C2/C3 | Whole-application peak (RTOS + IP stack + TLS + MQTT + E2E + FOTA) | Linker map + stack painting + heap high-water mark | Class boundaries |
| **Flash** | C2/C3 | Code size of the full firmware; A/B layout; external-flash slot | Build reports | FOTA storage minimum |
| **Energy** | C3 on a live network | mJ per wake by strategy | Power profiler | Replaces the ratio argument in §22 with measurements |
| **Watchdog** | C2/C3 | The worst crypto operation vs the watchdog period | Instrumented timing | D-9 settings |
| **TLS footprint** | C2/C3 | wolfSSL with X25519MLKEM768 + ECDSA + one AEAD + max_fragment_length | Build + runtime measurement | Whether C2 is truly feasible |

**Minimum useful set:** one nRF9160 DK (C3) plus one ~64 KB-RAM Cortex-M board with a modem (C2). This
redirects v2.1's ESP32 stretch goal to the actual target classes.

---

# 30. Future Work

| Item | Trigger / condition | Expected change |
|---|---|---|
| **ML-DSA hop certificates** | Credible CRQC timeline, or a deprecation milestone for device classes (CNSA 2.0 puts constrained devices at 2030 prefer / 2033 exclusive for national-security systems) | ML-DSA-44 certificates; E1 quantifies (23.8 KB full handshake measured) |
| **FN-DSA-512** for commands and GRANTs | FIPS 206 final + a vetted library in OpenSSL/pqm4-class stacks | −77% command bytes; the device only verifies |
| **HQC** as a diverse KEM backup | HQC standard final | An optional third component, or a replacement if ML-KEM weakens |
| **New SLH-DSA parameter sets** | NIST standardises smaller-signature sets for a limited number of signatures (proposed in the community) | Firmware signing (a few signatures per year) is an ideal use; smaller manifests |
| **LMS/HSS firmware signing** | A production station with an HSM managing state | Much smaller signatures (~1.5–1.8 KB); CNSA 2.0 alignment |
| **Hardware acceleration** | Target parts with ECC, SHA-256, AES, (future) Keccak/NTT engines | Measure the real ECDSA share and SLH-DSA speed-up (§29) |
| **HSM integration** | Production | STEK, command key, CA key in an HSM; measure the ML-DSA signing rate |
| **Formal model** | — | ProVerif/Tamarin model of §9.4 (full + resume, finished-carries-data, POLICY_INFO binding) |
| **Pure ML-KEM** (TLS and E2E) | Guidance permits dropping hybrid | One config line (TLS); a KEM-identifier change (E2E) |
| **TLS 1.3 external PSK on the hop** | A broker supporting TLS 1.3 PSK with psk_dhe_ke + hybrid groups | Removes ECDSA from constrained devices (57% of cold-start cycles) |
| **MQTT-SN / CoAP / DTLS transport** | Scope extension | Avoids TCP on NB-IoT |
| **SUIT/COSE manifests** (RFC 9019/9124 ecosystem) | Interoperability requirement | Replace the custom manifest encoding |
| **Delta updates** | Large images on C2 | Smaller downloads (outside the current scope) |
| **Freshness heartbeat** (stretch) | Phase 2 time allows | Devices detect withheld updates |
| **8-bit KEM-MQTT-only profile** | Separate research track | Direct C0/C1 participation (Kim & Seo style) |
| **Authenticated network time** | Available on target modems | Feeds the time floor |
| **High availability** | Multiple utility servers | Replicated database + shared HSM for STEK and the used-ticket set (Rationale OPS-7) |
| **Actuator feedback** | Hardware support | Resolve INTERRUPTED automatically |

---

# 31. Complete Change History

| Version | Date | What changed | Why |
|---|---|---|---|
| **Mid-semester report** | 2026-09-21 | Three objectives; hybrid TLS X25519MLKEM768; `K_session = KDF(K_TLS, policy_id, tier)`; POLICY_INFO through MQTT 5 enhanced auth; broker-hosted policy engine and ticket manager; ML-DSA-65 manifests with a per-chunk hash list; "control excluded from resumption"; expected 60–70% reconnection gain | Phase 1 (literature + methodology) |
| **v1 plan** | 2026-09-21 | App-layer ML-KEM-768 handshake with the **broker**; device-local tier floor; most-specific rule; STEK rotation; nonce cache; Merkle tree | First design review (6 problems) |
| **v2** | 2026-09-22 | E2E session moved to **device ↔ utility** (KEM-MQTT lifted, hybrid, X-Wing); **strongest rule wins**, CONTROL default; ticket manager at the utility; **SLH-DSA-SHA2-192s** firmware + policy; ECDSA P-256 hop certificates; policy through FOTA; binary codec; pinned hybrid-only groups | Review found: the E2E claim was false under eq. 3.2; K_TLS not exportable; a double ML-KEM with the same broker; an unauthenticated device; control exclusion not implementable; an irreplaceable lattice anchor |
| **v2.1** | 2026-09-22 | Robustness rules: identical replies to duplicates (120 s); confirm before use; utility-authenticated time; one half-open handshake per device; one session per device; constant-time MACs; strict parsing; E2E ACKs with alert IDs and flash outbox; command status ACKs, redelivery and apply-at-most-once; persisted STEK and used list; A/B commit after boot; broker persistence and packet limits; resync hint; device-ID rules. **80/80 validation + N1–N7** | Edge testing of v1 found real bugs: a duplicate CH broke the handshake, a duplicate DF crashed the utility, a duplicate RH gave "already used", a 1970 clock → "stale client hello", a lenient final-message check (fuzz), non-constant-time MACs |
| **Audit** | 2026-09-22 | Constrained-IoT / smart-grid audit: 7 RED, 7 ORANGE, 14 YELLOW; S1–S5, T1–T7, analytical budgets | Feasibility on real device classes; persistence under crashes |
| **v2.2 (this document)** | 2026-09-22 | Every audit change adopted (§19): clock/certificate handling; epoch ‖ counter commands + intent log + statuses; GRANT/SETPOINT; ZONEKEY under session; SQLite WAL; **SLH-DSA-SHA2-128s**; parted manifests; ≥ 2 anchors + KEYREVOKE; finished carries data; persistent MQTT sessions + reconnect strategy + back-off; one AEAD per class; binary policy + class profiles; TLS 1.3-only listeners; device classes and constrained profile | Audit evidence (§18) |
| **v2.2 + remediation** | 2026-09-29 | Eight finalized clarifications (Appendix F): command classification order; logical zones with per-AEAD crypto groups, logical σ (`pqgrid/v2/bcast`) and re-send under the current key, no early-event buffer; `bseq` per logical zone, no floor; software-enforced 7-day residue; A/B anchor lifecycle. Fixes: live device revocation; bounded intent log (3 writes per command); guarded MQTT callbacks; policy race at DF; chain end on live sessions; scrub call paths; main loops; bounded caches and logs; independent X-Wing KAT and byte fixtures | Read-only correctness/security audit of the implementation |
| **v2.2 + final remediation** | 2026-09-30 | Device storage budget and start-up check (2 × 4 × 4 KiB; true-bytes outbox; one pending body; zone/chunk/alert bounds); DF carries what its reply can ACK (C2: 53); reconnect back-off kept across main-loop ticks; E-2 zone sync (no cross-topic ordering assumption); E-3 cumulative SETPOINT ACK rules; E-4 deterministic republish triggers and validity | The audit's remaining items |
| **v2.2 + continuous audit, cycle 1** | 2026-09-30 | Implementation brought in line with this document, no design decision changed: the device keeps and re-verifies its installed policy (§4.1, §15.11) and follows every class value of a new one; the utility's rollout state is durable (U-4); a torn flash-record header no longer blocks the store; a commit interrupted by power loss is finished at boot; identifier grammars match the whole string; GRANT memory bounded; the utility loop survives a refused scheduled policy; 17 test gaps closed by mutation analysis (112 of 117 mutants killed, 5 equivalent) | Iterative implementation audit, each item shown by a failing test first (IMPLEMENTATION-ROADMAP §14) |

**Semester 1 (separate):** the SLE-KEMQTT prototype (`pq-mqtt-session-security/`), its design spec and the
Semester 1 PDFs were removed from this folder on 2026-09-22. They were moved to the macOS Trash folder
`MajorProject-cleanup-2026-09-22`, and the committed history is also on GitHub. Its two-phase replay-guard
idea carries forward (§9.6).

---

# 32. Source / Evidence Registry

## 32.1 Project experiments (all in Docker)

| ID | Artifact | Contents |
|---|---|---|
| DOCKER-VAL | `design-validation/results/validate.txt` | 80/80: 47 CORE, 31 EDGE, 2 RISK |
| DOCKER-NET | `design-validation/results/network.txt` | N1–N7 through an interception proxy |
| DOCKER-BRK | `design-validation/results/broker.txt` | Default group negotiation; ACL at delivery; MQTT 5 properties; retained 16 KB/256 KB; TLS resumption; Nagle; certificate-type handshake bytes |
| DOCKER-BENCH | `design-validation/results/bench.txt` | E2E handshake/resume compute and bytes; per-tier message sizes; FOTA costs |
| DOCKER-SIG | `design-validation/results/signature_speed.txt` | ML-DSA-65, SLH-DSA-192s, SLH-DSA-128s (openssl speed) |
| DOCKER-HYB | `design-validation/results/hybrid_cost.txt` | X25519 vs ML-KEM-768 compute (+122%) |
| DOCKER-S | `design-validation/constrained-audit/results/state.txt` | S1–S5 |
| DOCKER-T | `design-validation/constrained-audit/results/tls_time.txt` | T2 ticket lifetime; T3 max_fragment_length; T4 clocks and certificates; T7 PSK |
| DOCKER-TR / SIM | `design-validation/constrained-audit/results/transport.txt` | T1 packet limit; T5 bytes on the wire; T6 modelled links |
| ANALYTICAL | `design-validation/constrained-audit/results/analysis.txt` (from `analysis.py`) | Cycles, RAM, flash wear, bytes per day, v2.2 message sizes |
| Runners | `design-validation/run_all.sh`, `design-validation/constrained-audit/run_audit.sh` | One command each |

## 32.2 Literature

| ID | Source | Hardware | Used for |
|---|---|---|---|
| LIT-KS25 | Kim & Seo, "An Optimized Instantiation of Post-Quantum MQTT protocol on 8-bit AVR Sensor Nodes", ASIA CCS 2025 (base paper) | ATmega4808 (6 KB SRAM, 48 KB flash) at 7.37 MHz; simulated transmission | KEM-MQTT (Fig. 4); AVR feasibility; OpenSSL ≥ 16 KB stack |
| LIT-MAL24 | Malina et al., "Quantum-Resistant and Secure MQTT Communication", ARES 2024 | RPi Zero (5 runs), phones | Level-5 Falcon/Kyber costs; broker re-encryption; CNSA 2.0 / ANSSI / BSI notes |
| LIT-SET25 | Setyowati et al., ICCED 2025 | 3 VMs | TLS 1.2 + app-layer ML-KEM-768 latency (+~13%) |
| LIT-ALG26 | Alghawli et al., Frontiers 2026 | NS-3 802.15.4 simulation; RPi 4B crypto timing (INA219) | Stress traffic profile; fragment counts; Pi timings |
| LIT-DOM25 | Domingo Martín et al., ITASEC 2025 | 2012 Intel i5 laptop (SUPERCOP) | Meter update practice (DLMS/COSEM, ~yearly); signature survey (with errata) |
| LIT-SUL25 | Suleiman & Javeed, ICEEE 2025 | Orange Pi Zero 2W, RPi Zero 2 W | Background only; figures unreliable |
| LIT-PQM4 | mupq/pqm4 `benchmarks.md` (master) and tag Round3 | NUCLEO-L4R5ZI / STM32F4DISCOVERY, Cortex-M4 at 24 MHz | Cycles, stack, code size |
| LIT-HL19 | Haase & Labrique, TCHES 2019 | STM32F407 | X25519 625,358 cycles |
| LIT-DULL15 | Düll et al., Des. Codes Cryptogr. 2015 | AVR, MSP430X, Cortex-M0 | X25519 cycles |
| LIT-RP2040 | Chhetri et al., arXiv 2603.19340 (preprint, 2026) | RP2040 Cortex-M0+ at 125 MHz | M0+ timings, RAM, code; energy **estimated** |
| LIT-TAS22 | Tasopoulos et al., ISPEC 2022 (eprint 2021/1553) | NUCLEO-F439ZI Cortex-M4 at 180 MHz, wolfSSL, Ethernet | PQ TLS 1.3 handshake times, bytes, memory; ECDSA timings |
| LIT-TAS23 | Tasopoulos et al., CF'23 workshop (eprint 2023/506) | Same board; PicoScope + shunt | **Measured** crypto and TLS energy |
| LIT-ANA24 | Anastasova et al., eprint 2024/2083 | STM32F413 at 76.6 MHz | Fully hybrid TLS 1.3 (Level 5) cycles |
| LIT-LUK20 | Lukic et al., arXiv 2005.13648 | Quectel BC68, live NB-IoT | **Measured** radio charge per exchange |
| LIT-NBP | Wang et al., "A Primer on 3GPP NB-IoT", arXiv 1606.04171 | — | NB-IoT latency and rates |
| LIT-MSP | Optimized Keccak, Kyber and Dilithium on MSP430, TCHES 2026 | MSP430 | Existence of 16-bit PQ implementations |
| LIT-NBSM | "Experimental Performance Analysis of MQTT and CoAP Protocol Usage for NB-IoT Smart Meter" (IEEE) | NB-IoT | CoAP/UDP vs MQTT/TCP |
| LIT-VEND | Nordic nRF9160 product specification and nrfxlib docs; Microchip SAM4CM datasheet; TI MSP430F6765A; wolfSSL 5.8.0 release notes; Mbed TLS / TF-PSA-Crypto roadmap | — | Target-part capabilities; library status |
| LIT-2030.5 | IEEE 2030.5 pollRate default (900 s); SunSpec CSIP implementation guide (DERControl polling 10 min) | — | DER traffic realism |

## 32.3 Standards

| ID | Standard | Used for |
|---|---|---|
| STD-203/204/205 | NIST FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA; §11.2 SHA-2 instantiations) | Algorithms and sizes |
| STD-206 | FIPS 206 (FN-DSA): draft submitted Aug 2025; **not final** in the sources found | Future trigger |
| STD-232 | NIST SP 800-232 (Ascon), final 13 Aug 2025 | AEAD alternative |
| STD-208 | NIST SP 800-208; RFC 8554 (LMS), RFC 8391 (XMSS) | Stateful hash-based alternative |
| STD-TLS | RFC 8446 (TLS 1.3); draft-ietf-tls-ecdhe-mlkem (X25519MLKEM768 key-share sizes); RFC 6066 (max_fragment_length); RFC 5280 §4.1.2.5 (99991231235959Z) | Hop design |
| STD-XW | IETF CFRG X-Wing draft | Combiner |
| STD-MQTT | OASIS MQTT 5.0, including [MQTT-3.1.2-25] (silent discard over Maximum Packet Size) | Packet limits |
| STD-7228 | RFC 7228 (device classes) | Classes |
| STD-KDF | RFC 5869 (HKDF), RFC 2104 (HMAC), RFC 8439 (ChaCha20-Poly1305), RFC 7748 (X25519), RFC 6962/9162 (Merkle) | Primitives |
| STD-CNSA | NSA CNSA 2.0 (LMS/XMSS for firmware; ML-KEM-1024/ML-DSA-87; timelines) | Context |
| STD-SUIT | RFC 9019, RFC 9124 | Future manifest format |

---

# 33. Final Architecture Snapshot

**Transport.** Every client ↔ Mosquitto 2.0 hop runs TLS 1.3 only:
- **X25519MLKEM768** (pinned hybrid-only; TLS 1.2 forbidden);
- mutual **ECDSA P-256** certificates from a private CA (device CN = device ID, device certificates never
  expire, devices do not check certificate dates);
- **one AEAD per class** (AES-256-GCM or ChaCha20-Poly1305);
- max_fragment_length for constrained devices;
- persistent MQTT sessions, packet limits per class, retained artifacts with persistence.

**End to end.**
- **Establishment.** Device ↔ utility hybrid KEM-MQTT (X25519 + ML-KEM-768, X-Wing combiner): ephemeral +
  utility-static + device-static KEMs, with POLICY_INFO bound into `K_master` by HKDF-SHA-256.
- **Finished carries data.** Utility-authenticated time repairs the device clock (plus a flash time floor).
- **Tiers.** TELEMETRY is hop-only; ALERT adds E2E AEAD with ACKs and a bounded outbox; CONTROL adds E2E
  AEAD plus:
  - **ML-DSA-65** for discrete commands (intent log, epoch ‖ counter sequence, honest statuses);
  - **GRANT + SETPOINT** for high-rate set-points (signed, session-bound bounds; AEAD set-points);
  - **ZONEKEY** under the session for signed demand-response broadcasts.

**Resumption.** Utility-issued single-use STEK-sealed tickets with a binder and 9 checks. PSK or PSK+KEM by
class (unicast-control ⇒ PSK+KEM or none); chains ≤ 7 days. Invalidated by policy, firmware, revocation and
STEK retirement. 1-RTT resume over persistent MQTT sessions. Utility state is in SQLite WAL, persisted
before responding.

**Updates.** An offline station signs FIRMWARE, POLICY and KEYREVOKE with **SLH-DSA-SHA2-128s** under
**≥ 2 anchors**:
- manifests (8,031 B) are delivered in parts no larger than the class limit, staged and verified from flash;
- RFC 6962 Merkle chunks;
- A/B slots, commit after boot, external-slot re-verification;
- monotonic protected counters;
- the signed binary policy (tiers, class profiles, keys, CA set) travels the same pipeline with
  `activate_at`.

**Scope.** C2 (constrained profile), C3 and C4 connect directly. C0/C1 meters reach the system through C4
gateways, where E2E ends.

---

# 34. Final "Do Not Change Without Re-evaluating" List

| # | Invariant | What breaks if it changes |
|---|---|---|
| I-1 | Every recordable key exchange is **hybrid** (TLS and E2E) | Record-now protection rests on one algorithm |
| I-2 | **Hybrid-only groups pinned** and **every listener TLS 1.3** | Silent classical fallback (N3, T7) |
| I-3 | ALERT/CONTROL keys derive **only** from device ↔ utility secrets, never from TLS | The broker reads and forges |
| I-4 | POLICY_INFO is bound into `K_master` and into tickets | Silent policy downgrade |
| I-5 | Strongest rule wins; unmatched → CONTROL | Downgrade by a broad rule; fail-open topics |
| I-6 | Session keys and counters live in RAM only and die together; never persist a session key | Nonce reuse |
| I-7 | Two-phase replay check (validate before AEAD, accept after) | Forged messages burn valid sequences |
| I-8 | Tickets: consume **after** the binder; **persist before responding**; single use | Ticket burning; replay after a crash |
| I-9 | Unicast-control classes resume only with PSK+KEM or not at all | No forward secrecy on command channels |
| I-10 | Command sequence = epoch ‖ counter, persisted with the queue before sending | Silent command loss (S1) |
| I-11 | "OK" only after APPLIED is durable; INTERRUPTED is reported | False confirmations (S2) |
| I-12 | SETPOINTs only within a signed GRANT bound to the **same** sid | Forgery without the command key |
| I-13 | Command key held apart from the E2E key | The command signature adds nothing |
| I-14 | Firmware and policy signed by a **hash-based** scheme under **≥ 2** revocable anchors | Irrecoverable anchor failure; lattice risk |
| I-15 | The committed version moves only after a successful boot, in protected storage | Bricking or rollback |
| I-16 | Every artifact message ≤ the target class `max_packet` | Silent non-delivery (T1) |
| I-17 | Devices never need a correct clock to connect; expiry is judged only with authenticated time | Clock deadlock (T4) |
| I-18 | Handlers idempotent under QoS 1; identical replies to identical messages within per-class windows | Broken handshakes, crashes |
| I-19 | Data after SH/RS rides **inside** DF, processed only after MAC_D | Unauthenticated data or ordering races |
| I-20 | The profile is fixed per class in the signed policy, **never negotiated** | Profile downgrade |
| I-21 | Strict parsing: exact fields, known types, caps, the device-ID regex | Injection; memory exhaustion |
| I-22 | Evidence labels on every number; no laptop number presented as an MCU number | Loss of credibility; false claims |

---

# Appendix A — Terminology

| Term | Meaning |
|---|---|
| Hop / end-to-end | Protection for one link (device → broker) vs from sender to final receiver, so the middle cannot open it |
| KEM | Key-encapsulation mechanism: one side encapsulates to a public key; only the private-key holder recovers the shared secret |
| Hybrid | Two algorithms combined (classical + post-quantum); secure while either holds |
| Tier | TELEMETRY / ALERT / CONTROL protection level assigned to a topic by the policy |
| POLICY_INFO | policy_id ‖ version, bound into session keys |
| Ticket / chain | A sealed re-entry pass / one full handshake plus the resumptions that follow it |
| STEK | The utility's ticket-sealing key |
| Binder | MAC proving possession of the ticket's psk |
| GRANT / SETPOINT | A signed, session-bound authority for a bounded stream / an AEAD-only set-point inside it |
| Intent log | Flash records PENDING → APPLIED around actuation |
| Anchor | A firmware public key burned into the bootloader |
| KEYREVOKE | A signed artifact that revokes an anchor |
| Manifest / part / chunk | A signed description of an artifact / a slice of the manifest ≤ max_packet / a Merkle-verified piece of the payload |
| A/B slots | Two firmware slots; boot the new one, commit after success, else revert |
| Time floor | The last authenticated utility time, persisted; the lower bound for the device clock |
| Persist then respond | Make a promise durable before communicating it |
| Profile | Per-class settings in the signed policy (FULL / CONSTRAINED) |
| Fail closed | A failed check refuses; it never silently weakens |
| SIMULATED | Produced by a model, not measured; always labelled |

# Appendix B — Acronyms

AEAD (Authenticated Encryption with Associated Data) · ACL (Access Control List) · AMI (Advanced Metering
Infrastructure) · CA (Certificate Authority) · CNSA (Commercial National Security Algorithm Suite) · CRQC
(Cryptographically Relevant Quantum Computer) · DER (Distributed Energy Resource) · DLMS/COSEM (Device
Language Message Specification / Companion Specification for Energy Metering) · DR (Demand Response) · DRBG
(Deterministic Random Bit Generator) · E2E (End-to-End) · ECDSA (Elliptic Curve Digital Signature Algorithm)
· eDRX (extended Discontinuous Reception) · FOTA (Firmware Over-The-Air) · FS (Forward Secrecy) · HKDF
(HMAC-based Key Derivation Function) · HMAC (Hash-based Message Authentication Code) · HSM (Hardware Security
Module) · KEM (Key Encapsulation Mechanism) · LMS/HSS (Leighton-Micali / Hierarchical Signature System) ·
LTE-M (LTE for Machines) · MCU (Microcontroller Unit) · MFL (max_fragment_length) · ML-DSA (Module-Lattice
Digital Signature Algorithm) · ML-KEM (Module-Lattice KEM) · MQTT (Message Queuing Telemetry Transport) ·
NB-IoT (Narrowband IoT) · NITZ (Network Identity and Time Zone) · OTP (One-Time Programmable) · PASR
(Policy-Aware Session Resumption) · PCHC (Per-topic Cryptographic Hierarchy Control) · PKI (Public Key
Infrastructure) · PSM (Power Saving Mode) · PSK (Pre-Shared Key) · QoS (Quality of Service) · RTC (Real-Time
Clock) · RTT (Round-Trip Time) · SLH-DSA (Stateless Hash-based DSA) · STEK (Session Ticket Encryption Key) ·
TRNG (True RNG) · WAL (Write-Ahead Log) · XMSS (eXtended Merkle Signature Scheme).

# Appendix C — Parameters

| Parameter | Value | Source |
|---|---|---|
| ML-KEM-768 ek / dk / ct / ss | 1,184 / 2,400 / 1,088 / 32 B | FIPS 203 |
| HKEM pk / ct | 1,216 / 1,120 B | §6.2 |
| ML-DSA-65 pk / sig | 1,952 / 3,309 B | FIPS 204 |
| SLH-DSA-SHA2-128s pk / sig | 32 / 7,856 B | FIPS 205 |
| ECDSA P-256 leaf certificate | 394–426 B | [DOCKER] |
| TLS full / resumed (with CONNECT) | 6,262 / 4,438 B | [DOCKER T5] |
| TLS hop ticket lifetime | 7,200 s | [DOCKER T2] |
| E2E full / PSK / PSK+KEM | 5,221 / 761 / 3,097 B (v2.1: 5,212 / 755 / 3,103) | [DOCKER, v2.2 code] |
| ALERT envelope | 137 B (64 B payload) | [DOCKER] |
| CMD / GRANT / SETPOINT / ZONEKEY envelopes | 3,466 / 3,477 / 97 / 138 B (estimates: 3,454 / 3,461 / 93 / 132) | [DOCKER, v2.2 code] |
| DF alone / with one ALERT | 46 / 193 B | [DOCKER, v2.2 code] |
| Status ACK / DR event (64 B event, ChaCha group) / ZONESYNC (2- / 32-character zone) | 83 / 3,488 / 83–113 B | [DOCKER, v2.2 code]; DR event hand-derived |
| Alerts per DF | `min(64, (max_packet − 420) ÷ 69)`: 53 at 4,096 B (reply 4,008 B; largest C2 DF 6,109 B) | §9.4 |
| Device record store | 2 banks × 4 pages × 4 KiB; worst case 10,758 B ≤ 12,068 B per bank | §16 Device Storage Capacity |
| Intent log / zones per device / FOTA chunks / ALERT payload, kind | 32 / 16 / 1,024 / 1,024 B, 16 B | §13.7, §11, §15, §16 |
| Retained DR events per zone | 64 (overflow raises an alarm) | §11 |
| Zone sync | ≤ 1 outstanding per zone (retry 10 s); utility ≤ 1 answer per 5 s per (device, zone) | §11 (E-2) |
| Cumulative SETPOINT ACK | every 30 s (inclusive); final ACK at GRANT end | §13.5 (E-3) |
| Republish | device: stalled download 600 s; utility: at most 1 per hour per device | §15.8 (E-4) |
| Reconnect back-off | full jitter, window `min(cap, base × 2^attempt)`, attempt kept across ticks, reset on CONNACK | §10.5 |
| Signed manifest (128s) | 8,031 B (estimate 8,042) | [DOCKER, v2.2 code] |
| Merkle proof per chunk (1 MiB, 4 KiB) | 256 B | [DOCKER] |
| Broker `max_packet_size` | 300,000 B | Config, [DOCKER N6] |
| Class `max_packet` (C2 example) | 4,096 B | Policy |
| `tls_max_record` (C2) | 512–1,024 B | Policy; [DOCKER T3] |
| DUP_WINDOW / PENDING_TTL minimum | 120 s / 60 s (per class ≥ 2× the worst handshake) | Policy |
| Resync hint rate | 1 per 30 s per device | Design |
| STEK rotation / retirement | 24 h / after maximum ticket lifetime | Design |
| STEK kid | 16 bits | v2.2 |
| Ticket lifetime / chain cap | ≤ chain ≤ 7 days | Policy validator |
| Command sequence | epoch(32) ‖ counter(32) | §13.6 |
| Device applied-window | 64 sequences | §13.6 |
| Outbox cap (C2 example) | 4 KiB | Policy |
| Time-floor write | ≤ 1/day + after first authenticated time | §8.9 |
| Retention window | e.g. 30 days | Operations |
| Device ID | `^[a-z0-9][a-z0-9-]{0,31}$` | §10.1 |
| Codec field cap | 1 MiB | §12 |
| HKDF labels | `early`, `k1`, `key|ALERT|up`, `key|CONTROL|down`, `key|ACK|up`, `key|ACK|down`, `key|SYNC|up` (E-2), `kc_U`, `kc_D`, `sid`, `res|<ticket_id>`, `binder`, `new-ticket`, `fin` | §9.5 |
| Signature contexts | `pqgrid/v2/cmd`, `pqgrid/v2/grant`, `pqgrid/v2/bcast` (logical event: zone, bseq, expires_at, event; v1 also covered key_epoch) | §13, §11 |
| X-Wing label | `\.//^\` | §6.4 |

# Appendix D — Test Matrix

| Objective × category | Security | Crash / reboot | Loss / duplicate / reorder | Resource | Hardware |
|---|---|---|---|---|---|
| **PCHC** (tiers, E2E, commands) | A1–A13, C-*, E-X*, V-G*, V-Z1, V-D2 | S1, S2, V-S1, V-S3, T4 | E-CMD*, V-D1, V-D3, E-duplicates | T5, T6, E3 | C2/C3 RAM, cycles, energy |
| **PASR** | P1–P10, RISK-1/2 | S3, E-P2, E-P3, E-P4, S5 | E-P1, lost RS/NT | S4, T2, T6-D, E2, E4 | Wake energy by strategy |
| **PQC-FOTA** | F1–F7, V-F2, V-F3, V-F5 | E-F1, E-F2, KEYREVOKE crash | Part/chunk loss and reorder | T1, V-F1, E5 | External slot V-F4, swap power safety, verify timing |
| **Transport** | N1–N7, V-N1, T7 | Broker restart (N5) | — | T3, T5 | TLS footprint, NAT timeouts |
| **Integrated** | I1 | Lifecycle with restarts | E8 | E6 | — |

# Appendix E — Historical Design Notes

- **Semester 1 (SLE-KEMQTT, `pq-mqtt-session-security/`).** It carried a KEM handshake + HMAC ratchet +
  replay guard with Kyber-512. Its **two-phase replay guard** carries forward (I-7). The rest was
  superseded. It was removed from this folder on 2026-09-22 as unrelated to the current design.
- **Report → v2.** The end-to-end claim moved from TLS-derived keys to a device ↔ utility session. The
  report's slide claims about hybrid TLS remain valid for the hop.
- **Why the design once had a "tier floor" (v1).** It guarded against a broker serving a weak policy. v2
  replaced it with signed policy + POLICY_INFO binding + receivers enforcing tier by topic from their own
  policy. That is stronger and simpler.
- **Why 192s was chosen in v2 and replaced in v2.2.** v2 optimised for uniform Category 3 and the
  irreplaceable-anchor argument. The audit showed the 16 KB manifest is silently undeliverable to devices
  with small packet limits, and that 192s drags SHA-512 into bootloaders. The pre-recorded B10 trigger
  applied.
- **Why "confirm before use" existed (v2.1) and was replaced.** It prevented alert loss when DF was lost.
  The ACK + outbox made it redundant, and it cost a round trip on high-latency links.
- **Pitfalls learnt in Docker** (carried as requirements):
  - defaults accept classical-only clients;
  - QoS 1 duplicates are normal;
  - device clocks reset;
  - Mosquitto persistence is off by default;
  - Nagle/delayed-ACK adds ~40–90 ms per handshake without TCP_NODELAY;
  - Python 3.13 needs CA basicConstraints/keyUsage;
  - one SSLContext per device for session reuse;
  - paho needs a subclass for TLS session reuse (pin `paho-mqtt==2.1.0`);
  - OpenSSL puts client certificates inside TLS tickets;
  - `mlkem.encapsulate()` returns `(shared_secret, ciphertext)`;
  - Mosquitto answers "Granted" to forbidden subscriptions (test delivery, not SUBACK);
  - Docker Desktop cannot mount ~/Desktop (copy into images);
  - the TLS 1.2 PSK listener bypasses the hybrid pin;
  - the broker sends 16 KB TLS records unless asked for smaller;
  - the broker silently drops over-size packets.


---

# Appendix F — Remediation Record (2026-09-29)

A read-only audit found implementation defects; they were fixed under eight finalized clarifications. Where each
landed in this document, and what remains open. Code, tests and results per item: IMPLEMENTATION-ROADMAP §13.

| Clarification / item | Where in this document |
|---|---|
| 1. DF MAC binds the exact bundle | §9.4 (DR-044, unchanged) |
| 2. Status ACK authenticates sid, msg_seq, cmd_seq, status | §11 (DR-045, unchanged) |
| 3. Command classification order | §13.1, DR-046 |
| 4. Logical zone, per-AEAD crypto groups | §10.1, §11, DR-047 |
| 5–6. `bseq` = epoch ‖ counter; highest accepted per logical zone, no floor | §11, DR-048 |
| 7. Secret residue at most 7 days (software), no powered-off claim | §16 Flash Wear, DR-049 |
| 8. Anchor lifecycle A/B | §15.13, §15.14, DR-050 |
| H1 live device revocation | §4 key table (Revocation) |
| H2 bounded intent log, three writes per command | §13.7 |
| M1 policy activation race | §12 Policy Distribution |
| M2 chain end on live sessions | §9.7 |
| M4/M5 re-send under the current key; no early buffer | §11 |
| M9 main loops | §10.5 |

**Former open points, as decided in the final remediation pass (2026-09-30):**
- **E-1 (interpretation, kept):** the chain cap applies to every live session (a full handshake starts the
  chain), following §9.7 and the glossary; a new full handshake always starts a new 7-day chain and is never
  limited by an old one.
- **E-2 (resolved):** no reliance on cross-topic MQTT ordering; an event that overtakes its key is recovered by
  a zone sync (§11).
- **E-3 (resolved):** cumulative SETPOINT ACK every 30 s (inclusive), final ACK at GRANT end (§13.5).
- **E-4 (resolved):** deterministic republish triggers and validity rules, independent of the time floor (§15.8).
- **Device storage (resolved):** worst case 10,758 B per bank, store 2 × 4 × 4 KiB (§16 Device Storage Capacity);
  DF carries at most what its reply can ACK (C2: 53 alerts, §9.4).

**Not claimed:** hardware validation; guaranteed erasure while powered off; exactly-once actuation (the claim is
at most once, with INTERRUPTED reported); latency gains beyond the measured [SIM]/[DOCKER] figures; security
against all attacks.
