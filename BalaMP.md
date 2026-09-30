# BalaMP — Final Design and Build Plan (v2.1)

**Project:** Post-Quantum Secure MQTT for Smart Grid Communication
**Team 14:** Sanga Balanarsimha (231IT062) · C. Lohith Kumar Reddy (231IT016) · P. Pavan Kumar (231IT046)
**Guide:** Dr. Bhawana Rudra · B.Tech IT, NIT Karnataka · Major Project IT449
**Version:** v2.1, 2026-09-22. Replaces v1 (2026-09-21) completely. v2.1 adds the fixes from edge-case
analysis. **Read with [BalaMP-Rationale.md](BalaMP-Rationale.md):** why every choice was made, its
alternatives and trade-offs, step-by-step reconnection walkthroughs, and the full edge-case catalogue.
**Status:** design frozen and validated. Implementation is Semester 2.

---

## Contents

0. [Read this first](#0-read-this-first)
1. [The project in one paragraph](#1-the-project-in-one-paragraph)
2. [The three objectives](#2-the-three-objectives)
3. [Frozen cryptographic choices](#3-frozen-cryptographic-choices)
4. [System architecture](#4-system-architecture)
5. [Protocol specifications](#5-protocol-specifications)
6. [Threat model and security goals](#6-threat-model-and-security-goals)
7. [Evidence already obtained](#7-evidence-already-obtained)
8. [Build plan](#8-build-plan)
9. [Attack suite](#9-attack-suite)
10. [Evaluation plan](#10-evaluation-plan)
11. [What we claim and what we do not](#11-what-we-claim-and-what-we-do-not)
12. [Changes from the mid-semester report](#12-changes-from-the-mid-semester-report)
13. [Risk register](#13-risk-register)
14. [Decision log](#14-decision-log)
15. [Glossary](#15-glossary)

---

## 0. Read this first

**What this is.** The single source of truth for what we build and why. Every choice in §3 and §14 is
**frozen**. To change one, write the new decision and its reason into §14 first. That stops the
"this algorithm or that one" loop.

**Why a refactor was needed.** Reviewing the mid-semester report and plan v1 found real contradictions:

| Problem found | Why it mattered |
|---|---|
| Alert and control tiers were called "end-to-end", but their key was derived from the TLS key, which the **broker holds** | The broker could read them, so the central security claim was false |
| Policy binding used `K_TLS`, which Python's TLS library cannot export | The mechanism could not be built as written |
| Plan v1 ran a second ML-KEM exchange with the **same** broker that TLS already covered | Double cost, no added protection |
| The v1 handshake never authenticated the device | Anyone could claim any device ID |
| "Control-tier topics are excluded from resumption", but one MQTT connection carries all tiers | Could not be implemented per topic |
| Firmware was signed with a new lattice scheme using a key that can **never** be replaced | A single future break would be permanent |

**How the new design was checked.** Nothing here is assumed:

- Every broker assumption was tested in a Docker container: real Mosquitto, OpenSSL 3.5, and Python.
- A reference implementation of all three objectives runs **80 scenarios**, and every one behaves as expected:
  - **47 core** checks (every mechanism works; every attack fails closed)
  - **31 edge cases**: duplicates, lost messages, crashes, restarts, clock resets, clones, and 3,300
    corrupted messages per run
  - **2 documented risks**, deliberately shown succeeding so the limits are honest
- An interception proxy between a real meter and the broker shows that **replayed and tampered network
  traffic is rejected**, and that **default TLS settings silently accept classical-only clients**, which is
  why hybrid-only is pinned.
- Every cost number was measured.

The evidence is in [`design-validation/`](design-validation/) and reproduces with one command
(`design-validation/run_all.sh`), entirely inside Docker.

---

## 1. The project in one paragraph

Smart meters, solar and battery controllers, and EV chargers talk to the power company through an MQTT
broker. We protect that traffic against today's attackers and against future quantum computers, while
spending heavy cryptography only where it matters. Every connection to the broker uses hybrid
post-quantum TLS. On top of that, **alerts and control commands are protected end to end between the device
and the utility**: the broker passes them on but cannot read or forge them. A **signed policy** decides which
topic gets which protection (**PCHC-MQTT**). Devices can recover after power outages without repeating the
expensive post-quantum handshake, but only in ways the policy allows (**PASR-MQTT**). Firmware, and the
security policy itself, are updated through a post-quantum signed pipeline that cannot be rolled back
(**PQC-FOTA**).

---

## 2. The three objectives

### Objective 1 — PCHC-MQTT: Per-topic Cryptographic Hierarchy Control

> **Objective.** Design and implement a signed, operator-defined policy that assigns every MQTT topic a
> protection tier, and enforce it end to end between device and utility, so that no attacker, including
> the broker, can silently weaken a topic's protection.

**What we build**
- **Signed policy.** A policy document signed by the offline station. It maps topic patterns to tiers:
  the strongest matching rule wins, and an unmatched topic gets CONTROL. It also sets per-device-class rules
  and carries the utility's public keys. One shared engine is used by devices, the utility, and the broker's
  access-control compiler.
- **Three tiers.**
  - TELEMETRY: hybrid TLS hop only.
  - ALERT: adds end-to-end ChaCha20-Poly1305, device → utility.
  - CONTROL: adds end-to-end encryption plus the utility's ML-DSA-65 signature. Broadcast
    demand-response uses zone keys.
- **End-to-end session.** Kim & Seo's KEM-MQTT handshake (their Figure 4), run between **device and
  utility** instead of device and broker. Every KEM in it is hybrid (X25519 + ML-KEM-768). The policy
  identifier (POLICY_INFO) travels inside the handshake and is bound into the key schedule.
- **Broker enforcement.** Mutual-TLS device identity plus an access-control list compiled from the signed
  policy and hot-reloaded when the policy changes.

**What is new**
- The operator's signed policy is bound into end-to-end post-quantum session keys, so a policy or tier
  downgrade fails closed, even when the broker is the attacker.
- Malina et al. [2] offer two security levels, but the *subscriber* chooses the level, and their broker
  decrypts and re-encrypts.
- Kim & Seo [1] secure only the device–broker hop, with one fixed configuration.

**How we prove it:** attacks A1–A13 (§9) and per-tier overhead measurements (E3).

### Objective 2 — PQC-FOTA: Post-Quantum Firmware and Policy Over-The-Air

> **Objective.** Design and implement an update pipeline over MQTT that delivers both firmware and the
> security policy itself, such that only an offline signing station can produce an acceptable update, no
> older version can ever be reinstalled, and constrained devices can verify every chunk as it arrives.

**What we build**
- **Manifests** signed with SLH-DSA-SHA2-192s. The trust anchor in the bootloader is only 48 bytes.
- **RFC 6962 Merkle tree over chunks**, so the signed manifest carries one 32-byte root whatever the image
  size, and each chunk is verified on arrival, in any order.
- **Monotonic version per artifact type**, stored persistently on the device.
- **Device-class targeting.**
- **Distribution** through retained topics, with cleanup after rollout.
- **The policy as an artifact type**, with an activation time.
- **Chunk size set per device class** by the policy.
- *Stretch:* a signed freshness heartbeat, so a device can detect that updates are being withheld.

**What is new**
- One post-quantum pipeline, over MQTT, for firmware **and** the security policy. This closes the loop:
  the rules that govern PCHC and PASR are themselves updated through PQC-FOTA.
- Domingo Martín et al. [5] evaluated signature algorithms only, with no delivery system, no MQTT and no
  rollback protection.
- A hash-based signature is chosen for the one key that can never be replaced.

**How we prove it:** attacks F1–F7 (§9) and update costs (E5).

### Objective 3 — PASR-MQTT: Policy-Aware Session Resumption

> **Objective.** Design and implement policy-aware resumption of the end-to-end post-quantum session. A
> device can recover after an outage, reboot or key expiry without repeating the full handshake. The signed
> policy decides, per device class, whether resumption is allowed, for how long, and whether it must include
> a fresh key exchange. Every policy, firmware or revocation change invalidates outstanding tickets.

**What we build**
- **Tickets.** The utility issues single-use tickets, sealed under a rotating ticket key (STEK).
- **Binder.** A proof that the device holds the ticket's secret.
- **Nine ordered validation checks.**
- **Two modes:** PSK (cheapest) and PSK+KEM (keeps forward secrecy).
- **Chain-age cap.** Forces a full handshake at least weekly.
- **Policy invariant.** Devices that receive unicast control never resume without a fresh KEM.
- **Invalidation** on a new policy version, a new firmware version, revocation, or retirement of a ticket
  key.
- **Outage-restoration experiment.** Many devices reboot at once.

Standard TLS 1.3 resumption is also used on the broker hop and measured, but it is **not** claimed as our
contribution.

**What is new**
- Resumption whose permission, lifetime and forward-secrecy mode come from a signed policy, bound to the
  policy and firmware versions, applied to an end-to-end post-quantum session in publish/subscribe.
- Existing post-quantum MQTT work repeats the full handshake on every reconnection (report gap 2).
- TLS 1.3 resumption is neither policy-aware nor firmware-bound, and it does not check revocation.

**How we prove it:** attacks P1–P10 (§9). Already measured on the reference implementation (§7.4):
- PSK mode: **92% less device computation and 86% fewer bytes** than a full handshake.
- PSK+KEM mode: 47% and 41% less.

### How the objectives connect

```
       ┌────────────── new signed policy (delivered by PQC-FOTA) ────────────────┐
       ▼                                                                           │
  PCHC-MQTT ──── defines tiers, the end-to-end session, and resume rules ───▶ PASR-MQTT
       │                                                                           │
       │ policy id + version bound into session keys      tickets bound to policy │
       ▼                                                   and firmware version    ▼
  End-to-end session (device ↔ utility) ◀──────── resumed cheaply within limits ───┘
       ▲
       └──── invalidated when PQC-FOTA installs new firmware or a new policy ──────┘
```

PCHC defines the protection and the session. PASR resumes that session within limits PCHC sets. PQC-FOTA
updates the firmware and the PCHC policy, and every update invalidates old tickets and sessions, so devices
re-establish under the new rules. This is the lifecycle in report §3.6, with every arrow now a concrete,
tested mechanism.

---

## 3. Frozen cryptographic choices

### 3.1 The rule we used to choose

Three questions, asked about every key and every exchange:

1. **Could an attacker record this traffic now and break it later with a quantum computer?**
   Then the key exchange must be post-quantum *today*, and **hybrid** (classical + ML-KEM). Recorded
   traffic can never be re-protected, so we do not bet it on one algorithm.
   → Applies to the TLS hop **and** the end-to-end handshake. The broker itself can record end-to-end
   traffic.
2. **Can this key be replaced remotely if its algorithm weakens?**
   - **No:** the bootloader trust anchor is burned in at manufacture. Use the most conservative
     post-quantum scheme, **hash-based SLH-DSA**.
   - **Yes:** the utility's command key is replaced by a signed policy update. Use standard **ML-DSA-65**.
3. **Is this only authentication checked live, at connection time, and replaceable through our
   post-quantum update channel?**
   Then classical is acceptable today (**ECDSA P-256** broker-hop certificates). A future quantum computer
   cannot attack a connection that already happened. Switch to ML-DSA certificates before quantum
   computers are plausible; it's a configuration change (§7.1 has the measured cost).

### 3.2 The final suite

| Where | Purpose | Algorithm | Why (one line) |
|---|---|---|---|
| Broker hop, TLS 1.3 | Key exchange | **X25519MLKEM768** (hybrid), **pinned hybrid-only** on broker and devices | Rule 1. Pinning matters: the defaults silently accept classical-only clients (verified) |
| Broker hop, TLS 1.3 | Encryption | **AES-256-GCM** | 256-bit key keeps about 128-bit strength against quantum search; negotiated by default (verified) |
| Broker hop, TLS 1.3 | Certificates (mutual) | **ECDSA P-256**, private CA | Rule 3; full handshake 4.7 KB vs 23.8–31.7 KB with ML-DSA certificates (measured) |
| End-to-end, device ↔ utility | Key agreement + mutual authentication | **KEM-MQTT** (Kim & Seo), each KEM = **X25519 + ML-KEM-768** with the X-Wing combiner | Base paper's signature-free design; rule 1; ephemeral KEM gives forward secrecy |
| End-to-end | Message encryption | **ChaCha20-Poly1305** (RFC 8439), counter nonces | 256-bit key; fast in software on MCUs without AES hardware |
| End-to-end | Key derivation, MAC, hash | **HKDF-SHA-256** (RFC 5869), **HMAC-SHA-256**, **SHA-256** | Standard |
| Control commands | Authority signature | **ML-DSA-65** (FIPS 204), utility online key | Rule 2 (rotatable); 0.10 ms to verify, 0.12 ms to decrypt and verify a whole command (measured) |
| Firmware and policy | Authority signature | **SLH-DSA-SHA2-192s** (FIPS 205), offline station | Rule 2 (never replaceable); security rests on hash functions only; 48-byte anchor; about 0.28 ms to verify (measured) |
| Firmware chunks | Integrity | **SHA-256 Merkle tree** (RFC 6962) | Manifest size and device memory independent of image size; chunks verified in any order |
| Resumption tickets | Sealing | **ChaCha20-Poly1305** with a rotating STEK | Standard stateless-ticket approach |

All post-quantum parts sit at **NIST Category 3** (ML-KEM-768, ML-DSA-65, SLH-DSA-192s). All symmetric keys
are 256-bit.

### 3.3 Considered and rejected

| Option | Why not |
|---|---|
| Pure ML-KEM-768 (as in the base paper) | Fails rule 1: one algorithm protecting recordable traffic. Kept only as a benchmark comparison (E1) |
| ML-KEM-512 | Minimum level; the Python `cryptography` library does not provide it; FIPS 203 recommends 768 as the default |
| ML-KEM-1024 | Larger (1,568-byte keys) with no need at our threat level |
| HQC | Selected by NIST in 2025 as a backup KEM; not yet a final standard |
| ML-DSA-65 for firmware (the report's original) | The anchor can never be replaced; SLH-DSA relies only on hash functions, and its verification is still well under a millisecond (0.28 ms vs 0.10 ms). Only its signing is slow (0.32 s), and signing happens offline once per release |
| ML-DSA + Ed25519 dual signature for firmware | Once quantum computers exist, its security reduces to ML-DSA alone; SLH-DSA is more conservative and simpler |
| LMS / XMSS (stateful hash-based) | Reusing a one-time key is catastrophic; state management is too risky for a student-run signing station. SLH-DSA is stateless |
| FN-DSA (Falcon) | Smaller signatures, but floating-point arithmetic makes constant-time MCU code hard (your report §5.2); no Python support |
| ML-DSA certificates at the broker hop | 5–7× larger handshakes (measured). Kept as the ready migration path |
| AES-256-GCM at the application layer | Fine, but ChaCha20-Poly1305 is faster in software on MCUs without AES instructions. TLS still uses AES-256-GCM |
| Ascon-AEAD128 (NIST SP 800-232) | Lightweight, but a 128-bit key; we keep 256-bit keys everywhere. A candidate for 8-bit future work |
| Canonical JSON envelopes (Semester 1 prototype) | Deterministic only in CPython; replaced by a length-prefixed binary format |

---

## 4. System architecture

### 4.1 Actors and trust

| Actor | Role | Trusted for | Not trusted for |
|---|---|---|---|
| Field device (meter, DER controller, EV charger, gateway) | MQTT client: publishes telemetry and alerts; receives commands, demand-response events and updates | Its own data | Anything outside its authorisation (it may be captured) |
| Broker (Mosquitto) | Routes messages, stores retained artifacts, enforces access control | Availability and honest routing | Confidentiality or integrity of alerts and commands (it may be curious or compromised) |
| Utility headend | End-to-end endpoint, ticket issuer, command issuer, artifact publisher | Issuing commands and tickets | — (a compromised utility is out of scope) |
| Offline signing station | Signs firmware and policy | Root of trust | — (never on a network; in our Docker setup it has no network at all, `network_mode: none`) |
| TLS certificate authority | Issues broker and device certificates | Hop identity | — |

### 4.2 Who protects what, against whom

```
 Device ──[ TLS 1.3 · X25519MLKEM768 · ECDSA certs ]── Broker ──[ TLS 1.3 · X25519MLKEM768 ]── Utility
   │     hop layer: stops network attackers, including              reads TELEMETRY,              │
   │     record-now-decrypt-later; carries device identity           relays everything else        │
   │                                                                                               │
   └────────────[ end-to-end layer: hybrid KEM-MQTT session · ChaCha20-Poly1305 ]─────────────────┘
                 ALERT and CONTROL: the broker relays ciphertext it cannot read or forge

 CONTROL commands are also signed by the utility (ML-DSA-65).
 Firmware and policy are signed by the offline station (SLH-DSA-SHA2-192s).
```

Even if the broker-hop certificates were forged someday, alerts and commands stay protected. A forger could
publish on a device's topics, but it has no end-to-end session key and no utility signing key, so the
utility and the devices reject everything it sends. Hop authentication only guards TELEMETRY.

### 4.3 Key inventory

| Key | Algorithm | Private part held by | Public part known to | Rotation |
|---|---|---|---|---|
| Station signing key | SLH-DSA-SHA2-192s | Offline station only | Every bootloader (48 B) | Never, by design |
| Utility end-to-end static key | X25519 + ML-KEM-768 | Utility | Devices, through the signed policy | New policy version |
| Utility command key | ML-DSA-65 | Utility | Devices, through the signed policy | New policy version |
| Ticket key (STEK) | 256-bit, ChaCha20-Poly1305 | Utility | — | Every 24 h; previous keys kept ≤ 7 days |
| Device end-to-end static key | X25519 + ML-KEM-768 | Device | Utility registry (at provisioning) | Re-provisioning |
| Device TLS key and certificate | ECDSA P-256 | Device | Broker, through the CA | CA re-issue |
| Broker TLS key and certificate | ECDSA P-256 | Broker | Devices and utility, through the CA | CA re-issue |
| Zone keys (demand-response broadcast) | 256-bit | Utility and zone members | — | Membership change, policy change, daily |
| Session keys | HKDF from the handshake | Device and utility | — | Every resumption; full handshake at least every 7 days |

### 4.4 The tiers

| Tier | Traffic | Security properties | Mechanism | Who can read | Who can forge |
|---|---|---|---|---|---|
| **TELEMETRY** | Periodic readings | Confidential and integrity-protected against the network; device identified | Hybrid TLS hop only | Broker, utility | Broker |
| **ALERT** | Anomaly notifications, device → utility | + confidential and integrity-protected against the broker; replay-protected | + end-to-end ChaCha20-Poly1305 with per-session keys and sequence numbers | Utility only | Nobody except the device |
| **CONTROL** | Setpoints (unicast), demand-response events (broadcast) | + authenticity checked by the device, non-repudiation, expiry, replay protection | + end-to-end encryption (session key or zone key) + utility ML-DSA-65 signature | Target device, or zone members | Nobody without the utility signing key: not the broker, not a captured meter |

Firmware and policy artifacts are signed by the offline station. Their content is public, and integrity and
authenticity are what matter.

**Why telemetry is broker-readable.** The utility runs the broker and bills from these readings. This is
deliberate, and the report must say so, because meter data can reveal occupancy patterns. Anything more
sensitive belongs on an ALERT topic.

### 4.5 Topics and access control

| Topic | Tier | Publisher | Subscriber |
|---|---|---|---|
| `grid/{class}/{id}/telemetry` | TELEMETRY | Device | Utility |
| `grid/{class}/{id}/alert` | ALERT | Device | Utility |
| `grid/{class}/{id}/control` | CONTROL | Utility | Device |
| `grid/dr/{zone}/event` | CONTROL (broadcast) | Utility | Zone members |
| `pqgrid/hs/{id}/up` · `/down` | Handshake (self-protected) | Device · Utility | Utility · Device |
| `pqgrid/fota/{class}/manifest` · `/{version}/chunk/{i}` | Signed artifact (retained) | Utility, relaying the station's output | Devices of that class |
| `pqgrid/policy/manifest` · `/chunk/{i}` | Signed artifact (retained) | Utility | All |

The access-control list is generated from the signed policy and the device registry. Each device may use
only topics containing its own ID. The utility has full access. No device can publish on firmware or policy
topics. The broker learns identity from the certificate's CN (`use_identity_as_username`).

### 4.6 What happens on each kind of reconnection

| Event | What survives on the device | Broker hop | End-to-end session | Cost |
|---|---|---|---|---|
| Link drop, NB-IoT sleep with RAM kept | Session and TLS session in RAM | TLS 1.3 resumption (standard) | Continues; no handshake | Hop resumption only |
| Broker restart | Session and TLS session in RAM | Full TLS (a restarted broker has new ticket keys) | Continues; the session lives in the device and the utility, not the broker | Full TLS only |
| Utility restart | Everything | Unaffected | Utility lost the session → sends a resync hint → **PASR resumption** (STEK and used-ticket list persisted); unacknowledged alerts resent | Cheap resume |
| Power outage or reboot (RAM lost, flash kept) | PASR ticket, secret, outbox and command counter in flash | Full TLS (Python cannot store TLS sessions across restarts) | **PASR resumption** (PSK or PSK+KEM per policy); clock re-set from the utility; outbox resent; pending commands redelivered | Full TLS + cheap resume |
| Ticket lifetime reached | — | — | PASR resumption (re-key) | Cheap |
| Chain age reached (≤ 7 days) | — | — | Full handshake (re-anchor) | Full |
| New firmware installed | — | Full TLS | Full handshake (tickets bound to old firmware) | Full |
| New policy activated | — | Unaffected | Full handshake under the new policy (random 0–60 s jitter) | Full |
| Device revoked | — | Removed from the access-control list | Every attempt refused | — |

---

## 5. Protocol specifications

### 5.1 The policy document

**Fields:**
- `policy_id`, `version`, `activate_at`
- `default_tier`, which is always `CONTROL`
- `rules`: a list of `{pattern, tier}`
- `classes`: per class, `resume` (`NONE` | `PSK` | `PSK_KEM`), `ticket_lifetime_s`, `max_chain_age_s`,
  `unicast_control`, `fota_chunk_size`
- `utility_kem_pk`, `utility_cmd_pk`

**Tier rule:** `tier(topic)` = the strongest tier among all matching rules. If no rule matches, the topic is
**CONTROL**. So no rule can ever make a topic weaker than another matching rule says, and a forgotten topic
gets maximum protection.

**Validator.** A policy that fails any of these checks is never installed:

- `default_tier = CONTROL`
- every tier name is valid
- a class with `unicast_control = true` must have `resume ∈ {PSK_KEM, NONE}`
- `0 < ticket_lifetime ≤ max_chain_age ≤ 7 days`
- `version` > the installed version

**Encoding.** The exact signed bytes are what gets installed. Nothing is re-serialised.

Example:

```json
{
  "policy_id": "nitk-grid", "version": 7, "activate_at": 0, "default_tier": "CONTROL",
  "rules": [
    {"pattern": "grid/+/+/telemetry", "tier": "TELEMETRY"},
    {"pattern": "grid/+/+/alert",     "tier": "ALERT"},
    {"pattern": "grid/+/+/control",   "tier": "CONTROL"},
    {"pattern": "grid/dr/+/event",    "tier": "CONTROL"}
  ],
  "classes": {
    "smart_meter":    {"resume": "PSK",     "ticket_lifetime_s": 86400, "max_chain_age_s": 604800, "unicast_control": false, "fota_chunk_size": 4096},
    "der_controller": {"resume": "PSK_KEM", "ticket_lifetime_s": 43200, "max_chain_age_s": 604800, "unicast_control": true,  "fota_chunk_size": 16384},
    "ev_charger":     {"resume": "PSK_KEM", "ticket_lifetime_s": 43200, "max_chain_age_s": 604800, "unicast_control": true,  "fota_chunk_size": 16384},
    "gateway":        {"resume": "PSK_KEM", "ticket_lifetime_s": 86400, "max_chain_age_s": 604800, "unicast_control": true,  "fota_chunk_size": 65536}
  },
  "utility_kem_pk": "…1,216 bytes hex…", "utility_cmd_pk": "…1,952 bytes hex…"
}
```

### 5.2 The end-to-end handshake (hybrid KEM-MQTT with POLICY_INFO)

**Hybrid KEM (HKEM)** = ML-KEM-768 + X25519. The shared secret is
`SHA3-256(ss_ML-KEM ‖ ss_X25519 ‖ ct_X25519 ‖ pk_X25519 ‖ label)`, the X-Wing construction (IETF CFRG
draft). Sizes: public key 1,216 B, ciphertext 1,120 B.

**Known in advance:** the device knows `pk_U` from its signed policy; the utility knows `pk_D` and the
device class from its registry.

```
Device D                                                        Utility U   (the broker only relays)
(pk_e, sk_e) ← HKEM.KeyGen()                       ephemeral: gives forward secrecy
(ss_U, ct_U) ← HKEM.Encaps(pk_U)                   only U can open this: authenticates U
K_B ← HKDF(ss_U, "early" ‖ H(pk_e, ct_U, n_D))
CH:  pk_e, ct_U, n_D, AEAD_KB( id_D ‖ class ‖ POLICY_INFO_D ‖ fw_version ‖ device_time ) ────────▶
                                          ss_U ← Decaps(ct_U); open AEAD. Check: id = topic id;
                                          registered and active; class; POLICY_INFO_D = current
                                          (device_time is informational only: never a gate)
                                          (ss_e, ct_e) ← Encaps(pk_e)
                                          (ss_D, ct_D) ← Encaps(pk_D)    only D can open: authenticates D
                                          K1 ← HKDF(ss_e ‖ ss_U, H(CH))
                                          K_master ← HKDF-Extract(H(transcript), ss_e ‖ ss_U ‖ ss_D)
       ◀── SH: ct_e, n_U, AEAD_K1( ct_D ‖ POLICY_INFO_U ‖ resume_mode ‖ chain_expiry ‖ utility_time ), MAC_U
ss_e ← Decaps(ct_e); open AEAD; check POLICY_INFO_U = installed policy
ss_D ← Decaps(ct_D); derive K_master; verify MAC_U        (U is now explicitly authenticated)
set clock from utility_time                               (fixes clocks reset by power loss)
DF:  MAC_D ───────────────────────────────────────────────────────▶ verify MAC_D → session established
       ◀── NT: AEAD(ticket)   or   FIN: MAC(fin key, sid)           (PASR, §5.4)
device marks the session CONFIRMED only after NT/FIN, then sends queued alerts
```

**Key schedule**
- `K_master = HKDF-Extract(salt = H(transcript), IKM = ss_e ‖ ss_U ‖ ss_D)`
- `K_{name,dir} = HKDF-Expand(K_master, "key|" ‖ name ‖ "|" ‖ dir)`, for `ALERT|up`, `CONTROL|down`,
  `ACK|up` and `ACK|down`
- Confirmation keys `kc_U`, `kc_D`; session id `sid = HKDF-Expand(K_master, "sid", 8)`; resumption secret
  `psk = HKDF-Expand(K_master, "res|" ‖ ticket_id)`

**The report's formula, corrected**

| | Formula |
|---|---|
| Report (eq. 3.2) | `K_session = KDF(K_TLS, policy_id, tier)` |
| Now | `K_tier = KDF(ss_e ‖ ss_U ‖ ss_D, H(transcript ∋ policy_id, policy_version), tier)` |

Same idea, but the input secret is now shared only by device and utility.

**Robustness rules** (each one found by edge-case testing; [BalaMP-Rationale.md](BalaMP-Rationale.md)
Part D)

| Rule | Why |
|---|---|
| **Duplicates get identical answers.** A duplicated CH, DF or RH within 120 s receives the same stored reply | MQTT QoS 1 is "at least once". In v1, a duplicated CH broke the handshake and a duplicated DF crashed the utility |
| **Confirm before use.** The device sends nothing until NT or FIN arrives; if they're lost, it resends DF | Otherwise a lost DF leaves the device "connected" while the utility is not |
| **Time comes from the utility**, inside the authenticated SH/RS | A clock reset by a power cut locked devices out in v1 |
| **At most one half-open handshake per device**, forgotten after 60 s | Limits utility memory under a flood |
| **One live session per device.** A new session replaces the old one | Simple replay tracking; clones become visible |
| **Constant-time comparison** for every MAC | Avoids timing leaks |
| **Strict parsing:** exact field count, known message types only, 1 MiB cap per field | The fuzz test found a lenient type check in v1 |

**Properties (all tested, §9)**
- Mutual authentication without signatures, as in Kim & Seo.
- Forward secrecy from the ephemeral KEM.
- Hybrid.
- The policy is bound into the keys: change one byte of POLICY_INFO in either direction and the handshake
  aborts.
- Replay-safe: nonces, key confirmation, duplicate cache.
- Measured cost: 5,212 bytes; 0.28 ms on the device and 0.23 ms on the utility (§7.4).

**Differences from Kim & Seo, Figure 4**

| | Kim & Seo | This design |
|---|---|---|
| Endpoints | Device ↔ broker | Device ↔ utility, with the broker excluded |
| KEM | Kyber-512 | Hybrid X25519 + ML-KEM-768 |
| POLICY_INFO | None | Added and bound into keys |
| Device public key | Sent under AEAD, because their broker stores only a hash | Held in the utility's registry; the device sends only its ID |
| Time | Device timestamp | Authenticated utility time sent to the device |
| Transport | Direct to the broker | MQTT 5 publishes through the broker, using a response topic and correlation data (verified to pass through) |

### 5.3 Tier messages

**ALERT (device → utility), acknowledged end to end**
- Envelope: `0x02 ‖ sid(8) ‖ seq(8) ‖ ChaCha20-Poly1305(K_ALERT|up, nonce = 0x01‖000‖seq,
  AAD = H("ALERT", topic, sid, seq))`. The plaintext is `alert_id(16) ‖ payload`.
- The utility checks that the topic's device owns the session, then replies
  `ACK = 0x05 ‖ sid ‖ seq ‖ MAC(K_ACK|down, sid ‖ seq)`.
- The device keeps every unacknowledged alert in a **flash outbox**. After any re-establishment it resends
  them under the new session with the **same alert_id**, so the utility recognises duplicates.
- Overhead: +73 bytes (the alert ID and framing).

**CONTROL, unicast (utility → device), applied at most once**
- Envelope: `0x03 ‖ sid ‖ seq ‖ AEAD(K_CONTROL|down; plaintext = command ‖ expires_at ‖ σ)`
- Signature: `σ = ML-DSA-65_U("pqgrid/v1/cmd" ‖ H(device_id, topic, seq, expires_at, command))`
- The device decrypts and verifies first, then:
  - `seq > last_applied` and not expired → **apply**, then save `seq` to flash
  - `seq ≤ last_applied` → **DUP**, never re-applied
  - expired, judged by utility-provided time → **EXPIRED**
- It always replies `ACK = 0x06 ‖ sid ‖ seq ‖ status ‖ MAC(K_ACK|up, sid ‖ seq ‖ status)`.
- The utility keeps unacknowledged, unexpired commands and **re-sends them on the next session** with the
  same `seq` and signature, re-encrypted under the new keys. Commands are ordered: a newer command
  supersedes an older one that never arrived.
- Overhead: +3,378 bytes, almost all of it the signature.

**CONTROL, broadcast (demand-response)**
- Envelope: `0x04 ‖ zone ‖ epoch ‖ seq ‖ nonce ‖ AEAD(K_zone,epoch; event ‖ expires_at ‖ σ)`
- Zone keys reach each member as unicast CONTROL messages. They are rotated on membership change, on policy
  change, and daily.
- A captured meter knows the zone key but cannot produce σ (tested).
- There is no per-device ACK (it wouldn't scale). Events are re-broadcast until their start time.

**Resync hint.** If the utility receives an envelope for a session it no longer has (for example after a
restart), it replies `0x07 ‖ sid`. The hint is unauthenticated, so the device treats it only as a reason to
**resume**, which is itself authenticated, and acts on at most one hint per 30 s.

**Rules for every receiver**
1. **Two-phase replay check.** A counter or sequence is consumed only after decryption and signature checks
   succeed, so a forged message never burns a valid number (tested).
2. **Expiry** is judged with utility-provided time.
3. **Tier by topic.** The receiver takes each topic's tier from **its own installed policy**. A plaintext or
   wrong-tier message on an ALERT or CONTROL topic is dropped.
4. **Ownership.** An envelope must belong to the session of the device named in its topic.

### 5.4 PASR: tickets and resumption

**The ticket**
- Plaintext (sealed inside the ticket): `ticket_id(16) ‖ device_id ‖ class ‖ POLICY_INFO ‖ fw_version ‖
  resume_mode ‖ issued_at ‖ expires_at ‖ chain_expires_at ‖ psk(32)`
- Sealed blob: `0x01 ‖ kid ‖ nonce(12) ‖ ChaCha20-Poly1305(STEK[kid], AAD = 0x01 ‖ kid)`, about 250 B.
- Stored in device flash: the blob, the device's copy of `psk`, the expiry and the mode.

A **chain** is one full handshake plus every resumption that follows it.

```
D: RH: blob, n_D, mode, [pk_e′ if PSK_KEM], id, POLICY_INFO, fw_version, device_time,
       binder = MAC(HKDF(psk,"binder"), H(all fields))                                  ──▶
U: run the 9 checks → consume ticket_id → [ (ss_e′, ct_e′) ← HKEM.Encaps(pk_e′) ]
   K_master′ = HKDF-Extract(H(transcript), psk ‖ [ss_e′])
                                  ◀── RS: n_U, [ct_e′], (utility_time ‖ chain_expiry), MAC_U
D: verify MAC_U, set clock → DF: MAC_D ──▶  U: verify → session; new ticket, same chain expiry  ◀── NT
```

**The 9 checks, in order.** If any fails, the device must do a full handshake. It never gets a weaker
session.

1. The ticket key (`kid`) is still live.
2. The ticket decrypts and authenticates.
3. The device ID in the ticket = the topic's ID = the claimed ID.
4. The device is registered and **not revoked**.
5. The ticket has not expired, and neither has its chain (utility clock).
6. POLICY_INFO in the ticket = the claimed one = the **current** policy.
7. The firmware version in the ticket = the claimed version.
8. The resume mode in the ticket = the requested mode = the **current policy's** mode for the class (not
   `NONE`). PSK_KEM must carry a fresh key.
9. The binder is valid, which proves the device holds `psk`. **Then** the ticket must be unused, and it is
   consumed.

The ticket is consumed only *after* the binder checks out, so a stolen blob cannot burn the legitimate
device's ticket (tested). A duplicated RH within 120 s gets the identical RS, not "ticket already used".
v1 got this wrong.

**Modes** (measured, §7.4)

| Mode | Device | Utility | Bytes | Forward secrecy | Policy uses it for |
|---|---|---|---|---|---|
| Full handshake | 0.278 ms | 0.229 ms | 5,212 | Yes | First contact, re-anchor, after updates |
| PSK | 0.021 ms (−92%) | 0.030 ms (−87%) | 755 (−86%) | No | Classes without unicast control (meters) |
| PSK+KEM | 0.144 ms (−47%) | 0.103 ms (−54%) | 3,103 (−41%) | Yes | Classes with unicast control (DER, EV, gateways) |

Each percentage compares against the full handshake of the **same device class**. The full-handshake row
shows the meter; the DER controller's full handshake is 0.271 ms, 0.223 ms and 5,222 B.

**Invalidation**

| Change | What becomes invalid |
|---|---|
| New policy version | All tickets and sessions |
| New firmware | That device's tickets |
| Revocation | That device's tickets and sessions. Plain TLS resumption does not check this |
| Ticket-key retirement | Tickets sealed with that key |
| Reboot | The session (the ticket survives in flash) |

**Housekeeping**
- The STEK rotates every 24 h, and previous keys are kept for up to the maximum ticket lifetime.
- **The STEKs and the used-ticket list are persisted**: a file in the prototype, an HSM in production.
  - If the STEK were lost on a utility restart, every ticket in the fleet would die and every device would
    need a full handshake at once (tested counterfactual).
  - If the used-ticket list were lost, consumed tickets could be replayed (tested).
- Each used-ticket record is dropped when that ticket would have expired, so memory stays bounded.
- A **stolen STEK lets an attacker forge tickets.** This was shown working in the RISK test, which is why the
  STEK belongs in an HSM.

**What PASR is not**
- It is not TLS resumption. We use that too, on the hop, as standard behaviour.
- There is no 0-RTT data. A resumed session carries data only after both key confirmations, so resumption
  can never replay a command. That was the real worry behind the report's "control excluded from
  resumption".

### 5.5 PQC-FOTA

**Manifest**
- Fields: `"PQFW1"`, artifact type (FIRMWARE | POLICY), device class, version (u64), payload length,
  SHA-256 of the payload, chunk size, chunk count, **Merkle root**, `activate_at`, `issued_at`.
- Signed with SLH-DSA-SHA2-192s: the signature is 16,224 B, so a signed manifest is 16,405 B (measured).
- Device limits: at most 65,536 chunks and 64 MiB. Larger manifests are refused before any download.

**Chunk:** type, version, index, data, and the Merkle audit path (log₂ n × 32 B). Duplicate chunks are
harmless, and chunks from another artifact or version are refused.

**Merkle tree:** RFC 6962. Leaf = `SHA-256(0x00 ‖ data)`, node = `SHA-256(0x01 ‖ left ‖ right)`.
Verification follows RFC 9162 §2.1.3.2.

**What the device does: A/B slots, commit after a successful boot**
1. Verify the SLH-DSA signature against the bootloader anchor (48 B).
2. Check the magic value, the device class and the limits.
3. Check `version > committed[type]`. The committed counters live in protected storage that a factory reset
   cannot erase.
4. Write chunks, in any order, into the **inactive slot**, verifying each audit path.
5. Once all chunks are present, check the payload length and its SHA-256. The image is now **staged**, not
   yet committed.
6. What happens next depends on the artifact:

| Artifact | Next step |
|---|---|
| **Firmware** | Reboot into the new slot. When the self-test passes, **commit**: the counter moves forward. If it fails, **revert** to the old slot; the counter is unchanged, so the same version can be retried |
| **Policy** | Validate it, then activate at `activate_at` and commit |

After a firmware commit, the new version invalidates old tickets, so the device does a full handshake.

**Why commit after boot:** if the counter moved forward before the new firmware proved it boots, a bad image
would strand the device. The old version would be refused, and the new one doesn't work.

**Distribution**
- The utility publishes the manifest and chunks as **retained** QoS 1 messages. Retained delivery to a
  late subscriber was verified for 16 KB and 256 KB messages.
- The broker must run with `persistence true`. Without it, retained artifacts vanish on a broker restart
  (verified).
- A device that loses power mid-download simply re-fetches the retained chunks (tested).
- Clean-up happens after the rollout, and only after a retention window (for example 30 days) so slow devices
  can finish.
- Chunk size comes from the policy, per class, and must stay below the broker's `max_packet_size`.

**Honest trade-off: Merkle tree vs a flat hash list** (1 MiB image, 4 KiB chunks, measured)

| | Flat hash list (the report's original) | Merkle tree (this design) |
|---|---|---|
| Size of the signed manifest's hash data | 8,192 B, and it grows with the image | 32 B (the root), always |
| Hash data the device holds while installing | 8,192 B | 32 B + one 256-byte proof |
| Extra bytes per chunk | 0 | 256 B |
| Total integrity bytes on the wire | 8 KB | 64 KB (6% of the image) |

So Merkle **costs more bandwidth** and **saves device memory**, and its saving grows with image size. A
16 MiB gateway image at 4 KiB chunks would need a 128 KB flat list in the signed manifest; with Merkle it
still needs 32 B. The knob is chunk size. At 64 KiB chunks a 1 MiB image has 16 chunks, 128 B of proof
each, 2 KB in total. So the policy sets small chunks for meters on lossy links and large chunks for
gateways.

**Policy as an artifact.** The policy travels through the same pipeline, with type POLICY. After
`activate_at`, the utility refuses old-policy sessions and tickets, and devices re-handshake after a random
0–60 s delay so they don't all reconnect at once. A device offline across several versions installs the
newest directly (tested).

**Stretch goal: freshness heartbeat.** The utility periodically signs (ML-DSA-65) and retains
`{class, latest firmware, latest policy, valid_until}`. A device raises an ALERT if the heartbeat goes
stale, or if it shows a version the device never received. That lets a device detect a broker that is
withholding updates.

### 5.6 Broker configuration essentials

```
listener 8883
tls_version tlsv1.3
cafile …  certfile …  keyfile …        # ECDSA P-256
require_certificate true
use_identity_as_username true          # certificate CN = device id = ACL user
acl_file /mosquitto/acl                # generated from the signed policy; reloaded with SIGHUP (verified)
allow_anonymous false
set_tcp_nodelay true                   # without it every handshake stalls 40–90 ms (measured)
persistence true                       # without it retained firmware/policy vanish on restart (verified)
persistence_location /mosquitto/data/
max_packet_size 300000                 # larger packets are refused (verified); chunk size must stay below
```

**Pin hybrid-only key exchange.** Start Mosquitto with `OPENSSL_CONF` pointing to a file containing
`Groups = X25519MLKEM768:SecP256r1MLKEM768`, and give devices the same file.

- With the defaults, a client offering **only classical X25519** is accepted silently: verified
  (`Peer Temp Key: X25519`).
- With pinning, it gets a handshake failure, while normal clients still negotiate `X25519MLKEM768`
  (verified).
- Mosquitto has no groups setting of its own, and Python cannot set groups in code, so this file is the
  only mechanism.

**Other broker rules**
- **The access-control compiler** verifies the policy's signature, reads the device registry, writes one
  user block per device, and sends SIGHUP to Mosquitto.
- **Device IDs** must match `^[a-z0-9][a-z0-9-]{0,31}$`. They become topic levels and ACL user names, so
  `+`, `#` and `/` could otherwise inject access rules (tested).
- **Run as the `mosquitto` user**, with files owned accordingly. The validation configurations that use
  `user root` are test-only.
- **Last Will:** each device registers `grid/{class}/{id}/status = offline`. It is informational only, and
  lets the utility hold commands for offline devices.
- **Clone warning:** a second connection with the same identity kicks the first one off
  ("already connected, closing old connection", verified). The utility should alarm on repeated takeovers.

---

## 6. Threat model and security goals

**Adversaries**

| Adversary | Can do |
|---|---|
| Network attacker | Observe, inject, replay, delay, drop, and **record** traffic for future quantum decryption |
| Curious or compromised broker | Read everything it can, record, modify or inject relayed messages, serve stale retained messages, drop messages |
| Captured device(s) | Use their own keys and state; try to act beyond their authorisation (other topics, forged commands, clones) |
| Future quantum computer | Break classical public-key cryptography on recorded data, or live once it exists |

**Trusted:** the offline station, the utility headend, and manufacturing and provisioning.

| Goal | Mechanism | Attacks (§9) |
|---|---|---|
| G1 · All traffic confidential against the network, including record-now-decrypt-later | Hybrid TLS 1.3 pinned hybrid-only, AES-256-GCM | N1–N3, E1 |
| G2 · Alerts and commands confidential and intact against the broker | End-to-end hybrid KEM-MQTT session | A5, A6 |
| G3 · Commands authentic against the broker and captured devices | Utility ML-DSA-65 signatures | A10, A11 |
| G4 · No silent policy or tier downgrade | Signed policy, monotonic version, POLICY_INFO bound into keys, strongest-rule tier with CONTROL default, receivers enforce tier by topic | A1–A4, A7, A13, F6 |
| G5 · Replay protection for messages, handshakes, tickets and updates | Two-phase sequence checks, nonces, key confirmation, single-use tickets, monotonic versions; TLS record protection on the hop | A8, A9, P1, F4, F5, N1 |
| G6 · Firmware and policy authentic, intact, not rollback-able | SLH-DSA + Merkle + persisted monotonic versions | F1–F7 |
| G7 · Least privilege for captured devices | Per-device certificates and ACL, per-device keys, utility-only signing | A3, A11, A12, P3 |
| G8 · Forward secrecy | Ephemeral hybrid KEM in full handshakes and PSK+KEM resumes; PSK chains capped at 7 days | P6; E2 |
| G9 · Cheap resumption within policy limits, invalidated on any change | PASR | P1–P10 |
| G10 · Correct behaviour despite duplicates, losses, crashes and restarts | Idempotent handlers, confirm-before-use, end-to-end ACKs with alert IDs, command redelivery with apply-at-most-once, persisted STEK and used list, A/B firmware commit, utility-authenticated time | EDGE tests ([BalaMP-Rationale.md](BalaMP-Rationale.md) Part D) |

**Out of scope (said openly)**
- **Denial of service.** A broker can drop messages; we can only detect that (stretch heartbeat).
- **Traffic analysis.** Who talks to whom, when, and message sizes.
- **A compromised utility headend.** Devices should enforce local safety limits; future work.
- **Side channels.**
- **Formal proof.** A ProVerif or Tamarin model of §5.2 is future work.
- **Real constrained hardware.** An ESP32 is a stretch goal.

---

## 7. Evidence already obtained

All of this ran in Docker (Debian trixie, OpenSSL 3.5.7, Mosquitto 2.0.21, Python 3.13.5,
`cryptography` 50.0.1, `paho-mqtt` 2.1.0). Re-run it with `design-validation/run_all.sh`. The raw output is
in `design-validation/results/`. These are **laptop-in-container numbers, not smart-meter numbers**. Timings
vary by a few percent from run to run; the tables quote the run saved in `results/`, and re-running
regenerates it.

### 7.1 Broker experiments (`results/broker.txt`)

| Question | Result |
|---|---|
| Which key exchange does Mosquitto negotiate by default? | **`X25519MLKEM768`**, TLS 1.3, `TLS_AES_256_GCM_SHA384` |
| Do post-quantum certificates work end to end? | Yes: ML-DSA-65 CA, broker and client certificates, "Verification: OK" |
| Does per-device access control hold? | Publishing to another device's topic → **PUBACK "Not authorized"**, never delivered. Subscribing is answered "granted", but **nothing is delivered**, because Mosquitto checks at delivery. Tests must check delivery |
| Do MQTT 5 user properties, response topic and correlation data pass through? | Yes, intact |
| Are large retained messages delivered to late subscribers? | Yes: 16,624 B and 262,144 B |
| Does TLS 1.3 resumption work from Python? | Yes: **20/20** with raw `ssl`, **25/25** through a paho subclass |
| Does the ACL reload without a restart? | Yes: "Not authorized" before, accepted after editing and SIGHUP |

| Certificates (both sides) | Leaf certificate | Full handshake | Resumed handshake |
|---|---|---|---|
| **ECDSA P-256 (chosen)** | 394 B | **4,695 B** | 3,613 B |
| ML-DSA-44 | 3,991 B | 23,809 B | 7,213 B |
| ML-DSA-65 | 5,520 B | 31,702 B | 8,749 B |

### 7.2 Network attacks through an interception proxy (`results/network.txt`)

| Test | Result |
|---|---|
| N1 · Replay **all 16,043 bytes** a real meter sent, on a new connection | **0 messages delivered**; broker log shows `record layer failure`, `Client <unknown>` |
| N2 · Flip one bit inside the encrypted PUBLISH, in flight | **Not delivered**; connection dropped |
| N3 · Client offering **only classical X25519** | Default broker: **accepted** (`Peer Temp Key: X25519`). Hybrid-only broker: **handshake failure**. Normal client on the hybrid-only broker: `X25519MLKEM768` |
| N4 · Second connection with the same identity (clone) | Genuine device kicked off: "already connected, closing old connection" |
| N5 · Broker restart with a retained manifest | Survives with `persistence true`; **lost** without it |
| N6 · 400 KB publish against `max_packet_size 300000` | Sender disconnected; the 256 KB chunk still delivered |
| N7 · TLS resumption after the source IP changes (127.0.0.1 → 172.17.0.2) | Resumed |

### 7.3 Protocol validation (`results/validate.txt`)

**80/80 behave as expected.**

| Group | Count | What it covers |
|---|---|---|
| **Core** | 47 | Full handshakes for two classes; tier engine; alerts with end-to-end ACK; commands with signature, ACK and apply-once; broadcast demand-response; PSK and PSK+KEM resumption; policy v2 through PQC-FOTA; a 1 MiB firmware as 256 shuffled chunks; and every attack in §9 |
| **Edge** | 31 | Duplicate hello, finished and resume; lost server hello, finished and ticket; device clock at 1970 and a day ahead; utility restart with resync; restart without a persisted STEK (counterfactual); consumed ticket after restart; device reboot; lost alert ACK; command while offline, ACK lost (also across a reboot), expired, out of order; forged resync; device-ID injection; oversized field; power loss mid-download; failed boot; mixed-version chunks; offline across policy versions; clone; replayed old hello; handshake flood; zone re-key; cross-device envelope replay; **fuzzing: 3,300 corrupted messages into 11 handlers, all rejected cleanly** (5 more random seeds, 16,500 more messages, also all rejected) |
| **Risk** | 2 | Shown **succeeding** on purpose: a stolen utility end-to-end key reads new sessions but still cannot forge commands; a stolen STEK forges tickets (hence an HSM) |

### 7.4 Measured costs (`results/bench.txt`, median of 180 runs after 20 warm-up)

| | Device | Utility | Bytes on the wire |
|---|---|---|---|
| Full end-to-end handshake (3 hybrid KEMs) | 0.278 ms | 0.229 ms | 2,493 + 2,411 + 42 + ticket 266 = **5,212** |
| PASR resume, PSK | 0.021 ms | 0.030 ms | 337 + 110 + 42 + 266 = **755** |
| PASR resume, PSK+KEM | 0.144 ms | 0.103 ms | 1,560 + 1,230 + 42 + 271 = **3,103** |

| Per message (64-byte payload) | Bytes | Extra | Device cost |
|---|---|---|---|
| TELEMETRY | 64 | 0 (TLS only) | — |
| ALERT | 137 | +73 (includes the alert ID) | Seal 0.005 ms |
| CONTROL (unicast) | 3,442 | +3,378 | Open + verify 0.118 ms |
| CONTROL (broadcast) | 3,468 | +3,404 | — |

| PQC-FOTA (1 MiB image, 4 KiB chunks) | Value |
|---|---|
| Signed manifest | 16,405 B |
| Trust anchor | 48 B |
| Merkle proof per chunk | 256 B |
| Station build and sign (offline) | 472 ms |
| Device manifest verification | 0.272 ms |
| Full install, 256 chunks shuffled | 3 ms |

| Signature algorithm (`openssl speed`, `results/signature_speed.txt`) | Sign | Verify | Signature | Public key |
|---|---|---|---|---|
| ML-DSA-65 | 0.56 ms | 0.10 ms | 3,309 B | 1,952 B |
| SLH-DSA-SHA2-192s (chosen) | 324 ms | 0.28 ms | 16,224 B | 48 B |
| SLH-DSA-SHA2-128s (smaller alternative) | 168 ms | 0.16 ms | 7,856 B | 32 B |

| Hybrid key exchange (`results/hybrid_cost.txt`) | Value |
|---|---|
| X25519, both sides | 93.8 µs |
| ML-KEM-768, keygen + encapsulate + decapsulate | 76.9 µs |
| What hybrid adds | **About +120% compute** (roughly double) and 64 bytes. On the macOS Python environment it was +67%, which is why the environment must always be stated |

### 7.5 Pitfalls found (each would have cost the team days)

| Pitfall | Effect | Fix |
|---|---|---|
| **Default TLS settings accept classical-only clients** | Quantum safety lost silently | Pin hybrid-only groups with `OPENSSL_CONF` on the broker and the devices (§5.6) |
| **MQTT QoS 1 duplicates are normal** | In v1: broken handshakes, a utility crash, killed tickets | Idempotent handlers (§5.2) |
| **Device clocks reset after outages** | In v1: devices locked out | Utility-authenticated time (§5.2) |
| **Mosquitto persistence is off by default** | Retained firmware and policy vanish on a broker restart | `persistence true` |
| Nagle's algorithm with delayed ACK | TLS handshakes measured **about 91 ms** instead of **1.9 ms** | `set_tcp_nodelay true` in Mosquitto **and** `TCP_NODELAY` on every client. paho does not set it |
| Python 3.13 strict certificate checks | Connections fail with "CA cert does not include key usage extension" | Generate the CA with `basicConstraints` and `keyUsage` (see `broker/setup_pki.sh`) |
| TLS session reuse in Python | "Session refers to a different SSLContext" | Keep **one** `SSLContext` per device for its whole lifetime |
| paho has no session parameter | Hop resumption impossible out of the box | Subclass overriding `_ssl_wrap_socket` (private method: pin `paho-mqtt==2.1.0`) |
| OpenSSL puts the client certificate inside TLS tickets | Resumed handshakes are bigger than expected (7–9 KB with ML-DSA certificates) | Another reason for ECDSA certificates on the hop |
| No SLH-DSA in Python `cryptography` | Cannot verify firmware signatures | 30-line `ctypes` wrapper around OpenSSL ≥ 3.5 (verified); station signs with the `openssl` CLI |
| `mlkem.encapsulate()` returns `(shared_secret, ciphertext)` | The opposite order to the old `pqcrypto` library; swapping gives "Invalid ciphertext" | Name the variables explicitly |
| Mosquitto answers "granted" to forbidden subscriptions | False alarms in tests | Test for delivery, not for SUBACK |
| Environment speed and ratios vary (e.g. hybrid overhead +67% on macOS vs +120% in the container) | Numbers not comparable | Measure only in the pinned container, and always state the environment |
| Docker Desktop cannot read folders on the macOS Desktop | Volume mounts fail with "operation not permitted" | Copy files into the image (as `design-validation/` does), or grant Docker access in System Settings yourself |

---

## 8. Build plan

### 8.1 Environment (Docker only)

Docker Compose, with every version pinned. Build from the verified image in `design-validation/Dockerfile`.
Do not switch to another broker image without re-running `design-validation/run_all.sh`.

| Service | What it is |
|---|---|
| `broker` | Mosquitto with the §5.6 configuration |
| `utility` | Headend service |
| `device` | Simulator, scaled to N copies |
| `station` | **`network_mode: none`**. It exchanges artifacts only through a mounted folder, the "USB stick" |
| `bench` | Experiment runner |

### 8.2 Repository layout

```
smart-grid-pqc-mqtt/
├── docker/            Dockerfile, compose.yaml, mosquitto.conf
├── pqgrid/
│   ├── suite.py        hybrid KEM, AEAD, HKDF, ML-DSA, SLH-DSA (ctypes)
│   ├── wire.py         length-prefixed codec
│   ├── policy/         model, engine, validator, acl_compiler
│   ├── e2e/            handshake, session, tiers (alert, control, broadcast), replay guard
│   ├── pasr/           ticket, stek, utility-side manager, device-side client
│   ├── fota/           manifest, merkle, station CLI, publisher, installer
│   ├── mqtt/           PQClient (paho subclass: TCP_NODELAY + TLS session reuse), topic helpers
│   ├── device/         simulator: flash file, reboot, telemetry and alert generators
│   └── utility/        headend: registry, sessions, commands, zones, artifact publishing
├── tools/             provision (PKI, device keys, registry, factory image), make_policy, rollout
├── attacks/           one script per attack in §9
├── experiments/       E1–E7 runners + analyze.py (CSV → figures)
└── tests/             pytest, run inside Docker
```

### 8.3 Phases (14 weeks)

| Phase | Weeks | Owner | Work | Done when |
|---|---|---|---|---|
| **0 · Foundation** | 1–2 | All | Compose environment; provisioning tool (ECDSA CA and certificates, device hybrid keys, registry, station SLH-DSA key, signed factory policy v1); promote `design-validation/reference` into `pqgrid/` with tests; `PQClient`; benchmark harness with the §10 rules; **freeze interfaces (§8.4)** | `docker compose up` starts the broker, utility and 3 devices over hybrid TLS with certificates; pytest passes in the container; the 80 validation scenarios run as unit tests; broker runs with hybrid-only pinning, persistence and `max_packet_size` |
| **1 · PCHC** | 3–6 | **Bala** | Policy engine, validator (incl. device-ID rules), ACL compiler with SIGHUP reload; end-to-end handshake over MQTT (QoS 1, correlation data, duplicate cache, confirm-before-use, retry with back-off, utility time); ALERT with end-to-end ACK and flash outbox; unicast CONTROL with status ACK, redelivery and apply-at-most-once; resync hint; broadcast zones (distribution and rotation) | A1–A13 and the PCHC edge cases pass on the live system; E3 measured |
| **2 · PQC-FOTA** | 3–6 | **Lohith** | Station CLI; manifest, Merkle and chunks; publisher with retained cleanup after a retention window; installer with A/B slots, commit-after-boot, revert, protected counters and `activate_at`; policy as an artifact feeding the ACL compiler; *stretch:* freshness heartbeat | F1–F7 and the FOTA edge cases pass live; 256 KiB and 1 MiB images install with shuffled and duplicated chunks, and after a mid-download power loss; E5 measured |
| **3 · PASR** | 3–8 | **Pavan** | Weeks 3–5: ticket format, STEK rotation, **persisted** STEKs and used-ticket list, duplicate cache, the 9 checks, both modes, against the frozen session interface. Weeks 6–8: live integration; invalidation hooks (policy activation, firmware install, revocation); flash storage, reboot and utility-restart simulation | P1–P10 and the PASR edge cases pass live; E2 and E4 measured |
| **4 · Integration** | 9–10 | All | Full lifecycle scenario (policy change → sessions re-established; firmware update → tickets void); combined attack I1; outage-restoration simulation | Lifecycle and I1 pass |
| **5 · Evaluation and report** | 11–14 | All | Experiments E1–E8, analysis, figures, final report and slides; week 14 is buffer | Every number traces to a CSV |

Phases 1–3 run **in parallel** from week 3, against interfaces frozen in week 2.

### 8.4 Interfaces frozen at the end of Phase 0

| Module | Frozen interface |
|---|---|
| `suite` | `hkem_keygen/encaps/decaps`, `aead_seal/open`, `hkdf_extract/expand`, `mldsa sign/verify`, `slh_verify` |
| `wire` | `enc`, `dec` |
| `policy` | `load`, `validate`, `tier(topic)`, `info()` |
| Session object | `device_id`, `dclass`, `policy_info`, `fw_version`, `k_master`, `sid`, `resume_mode`, `chain_expires`, `key(tier, dir)` |

Changing any of these after week 2 needs all three members to agree, because it breaks two other people's
work.

### 8.5 What to reuse

- **`design-validation/reference/`** is the starting point for `pqgrid/`. It is reference quality: the
  logic is complete and tested, but it has no persistence, no networking, and no hardening.
- **`pq-mqtt-session-security/`** (Semester 1): keep it **untouched**, because it backs the Semester 1
  PDFs. Its two-phase replay-guard idea is already carried forward, and its experiment-runner and CSV
  pattern can be copied. Everything else is superseded.

---

## 9. Attack suite

Every attack must **fail closed**. If one succeeds, that is a bug, not a result. "Validated" means the
attack already fails in `design-validation/` with the rejection shown.

| ID | Objective | Attack | Expected rejection | Validated |
|---|---|---|---|---|
| A1 | PCHC | Broker changes POLICY_INFO inside the client hello | "client hello failed authentication" | ✅ |
| A2 | PCHC | Broker changes POLICY_INFO inside the server hello | "server hello failed authentication" | ✅ |
| A3 | PCHC | Replay a device's client hello on another device's topic | "identity does not match the device's topic" | ✅ |
| A4 | PCHC | Device on an old policy tries to connect | "POLICY_INFO mismatch" | ✅ |
| A5 | PCHC | Curious broker reads an alert | Only ciphertext visible | ✅ (live test in Phase 1) |
| A6 | PCHC | Tier stripping: plaintext on an ALERT topic | "unknown session" (not a valid envelope) | ✅ |
| A7 | PCHC | Sending an alert on a TELEMETRY topic | Refused by the sender's policy | ✅ |
| A8 | PCHC | Alert replay; forged alert must not burn the sequence number | Replay rejected; next genuine alert accepted | ✅ |
| A9 | PCHC | Command replay or redelivery, including after a reboot | Acknowledged as DUP, **never re-applied** (the applied-sequence counter lives in flash) | ✅ |
| A10 | PCHC | Forged command by someone with the session key but not the utility signing key | "command signature invalid" | ✅ |
| A11 | PCHC | Captured meter forges a demand-response event (it holds the zone key); event replay | "broadcast signature invalid"; "broadcast replay" | ✅ |
| A12 | PCHC | Publish or subscribe to another device's topics | PUBACK "Not authorized"; nothing delivered | ✅ (broker) |
| A13 | PCHC | Unsafe policy (unicast-control class with PSK-only resume) | Validator rejects | ✅ |
| P1 | PASR | Resume hello replayed after the 120 s duplicate window; or the same ticket with a fresh hello (clone) | "ticket already used" (a duplicate *within* the window just gets the identical answer) | ✅ |
| P2 | PASR | Stolen ticket blob without the secret | "binder invalid", and the genuine ticket still works | ✅ |
| P3 | PASR | Ticket presented on another device's channel | "ticket/device identity mismatch" | ✅ |
| P4 | PASR | Expired ticket or chain | "ticket expired" | ✅ |
| P5 | PASR | Ticket after a policy change | "issued under a different policy" | ✅ |
| P6 | PASR | Mode downgrade (strip the fresh KEM) | "resume mode does not match policy" | ✅ |
| P7 | PASR | Ticket after a firmware update | "issued for different firmware" | ✅ |
| P8 | PASR | Ticket sealed under a retired STEK | "ticket key retired" | ✅ |
| P9 | PASR | Revoked device (resume and full handshake) | "unknown or revoked" | ✅ |
| P10 | PASR | Alerts on an old-policy session after activation | "session belongs to an old policy" | ✅ |
| F1 | FOTA | Tampered chunk | "failed Merkle verification" | ✅ |
| F2 | FOTA | Tampered manifest | "manifest signature invalid" | ✅ |
| F3 | FOTA | Artifact signed by a non-station key | "manifest signature invalid" | ✅ |
| F4 | FOTA | Rollback to a validly signed older firmware | "rollback" | ✅ |
| F5 | FOTA | Replay of the installed version | "rollback" | ✅ |
| F6 | FOTA | Broker re-serves an old signed policy | "rollback" | ✅ |
| F7 | FOTA | Firmware for another device class | "targets another device class" | ✅ |
| I1 | All | During a firmware rollout: a tampered chunk + a replayed command + a policy downgrade attempt | Each rejected by its own mechanism | Phase 4 |

---

## 10. Evaluation plan

| ID | Experiment | Measures |
|---|---|---|
| E1 | Broker hop | Full vs resumed TLS 1.3; hybrid vs pure `MLKEM768` (one configuration change); ECDSA vs ML-DSA-44/65 certificates. Bytes and time |
| E2 | End-to-end session | Full vs PSK vs PSK+KEM. Device and utility compute, bytes |
| E3 | Tier overhead | Bytes and time per message per tier; daily bytes per device for a traffic mix (**SIMULATED** profile from Alghawli et al. [4]) |
| E4 | Outage restoration | N = 100 / 500 / 1,000 devices reboot together. Time until all sessions restored, utility and broker CPU, bytes: full handshake vs PASR |
| E5 | PQC-FOTA | Signing, verification, Merkle vs flat hash list (bytes and memory), install time vs chunk size (1 / 4 / 16 / 64 KiB), with injected chunk loss (**SIMULATED**) |
| E6 | Policy rollout | Time from publishing a new policy until every device has re-established; bytes |
| E7 | Security | Pass/fail table for §9 and the network attacks N1–N7 on the live system |
| E8 | Reliability | Inject message loss, duplication and restarts (utility, broker, device) through the proxy; count lost, duplicated and double-applied messages: all must be zero (**SIMULATED** impairments) |

**Measurement rules**

1. Run only in the pinned container.
2. Enable `TCP_NODELAY` on both ends.
3. Discard the first 20 runs.
4. Report **median and mean** together, with n.
5. Save raw per-run CSV files.
6. Label every number with its environment.
7. Label traffic profiles, impairments and loss as **SIMULATED**.

**Replacing the report's "60–70%".** Report the measured E2 and E4 values. Current evidence from the
reference implementation in the container: 92% less device computation and 86% fewer bytes (PSK); 47% and
41% (PSK+KEM).

---

## 11. What we claim and what we do not

**We will claim**, once it has been measured on the live system:

- Post-quantum confidentiality of every hop, and of alerts and commands end to end, with hybrid key
  exchange.
- Operator-controlled per-topic protection that fails closed against downgrade.
- Policy-aware resumption with the measured savings.
- An update pipeline for firmware and policy that resists forgery, tampering and rollback.
- All with measured costs.

**We will not claim:**

- that it is formally verified
- that it is production-ready
- smart-meter hardware performance
- end-to-end encryption of telemetry
- forward secrecy for PSK-mode sessions
- protection against a compromised utility
- resistance to denial of service
- that hybrid is "twice as secure". It is secure as long as either algorithm holds

---

## 12. Changes from the mid-semester report

| # | Report says | Now | Why |
|---|---|---|---|
| 1 | §3.3 eq. 3.2: `K_session = KDF(K_TLS, policy_id, tier)` | `K_tier = KDF(ss_e ‖ ss_U ‖ ss_D, transcript ∋ policy, tier)`, between device and utility | The broker holds `K_TLS`, so alert and control could not be end-to-end; Python cannot read `K_TLS` |
| 2 | §3.3: client and broker exchange POLICY_INFO through MQTT 5 enhanced authentication | Device and utility exchange POLICY_INFO inside the end-to-end handshake, carried in MQTT 5 publishes through the broker | The broker is not a party to the protected session; Mosquitto needs a C plugin for custom authentication methods |
| 3 | Fig. 3.1: broker hosts the policy engine and the ticket manager | Broker = TLS + ACL compiled from the signed policy; **ticket manager at the utility** | A ticket resumes a session, so it must be issued by whoever holds that session's secret |
| 4 | §3.4: ML-DSA-65 manifests (Objective 3 said "ML-DSA-65 or SLH-DSA") | **SLH-DSA-SHA2-192s** | The anchor can never be replaced; hash-only assumption; 48 B anchor; 0.28 ms to verify |
| 5 | §3.4: per-chunk hash list | Merkle root + per-chunk proof; chunk size per class | Constant device memory; trade-off stated in §5.5 |
| 6 | §3.5: control-tier topics excluded from resumption | Classes that receive unicast control resume only with a fresh KEM, or not at all; no 0-RTT data ever | One MQTT connection carries all tiers; the real risk was missing forward secrecy, and resumption cannot replay data |
| 7 | §3.5 eq. 3.8: `K = KDF(K_ticket, nonces)` | `K = KDF(psk [‖ ss_e′], transcript)` + binder; mode set by policy | Forward-secrecy option; proof that the device holds the ticket |
| 8 | §3.5: broker-held ticket key | Utility STEK rotated daily; single-use tickets; revocation checked | Bounded exposure, clone detection |
| 9 | §2.3.2 Objective 1: "Policy-Driven Hybrid Cryptographic Configuration"; Kyber-512/768/1024 or hybrid per topic | Name "Per-topic Cryptographic Hierarchy Control" everywhere; one hybrid baseline; tiers differ by protection layers | The report used two names, and §2.3.2 contradicted §3.3 |
| 10 | Table 2.1: Malina et al. "fixed configuration" | They offer two *subscriber-chosen* levels; their broker decrypts and re-encrypts | Accuracy (checked in their paper) |
| 11 | §4.2.3: 60–70% expected | Measured values (§7.4, E2, E4) | Honesty rules |
| 12 | Ch. 4: oqs-provider for OpenSSL 3 | Not needed: OpenSSL ≥ 3.5 is native | Verified |
| 13 | End-to-end layer (new) | Hybrid KEM inside the end-to-end handshake too | Same record-now rule as TLS; the broker can record |
| 14 | Broker-hop certificates (not specified) | ECDSA P-256; ML-DSA migration path | Measured 4.7 KB vs 23.8–31.7 KB |
| 15 | "PCHC governs FOTA distribution" (vague) | Chunk size per class + `activate_at` | The claimed coupling is now a concrete mechanism |
| 16 | (not addressed) Delivery of alerts and commands | End-to-end ACKs, alert IDs, command status ACKs, redelivery, apply-at-most-once | A broker PUBACK is not end-to-end delivery; alerts were lost across utility restarts in testing |
| 17 | (not addressed) Duplicate MQTT messages | Idempotent handshake and resume handling | QoS 1 duplicates broke three v1 handshake paths (verified) |
| 18 | (not addressed) Device time | Utility-authenticated time | Clocks reset by outages locked v1 devices out (verified) |
| 19 | (unspecified) Broker TLS and storage settings | Hybrid-only pinning, `persistence true`, `max_packet_size` | Defaults accept classical-only clients, and retained artifacts vanish on restart (verified) |

**How to explain the refactor to your guide (about 30 seconds)**

> "After the mid-semester review we tested our design in a container and found that our end-to-end claim
> did not hold: the alert and control key came from TLS, which the broker controls. So we moved the
> protected session to where the claim is true, between the device and the utility, using our base paper's
> KEM-MQTT handshake, made hybrid, with the policy bound into its keys. The ticket manager moved to the
> utility for the same reason. We also switched firmware signing to SLH-DSA, because the bootloader key can
> never be replaced. Then we attacked our own design with duplicates, lost messages, restarts, clock resets,
> corrupted packets and captured-traffic replay, fixed every problem we found, and now all 80 validation
> scenarios behave as expected. The three objectives are unchanged; every mechanism is now implementable."

---

## 13. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Handshake over publish/subscribe: duplicates, ordering, timeouts | Medium | Medium | Correlation data; idempotent handlers; retry with back-off; test with QoS 1 duplicates |
| paho private-method override breaks on upgrade | Low | Medium | Pin `paho-mqtt==2.1.0`; a test covers it |
| SLH-DSA missing from the Python library | Known | Low | `ctypes` wrapper (verified); pin OpenSSL ≥ 3.5 in the image |
| Benchmark artefacts (Nagle, warm-up, environment) | High if ignored | High | §10 rules; §7.5 pitfalls |
| Docker cannot read the Desktop folder on macOS | Known | Low | Copy into the image, or grant access in System Settings (your own decision) |
| Many devices re-handshake at once after a policy change | Medium | Medium | `activate_at` + 0–60 s random jitter |
| Clock skew or reset after an outage | Medium | Medium | The device takes its time from the authenticated utility handshake; the device clock never gates a connection |
| STEK theft (forged tickets shown possible) | Low | High | HSM in production; daily rotation; revocation still checked on every resume |
| Clone connects and kicks the genuine device off | Low | Medium | Alarm on repeated takeovers and on "ticket already used"; revoke and re-provision |
| Retained firmware cleared while slow devices still download | Medium | Low | Retention window (e.g. 30 days) before clean-up |
| Silent classical fallback on the hop | Medium if unpinned | High | Hybrid-only pinning via `OPENSSL_CONF` (verified) |
| Scope overrun | Medium | High | Stretch items marked; week 14 is buffer; broadcast zones can fall back to signed-only (state it) |
| Coupling between the three parallel phases | Medium | High | Interfaces frozen at the end of week 2 (§8.4) |

---

## 14. Decision log

| # | Date | Decision | Reason |
|---|---|---|---|
| D1 | 2026-09-21 | Keep hybrid TLS 1.3 (`X25519MLKEM768`) | Matches the report; record-now rule; OpenSSL default |
| D2 | 2026-09-22 | End-to-end session between device and utility (KEM-MQTT lifted end-to-end) | Only placement where "the broker cannot read alerts or commands" is true |
| D3 | 2026-09-22 | Hybrid KEM (X-Wing combiner) inside the end-to-end handshake | The broker can record end-to-end traffic; same rule as TLS |
| D4 | 2026-09-22 | ChaCha20-Poly1305 at the application layer; AES-256-GCM in TLS | 256-bit keys; software speed on MCUs |
| D5 | 2026-09-22 | ML-DSA-65 for commands | Rotatable through the policy; fast verification |
| D6 | 2026-09-22 | SLH-DSA-SHA2-192s for firmware and policy | Irreplaceable anchor; hash-only assumption |
| D7 | 2026-09-22 | ECDSA P-256 broker-hop certificates | Live-only threat; 5–7× smaller handshakes; ML-DSA migration ready |
| D8 | 2026-09-22 | Strongest matching rule wins; default tier CONTROL | Fail-safe and monotone |
| D9 | 2026-09-22 | Tickets issued by the utility; single-use; STEK rotated every 24 h | The issuer must hold the session secret |
| D10 | 2026-09-22 | Resume modes PSK / PSK+KEM per class; unicast control ⇒ PSK+KEM or NONE | Policy-controlled forward-secrecy trade-off |
| D11 | 2026-09-22 | Merkle chunks; chunk size per class | Manifest and device memory independent of image size; costs more bandwidth (stated in §5.5) |
| D12 | 2026-09-22 | Policy delivered through FOTA with `activate_at` | Closes the lifecycle loop; avoids reconnection storms |
| D13 | 2026-09-22 | All development and measurement in Docker | Reproducibility; host stays untouched |
| D14 | 2026-09-22 | Length-prefixed binary encoding everywhere | Deterministic; portable; analysable |
| D15 | 2026-09-22 | Pin hybrid-only TLS groups on broker and devices | Defaults silently accept classical-only clients (verified) |
| D16 | 2026-09-22 | Idempotent handshake and resume handling (duplicate cache, 120 s) | MQTT QoS 1 duplicates broke v1 in three ways (verified) |
| D17 | 2026-09-22 | Confirm before use (NT/FIN) | A lost finished otherwise loses alerts silently |
| D18 | 2026-09-22 | Utility-authenticated time; device time never gates | Clocks reset by outages locked v1 devices out (verified) |
| D19 | 2026-09-22 | End-to-end ACKs; alert IDs; command status ACKs, redelivery, apply-at-most-once | Broker PUBACK is not delivery; utility restarts lost alerts |
| D20 | 2026-09-22 | Persist STEKs and the used-ticket list | Otherwise a utility restart kills every ticket or re-opens replay (verified) |
| D21 | 2026-09-22 | A/B firmware slots; commit counter only after a successful boot | Otherwise a bad image strands the device |
| D22 | 2026-09-22 | Device-ID character rules; parser field cap; one half-open handshake per device | Topic/ACL injection; memory exhaustion |
| D23 | 2026-09-22 | Broker `persistence true`, `max_packet_size 300000`, runs as `mosquitto` | Retained artifacts survive restarts; memory limit (verified) |
| D24 | 2026-09-22 | Resync hint (unauthenticated, rate-limited) after unknown sessions | Fast recovery after a utility restart; forging it only costs one cheap resume |

---

## 15. Glossary

| Term | Plain meaning |
|---|---|
| Broker | The "post office" in the middle; every MQTT message passes through it |
| Hop / end-to-end | Hop = protection for one leg (device→broker). End-to-end = protection from sender to final receiver, so the middle cannot open it |
| KEM | A way for two parties to agree on a secret key over an open network |
| Hybrid | Two algorithms combined (one classical, one post-quantum); secure as long as either holds |
| ML-KEM / ML-DSA / SLH-DSA | The NIST post-quantum standards for key agreement, lattice signatures, and hash-based signatures (FIPS 203/204/205) |
| AEAD | Encryption that also detects tampering (ChaCha20-Poly1305, AES-GCM) |
| Forward secrecy | Stealing a key later does not unlock traffic recorded earlier |
| Ticket / resumption | A sealed "re-entry pass" that lets a device skip the full handshake next time |
| STEK | The utility's secret key for sealing tickets |
| Binder | Proof, attached to a resume request, that the sender holds the ticket's secret |
| Manifest | The signed "packing slip" of an update: what it is, its version, its fingerprint |
| Merkle tree | A hash structure that lets each chunk be checked on its own against one small root value |
| Rollback | Tricking a device into installing an older, vulnerable version |
| Fail closed | When a check fails, the connection or update is refused; never quietly weakened |
| SIMULATED | A number produced by a model or emulation, not a real measurement; always labelled |
