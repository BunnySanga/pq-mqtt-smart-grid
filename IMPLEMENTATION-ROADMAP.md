# Implementation Roadmap

**Authority:** [BalaMP-Master.md](BalaMP-Master.md) (design v2.2). This file plans **how** that design becomes
code. It settles no design questions; where Master.md is silent on an implementation detail, this file either
records an engineering choice or raises a **SECURITY-CRITICAL OPEN DECISION** (§6).

**Status vocabulary** (used in §7 and in every later status report):
`SPECIFIED` → `IMPLEMENTED` → `UNIT-TESTED` → `INTEGRATION-TESTED` → `DOCKER-VALIDATED` → `SIMULATED` →
`HARDWARE-VALIDATED`. A thing is only at the level its evidence supports.

---

## 1. The three objectives, as buildable components

### PCHC-MQTT (Objective 1) — per-topic protection, bound to a signed policy

| Aspect | Content |
|---|---|
| **Purpose** | Every topic gets a tier (TELEMETRY / ALERT / CONTROL) from an operator-signed policy, enforced end to end so no attacker, including the broker, can silently weaken it (Master §11, §12) |
| **Components** | `wire` codec · `suite` (crypto primitives) · `policy` (model, codec, engine, validator, POLICY_INFO) · `e2e` (handshake, key schedule, session, replay guard, envelopes) · `tiers` (ALERT, CONTROL sub-types, broadcast) · `registry` (device → class, keys, revocation, `max_packet`) · broker ACL compiler |
| **Protocols** | CH → SH → DF(+bundle) → NT/FIN (Master §9.4); ALERT + ACK; CONTROL CMD / GRANT / SETPOINT / ZONEKEY + status ACK (§11, §13) |
| **Crypto** | HKEM = X25519 + ML-KEM-768 with the X-Wing combiner (§6.2, §6.4); AEAD per class (§6.5); HKDF-SHA-256, HMAC-SHA-256, SHA-256, SHA3-256 (§6.6–§6.8); ML-DSA-65 for CMD/GRANT (§13) |
| **Data structures** | Policy document; POLICY_INFO; session (sid, K_master, per-tier/direction keys and counters); replay guard; duplicate cache; GRANT table; intent log records |
| **Persistent state** | Device: installed policy, E2E static key, time floor, command state + intent log, alert outbox. Utility: registry, sessions (RAM), command sequence + queue, zone keys |
| **Key tests** | A1–A13 (downgrade, forgery, ownership), tier engine, validator rules 1–10, codec strictness and fuzz, V-G1…G6 (GRANT/SETPOINT), V-D1…D3 (DF-carries-data) |
| **Depends on** | Nothing outside itself for the session core; the signed policy needs the FOTA **verifier** (SLH-DSA) but not the FOTA transport |
| **Depended on by** | **Everything.** PASR resumes this session; commands ride its keys; FOTA activation invalidates its sessions; MQTT/TLS only carries its bytes |

### PQC-FOTA (Objective 2) — signed firmware **and** policy delivery

| Aspect | Content |
|---|---|
| **Purpose** | Only the offline station can produce an acceptable update; no rollback; constrained devices verify every piece as it arrives (§15) |
| **Components** | `fota.station` (offline signer) · `fota.manifest` (codec) · `fota.merkle` (RFC 6962) · `fota.parts` (manifest split to `max_packet`) · `fota.installer` (staging, A/B, commit-after-boot, anchors, KEYREVOKE) · publisher (retained topics, retention window) |
| **Protocols** | Manifest parts + chunks over retained MQTT topics; KEYREVOKE artifacts (§15.8, §15.14) |
| **Crypto** | SLH-DSA-SHA2-128s verify (≥ 2 anchors); SHA-256 Merkle tree and payload hash |
| **Data structures** | Manifest (magic, type, class, version, length, payload hash, chunk size/count, Merkle root, activate_at, issued_at, signer anchor id); chunk (+ audit path); received-chunk bitmap; anchor table + revocation counter |
| **Persistent state** | Committed version per artifact type (protected storage); anchor revocation state; staging area; chunk bitmap |
| **Key tests** | F1–F7, V-F1…V-F5 (parted manifest, KEYREVOKE, last-anchor refusal, slot-size limit) |
| **Depends on** | `wire`, `suite` (SLH-DSA + SHA-256), **policy model** (class `fota_chunk_size`, `max_packet`), registry (declared maximum) |
| **Depended on by** | Policy distribution (the policy is a FOTA artifact), firmware version binding in PASR tickets, `activate_at` behaviour |

### PASR-MQTT (Objective 3) — policy-aware resumption

| Aspect | Content |
|---|---|
| **Purpose** | Recover a session after outage/reboot without the full handshake, only as the policy allows (§14) |
| **Components** | `pasr.ticket` (seal/open) · `pasr.stek` (rotation, retirement) · `pasr.server` (9 checks, single-use set, duplicate cache) · `pasr.client` (RH build, identical retransmission) · persistence (SQLite WAL) |
| **Protocols** | RH → RS → DF(+bundle) → NT (§9.4) |
| **Crypto** | ChaCha20-Poly1305 ticket sealing under STEK; HKDF (psk, binder); optional fresh HKEM for PSK_KEM |
| **Data structures** | Ticket plaintext (ticket_id, device, class, POLICY_INFO, fw_version, mode, issued/expires/chain_expires, psk); sealed blob; used-ticket set; STEK table |
| **Persistent state** | Utility: used tickets, STEK, (with commands) sequences. Device: ticket + psk + expiry + mode, and the stored RH bytes until RS |
| **Key tests** | P1–P10, E-P1…E-P5, S3/S4 regressions, S5 retransmission rule |
| **Depends on** | **E2E session + key schedule** (a ticket resumes *that* session), policy (class resume mode, lifetimes), registry (revocation), firmware version (binding), persistence |
| **Depended on by** | Reconnect behaviour and all measured savings (E2/E4/T6) |

---

## 2. Dependency graph

```
                       ┌──────────────┐        ┌──────────────┐
                       │ L0  wire     │        │ L0  suite    │  HKEM(X25519+ML-KEM-768, X-Wing),
                       │ codec (§12)  │        │ crypto (§6,7)│  AEAD, HKDF/HMAC/SHA, ML-DSA, SLH-DSA
                       └──────┬───────┘        └──────┬───────┘
                              └──────────┬────────────┘
                                         ▼
                              ┌─────────────────────┐
                              │ L1 policy + registry│  model, binary codec, tier engine,
                              │  (§12, §4.4)        │  validator 1–10, POLICY_INFO
                              └─────────┬───────────┘
                                        ▼
                              ┌─────────────────────┐
                              │ L2 E2E session core │  CH/SH/DF/NT, key schedule, sid,
                              │  (§9.4–§9.7)        │  replay guard, envelope framing
                              └───┬───────────┬─────┘
                ┌─────────────────┘           └──────────────┐
                ▼                                            ▼
      ┌───────────────────┐                        ┌────────────────────┐
      │ L3 tiers/commands │ ML-DSA-65 CMD,         │ L3 PASR (§14)      │ tickets, STEK, 9 checks
      │  (§11, §13)       │ GRANT/SETPOINT, ZONEKEY│                    │
      └─────────┬─────────┘                        └─────────┬──────────┘
                └───────────────┬─────────────────────────────┘
                                ▼
                     ┌─────────────────────┐
                     │ L4 persistence      │  device record store + intent log,
                     │  (§16)              │  utility SQLite WAL (seq, queue, tickets, STEK)
                     └──────────┬──────────┘
                                ▼
                     ┌─────────────────────┐
                     │ L5 transport        │  MQTT 5 client/broker config, TLS 1.3 hybrid,
                     │  (§8, §10)          │  persistent sessions, back-off
                     └──────────┬──────────┘
                                ▼
                     ┌─────────────────────┐
                     │ L6 FOTA + station   │  manifest, Merkle, parts, installer, anchors
                     │  (§15)              │  (policy artifacts ride this)
                     └─────────────────────┘
```

**Why this order, and not the document order**

- `suite` and `wire` have **no** dependencies and **everything** depends on them.
- The **policy** must exist before the session, because POLICY_INFO is an input to the handshake and is bound
  into `K_master` (§12 Policy Binding). A session built first would have to be retrofitted.
- **PASR cannot precede the session**: a ticket resumes a session and its psk is derived from `K_master`
  (§9.5). Building PASR first would mean inventing a session to resume.
- **Commands cannot precede the session**: they use `K_CONTROL|down`, the sid and the replay guard.
- **Persistence is L4**, not L0: what must be persisted is only known once the session, PASR and command
  state machines exist (S1–S4 are about *those* states). Building storage first would guess at schemas.
- **Transport is L5**, deliberately late: TLS/MQTT carries bytes but defines none of the security properties.
  The broker facts are already proven in `design-validation` [DOCKER], so nothing is at risk by deferring it.
- **FOTA is L6** even though the policy is delivered by it. The cycle (policy ← FOTA ← policy classes) is
  broken exactly as the design says: the **first** policy is factory-provisioned at manufacturing (§4.1,
  §4.5), so FOTA is only needed for *updates*. FOTA's verifier (SLH-DSA) is in L0 and is used earlier to
  check the provisioned policy's signature.

**Order:** L0 → L1 → L2 → (L3 tiers/commands ∥ L3 PASR) → L4 → L5 → L6.

---

## 3. First implementation slice

**Slice 1 — "trust and session core": `wire` + `suite` + `policy`/registry + the E2E establishment
(CH/SH/DF/NT) with its key schedule, replay guard and ALERT envelope.**

### Why this slice is first

1. It is exactly the part with **zero** inbound dependencies and the **highest** outbound fan-out: L0 + L1 +
   L2 in the graph. Every other component consumes it.
2. It makes the two **v2.2-specific** changes real where they matter most, so later slices are never built
   against v2.1 semantics: the **binary signed policy with class profiles**, and **finished-carries-data**
   (I-19).
3. It is independently testable without MQTT, TLS or storage: two in-process endpoints exchanging bytes.
4. It re-establishes the v2.1 attack coverage (A1–A8) on the v2.2 code before anything is layered on it.

### Master.md sections that define it

| Area | Sections |
|---|---|
| Codec | §12 Binary Encoding; I-21 |
| Crypto primitives | §6.2–§6.8, §7.1–§7.4, §7.8–§7.13 |
| Policy | §12 (structure, validator, binding, distribution), §11 (tiers), §5 (class profiles) |
| Session | §9.4 (full handshake), §9.5 (key separation), §9.6 (replay), §9.7 (counters) |
| ALERT tier | §11 Alert |
| Invariants | I-1, I-3, I-4, I-5, I-6, I-7, I-18, I-19, I-21 |

### Modules (proposed tree, §5 below)

`pqgrid/wire.py` · `pqgrid/suite/*` · `pqgrid/policy/*` · `pqgrid/e2e/*` · `pqgrid/registry.py` ·
`tests/unit/*`, `tests/security/*`

### What depends on it later

PASR (needs `K_master`, sid, session object, DF), commands (need `K_CONTROL|down`, replay guard, policy
`cmd_types`), FOTA (needs the policy model and `suite.slh_verify`), transport (carries these messages),
persistence (persists these states).

### Deliberately **not** in slice 1

| Not now | Why | Slice |
|---|---|---|
| PASR tickets, STEK, resume | Needs the session to exist first | 2 |
| CMD / GRANT / SETPOINT / ZONEKEY, broadcast | Needs session keys + policy `cmd_types`; ML-DSA verify is in `suite` but unused in slice 1 | 3 |
| Intent log, device record store, SQLite WAL | Schemas follow from slices 2–3 | 4 |
| MQTT client, broker config, TLS, back-off, persistent sessions | Transport only; broker behaviour already proven [DOCKER] | 5 |
| FOTA manifest/Merkle/parts/installer/anchors, station | Highest layer; the first policy is provisioned | 6 |
| Time floor, clock recovery | Belongs with transport/TLS (§8.9); slice 1 takes authenticated utility time in SH only | 5 |

---

## 4. Code-readiness for slice 1

### 4.1 Cryptographic primitives: exact roles

| Primitive | Role in slice 1 | Input → output | Sizes | Lifetime / ownership / storage | Zeroization | Errors |
|---|---|---|---|---|---|---|
| **X25519** (RFC 7748) | Classical half of HKEM | sk ← 32 random B; pk = X25519(sk, base) | pk/sk 32 B, shared 32 B | Ephemeral part per handshake (RAM); static part of the device/utility E2E key (device flash / utility store) | Best-effort `bytearray` wipe on session close; Python cannot guarantee (documented limitation) | Any exception → `HandshakeError`, no detail to the peer |
| **ML-KEM-768** (FIPS 203) | PQ half of HKEM | KeyGen → (ek 1,184 B, dk 2,400 B); Encaps(ek) → (ss 32 B, ct 1,088 B); Decaps(dk, ct) → ss | as stated | As above | as above | Decaps never reports "why" (implicit rejection is inside ML-KEM) |
| **HKEM** (§6.2) | The only KEM used end to end | pk = ek ‖ pk_x (1,216 B); ct = ct_m ‖ ct_x (1,120 B); ss = X-Wing combiner output (32 B) | 1,216 / 1,120 / 32 B | per handshake (ephemeral) or long-term (static) | as above | length checks before use; wrong length → `HandshakeError` |
| **X-Wing combiner** (§6.4) | Binds both halves | `SHA3-256(ss_m ‖ ss_x ‖ ct_x ‖ pk_x ‖ "\.//^\")` | 32 B out | per encapsulation | n/a | — |
| **AEAD** (§6.5, class `aead`) | CH inner block, SH inner block, ALERT envelopes | (key 32 B, nonce 12 B, pt, aad) → ct+16 B tag | key 32, nonce 12, tag 16 | Session lifetime, **RAM only** (I-6) | drop with the session | tag failure → `HandshakeError`/`ReplayError`, counter **not** consumed (I-7) |
| **HKDF-SHA-256** (§6.6) | All key derivation | Extract(salt, ikm) → PRK 32 B; Expand(PRK, label, L) | 32 B keys | per session | — | — |
| **HMAC-SHA-256** (§6.7) | MAC_U, MAC_D, ACK MACs, binder | (key 32 B, msg) → 32 B | 32 B | per session | — | **constant-time compare only** (I-7, §6.7) |
| **SHA-256 / SHA3-256** | Transcript hash, AAD digests, X-Wing | length-prefixed parts → 32 B | 32 B | — | — | — |
| **ML-DSA-65** (§7.6) | *Present in `suite`*, used from slice 3 | verify(pk 1,952 B, sig 3,309 B, msg) → bool | as stated | Utility key, rotated by policy | — | verify failure → reject |
| **SLH-DSA-SHA2-128s** (§7.7) | Verification **primitive** in slice 1, tested against real OpenSSL signatures. The signed wrapper around a policy is the FOTA manifest (slice 6), so no interim signed format is invented (E13) | verify(pk 32 B, sig 7,856 B, msg) → bool | as stated | Anchors, burned in | — | verify failure → artifact refused |

**Randomness:** one source, `os.urandom` on the prototype host, wrapped in `suite.random_bytes()` so the
device port can bind it to a TRNG+DRBG (§7.13, D-8).

### 4.2 Key schedule trace (slice 1)

| Key | Input | Operation | Context / label | Purpose | Lifetime |
|---|---|---|---|---|---|
| `ss_U` | `pk_U` | HKEM.Encaps | — | Authenticates the utility | handshake |
| `K_B` | `ss_U` | `HKDF-Expand(HKDF-Extract(SALT, ss_U), "early" ‖ H(pk_e, ct_U, n_D))` | `early` | Encrypts the CH inner block | one message |
| `ss_e` | `pk_e` | HKEM.Encaps/Decaps | — | Forward secrecy | handshake |
| `ss_D` | `pk_D` | HKEM.Encaps/Decaps | — | Authenticates the device | handshake |
| `K1` | `ss_e ‖ ss_U` | `HKDF-Expand(HKDF-Extract(SALT, ss_e‖ss_U), "k1" ‖ H(CH))` | `k1` | Encrypts the SH inner block | one message |
| `K_master` | `ss_e ‖ ss_U ‖ ss_D` | `HKDF-Extract(salt = H(transcript), ikm = …)` | transcript ∋ POLICY_INFO | Root of the session | session (≤ 7-day chain) |
| `kc_U`, `kc_D` | `K_master` | HKDF-Expand | `kc_U` / `kc_D` | Key confirmation (MAC_U, MAC_D) | handshake |
| `sid` | `K_master` | HKDF-Expand, 8 B | `sid` | Session identifier on the wire | session |
| `K_ALERT|up`, `K_CONTROL|down`, `K_ACK|up`, `K_ACK|down` | `K_master` | HKDF-Expand | `key|<tier>|<dir>` | Tier traffic keys | session |
| `psk` (slice 2) | `K_master` | HKDF-Expand | `res|<ticket_id>` | Resumption secret | ticket lifetime |
| `fin key` | `K_master` | HKDF-Expand | `fin` | FIN message when no ticket is issued | handshake |

`SALT` is a fixed domain-separation constant, carried over from the validated v2.1 reference.

### 4.3 Message catalogue (slice 1)

Codec: every field is `u32 big-endian length ‖ bytes`; exact field count; no trailing bytes; 1 MiB field cap
checked **before** allocation (§12, I-21).

| # | Message | Sender → receiver | Fields (in order) | Validation | On failure |
|---|---|---|---|---|---|
| 1 | **CH** | D → U | `"CH"`, `pk_e`(1,216), `ct_U`(1,120), `n_D`(32), `nonce`(12), `AEAD_KB(enc[id_D, class, POLICY_INFO_D, u64 fw_version, u64 device_time], aad = H("CH", pk_e, ct_U, n_D))` | id = topic id; registered and active; class matches registry; POLICY_INFO_D = current; device_time **informational** | `HandshakeError`; ≤ 1 half-open per device; duplicate CH bytes → identical SH from the cache |
| 2 | **SH** | U → D | `"SH"`, `ct_e`(1,120), `n_U`(32), `nonce`(12), `AEAD_K1(enc[ct_D, POLICY_INFO_U, resume_mode, u64 chain_expiry, u64 utility_time], aad = H("SH", ct_e, n_U))`, `MAC_U`(32) | POLICY_INFO_U = installed policy; MAC_U verifies (constant time) | abort; device may retry with a fresh CH |
| 3 | **DF** | D → U | `"DF"`, `MAC_D`(32), `bundle` | MAC_D verifies **before** the bundle is parsed (I-19); then envelopes processed in order | abort; duplicate DF bytes → identical NT/FIN |
| 3a | `bundle` | inside DF | `enc[u16 count, env₁ … env_n]`, `count ≤ class limit` | each envelope: ownership, tier, two-phase replay (I-7) | one bad envelope → that envelope rejected; the session stays up |
| 4 | **NT** / **FIN** | U → D | NT: `"NT"`, `nonce`(12), `AEAD(K_master-derived "new-ticket")`, `ack_bundle` · FIN: `"FIN"`, `MAC(fin key, sid)`, `ack_bundle` | MAC/AEAD verify | device resends the identical DF |
| 5 | **ALERT envelope** | D → U | `0x02`, `sid`(8), `msg_seq`(8), `AEAD(K_ALERT|up, nonce = 0x01‖0x000000‖msg_seq, pt = enc[alert_id(16), payload], aad = H("ALERT", topic, sid, msg_seq))` | topic tier = ALERT in the **receiver's** policy; topic device owns the session; replay guard validate → open → accept | `ReplayError`/`ValueError`; counter not consumed on AEAD failure |
| 6 | **ALERT ACK** | U → D | `0x05`, `sid`(8), `msg_seq`(8), `MAC(K_ACK|down, sid ‖ msg_seq)` | constant-time MAC compare | ignored |

**State transitions (device):** `IDLE → SENT_CH → (SH ok) SESSION_UNCONFIRMED → (sends DF + bundle) →
(NT/FIN ok) SESSION_CONFIRMED`. Data may be sent from `SESSION_UNCONFIRMED` **only inside DF** (I-19).
**Utility:** `IDLE → PENDING(≤ PENDING_TTL, one per device) → (DF ok) SESSION`, replacing any previous
session for that device (I-36/DR-036: one live session per device).

**Duplicate handling:** identical CH/DF bytes within `dup_window_s` return the identical stored reply
(I-18). Windows come from the class profile.

### 4.4 Engineering choices I will make and document (no security-model change)

| # | Choice | Rationale |
|---|---|---|
| E1 | Policy binary field order exactly as §12's table, classes sorted by name, rules in declaration order | The **signed bytes** are installed and never re-serialised, so ordering only needs to be deterministic |
| E2 | `bundle` is `enc[u16 count, env₁ … env_n]`; an **empty** bundle is a zero-length field (DF alone = 46 B, matching Appendix C), and a non-empty encoding of zero items is refused | Matches the sizes already published in Master; one encoding per meaning |
| E3 | `ack_bundle` is `enc[u16 count, ack₁…]`, ACKs unchanged from §11 | Each ACK is individually MAC'd, so bundling adds no security property |
| E4 | `resume_mode` on the wire is an ASCII token (`NONE`/`PSK`/`PSK_KEM`) | Same as the validated v2.1 reference |
| E5 | `H(...)` = SHA-256 over length-prefixed parts (v2.1 helper) | Already used by the validated reference; avoids inventing a second transcript hash |
| E6 | `SALT` constant reused from the v2.1 reference | Domain separation only |
| E7 | Alert dedup memory bounded per device (4,096 ids, as v2.1) | Bounded memory; Master leaves the number open |
| E8 | SETPOINT ordering (slice 3) uses `msg_seq`, since SETPOINTs carry no command sequence | Monotonic per session; authority is bounded by the GRANT |
| E9 | The CH/SH inner blocks use the **device class AEAD**; the utility resolves the class from its registry entry for the topic's device ID before opening CH | Keeps "one AEAD per device" (DR-003) true for the handshake as well |
| E10 | The validator refuses policy versions ≥ 2³², because POLICY_INFO carries `u32(version)` | Two versions could otherwise share one POLICY_INFO |
| E11 | Rule 7's "proof + headers" bound is 677 B (16 × 32 B proof, 37 B chunk record, 128 B MQTT reserve) | Master states the rule, not the constant |
| E12 | At most 64 envelopes per DF bundle or FIN ACK bundle | Bounded parsing; the class outbox cap bounds real usage |
| E13 | No interim "signed policy" format in slice 1; the FOTA manifest (slice 6) is the only signed wrapper | Avoids inventing a format that slice 6 would have to replace |
| E14 | Handshake domain salt `pqgrid/v2/hs` (v2.1 used `pqgrid/v1/hs`); key-confirmation labels are Master's `kc_U` and `kc_D` | Separates v2.2 transcripts from v2.1; labels as written in Master Appendix C |
| E15 | Expired half-open handshakes are dropped from the oldest end (O(1) amortised) plus an exact expiry check at lookup | Avoids the per-message O(n) scan pattern the audit flagged in S4 |

### 4.5 Clarifications resolved **from** Master text (recorded, not invented)

| # | Question | Resolution | Where Master settles it |
|---|---|---|---|
| C1 | Does the AEAD nonce use the command sequence or a per-session counter? | **Per-session, per-direction counter** (`msg_seq`), 8 B, RAM only | §9.7 "Message sequence numbers … per session, per direction, in RAM only. Nonce = direction ‖ seq" **and** §13.6 "The command sequence … lives in the signed command body, **not in the nonce**" |
| C2 | Then what is the `seq` inside σ in §13.1? | The **command** sequence (`epoch ‖ counter`), carried inside the AEAD plaintext, not the envelope header | §13.1 "σ does not cover `sid`… redelivered in a later session with the same `seq`"; a per-session counter could not survive a new session |
| C3 | Envelope header field | Carries `msg_seq`; the replay guard uses it; the command classification uses the plaintext's command sequence | §9.6 "Per-direction sequence numbers; two-phase check" + C1, C2 |

### 4.6 SECURITY-CRITICAL OPEN DECISIONS

Both were **resolved by the team on 2026-09-25** with the recommended option, and recorded in Master.md as
DR-044 (MAC_D binds `H(bundle)`) and DR-045 (ACK MAC covers `sid ‖ msg_seq ‖ cmd_seq ‖ status`). The original
analysis follows.

**OPEN-1 — Does `MAC_D` cover the piggybacked bundle?**

- Master §9.4 writes `DF: MAC_D ‖ bundle(envelopes…)` and says the utility verifies MAC_D **then** processes
  the bundle (I-19). It does not say whether MAC_D's input includes the bundle.
- If it does **not**: an on-path attacker (the broker) can strip, truncate or append envelopes to a valid DF.
  Each envelope is still AEAD-protected and replay-checked, so forgery and replay remain impossible, but
  bundle **content** is not bound to the device's key confirmation.
- If it **does**: DF is atomic; any tampering fails one check.
- **Recommendation:** `MAC_D = HMAC(kc_D, "D-finished" ‖ H(th2, MAC_U, H(bundle)))`. Cost: one hash.
- **Impact if we choose wrong later:** a wire-format change affecting authentication.

**OPEN-2 — What exactly does the CONTROL status ACK MAC cover?**

- Master §11 gives `0x06 ‖ sid ‖ seq ‖ status ‖ MAC(K_ACK|up, …)` with the MAC input elided, and §13.6 needs
  the utility to match a status to a **command** across sessions and redeliveries.
- If the MAC covers only `sid ‖ msg_seq ‖ status`, a status could be matched to the wrong command after a
  redelivery, which is what the S1/S2 fixes exist to prevent.
- **Recommendation:** `MAC(K_ACK|up, sid ‖ msg_seq ‖ cmd_seq ‖ status)`, with `cmd_seq` also carried in the
  ACK body.
- This only matters from slice 3, but the ACK framing is defined in slice 1, so it is raised now.

---

## 5. Repository structure (minimum practical)

```
Major Project/
├── BalaMP-Master.md            design authority (unchanged)
├── BalaMP.md, BalaMP-Rationale.md, BalaMP-Audit.md   history (unchanged)
├── IMPLEMENTATION-ROADMAP.md   this file
├── design-validation/          FROZEN v2.1 evidence — never edited (it backs every [DOCKER] number)
├── .venv/                      project-local environment
├── requirements.txt            pinned dependencies
├── pqgrid/                     ← the implementation
│   ├── wire.py                 length-prefixed codec (slice 1)
│   ├── suite/                  crypto only: hkem.py, aead.py, kdf.py, sig.py, rand.py (slice 1)
│   ├── policy/                 model.py, codec.py, engine.py, validator.py (slice 1)
│   ├── registry.py             device → class, E2E public key, active, max_packet (slice 1)
│   ├── e2e/                    keys.py, session.py, handshake.py, replay.py, envelopes.py (slice 1)
│   ├── pasr/                   stek.py, tickets.py (slice 2; RH/RS/NT live in e2e/handshake.py)
│   ├── commands/               codec.py, device.py, utility.py, zones.py (slice 3)
│   ├── persistence/            flash.py, device.py, utility_db.py, atomic.py (slice 4)
│   ├── mqtt/                   topics, tls, pki, broker (config + ACL), device_node, utility_node (slice 5)
│   └── fota/                   merkle, artifact, station, installer, publisher, policy_artifact (slice 6)
└── tests/
    ├── unit/                   codec, policy, key schedule, primitives
    ├── security/               attack scenarios (A-*, later P-*, F-*, V-*)
    └── integration/            (from slice 5)
```

**Reuse policy:** `design-validation/reference/pqgrid_ref/` is **evidence, not a library**. Slice 1 ports its
validated logic (codec, X-Wing, handshake skeleton, replay guard) into `pqgrid/` and adapts it to v2.2. The
evidence folder itself is never modified, so every published [DOCKER] number stays reproducible.

**No new frameworks:** plain modules, dataclasses, `pytest`. No dependency injection layer, no ORM (SQLite
arrives in slice 4 through the stdlib).

---

## 6. Execution environment

| Item | Value |
|---|---|
| Interpreter | `.venv/bin/python` — Python 3.14.7 (created at the project root) |
| Packages | `cryptography==50.0.1` (ML-KEM-768, ML-DSA-65, X25519, AES-GCM, ChaCha20-Poly1305), `pytest` |
| SLH-DSA-SHA2-128s | Not in `cryptography`; reached through `ctypes` to OpenSSL (host has 3.6.4, which lists `SLH-DSA-SHA2-128s`), exactly as the validated v2.1 reference does. Canonical runs stay in Docker (OpenSSL 3.5) |
| Dependency file | `requirements.txt` at the project root |
| Docker | Unchanged: no `--privileged`, no host network, no socket, no host mounts. `design-validation/run_all.sh` and `constrained-audit/run_audit.sh` still reproduce all v2.1 + audit evidence |
| Host | No global installs, no `sudo`, no Homebrew or macOS changes |

Evidence labels stay as defined in Master §17.3: **[DOCKER] [SIM] [LIT] [ANALYTICAL] [HW]**. Nothing from
this laptop or a container is ever reported as MCU hardware.

---

## 7. Slice plan and status ledger

| Slice | Contents | Status |
|---|---|---|
| **1** | wire codec · suite · policy + registry · E2E establishment (CH/SH/DF/FIN, key schedule, replay guard) · ALERT envelope + ACK | **IMPLEMENTED · UNIT-TESTED · DOCKER-VALIDATED** (§7.1) · **INTEGRATION-TESTED** over the broker in slice 5 (full handshake, DF with outbox alert, live ALERT + ACK, lost-reply retransmission) |
| **2** | PASR: tickets, STEK, 9 checks, identical-RH rule, 1-RTT resume, NT | **IMPLEMENTED · UNIT-TESTED · DOCKER-VALIDATED** (§8.6) · **INTEGRATION-TESTED** in slice 5 (PSK_KEM resume, resume after a utility restart, refused resume → full handshake) |
| **3** | Commands: CMD, GRANT, SETPOINT, ZONEKEY, broadcast, statuses | **IMPLEMENTED · UNIT-TESTED · DOCKER-VALIDATED** (§9.9) · **INTEGRATION-TESTED** in slice 5 (CMD + status, GRANT + SETPOINT + cumulative ACK, ZONEKEY + DR event, CMD queued in the persistent session) |
| **4** | Persistence: device record store + intent log, utility SQLite WAL | **IMPLEMENTED · UNIT-TESTED · DOCKER-VALIDATED** (§10.8) · **INTEGRATION-TESTED** in slice 5 (utility restart on its database, device reboot from flash with a queued DR event) |
| **5** | Transport: MQTT 5 + TLS 1.3 hybrid, sessions, back-off, clock recovery | **IMPLEMENTED · UNIT-TESTED · INTEGRATION-TESTED · DOCKER-VALIDATED** (§11.6) |
| **6** | FOTA: manifest, Merkle, parts, installer, anchors, KEYREVOKE, station | **IMPLEMENTED · UNIT-TESTED · INTEGRATION-TESTED · DOCKER-VALIDATED** (§12.4) |
| **R** | Remediation after the read-only audit (H1–H4, M1–M9, weak tests, independent oracles, hygiene) and the final pass (device storage capacity, C2 DF limit, reconnect back-off across ticks, E-2 zone sync, E-3 SETPOINT ACK, E-4 republish) | **IMPLEMENTED · UNIT-TESTED · INTEGRATION-TESTED · DOCKER-VALIDATED** (§13); nothing HARDWARE-VALIDATED |

Every slice ends with: run unit tests → run security tests → run the existing regression suites → fix →
re-run → update this ledger with the **evidence-backed** status.

### 7.1 Slice 1 status ledger (2026-09-25)

Evidence: `.venv/bin/python -m pytest` → **94 passed** (macOS, Python 3.14.7, OpenSSL 3.6.4).
`docker run --rm pqgrid-tests` → **94 passed** (Debian trixie, Python 3.13, OpenSSL 3.5.7). No skips.
Existing regression: `design-validation` v2.1 validation in Docker → **80/80 as expected** (unchanged).

| Component | Module | IMPLEMENTED | UNIT-TESTED | INTEGRATION-TESTED | DOCKER-VALIDATED | Evidence |
|---|---|---|---|---|---|---|
| Wire codec (strict, capped) | `pqgrid/wire.py` | ✓ | ✓ | — (slice 5) | ✓ | `tests/unit/test_wire.py`: count, trailing bytes, oversized length before allocation, exact-width integers, 2,000 random mutations |
| Hybrid KEM + X-Wing | `pqgrid/suite/hkem.py` | ✓ | ✓ | — | ✓ | sizes 1,216/1,120/32; 96-byte key storage round-trip; combiner recomputed independently; tamper at 5 offsets |
| AEAD per class + counter nonces | `pqgrid/suite/aead.py` | ✓ | ✓ | — | ✓ | both algorithms, tamper and AAD checks, nonce layout |
| HKDF / HMAC / transcript hash | `pqgrid/suite/kdf.py` | ✓ | ✓ | — | ✓ | RFC 5869 test case 1; length-prefix separation |
| ML-DSA-65 | `pqgrid/suite/sig.py` | ✓ | ✓ | — | ✓ | sign/verify/tamper (used from slice 3) |
| SLH-DSA-SHA2-128s verify | `pqgrid/suite/sig.py` | ✓ | ✓ | — | ✓ | verified against signatures produced by the `openssl` CLI (host 3.6.4, container 3.5.7); tamper, wrong key, wrong message |
| Policy model + binary codec | `pqgrid/policy/{model,codec}.py` | ✓ | ✓ | — | ✓ | exact round-trip; canonical-only (reordered classes refused); bad magic/tier; truncation |
| Tier engine | `pqgrid/policy/engine.py` | ✓ | ✓ | — | ✓ | 1/2/3/3 mapping; strongest wins in any rule order; filters are not topics |
| Validator rules 1–10 | `pqgrid/policy/validator.py` | ✓ | ✓ | — | ✓ | one failing case per rule, plus u32 version and key lengths |
| Registry | `pqgrid/registry.py` | ✓ | ✓ | — | ✓ | device-ID rules, revocation |
| Key schedule | `pqgrid/e2e/keys.py` | ✓ | ✓ | — | ✓ | all labels independent; MAC_D binds the bundle (DR-044) |
| Full handshake CH/SH/DF/FIN | `pqgrid/e2e/handshake.py` | ✓ | ✓ | — (slice 5) | ✓ | three classes (both AEADs, CONSTRAINED); A1, A2, A2b, A3, A4; unknown/revoked; utility impostor; clock from utility time |
| Finished carries data (I-19, DR-044) | `pqgrid/e2e/handshake.py` | ✓ | ✓ | — | ✓ | alerts delivered once; strip/append/reorder/truncate/empty bundle all fail key confirmation; genuine DF still completes |
| Duplicates, half-open, one session per device | `pqgrid/e2e/handshake.py` | ✓ | ✓ | — | ✓ | identical CH→SH and DF→FIN; replayed DF not re-delivered; lost FIN recovery; one half-open; exact per-class expiry; 50-device expiry; session replacement + resync hint |
| ALERT envelope + ACK | `pqgrid/e2e/envelopes.py` | ✓ | ✓ | — | ✓ | A5, A6, A7, A8 (forgery does not burn the sequence), E-X1, P10-style old policy, forged ACK, alert-id dedup |
| Fuzzing | all slice-1 handlers | — | ✓ | — | ✓ | 1,200 corrupted CH/SH/DF/ALERT messages: all refused with controlled errors; genuine message still accepted |
| Published sizes | — | — | ✓ | — | ✓ | CH 2,493 · SH 2,411 · DF alone 46 · DF + ALERT 193 · ALERT 137, exactly as in Master |

**Not claimed:** SIMULATED (no link model involved) and HARDWARE-VALIDATED (no MCU). Laptop and container
runtimes are not quoted as performance evidence.

**Documented properties (not defects):**

- **Half-open displacement.** A forged CH on `pqgrid/hs/{id}/up` can displace that device's half-open
  handshake, because the device is only authenticated at DF (inherent to KEM-MQTT). Publishing there
  requires that device's TLS identity (ACL, Master §10.1), so this is denial of service only: out of scope
  (Master §2.4).
- **No true erasure.** Python cannot erase key memory. `Session.close()` drops every reference, which is
  weaker than zeroisation and is described that way.

**How to run:**

```bash
.venv/bin/python -m pytest
docker build -f docker/pqgrid-tests.Dockerfile -t pqgrid-tests . && docker run --rm pqgrid-tests
```

---

## 8. Slice 2: PASR (policy-aware session resumption)

**What it is.** After a reboot or an outage, a device holding a ticket skips the full post-quantum handshake.
It shows the utility a sealed ticket plus proof that it knows the ticket's secret (the *binder*), and both
sides derive a fresh session in one round trip. The ticket is single-use, bound to device, policy, firmware
and resume mode, and every resume re-checks revocation (Master §14).

**Master sections:** §9.4 (resume diagram, DR-044 for the resume DF), §9.5 (labels `res|`, `binder`,
`new-ticket`), §6.5–§6.7, §8.9 (time is never gated by the device), §9.8, §14.3–§14.7, §24.2 (P1–P10, E-P*, S5).

### 8.1 Key schedule additions

| Key | Input | Operation | Purpose | Lifetime |
|---|---|---|---|---|
| `psk` | `K_master` of the issuing session, `ticket_id` | `HKDF-Expand(K_master, "res|" ‖ ticket_id)` | Resumption secret (in the ticket and in device RAM/flash) | one resume |
| `K_binder` | `psk` | `HKDF-Expand(psk, "binder")` | Proves possession of `psk` | one RH |
| `K_nt` | `K_master` | `HKDF-Expand(K_master, "new-ticket")` | Encrypts the ticket delivery in NT | one message |
| `K_master′` | `psk ‖ [ss_e′]` | `HKDF-Extract(salt = th_R, IKM)` | Root of the resumed session | new session |
| `kc_U′`, `kc_D′`, `sid′`, traffic keys | `K_master′` | same labels as the full handshake | as slice 1 | as slice 1 |
| STEK | `random_bytes(32)` | — | Seals tickets (ChaCha20-Poly1305, random 96-bit nonce) | current 24 h; retired automatically |

`th_R = H(RH, "RS", n_U, ct_e′, u64 utility_time, u64 chain_expiry)`: every byte sent before MAC_U, the same
rule as `th2`. `MAC_U = HMAC(kc_U′, "U-finished" ‖ th_R)`; `MAC_D` per DR-044 with `th_R`.

### 8.2 Message catalogue (slice 2)

| Message | Fields (in order) | Validation | On failure |
|---|---|---|---|
| **ticket blob** | `0x01`, `kid` (u16 BE), `nonce`(12), `ChaCha20-Poly1305(STEK[kid], enc[ticket_id(16), device_id, class, POLICY_INFO, u64 fw, mode, u64 issued, u64 expires, u64 chain_expires, psk(32)], AAD = 0x01 ‖ kid)` | version byte; checks 1–2 | refused; full handshake |
| **RH** | `"RH"`, `blob`, `n_D`(32), `mode`, `pk_e′` (1,216 for PSK_KEM, empty for PSK), `id`, `POLICY_INFO`, u64 `fw`, u64 `device_time`, `binder = HMAC(K_binder, H(first nine fields))` | the 9 checks (below) | `HandshakeError`; device falls back to a full handshake |
| **RS** | `"RS"`, `n_U`(32), `ct_e′` (1,120 or empty), u64 `utility_time`, u64 `chain_expiry`, `MAC_U` | device verifies MAC_U (constant time), then sets its clock | abort; device keeps resending its identical RH until a timeout |
| **DF** | unchanged from slice 1 (`"DF"`, `MAC_D`, `bundle`), transcript `th_R` | as slice 1 | as slice 1 |
| **NT** | `"NT"`, `nonce`(12), `AEAD_class(K_nt, enc[ticket_id, blob, u64 expires], AAD = H("NT", sid))`, `ack_bundle` | AEAD, then each ACK MAC | device resends the identical DF |

**The 9 checks** (utility, in Master's order; any failure means a full handshake, never a weaker session):

| # | Check | Error |
|---|---|---|
| 1 | `kid` is live | `ticket key retired` |
| 2 | ticket decrypts and authenticates | `ticket not authentic` |
| 3 | ticket device = topic device = claimed device | `ticket/device identity mismatch` |
| 4 | registered, active, and registry class = ticket class (E22) | `device unknown or revoked` / `ticket class does not match the registry` |
| 5 | `now < expires` and `now < chain_expires` (utility clock) | `ticket expired` |
| 6 | ticket POLICY_INFO = claimed = **current** | `ticket issued under a different policy` |
| 7 | firmware version matches | `ticket issued for different firmware` |
| 8 | ticket mode = requested = current class mode; PSK_KEM carries a 1,216-byte key, PSK carries none | `resume mode does not match policy` / `PSK_KEM requires a fresh ephemeral key` |
| 9 | binder valid, **then** unused, **then** consumed | `binder invalid` / `ticket already used` (`TicketReusedError`, so an operator can alarm on clones) |

**State (device):** `HAS_TICKET → SENT_RH (identical RH resent) → (RS ok; ticket dropped) UNCONFIRMED →
(DF + bundle) → (NT ok; new ticket stored) CONFIRMED`. **Utility:** the resume shares the one-half-open-per-device
table with CH, so a CH replaces a pending RH and vice versa.

### 8.3 Engineering choices (no security-model change)

| # | Choice | Rationale |
|---|---|---|
| E16 | RH keeps a fixed 10-field layout; `pk_e′` is empty for PSK and must be empty | Strict parsing: one encoding per meaning |
| E17 | RS fields are flat (`utility_time`, `chain_expiry` as two u64 fields) | Simpler than v2.1's nested tail; all fields are in `th_R` |
| E18 | NT uses the **class AEAD** with AAD `H("NT", sid)`; one NT per session (duplicates are served from the cache) | Same rule as E9; the `new-ticket` key is used once |
| E19 | `K_binder = HKDF-Expand(psk, "binder")` without a second Extract | `psk` is already a uniform HKDF output (RFC 5869 §3.3); as the validated v2.1 reference |
| E20 | `kid` is a big-endian u16 in the blob header; ticket expiry = `min(issued + ticket_lifetime, chain_expires)` | Master §14.3; the "same chain expiry" rule |
| E21 | The STEK rotates when a ticket is issued and the current key is ≥ 24 h old; `retire_at = created_at + 24 h + 7 days`; the kid never wraps into a live key | Validator rule 4 caps every ticket at 7 days, so no ticket sealed under a key can outlive `retire_at` |
| E22 | Check 4 also requires the registry class to equal the ticket class | Stricter only (a reclassified device does a full handshake) |
| E23 | Unknown/revoked devices are refused before the duplicate cache (as CH and DF); then the 9 checks run in Master's order | Cheapest refusal first; same as the slice-1 handlers |
| E24 | Slice 2 keeps the STEK table and the used-ticket set in memory, behind small classes; `consume()` runs **before** RS is built | I-8's *ordering* is enforced now; its *durability* (SQLite WAL, `synchronous = FULL`) is slice 4 |
| E25 | NT replaces FIN only for classes with `resume ≠ NONE`; FIN otherwise | Master §9.4 ("NT … or FIN") |
| E26 | The device drops its ticket when RS verifies and stores the new one only after NT verifies; a late or duplicate RS/SH is refused | Single use (§14.7); re-processing a reply would restart counters under the same keys (nonce reuse) |
| E27 | The device never checks ticket expiry against its own clock; the utility decides | §8.8: device time never gates a connection |
| E28 | The used-ticket set is pruned by expiry through a min-heap (O(log n) per resume) | Avoids the O(n) per-resume pattern the audit measured in S4 |

### 8.4 SECURITY-CRITICAL OPEN DECISIONS

**None.** Master §14 fixes the ticket contents, the check order, binder placement, single use, the resume key
schedule (`HKDF-Extract(H(transcript), psk ‖ [ss_e′])`) and DF binding (DR-044). The byte layouts above only
fix encodings, and every sent field is inside a MAC or AEAD.

**Residual risk (recorded, not a design change):** an attacker who reads a device's flash obtains its ticket
and `psk` and can keep resuming until the chain expires (≤ 7 days), even after the genuine device's full
handshake evicts its session. The same flash also holds the device's static E2E key, so Master's threat
model already treats this as device compromise (§2.4); single use turns it into a detectable "already used".

### 8.5 Not in slice 2

| Item | Why | Slice |
|---|---|---|
| Durable used-ticket set and STEK (SQLite WAL); device ticket in flash | Persistence layer | 4 |
| Restart tests E-P2, E-P3, E-P4; torn-write S3; 100k-ticket S4 | Need the durable store | 4 |
| Transport-level failure signalling (the device learns of a refused RH by timeout) | No MQTT until then | 5 |
| Firmware-commit invalidation driven by FOTA | Check 7 is implemented; FOTA is not | 6 |

### 8.6 Slice 2 status ledger (2026-09-25)

Evidence: `.venv/bin/python -m pytest` → **154 passed** (94 slice 1 + 60 slice 2; macOS, Python 3.14.7, OpenSSL 3.6.4).
`docker run --rm pqgrid-tests` → **154 passed** (Debian trixie, Python 3.13.5, OpenSSL 3.5.7). No skips.
Existing regression: v2.1 `validate.py` in Docker → **80/80 as expected** (unchanged).
Ad-hoc mutation check (script kept outside the repo): each of 19 security rules was removed in turn in a
scratch copy, and **every removal made at least one test fail**.

| Component | Module | IMPLEMENTED | UNIT-TESTED | INTEGRATION-TESTED | DOCKER-VALIDATED | Evidence |
|---|---|---|---|---|---|---|
| STEK table (24 h rotation, automatic retirement, 16-bit kid) | `pqgrid/pasr/stek.py` | ✓ (in memory) | ✓ | — | ✓ | rotation boundary; exact retirement; 8 live keys; no wrap onto a live kid |
| Ticket seal/open | `pqgrid/pasr/tickets.py` | ✓ | ✓ | — | ✓ | round trip; tamper (nonce, ciphertext, tag); header in AAD; foreign STEK refused |
| Single-use set | `pqgrid/pasr/tickets.py` | ✓ (in memory) | ✓ | — | ✓ | consume once; expiry pruning by heap, not insertion order |
| 9 checks | `TicketIssuer.redeem` | ✓ | ✓ | — | ✓ | P1 (replay + clone), P2 (stolen blob; ticket survives), P3, P4 (lifetime and 7-day chain), P5, P6 (mode strip, key strip, key on PSK), P7, P8, P9, E22 reclassification, check 4 direct |
| Resume key schedule | `pqgrid/e2e/keys.py`, `handshake.py` | ✓ | ✓ | — | ✓ | both sides derive the same K_master′; labels separated; RS tamper (each field) refused, genuine RS still accepted |
| RH/RS/DF/NT exchange | `pqgrid/e2e/handshake.py` | ✓ | ✓ | — (slice 5) | ✓ | PSK and PSK_KEM on three classes; FIN for resume = NONE; alerts in the resume DF delivered once; resent alert recognised as a duplicate; reset device clock |
| Duplicates and retransmission | `pqgrid/e2e/handshake.py` | ✓ | ✓ | — | ✓ | E-P1 (identical RS, consumed once); S5 (identical RH completes, rebuilt RH refused); lost NT → identical NT; duplicate RS/SH refused (no counter restart) |
| Clone detection | — | ✓ | ✓ | — | ✓ | E-P5 (genuine sees "already used"; full handshake evicts the clone); RISK test for the residual risk in §8.4, shown succeeding on purpose |
| Half-open state across CH and RH | `pqgrid/e2e/handshake.py` | ✓ | ✓ | — | ✓ | CH replaces a pending resume; pending resume expires |
| Fuzzing | RH, RS, resume DF, NT | — | ✓ | — | ✓ | 1,500 corrupted messages refused with controlled errors; a refused RH never consumes the ticket |
| Wire format | — | — | ✓ | — | ✓ | ticket AAD and NT format pinned; sizes pinned (below) |

**Sizes (v2.2 layout, measured in this implementation):**

| Exchange | Bytes (RH/CH + RS/SH + DF + NT) | Master §9.4 (v2.1 bench) |
|---|---|---|
| Full handshake | 2,493 + 2,411 + 46 + 271 = **5,221** | 5,212 |
| PSK resume | 338 + 106 + 46 + 271 = **761** | 755 |
| PSK+KEM resume | 1,555 + 1,226 + 46 + 270 = **3,097** | 3,103 |

The differences come from the 16-bit kid, the DF bundle field, the NT ACK field and the flat RS (E17). **Master
updated on 2026-09-29** (approved by the team), with the v2.1 figures kept alongside as history.

**Not done in slice 2:** durable used set and STEK (a restart loses both; E-P2, E-P3, E-P4, S3, S4 are slice 4);
device ticket in flash (slice 4); transport signalling of a refused RH (slice 5); SIMULATED and HARDWARE-VALIDATED: no.

---

## 9. Slice 3: CONTROL commands (CMD, GRANT, SETPOINT, ZONEKEY, DR broadcast, statuses)

**What it is.** How the utility tells devices what to do, so that nobody without the command key can forge an
order and no order is applied twice:
- **CMD:** a discrete order (trip, curtail, schedule), signed with ML-DSA-65, applied at most once;
- **GRANT:** a signed permission for one session: "set-points for this target between min and max, at most
  N per minute, until T";
- **SETPOINT:** the fast stream inside a GRANT, protected only by the session (no signature per value);
- **ZONEKEY:** delivers a demand-response zone key under the member's session;
- **DR broadcast:** one signed, zone-encrypted event for every member of a zone;
- **status ACK** (DR-045) for every unicast CONTROL message.

**Master sections:** §11 Control, §13.1–§13.7, §16 (utility command sequence, device command state, intent
log), §4.7 (zone keys), DR-020, §24.1 (A9–A11, C-E3, E-CMD1–5, E-Z1, S1, S2a/b, V-G1–6, V-S1–3, V-Z1).

### 9.1 Message catalogue

All unicast CONTROL messages share one envelope (as ALERT, other direction):
`0x03, sid(8), msg_seq(8), AEAD_class(K_CONTROL|down, nonce = 0x02‖000‖msg_seq, pt, AAD = H("CONTROL", topic, sid, msg_seq))`.
The receiver checks the topic is CONTROL in **its own** policy, that it is its own `grid/{class}/{id}/control`
topic, and runs the two-phase replay guard on `msg_seq`.

| Sub-type | Plaintext `pt` (enc fields, in order) | σ input (ML-DSA-65, utility command key) |
|---|---|---|
| **CMD** | `"CMD"`, u64 `cmd_seq`, `command`, u64 `expires_at`, u8 `idempotent`, σ | `"pqgrid/v2/cmd" ‖ H(device_id, topic, cmd_seq, expires_at, idempotent, command)` |
| **GRANT** | `"GRANT"`, u64 `cmd_seq`, `grant_id`(8), `sid`(8), `target`, i64 `min`, i64 `max`, u32 `max_rate`, u64 `not_before`, u64 `expires_at`, σ | `"pqgrid/v2/grant" ‖ H(device_id, topic, cmd_seq, grant_id, sid, target, min, max, max_rate, not_before, expires_at)` |
| **SETPOINT** | `"SETPOINT"`, `grant_id`(8), i64 `value`, u64 `expires_at` | none (session AEAD only) |
| **ZONEKEY** | `"ZONEKEY"`, `zone`, u64 `key_epoch`, `aead` (DR-047), `key`(32) | none (session AEAD only; DR-020) |

**Status ACK** (DR-045): `0x06, sid, u64 msg_seq, u64 cmd_seq, status, MAC(K_ACK|up, sid ‖ msg_seq ‖ cmd_seq ‖ status)`.
`status` ∈ `OK`, `DUP`, `SUPERSEDED`, `EXPIRED`, `INTERRUPTED`, `REJECTED:<reason>`. `status` is the only
variable-length MAC input and comes last, so the MAC input is unambiguous.

**DR broadcast** (as built in slice 3; **superseded 2026-09-29 by remediation M7, §13.2**) on `grid/dr/{zone}/event`:
`0x04, zone, u64 key_epoch, u64 bseq, nonce(12), AEAD_zone(K_zone, nonce, enc[event, u64 expires_at, σ], AAD = H("BCAST", zone, key_epoch, bseq))`,
σ over `"pqgrid/v1/bcast" ‖ H(zone, key_epoch, bseq, expires_at, event)`. Now: one topic per crypto group,
`grid/dr/{zone}/{group}/event`, a `group` field in the envelope and the AAD, and σ over the logical event
`"pqgrid/v2/bcast" ‖ H(zone, bseq, expires_at, event)` (Master §11).

### 9.2 Device processing of a signed command (CMD)

AEAD (envelope guard) → class allows CMD and `unicast_control` → σ verify → **classification** → intent log →
actuate → APPLIED → ACK `OK` (sent only after APPLIED is durable, §13.7).

Classification, with state `last_applied` + 64-bit bitmap + intent log (§13.6, §16), **in this order**
(DR-046: "already seen" before expiry):

| Incoming `cmd_seq` | Status |
|---|---|
| applied (`= last_applied` or in the bitmap) | `DUP` (re-ACK, never re-apply) |
| PENDING without APPLIED in the intent log | `INTERRUPTED` (never applied automatically; the utility re-issues it under a new `cmd_seq` if wanted) |
| expired (authenticated time) | `EXPIRED` |
| `< last_applied`, not applied | `SUPERSEDED` |
| otherwise | new: PENDING → actuate → APPLIED → `OK` |

**Recovery** (after authenticated time returns in the next session): for each PENDING without APPLIED, if
idempotent and unexpired, re-apply → APPLIED → unsolicited `OK`; otherwise an unsolicited `INTERRUPTED`.
An unsolicited status carries `msg_seq = 0` (real envelopes start at 1).

### 9.3 GRANT and SETPOINT

- **GRANT:** σ verify → `sid` = current session → `target` supported by the device → `min ≤ max` →
  `max_rate ≤` class `max_setpoint_rate` → not expired → newest `cmd_seq` per target wins (`DUP` if equal,
  `SUPERSEDED` if older) → installed in RAM, bound to the session.
- **SETPOINT** (all six rules of §13.5): AEAD under the current session; `grant_id` names the live GRANT for
  this session; authenticated time inside both windows; `min ≤ value ≤ max`; at most `max_rate` applied in
  any 60 s; newer than the last applied one (E8: `msg_seq`, already strictly enforced by the envelope guard).
  Applied set-points are acknowledged **cumulatively**: the device exposes the latest applied (msg_seq,
  grant cmd_seq) as one MAC'd `OK`, and the transport decides when to send it (slice 5). A rejected
  set-point gets an immediate `REJECTED:<reason>`.

### 9.4 Utility

- `cmd_seq = epoch(32) ‖ counter(32)`, with `epoch = max(now_s, last_epoch + 1)` fixed at start (§13.6).
  Allocating a sequence and queueing the signed command are **one** store operation, before sending (P8).
- Queue = redelivery queue: on every new session, each unacknowledged, unexpired command is re-sealed under
  the new keys (same `cmd_seq`, same σ). GRANTs and SETPOINTs are session-bound and never redelivered.
- Statuses: `OK`/`DUP`/`SUPERSEDED`/`EXPIRED`/`REJECTED` close the entry; `INTERRUPTED` closes it and is
  surfaced for an operator decision. **Alarm** (V-S2): a *fresh* command (sent once) answered `DUP` or
  `SUPERSEDED` means the sequence regressed.
- Zone manager: per zone a key epoch and key, rotated on membership change and on demand (weekly is an
  operations schedule); ZONEKEY to every current member, including again at each new session.

### 9.5 Clarifications resolved from Master text

| # | Question | Resolution | Where Master settles it |
|---|---|---|---|
| C4 | Which `seq` does the GRANT σ cover, and how are GRANTs ordered? | `cmd_seq` (the utility's allocator; the signer cannot know a session's `msg_seq`), carried in the GRANT plaintext. GRANTs are ordered **per target** by `cmd_seq`, kept in RAM, and never enter the discrete-command bitmap (a GRANT must not supersede a CMD) | §13.4 "same envelope as CMD", "newer GRANT … replaces", "RAM only"; C2 |
| C5 | Where is `cmd_seq` in the CMD plaintext? | Inside `pt`, covered by σ (Master's pt list omits it; its analytical 3,454 B also omits it, so CMD is 12 B larger) | §9.4 clarification (C2) |
| C6 | Where does recovery get an interrupted idempotent command from? | The PENDING record holds the verified command body and `expires_at`, since §13.7 re-applies at boot | §13.7 algorithm (§16's field list is a summary) |
| C7 | How is "older SETPOINT" (rule 6) detected? | `msg_seq`, strictly increasing per session (E8); the envelope guard already refuses a replayed or older one, so it is never applied (V-G5 therefore shows "dropped as replay", not a `SUPERSEDED` status) | §9.6 two-phase check; E8 |

### 9.6 Engineering choices

| # | Choice | Rationale |
|---|---|---|
| E29 | Set-point bounds and values are **signed 64-bit integers** in the target's base unit (e.g. W); no floats | NaN or ±∞ could defeat `min ≤ value ≤ max` |
| E30 | `target` is an ASCII token; each device declares the targets it supports; unknown → `REJECTED:target` | Local safety: a device never applies a value it cannot interpret |
| E31 | "Rate ≤ max_rate" = at most `max_rate` applied set-points in any 60 s window (Master's unit is per minute) | Literal reading; a sliding window is exact |
| E32 | CMD/GRANT/SETPOINT are sent and accepted only for classes with `unicast_control` **and** the sub-type in `cmd_types`; ZONEKEY and broadcasts for any class | Rule 3 (FS for unicast commands) is validated against the flag, so only flagged classes may receive commands; a misconfigured class is unusable, never downgraded |
| E33 | `REJECTED` carries its reason in the status token (`REJECTED:signature`, `:sid`, `:bounds`, `:rate`, `:time`, `:no-grant`, `:target`, `:not-allowed`) | "REJECTED (with a reason)", §13.5, without a new field |
| E34 | Status ACKs for SETPOINT carry the GRANT's `cmd_seq`; for ZONEKEY `cmd_seq = 0`; unsolicited reports carry `msg_seq = 0` | Ties set-point status to the signed authority; 0 is never a real sequence |
| E35 | `grant_id` is 8 random bytes chosen by the command service | Master fixes the size only |
| E36 | Device and utility stores are in memory behind small classes (as E24); every "write" happens in P8 order | Durability (flash records with CRC, SQLite WAL) is slice 4; crash tests use a surviving store object |
| E37 | Recovery re-applies an interrupted idempotent command only if it is still newer than `last_applied`; otherwise it reports `INTERRUPTED`. The same rule runs whichever comes first: the recovery step after re-establishment, or the utility's redelivery of that command | Re-applying an older command after a newer one was applied would undo the newer one (newest wins); the outcome must not depend on message timing |
| E38 | At the utility, an expired queued command that was **never sent** closes as `EXPIRED`; one that was sent but never answered closes as `UNKNOWN` and is surfaced | Sent-but-unanswered may have been applied; calling it "expired" would repeat the DR-046 mistake at the utility |

### 9.7 SECURITY-CRITICAL OPEN DECISIONS

All three were **resolved by the team on 2026-09-25** with the recommended option and recorded in Master.md:
**OPEN-3 → DR-047** (one AEAD per zone; ZONEKEY names it; a device refuses a foreign AEAD), **OPEN-4 → DR-048**
(`bseq` = utility epoch ‖ per-zone counter; the device keeps its last accepted `bseq` per zone in flash),
**OPEN-5 → DR-046** (DUP and INTERRUPTED before EXPIRED; §13.1 amended). The original analysis follows.

DR-048 was first decided as "a floor in ZONEKEY". While planning the code, I found that the floor also makes a
rebooted device refuse unexpired events the broker queued during its downtime (for example restoration events
after an outage). The team replaced it the same day with the device-side record.

**OPEN-3: which AEAD protects a zone broadcast when a zone's members use different class AEADs?**
DR-003 gives each device exactly one AEAD. A feeder can hold AES-GCM meters and ChaCha20 DER controllers.

**OPEN-4: how does the broadcast sequence survive a utility restart, and a device reboot?**
Master says "per-zone sequence + expiry + signature" but not where the sequence lives. A counter kept in RAM
repeats S1 for broadcasts: after a restart, devices silently drop new events as replays. A device that
reboots forgets its last sequence, so an old event can be replayed once within its expiry.

**OPEN-5: must DUP (and INTERRUPTED) take precedence over EXPIRED?**
§13.1 orders the device checks AEAD → signature → **expiry** → classification. Consider a command that was
applied, whose OK was lost, and whose redelivery arrives after `expires_at`: it is answered `EXPIRED`
("not applied"), although it *was* applied. An operator who re-issues it gets a second actuation, which is
the double-apply the design exists to prevent.

**Broadcast device checks** (after DR-047/048): key for (zone, key_epoch) held → `bseq` > last accepted for the
zone (validate) → AEAD open → not expired → σ verify → accept (`last = bseq`, a flash record in slice 4). A device keeps the two newest key
epochs per zone, so an event sealed just before a rotation still opens.

### 9.8 Planned tests

A9 (replay/redelivery incl. after reboot → DUP), A10 (session-key holder forges CMD/GRANT → `REJECTED:signature`),
A11 (member forges an event; event replay; a rebooted device refuses replays yet accepts queued events), C-E3, E-CMD1–5, E-Z1 (removed member cannot
read the new epoch), S1 and V-S1 (restart, restore from an old backup → new epoch wins), S2a/S2b and V-S3 (a crash
at each intent-log step → OK / INTERRUPTED / re-applied if idempotent), V-S2 (regression alarm), V-G1–G6, V-Z1,
DR-046 (late redelivery of an applied command → DUP), DR-047 (foreign-AEAD ZONEKEY refused), class gating
(E32), fuzzing of every new handler, and pinned sizes.

### 9.9 Slice 3 status ledger (2026-09-25)

Evidence: `.venv/bin/python -m pytest` → **229 passed** (154 before + 75 slice 3; macOS, Python 3.14.7, OpenSSL 3.6.4).
`docker run --rm pqgrid-tests` → **229 passed** (Debian trixie, Python 3.13.5, OpenSSL 3.5.7). No skips.
Existing regression: v2.1 `validate.py` in Docker → **80/80 as expected** (unchanged).
Ad-hoc mutation check (script outside the repo): 32 CONTROL rules were removed one at a time in a scratch copy,
and every removal made at least one test fail.

**Bug found and fixed during testing:** when the utility's epoch changes, `cmd_seq` jumps by about 2³² per second
of epoch. Shifting the applied-sequence bitmap by that distance allocated an integer billions of bits long
(an 18 s test on the laptop; memory exhaustion on an MCU after any utility restart). Fixed: a jump beyond the
64-sequence window clears the bitmap. A regression test pins it.

| Component | Module | IMPLEMENTED | UNIT-TESTED | INTEGRATION-TESTED | DOCKER-VALIDATED | Evidence |
|---|---|---|---|---|---|---|
| CONTROL envelope + status ACK (DR-045) | `pqgrid/e2e/envelopes.py` | ✓ | ✓ | — (slice 5) | ✓ | forged envelope does not burn `msg_seq`; status and `cmd_seq` tampering refused; old-session status refused |
| Plaintext codec and σ inputs | `pqgrid/commands/codec.py` | ✓ | ✓ | — | ✓ | round trips; 10 malformed cases; σ covers every field (GRANT includes `sid`); signed 64-bit values only |
| CMD: at most once, truthful statuses | `pqgrid/commands/device.py` | ✓ | ✓ | — | ✓ | C-E3, A9, A10, command moved to another device, E-CMD1–5, DR-046 (late redelivery → DUP), acceptance before NT |
| Intent log and recovery | `pqgrid/commands/device.py` | ✓ (in memory) | ✓ | — | ✓ | S2a/V-S3: 8 cases (crash before/after actuation × idempotent or not × recovery-first or redelivery-first); crash after APPLIED → DUP; E37 |
| Command sequence + queue (epoch ‖ counter) | `pqgrid/commands/utility.py` | ✓ (in memory) | ✓ | — | ✓ | S1 restart, V-S1 restore from an old backup, V-S2 regression alarm, E38 (EXPIRED vs UNKNOWN) |
| GRANT and SETPOINT | `pqgrid/commands/device.py`, `utility.py` | ✓ | ✓ | — | ✓ | V-G1–V-G6; newest GRANT wins, DUP, unknown target, rate cap; rate window per minute; not-yet-valid GRANT; cumulative ACK |
| Class gating (E32) | device and utility | ✓ | ✓ | — | ✓ | meters get no commands; `cmd_types` without `unicast_control` refused |
| Zones and DR broadcast | `pqgrid/commands/zones.py` | ✓ | ✓ | — | ✓ | A11 (forged event, replay), E-Z1, V-Z1, DR-047 (foreign AEAD refused at join and at the device), DR-048 (utility restart; rebooted device refuses replays and accepts queued events), rotation in flight, expiry, wrong topic |
| Fuzzing | CMD, GRANT, status, broadcast | — | ✓ | — | ✓ | 1,200 corrupted messages refused with controlled errors; the genuine message is still accepted |

**Sizes (v2.2 layout, measured):** CMD 3,466 B (64-byte command) · GRANT 3,477 B · SETPOINT 97 B · ZONEKEY 138 B ·
status ACK 83 B · DR broadcast 3,468 B (64-byte event). Master Appendix C lists 3,454 / 3,461 / 93 / 132 B
[ANALYTICAL]. Those omit `cmd_seq` (C5) and the ZONEKEY `aead` field (DR-047). **Master updated on 2026-09-29**
(approved by the team), with the estimates kept alongside.

**Known limits (recorded):**
- An applied command more than 64 sequences below `last_applied` falls outside the bitmap, so a very late
  redelivery is answered SUPERSEDED rather than DUP (Master's 64-sequence window). Expiry normally prevents
  this.
- INTERRUPTED records are kept until compaction arrives in slice 4, and are reported again at each recovery
  (the utility ignores repeats).

**Not done in slice 3:**
- durable device records and utility SQLite (slice 4);
- scheduling of the cumulative set-point ACK, and the broker ACL for control and DR topics (slice 5);
- weekly zone-key rotation as an operations schedule (`rotate()` exists).

SIMULATED and HARDWARE-VALIDATED: no.

---

## 10. Slice 4: Persistence and crash safety

**What it is.** The promises made in slices 2 and 3 have to survive a power loss or a restart:
- utility: consumed tickets, STEKs, command sequences, the command queue, registry and zone keys, kept in
  **SQLite (WAL, `synchronous = FULL`)**;
- device: ticket, command state, intent log, last broadcast sequence per zone and the alert outbox, kept in a
  **log-structured flash record store** with CRC.

Rule P8: every promise is durable **before** it is communicated.

**Master sections:** §16 (all), §9.7, §9.8, §13.6, §13.7, §14.5, §14.7, §10.6, DR-041 (resync hint);
tests S1, S2, S3, S4, V-S1, V-S3, E-P2, E-P3, E-P4.

### 10.1 Utility database (SQLite WAL, `synchronous = FULL`, file mode 0600)

| Table | Written | Transaction rule |
|---|---|---|
| `utility_epoch(last_epoch)` | once per start | committed before any command is issued |
| `device_seq(device_id PK, counter)` + `commands(device_id, cmd_seq, topic, body, sig, expires_at, idempotent, status, sends, last_sid)` | per command | sequence and queued command in **one** transaction, before sending (§16) |
| `used_tickets(ticket_id PK, expires_at)`, indexed on `expires_at` | per resume | one insert, committed **before** RS is built (I-8); expired rows pruned |
| `stek(kid PK, key, created_at, retire_at)` | per rotation | committed **before** the first ticket is sealed under it |
| `registry(device_id PK, dclass, e2e_pk, active, max_packet)` | provisioning, revocation | one statement |
| `zones(name PK, aead, key_epoch, key)`, `zone_members(name, device_id)` | membership change, rotation | membership and new key in one transaction |

Sessions, half-open handshakes and the duplicate cache stay in RAM (§4.4: recoverable through resync + PASR).

### 10.2 Device flash record store

- Record: `type(1) ‖ key_len(1) ‖ key ‖ wseq(8) ‖ len(2) ‖ payload ‖ CRC32(4)`. `wseq` is a write counter;
  the newest valid record per (type, key) wins; a record with `len = 0` is a deletion (tombstone).
- Flash model: NOR, 4 KiB pages erased to `0xFF`, and a byte is programmed only if erased. Pages form **two
  banks**. Writes append to the active bank. When it fills, the live records are copied into the other bank
  between a `BANK_HEADER(gen)` and a `COMMIT(gen)` record, and only then is the old bank erased.
- Boot: scan both banks; a record that fails its CRC ends that page's scan (torn write), and writing resumes on
  the next page. Only a bank with a `COMMIT` counts, and the one with the newest `COMMIT` is active. The other
  bank is erased, which finishes or undoes an interrupted compaction. Because nothing is ever merged across
  banks, no deleted key can come back.

**What the device stores** (one record per step, in P8 order):

| Key | Written | Cleared |
|---|---|---|
| `ticket` (ticket_id, blob, psk, expires_at, mode, POLICY_INFO, fw) | on NT, after it verifies | on RS (C9) |
| `rh` (the identical RH bytes, **PSK mode only**) | before the RH is first sent | on RS or on a full handshake (C8) |
| `intent/<cmd_seq>`: PENDING (idempotent, expires_at, command) → APPLIED (carries the new `last_applied` + bitmap) | before actuation / after actuation | compaction drops APPLIED intents except the newest (it holds the command state) |
| `zone/<name>` last accepted `bseq` | when an event is accepted (DR-048) | never |
| `outbox/<alert_id>` (topic, payload, kind) | when an alert is queued | on its end-to-end ACK |

### 10.3 Other parts

- **Outbox** (§16): bounded by the class `outbox_cap`. When full: merge queued alerts of the same `kind`
  (keep the newest), then drop the oldest, and count the drops. The count is itself sent as an alert
  (`DROPPED:<n>`). Every queued alert rides in the next DF.
- **Resync hint** (DR-041): the device drops its session and resumes on `0x07 ‖ sid` for its **current** sid,
  at most once per 30 s. Forging a hint costs one resume.
- **Atomic file writes** (§16): write a temporary file, `fsync` it, `rename` it over the target, `fsync` the
  directory; never `open(path, "w")` on the live file.

### 10.4 Clarifications resolved from Master text

| # | Question | Resolution | Where Master settles it |
|---|---|---|---|
| C8 | May the PSK_KEM ephemeral private key go to flash (to resend the identical RH after a reboot)? | **No.** It can recompute the resumed session's keys, so it is kept in RAM only. The stored RH is kept for PSK mode only; a PSK_KEM device that reboots after its RH was processed does a full handshake | §9.7 "a session key is **never** written to flash"; §9.8 "resend the stored identical RH **if it survived**; otherwise full handshake" |
| C9 | Is the flash ticket cleared at RS or at NT? | **At RS.** Otherwise a device that reboots between RS and NT presents a consumed ticket, and the utility raises a false clone alarm (`TicketReusedError`) | §9.8 "Reboot between RS and NT: **no ticket** (single-use), so a full handshake" |

### 10.5 Engineering choices

| # | Choice | Rationale |
|---|---|---|
| E39 | Explicit record key in the flash record (Master's `{type, seq, len, payload, CRC32}` plus `key`) | "Latest record per key" needs a key; `seq` is Master's write sequence |
| E40 | Two banks; a compaction writes `BANK_HEADER`, the live records and `COMMIT`, then erases the old bank; boot trusts only committed banks | Crash-safe compaction without resurrection (tested at every crash point) |
| E41 | Outbox `kind` is supplied by the application (e.g. `TAMPER`, `VOLTAGE_SAG`) | Master's "same alert type" is application-defined; the payload stays opaque |
| E42 | Alert deduplication at the utility stays in RAM, so after a **utility** restart a resent alert can reach the application twice (it carries its `alert_id`) | Master does not list it among the persisted tables (U-4) |
| E43 | `used_tickets` is pruned at most once a minute with an indexed `DELETE … WHERE expires_at <= now` | Constant cost per resume (S4); expired rows are already refused by check 5 |
| E44 | A command body is at most 1,024 bytes (the utility refuses to issue a larger one; a device answers `REJECTED:malformed`) | A PENDING intent, with its body, must fit one flash record |
| E45 | `cmd_seq` is stored as an 8-byte big-endian BLOB | epoch ‖ counter reaches 2⁶³ in January 2038, beyond SQLite's signed INTEGER; BLOB order equals numeric order |
| E46 | `PRAGMA fullfsync = ON` | On macOS, plain `fsync` does not flush the drive, so `synchronous = FULL` alone is not durable there; on Linux it has no effect |
| E47 | A PSK_KEM device writes an "RH in flight" marker, not the RH, before sending; at boot the marker drops the ticket | Its RH cannot be resent (C8), and a rebuilt RH would present a possibly consumed ticket: a false clone alarm |

### 10.6 SECURITY-CRITICAL OPEN DECISION

**OPEN-6: how long may superseded secrets (an old ticket's `psk`) stay in device flash?** Raised and decided
by the team on 2026-09-29 → **DR-049: at most 7 days.** The store compacts whenever a superseded secret record
is older than the 7-day chain cap, and at boot when any superseded secret is present (its age is unknown
after a reboot).

### 10.7 Planned tests

- **Record store:** a property test of random writes and deletes, with a power loss injected at every
  programmed byte and every erase. After reboot the state must equal the state before or after the
  interrupted write, never a mix and never a resurrected key. Also torn records, and an interrupted
  compaction in both directions.
- **Scrub:** DR-049 timing (not before 7 days, done after; done at boot).
- **Utility restarts** with the real database: S1, V-S1, E-P3 (counterfactual: no STEK), E-P4 (consumed
  ticket after a restart), S3 (the writer is killed with SIGKILL at random points and the database still
  opens with no promise lost), S4 (per-resume cost at 100,000 tickets vs 100).
- **Device reboots** with real flash: V-S3 over the flash store (torn intent records included); a reboot
  between RS and NT (full handshake, no false clone alarm); a reboot after the RH was processed (identical RH
  from flash for PSK; full handshake for PSK_KEM).
- **E-P2** end to end: utility restart → resync hint → PSK resume → the unacknowledged alert is resent from
  the outbox inside DF.
- **Outbox:** cap, merge by kind, the drop counter. **Resync:** a forged hint is rate-limited.
- **Atomic file:** a crash before the rename leaves the old file intact.

### 10.8 Slice 4 status ledger (2026-09-29)

Evidence: `.venv/bin/python -m pytest` → **269 passed** (229 before + 40 slice 4; macOS, Python 3.14.7, SQLite with
`F_FULLFSYNC`). `docker run --rm pqgrid-tests` → **269 passed** (Debian trixie, Python 3.13.5, SQLite 3.46.1,
OpenSSL 3.5.7; run 2026-09-29, after Docker Desktop was started). Existing regression: v2.1 `validate.py` in Docker
→ **80/80 as expected** (unchanged).
Ad-hoc mutation check (script outside the repo): 29 persistence rules were removed one at a time; **28 made a test
fail**. The survivor writes the PSK_KEM RH bytes instead of the in-flight marker. It is harmless: the RH holds
only the public ephemeral key, the device still drops the ticket at boot, and the private key (what C8 protects)
never reaches flash, which a test checks directly.

**Bugs found and fixed during testing:**
1. `TicketIssuer` chose its stores with `used or UsedTickets()`. An **empty** SQLite used-ticket set has
   `len() == 0`, so Python treated it as false and silently replaced it with an in-memory set. Consumed tickets
   were then forgotten at the next restart, and a replayed RH was accepted. E-P4 caught it. Fixed with explicit
   `is None` checks in all four places using the pattern; a regression test pins it.
2. On macOS, `synchronous = FULL` uses `fsync`, which does not flush the drive cache (a commit measured
   0.035 ms). `PRAGMA fullfsync = ON` makes a commit a real flush (≈4–5 ms on this laptop) (E46).

| Component | Module | IMPLEMENTED | UNIT-TESTED | INTEGRATION-TESTED | DOCKER-VALIDATED | Evidence |
|---|---|---|---|---|---|---|
| Flash record store | `pqgrid/persistence/flash.py` | ✓ | ✓ | — | ✓ | newest-wins, deletions, torn records, store-full refusal; **6,626 power-loss points** (every programmed byte and erase step of 120 random operations, compactions included), each followed by a second power loss during the reboot: always exactly the state before or after |
| DR-049 scrub | `flash.py` | ✓ | ✓ | — | ✓ | old psk still present before 7 days, erased at 7 days, erased at boot, and without writes (`maybe_scrub`) |
| Device state (ticket, RH, command state, zones) | `pqgrid/persistence/device.py`, `e2e/handshake.py` | ✓ | ✓ | — | ✓ | reboot keeps `last_applied`, bitmap, PENDING intents and zone sequences; two records per command (§16); C8 (the ephemeral key is never in flash); C9 (reboot between RS and NT: full handshake, no alarm); S5 (identical RH after a reboot); E47 |
| Crash-safe commands over flash | `commands/device.py` + flash | ✓ | ✓ | — | ✓ | **V-S3: power cut at each of the 145 flash operations** of processing a command, for idempotent and non-idempotent: never applied twice, OK/DUP only when APPLIED is durable, INTERRUPTED when unknown |
| Outbox | `pqgrid/persistence/device.py` | ✓ | ✓ | — | ✓ | kept across reboot until ACKed; merge by kind; drop oldest; `DROPPED:<n>` sent as an alert with a new alert_id on each change; DF order ↔ ACK mapping |
| Utility database | `pqgrid/persistence/utility_db.py` | ✓ | ✓ | — | ✓ | WAL + FULL + fullfsync verified; file 0600; STEK durable before use and deleted on retirement; used tickets, epoch, queue, registry and revocation survive restart; sequence + queue roll back together; cmd_seq ordering past 2038 (E45) |
| Restarts end to end | — | ✓ | ✓ | — | ✓ | E-P4, E-P3 (lost database → every ticket "not authentic"), S1 and V-S1 (restore from backup) with the real database, E-P2 (restart → resync hint → resume → the outbox alert rides in DF), DR-048 over device reboot and utility restart with zones reloaded |
| Resync hint (DR-041, U-6) | `e2e/handshake.py` | ✓ | ✓ | — | ✓ | bound to the live sid; 30 s limit at the device and at the utility |
| S3 process crash | — | — | ✓ | — | ✓ | the writer is killed with SIGKILL after 1, 37 and 211 promises; the database passes `integrity_check`, every announced ticket stays consumed and every announced command stays queued |
| S4 cost | — | — | ✓ | — | ✓ | per-resume median ≈ 4–5 ms at both 100 and 100,000 outstanding tickets on the laptop with a real flush; in the container 0.51 ms at 100 and 0.08 ms at 100,000 (no growth; v2.1: 41.9 ms and a 4.8 MB rewrite). The container's fsync lands in Docker Desktop's VM disk, so its figure shows the trend, not durable-storage latency |
| Atomic file write | `pqgrid/persistence/atomic.py` | ✓ | ✓ | — | ✓ | a crash before the rename keeps the old file and leaves no temporary |

**Honest limits:**
- S3 is a **process** crash (SIGKILL), not a power cut. Power-cut durability of the utility database relies on
  SQLite's fsync-per-commit guarantee, which a laptop or container test cannot re-prove. The device store is our
  own code and is tested at every simulated power-loss point.
- FlashSim models NOR semantics (erase to 0xFF, program-once bytes, partial erase in 256-byte steps), not a
  specific part's datasheet. Real wear and erase timing are **[HW]** work.
- After a **utility** restart a resent alert can reach the application twice (E42).

**Not done in slice 4:** MQTT/TLS transport and broker persistence settings (slice 5); FOTA staging, committed
versions and anchors (slice 6). SIMULATED and HARDWARE-VALIDATED: no.

---

## 11. Slice 5: Transport (MQTT 5 over hybrid TLS 1.3)

**What it is.** Everything from slices 1–4 runs over a real Mosquitto broker for the first time. The link is
TLS 1.3 pinned to `X25519MLKEM768` (hybrid), with ECDSA P-256 certificates, an ACL compiled from the policy and
registry, persistent MQTT sessions, per-class packet limits, and back-off. The device side also gets
certificate-time independence and clock recovery. This is the first slice that can be **INTEGRATION-TESTED**.
The tests run only inside the Docker test image, where the broker lives; nothing is installed on the Mac.

**Master sections:** §8 (all), §10 (all), §4.5, DR-041, §27.1 (configuration validator); tests N3, N4, N5,
N6, T1, T2, T4, T7, A12, E-P2 and I1 (the integrated lifecycle).

**Verified before planning** [DOCKER, OpenSSL 3.5.7, Mosquitto 2.0.21, Python 3.13.5]:
- Python's `ssl` can skip certificate time checks (`X509_V_FLAG_NO_CHECK_TIME`) while still verifying the
  chain and the hostname; a strict context refuses the same future-dated broker certificate;
- a broker pinned to hybrid groups negotiates `X25519MLKEM768`, refuses a classical-only client (`no suitable
  key share`) and a TLS 1.2 client (`protocol version`);
- a device certificate with `notAfter 99991231235959Z` is accepted;
- Python's `ssl` offers **no** API to choose TLS 1.3 groups or cipher suites. Hybrid is therefore enforced at the
  broker (the pin), and the negotiated group is evidenced with `openssl s_client`.

### 11.1 Components

| Component | Module | Content |
|---|---|---|
| PKI | `pqgrid/mqtt/pki.py` | ECDSA P-256 CA; broker certificate with SAN and a normal lifetime; device certificates with CN = device ID and `notAfter 99991231235959Z`; utility certificate (§8.5) |
| TLS contexts | `pqgrid/mqtt/tls.py` | Device: TLS 1.3 only, pinned CA set {current, next}, **no validity-time checks**, hostname checked (§8.8). Utility: TLS 1.3, full checks |
| Broker config | `pqgrid/mqtt/broker.py` | Renders `mosquitto.conf` and the OpenSSL group pin; a **validator** (§27.1): every listener `tls_version tlsv1.3`, `require_certificate true`, `use_identity_as_username true`; `allow_anonymous false`, `persistence true`, `max_packet_size 300000` |
| ACL compiler | `pqgrid/mqtt/broker.py` | One block per active device (own topics only, §10.1), zone read rights from membership, least-privilege utility block; written atomically, then SIGHUP |
| Device node | `pqgrid/mqtt/device_node.py` | MQTT 5 client: `clean_start = false`, Session Expiry, Maximum Packet Size and keep-alive from the class, Last Will `status = offline`. Runs full handshake or resume with **identical** retransmission, falling back to a full handshake. Also: outbox in DF, live alerts, control and DR handling, status ACKs, resync, time floor, back-off |
| Utility node | `pqgrid/mqtt/utility_node.py` | Handshake replies, alert and status handling, resync hints, command and zone-key delivery after each (re)establishment, DR events, and a refusal to publish anything larger than the device's `max_packet` (§10.2) |

### 11.2 Topic use (C10: resolved from §10.1 without adding any ACL right)

Master's §10.1 table does not say which topic carries the ACKs and the resync hint. Each goes on an **existing**
topic whose publisher and direction already match, so no party gains a right:

| Message | Topic | Direction (as in §10.1) |
|---|---|---|
| CH, RH, DF | `pqgrid/hs/{id}/up` | device → utility |
| SH, RS, NT/FIN, resync hint `0x07` | `pqgrid/hs/{id}/down` | utility → device |
| ALERT `0x02`, status ACK `0x06`, ZONESYNC `0x08` (E-2, final remediation) | `grid/{class}/{id}/alert` | device → utility |
| CONTROL `0x03`, ALERT ACK `0x05` | `grid/{class}/{id}/control` | utility → device |
| DR event `0x04` | `grid/dr/{zone}/{group}/event` (M7; also re-sent on the member's control topic, M4) | utility → members |

Receivers dispatch on the first byte (envelope tag) and still enforce the tier from their own policy. ACKs are
MAC-authenticated and carry no application data.

### 11.3 Engineering choices

| # | Choice | Rationale |
|---|---|---|
| E48 | Only the utility publishes on `hs/{id}/down`, `control` and `dr` topics. Its ACL block lists exactly the patterns of §10.1, not v2.1's `readwrite #` | Least privilege (G7) |
| E49 | A refused handshake is not answered (G-1): the device times out, retransmits the **identical** CH/RH, and falls back to a full handshake | No new message type; Master allows only "refused" or a hint externally |
| E50 | The time floor is a flash record, written after the first authenticated time following boot and at most once a day; at boot the clock starts from max(RTC, floor) | §8.9 |
| E51 | Back-off `random(0, min(cap, base·2^attempt))` with the class `backoff_base_s`/`backoff_cap_s` on every reconnect | §10.5 full jitter |
| E52 | Each device publishes `online` on its status topic after every CONNACK; the utility raises a takeover (clone) alarm at 5 connects within 10 minutes. Devices do their own jittered reconnects (paho's automatic reconnect is off) | §10.4 "alarms on repeated takeovers". **Revised during testing:** Mosquitto 2.0.21 does not publish the Last Will of a session that is taken over [DOCKER], so counting Wills (the first plan) cannot see a clone. paho's own reconnect backs off without jitter, which §10.5 forbids |
| E53 | The per-class TLS cipher suite (§8.4) is a device-TLS-stack property: Python cannot restrict TLS 1.3 suites. The broker's acceptance of both suites is shown with `s_client`; the Python device uses the default | Harness limit, stated rather than simulated |
| E54 | Telemetry uses QoS 1 (the policy has no per-class QoS field); `max_queued_messages` is set explicitly to 1,000 per client and required by the config validator (release audit L-7; sizing in Master §27.1 B-6; the same number Mosquitto 2.0 uses when the option is absent) | Correctness never depends on the queue: E2E redelivery covers drops (§10.4) |
| E55 | **Replaced 2026-09-29 (remediation M5, §13.2).** Was: a device keeps DR events that arrive before their zone key (up to 16, RAM, overflow silent) and retries them. Now: no buffer; such an event is refused with a recorded reason and the utility re-sends every still-valid event after the ZONEKEY | Found while planning: with persistent sessions the broker delivers a rebooted device's queue at CONNACK, before the new session's ZONEKEY. Without this, DR-048's "queued events are still delivered" fails over a real broker |
| E56 | A GRANT's default `not_before` is 60 s before issue | Found in integration: the device's clock (set from SH/RS time in whole seconds) lags the utility by up to one message transit plus 1 s, so a GRANT starting "now" was refused for its first second. Authority still starts when the GRANT is signed |

### 11.4 SECURITY-CRITICAL OPEN DECISIONS

**None found.** §8 and §10 specify the TLS version, the group pin, certificate lifetimes, time handling, the ACL
rules, sessions, packet limits and back-off. The ACK/hint topic use (C10) adds no right. Two items are
**deferred rather than open**:
- the ACL compiler's check of the **policy signature** needs the signed wrapper (the FOTA manifest, slice 6;
  E13);
- the retained-artifact rules (retention window, republish request) belong to FOTA.

### 11.5 Planned integration tests (Docker only; skipped elsewhere with the reason stated)

- **I1 lifecycle over the broker:** full handshake with an outbox alert in DF; live ALERT + ACK; CMD + status;
  GRANT + SETPOINT; ZONEKEY + DR event; disconnect and 1-RTT resume; a CMD queued in the **persistent session**
  while the device is offline; telemetry.
- **Utility restart** (E-P2 over MQTT): the database survives, sessions do not; the resync hint arrives on
  `hs/down`; the device resumes; its unacknowledged alert and command are delivered.
- **Broker restart** (N5): persistent session and queued QoS 1 CONTROL survive with `persistence true`.
- **N3 / T7:** classical-only and TLS 1.2 clients refused; `s_client` shows `X25519MLKEM768` and both cipher suites.
- **T4:** a strict context refuses a future-dated broker certificate; the device context connects; the broker
  accepts a 9999 device certificate and refuses an expired one.
- **A12 / ACL:** publish and subscribe to another device's topics are **not delivered** (delivery checked,
  not SUBACK); revocation → recompile → SIGHUP → the revoked device's next publish is not delivered.
- **N4:** a second connection with the same identity takes over; repeated takeovers raise the alarm.
- **N6 / T1:** a publish larger than the device's Maximum Packet Size is never delivered, so the utility refuses
  to send it.
- **T2:** the TLS hop resumes with a session ticket.
- **Config validator:** a listener without `tls_version tlsv1.3`, or `persistence false`, is rejected.
- **Unit tests** (everywhere): back-off bounds and jitter, time floor, topic dispatch, ACL text.

### 11.6 Slice 5 status ledger (2026-09-29)

Evidence:
- `.venv/bin/python -m pytest` → **278 passed, 13 skipped** (macOS). The 13 skipped are the broker tests, skipped
  with the reason "needs Mosquitto and OpenSSL ≥ 3.5: runs in the Docker test image"; nothing was installed on
  the Mac.
- `docker run --rm pqgrid-tests` → **291 passed**, none skipped (Debian trixie, Python 3.13.5, OpenSSL 3.5.7,
  Mosquitto 2.0.21, paho-mqtt 2.1.0).
- The 13 integration tests passed on **5 further repeat runs**, with no timing flakiness observed.
- Existing regression: v2.1 `validate.py` → **80/80 as expected**.
- Ad-hoc mutation check, run inside the container with the script on stdin (no mounts): 28 transport rules were
  removed one at a time. The first run caught 27. The survivor ("resend the identical CH/RH once") exposed a test
  gap: no test ever lost a reply. A lost-reply test was added, and the rerun caught it: **28/28**.

**Found and fixed during this slice:**
1. SQLite was used from paho's network thread (`ProgrammingError`). The database now has one lock around every
   statement and transaction, so sharing the connection across threads is safe.
2. **Mosquitto 2.0.21 does not publish the Last Will of a session that is taken over** [DOCKER, broker log shows
   "already connected, closing old connection" and no Will]. The planned clone detection (E52) could not work.
   Devices now announce `online` after each connect, and the utility alarms on 5 connects within 10 minutes.
3. paho's automatic reconnect backs off without jitter, against §10.5. Devices now reconnect themselves with
   full jitter.
4. The device's clock lags the utility by up to one transit plus 1 s, so a GRANT starting "now" could be refused
   for its first second (seen as an intermittent failure). E56 adds 60 s of `not_before` slack, pinned by a
   deterministic test.
5. Found while planning: a rebooted device receives its queued DR events before its new ZONEKEY. E55 held them
   in RAM and retried them (replaced in the remediation by the utility's re-send, §13.2).

| Component | Module | IMPLEMENTED | UNIT-TESTED | INTEGRATION-TESTED | DOCKER-VALIDATED | Evidence |
|---|---|---|---|---|---|---|
| Hybrid TLS 1.3 pin | `mqtt/broker.py`, `mqtt/tls.py` | ✓ | ✓ | ✓ | ✓ | N3: `s_client` shows `X25519MLKEM768`; a classical-only client is refused; T7: TLS 1.2 is refused; both class cipher suites are accepted (E53) |
| Certificate time (§8.8) | `mqtt/tls.py`, `mqtt/pki.py` | ✓ | — | ✓ | ✓ | T4: a strict context refuses a future-dated broker certificate; the device context connects; a rogue CA is refused; an expired device certificate is refused by the broker; 9999 device certificates are accepted throughout |
| Config validator (§27.1) | `mqtt/broker.py` | ✓ | ✓ | ✓ | ✓ | 7 violations refused (TLS 1.2, persistence off, anonymous, no client certificate, no identity-as-user, packet size, plaintext listener); the test broker runs on the rendered config |
| ACL compiler + reload | `mqtt/broker.py` | ✓ | ✓ | ✓ | ✓ | A12: another device's control, telemetry and handshake topics are not delivered (delivery checked); revocation → recompile → SIGHUP → the next publish is not delivered; zone read rights follow membership |
| Device node | `mqtt/device_node.py` | ✓ | ✓ | ✓ | ✓ | I1; persistent session (no SUBSCRIBE on wake, queued CMD delivered); identical retransmission after a lost SH; refused resume → full handshake (E49); T2 TLS resumption; E55 (replaced by M5, §13) |
| Utility node | `mqtt/utility_node.py` | ✓ | ✓ | ✓ | ✓ | handshake replies, redelivery and zone keys after DF, alert ACKs, resync hint after a restart (E-P2), status ACKs; N6/T1: an over-limit publish is silently dropped by the broker, so the utility refuses it |
| Takeover alarm | both nodes | ✓ | — | ✓ | ✓ | N4: repeated takeovers (broker log confirms) raise the alarm |
| Restarts | — | — | — | ✓ | ✓ | utility restart (database kept, resync, resume, outbox alert, new command); broker restart (N5: persistent session and queued QoS 1 CMD survive) |
| Back-off, time floor | `mqtt/topics.py`, persistence | ✓ | ✓ | — | ✓ | full-jitter bounds and mean; time floor starts the clock after a 1970 reset; written after the first authenticated time and then at most daily |

**Honest limits:**
- Everything ran on **loopback inside one container**: no radio link, NAT, packet loss (other than injected) or
  real latency. Link-level timing remains the v2.1 [DOCKER T5] and [SIM T6] evidence; no new latency or bandwidth
  figure is claimed here.
- The device side is Python, not an MCU TLS stack. It cannot restrict TLS 1.3 groups or suites (E53): hybrid is
  enforced by the broker pin and shown with `s_client`. A device-side TLS stack (wolfSSL-class) is **[HW]**.
- ~~The ACL compiler does not yet verify the policy **signature**, and the FOTA topic rights are not yet compiled:
  both arrive with slice 6 (E13).~~ Done in slice 6 (`compile_acl` verifies the signed POLICY artifact).
- The takeover threshold (5 connects in 10 minutes) is a heuristic that signals "investigate", not proof of a
  clone.

SIMULATED and HARDWARE-VALIDATED: no.

---

## 12. Slice 6: PQC-FOTA (Objective 2)

**What it is.** Firmware, policies and key revocations travel as **artifacts**, signed offline with
SLH-DSA-SHA2-128s:
- the device checks the signature, then every chunk against a Merkle root the signature covers, then the whole
  payload's hash;
- it never accepts an older or equal version;
- it keeps two slots, so a firmware that fails to boot is reverted;
- two independent anchors let a stolen station key be revoked.

The policy finally gets its signed wrapper: it is a POLICY artifact, and the ACL compiler and the utility install
it only after verifying it (closing E13).

**Master sections:** §15 (all), §12 Signed Policy / Distribution / Updates, §10.1–§10.3 (FOTA topics, packet
limits, retained artifacts), §16 (protected storage); tests F1–F7, E-F1–E-F4, V-F1–V-F5, KEYREVOKE crash, P5/P10
after an activation.

### 12.1 Components

| Component | Module | Content |
|---|---|---|
| Merkle tree | `pqgrid/fota/merkle.py` | RFC 6962 hashing (leaf `0x00`, node `0x01`), audit paths, RFC 9162 §2.1.3.2 verification |
| Artifact codec | `pqgrid/fota/artifact.py` | Manifest `"PQFW2"` with the §15.2 fields; signed form `enc[manifest, σ]`; parts `enc["MP", type, version, index, total, bytes]`; chunks `enc[type, version, index, data, path]` |
| Station | `pqgrid/fota/station.py` | Offline signer with anchors **A** (id 0, releases) and **B** (id 1, recovery) via the OpenSSL CLI; builds per-class artifacts (parts sized for the class `max_packet`, chunks of the class `fota_chunk_size`) |
| Installer (device) | `pqgrid/fota/installer.py` | Parts into a staging area; signature (non-revoked anchor) → magic, class, limits (payload ≤ **own slot**, V-F5) → `version > committed[type]`; chunks verified and written to the inactive slot with a durable bitmap (resume after power loss); length and SHA-256 → staged. FIRMWARE: boot → self-test → commit, or revert. POLICY: validate (rules 1–10) → activate at `activate_at` → commit. KEYREVOKE: §15.14 |
| Protected storage | `installer.py` | `committed[type]` and the anchor revocation state as one atomic record in a **separate** record store that a factory reset does not erase (§15.11) |
| Publisher (utility) | `pqgrid/fota/publisher.py` | Retained parts and chunks on `pqgrid/fota/{class}/{type}/{version}/manifest/{i}` and `…/chunk/{i}`, each checked against the class `max_packet`; cleanup after the retention window; rate-limited republish on `pqgrid/fota/{class}/request/{id}` |
| Signed policy | `publisher.py`, `mqtt/broker.py` | The utility and the ACL compiler accept a policy only from a verified POLICY artifact |
| Device FOTA over MQTT | `pqgrid/mqtt/device_node.py` | Subscribes to its class's manifests, fetches the newest version per type, installs it, and survives a reboot mid-download |

### 12.2 Engineering choices

| # | Choice | Rationale |
|---|---|---|
| E57 | A POLICY manifest's `version` and `activate_at` must equal the policy's own `version` and `activate_at` | One version number per policy; a newer manifest cannot carry an older policy |
| E58 | KEYREVOKE payload = `enc[u8 revoked_anchor_id]` | Master names the artifact, not its payload; the payload hash is signed |
| E59 | An artifact whose signer anchor is revoked is refused at the manifest, **and again at commit** (a staged A-signed image does not commit after KEYREVOKE(A)) | V-F2, including the in-flight case |
| E60 | FIRMWARE reboots into the new slot only once authenticated time ≥ `activate_at` | "Activation windows" (§13.1); device time never comes from the broker |
| E61 | The manifest is refused before any download if `chunk_size` + the proof bound + headers exceed the device's `max_packet`, if `chunk_count ≠ ⌈payload_length / chunk_size⌉`, or if a proof is longer than ⌈log₂ chunk_count⌉ | Refuse early (§15.8); no unbounded parsing |
| E62 | A republish request carries nothing but the requester (its own topic); the utility re-publishes the class's newest artifacts at most once per hour per device | ACL-scoped and rate-limited (§15.8) |
| E63 | Slots, the staging area and protected storage are simulated (as FlashSim in slice 4); the bootloader's swap and the external-slot re-hash are modelled, not measured | V-F4 and swap power-safety are **[HW]** |

### 12.3 SECURITY-CRITICAL OPEN DECISION

**OPEN-7: who may revoke whom?** Raised and decided by the team on 2026-09-29 → **DR-050: only the recovery
anchor B (id 1) may revoke the release anchor A (id 0); A can never revoke B.** The device also refuses to
revoke its last active anchor (§15.14). With two anchors and DR-050, that rule is implied.

### 12.4 Slice 6 status ledger (2026-09-29)

Evidence:
- `.venv/bin/python -m pytest` → **352 passed, 20 skipped** (macOS; the 20 are the broker tests, skipped with the
  stated reason).
- `docker run --rm pqgrid-tests` → **372 passed**, none skipped (Debian trixie, Python 3.13.5, OpenSSL 3.5.7,
  Mosquitto 2.0.21).
- The 20 broker tests passed on **5 further repeat runs**.
- Existing regression: v2.1 `validate.py` → **80/80 as expected**.
- Mutation check inside the container: 26 FOTA rules removed one at a time. The first run caught 25. The
  survivor (the device's re-subscription to its download's chunks after a reboot) exposed a missing scenario:
  chunks acknowledged by MQTT but lost before reaching flash. A test for it was added, and the rerun caught the
  survivor: **26/26**.
- The Merkle tree reproduces the **Certificate Transparency reference roots** for 1–8 leaves exactly.

**Bugs found and fixed during testing:**
1. **An interrupted KEYREVOKE stayed stuck.** If power failed while the revocation was written to protected
   storage, the artifact stayed "staged", and every redelivery was ignored as "already in progress", so the
   revoked anchor stayed trusted. The installer now finishes a staged KEYREVOKE at boot. The power-loss test at
   every protected-storage step now requires "revoked after the next boot".
2. **After the 30-day cleanup the publisher forgot the artifact**, so a device offline longer than the window got
   nothing when it asked for a republish. The unit test had encoded the wrong behaviour. Retained copies are now
   removed while the newest artifact per class and type is kept for republishing.

| Component | Module | IMPLEMENTED | UNIT-TESTED | INTEGRATION-TESTED | DOCKER-VALIDATED | Evidence |
|---|---|---|---|---|---|---|
| Merkle tree | `fota/merkle.py` | ✓ | ✓ | ✓ | ✓ | CT reference roots (1–8 leaves); every leaf of 36 tree sizes verifies; tampered data, wrong position, shortened or lengthened proof, other root: refused |
| Artifact codec + station | `fota/artifact.py`, `fota/station.py` | ✓ | ✓ | ✓ | ✓ | real SLH-DSA-SHA2-128s signatures; signed manifest **8,031 B** (Master estimate 8,042 B), 3 parts at 4,096 B, 1 at 8,192 B |
| Installer checks | `fota/installer.py` | ✓ | ✓ | ✓ | ✓ | F1, F2, F3, F4, F5, F6 (E-F4 path), F7, V-F5 (before any download), E61, E-F3; 900 fuzzed parts, chunks and signed manifests refused |
| A/B slots, commit, revert | `fota/installer.py` | ✓ | ✓ | ✓ | ✓ | V-F1; E-F2 (revert, counter unchanged, same version retried, rollback still blocked); E60; V-F4 **model** (bootloader re-hash); factory reset keeps the counters |
| Power loss | `fota/installer.py` | ✓ | ✓ | ✓ | ✓ | E-F1 at a bitmap write and over MQTT (reboot mid-download; chunks lost before flash); KEYREVOKE at every protected-storage step |
| Anchors and DR-050 | `fota/installer.py` | ✓ | ✓ | ✓ | ✓ | V-F2 (A-signed refused after the revoke, in-flight A-signed dropped (E59), B-signed installs), V-F3 (KEYREVOKE signed by A refused; B cannot revoke itself) |
| Signed policy | `fota/policy_artifact.py`, `mqtt/broker.py`, installer | ✓ | ✓ | ✓ | ✓ | installed ahead of activation, activated at `activate_at`; E57; a validly signed but unsafe policy is refused by the validator; the utility and the ACL compiler accept only a verified artifact (E13 closed); after activation, P10 at the utility and P5 on the device, then a full handshake under the new policy |
| Publisher | `fota/publisher.py` | ✓ | ✓ | ✓ | ✓ | every message fits the class `max_packet` (oversize refused); retained; older version cleared; retention cleanup; republish request, rate-limited |
| FOTA over MQTT | `mqtt/device_node.py`, `mqtt/utility_node.py` | ✓ | — | ✓ | ✓ | firmware to a 4 KiB device; reboot resume; republish after cleanup; policy rollout; KEYREVOKE; a captured device cannot publish artifacts (ACL) |

**Honest limits:**
- The slots, staging area and protected storage are **simulated** (FotaFlash, FlashSim). The bootloader's
  swap power-safety, the external-slot tamper (V-F4 beyond the model), watchdog budgets during verification and
  device verify timing are **[HW]**. Device verify cost remains [LIT pqm4].
- The Python device verifies the manifest from RAM. Master's "verify from the flash staging area" is a device
  memory property.
- The station's keys are generated per test run; custody and HSM operation are out of prototype scope (§2.4).
- Retention was tested by moving the publisher's clock, not by waiting 30 days.
- Not implemented: the stretch-goal freshness heartbeat (§15.1), which is marked optional in Master.

SIMULATED and HARDWARE-VALIDATED: no.

### 12.5 Master size tables updated (2026-09-29, approved by the team)

Every size that the v2.2 code measures (and the tests pin) now appears in Master with the label `[DOCKER, v2.2 code]`,
with the earlier v2.1 bench figure or hand estimate kept alongside:
- E2E full / PSK / PSK+KEM: 5,221 / 761 / 3,097 B;
- CMD / GRANT / SETPOINT / ZONEKEY: 3,466 / 3,477 / 97 / 138 B;
- signed manifest: 8,031 B;
- DF alone / with one ALERT: 46 / 193 B;
- PSK byte saving: 85% (was 86%).

Figures **not** re-measured keep their original labels: laptop compute times (v2.1 bench), T5/T6 link figures, and
the per-day and airtime tables (§13.3, §22.6). Each of those has a note: they move by under 1%, except the
GRANT + SETPOINT daily bytes, about +2% because SETPOINT is 97 B rather than 93 B. A copy of Master from before
this edit was kept in the session scratchpad.

---

## 13. Remediation after the read-only audit (2026-09-29)

A read-only correctness/security audit of slices 1–6 found real defects (H1–H4, M1–M9), weak tests and
self-referential oracles. They were fixed under the eight finalized clarifications (Master Appendix F). Every
change below is backed by a test that fails without it: each fix was mutation-checked (the fix removed, one at a
time, with a clean baseline first). Evidence labels: [SIM] = in-process with the FlashSim power-loss model,
[DOCKER] = the real Mosquitto 2.x broker with hybrid TLS 1.3 in the test container. Nothing is [HW].

### 13.1 High and medium defects

| # | Issue | Root cause | Code changed | Test added / changed | Result |
|---|---|---|---|---|---|
| H1 | A revoked device kept its live session: ALERTs, status ACKs and commands still worked; it stayed in its zones | Revocation only changed the registry; sessions, zones and the utility paths did not consult it | `UtilityEndpoint.revoke_device` (durable, then sessions and half-open closed), `active()` checked in `open_alert` and `CommandService.on_status`/`_topic`; `ZoneManager.remove_device` (rotate); `UtilityMqtt.revoke_device` (keys to remaining members, then `acl_hook`) | `tests/security/test_revocation.py` (4); `test_H1_live_revocation_over_the_broker_without_any_acl_change` | Refused everywhere at the E2E layer with no ACL change [SIM, DOCKER] |
| H2 | ~41 (or ~4 max-size) interrupted commands filled the flash bank and bricked the command path | One growing intent-log record; terminal INTERRUPTED entries never reclaimed | `FlashCommandState`: one record per intent, deleted after APPLIED; boot reconciliation; reclamation (newer applied, or expiry + session_expiry + dup_window); `MAX_INTENTS = 32` with explicit `REJECTED:capacity` | `tests/security/test_command_persistence.py` (5): 300 interrupted max-size commands, capacity + reclaim, page-full with reboots, power cut at every 3rd flash op while compacting (idempotent and not) | Bounded; never actuated twice; OK only after APPLIED is durable [SIM]. Three flash writes per command (was two) |
| H3 | An ACK before any session raised AttributeError and killed paho's network thread | Unguarded callbacks | `mqtt/guard.py` (`guarded`: expected refusals logged, anything else an internal alarm with type + code locations, no message text); session-less ACK is an explicit refusal | `test_H3_device_network_loop_survives_callback_faults` | Loop survives; second command OK; reconnect works [DOCKER] |
| H4 | B-signed ordinary releases were accepted while A was active | Only KEYREVOKE's signer was checked | `fota/artifact.py` `check_signer`/`release_anchor`, applied at accept, firmware boot, policy activation and in `verify_policy_artifact` | `tests/security/test_anchor_lifecycle.py` (4) + existing F/V-F tests | Clarification 8 enforced [SIM, DOCKER] |
| M1 | A policy activated between SH and DF produced an old-policy session with its bundle opened and a ticket | No policy check at DF | `on_finished` refuses after MAC_D (nothing installed, bundle unopened, no ticket); `UtilityEndpoint.install_policy` closes old sessions; `current_session` gates commands, zone keys and status | `tests/security/test_policy_race.py` (3); `test_M1_policy_activated_between_SH_and_DF_over_the_broker` | [SIM, DOCKER] |
| M2 | `chain_expires` was never enforced on live sessions | Only checked when redeeming a ticket | `end_expired_chain` on both sides; utility paths refuse and remove; resync hint; DF refused if the chain ended after RS | `tests/security/test_chain_expiry.py` (5): boundary −1/0, resumed and full, fresh handshake starts a new chain, lagging device clock recovers | [SIM]. Interpretation E-1 (Master Appendix F) |
| M3 | `maybe_scrub` had no production caller; age measured on the raw RTC | Scrub only on write/boot | `DeviceFlash.bind_clock` (authenticated device time), `maintenance()` after SH/RS and in the device loop | `tests/security/test_secret_scrub.py` (6): no-write week, stopped RTC + authenticated advance, boot after 30 days, resumes do not erase, power cut at every step of the scrub (and of the boot scrub) | [SIM] |
| M4 | An event queued under an old key epoch was lost after a rotation and reboot | Nothing re-sent it; the old key was gone | `ZoneManager` retains still-valid logical events (SQLite `zone_events`), `resend_for` re-encrypts under the current group key after establishment, bseq order, join point respected | `tests/security/test_zones_logical.py` M4 tests (4); `test_M4_rotation_while_down_then_reboot_over_the_broker` | [SIM, DOCKER] |
| M5 | E55 RAM buffer: 16 entries, silent overflow, lost on reboot | Chosen as a transport workaround | Buffer removed; `dr_refused` records every refusal; re-send (M4) delivers; re-sent duplicates counted (`dr_duplicates`) | `test_device_reboot_after_outage_gets_queued_dr_event` (rewritten), `test_M5_live_rotation_then_event_needs_no_buffer_over_the_broker` (5 rotations) | [DOCKER]; cross-topic order is broker behaviour (E-2) |
| M6 | Expiry was checked before supersession | DR-046 as written | `_command` order per clarification 3 | `test_clarification3_supersession_is_checked_before_expiry` | [SIM] |
| M7 | No logical zone: a mixed feeder had to be two zones with two identities and bseqs | DR-047 as decided | Logical `Zone` with per-AEAD `GroupKey`s, per-group topics and ACL, σ over the logical event (`pqgrid/v2/bcast`), `group` in the envelope and AAD, device keys per (zone, group), bseq per logical zone | `tests/security/test_zones_logical.py` M7 tests (3); `test_M7_aes_and_chacha_members_get_one_logical_event_over_the_broker`; `test_control.py` zone tests updated | [SIM, DOCKER]. DR event 3,488 B (hand-derived, pinned) |
| M8 | A database error in a utility callback killed its network thread | Unguarded callbacks | Same guard as H3 on the utility | `test_M8_utility_network_loop_survives_a_database_failure` | [DOCKER] |
| M9 | Reconnect, policy activation, firmware commit, republish, cleanup, rotation, ACL update had no production caller | No main loops | `DeviceMqtt.run/tick/housekeeping`, `UtilityMqtt.run/tick/schedule_policy`, `install_firmware`, `rotate_due`/`rotate_all`, `sweep`, `flush` (graceful `stop`) | `tests/integration/test_orchestration.py` (5): loops run in threads over the broker; 10 wiring mutations: 9 caught, the 10th targeted a redundant condition, which was removed. `tests/unit/test_device_loop.py`: a failed establishment backs off with full jitter (2, 4, 8 s) and resets on success (§10.5) | [DOCKER, SIM] |

### 13.2 Test-quality fixes

| Test | Was | Now |
|---|---|---|
| A12 | slept 1 s, asserted nothing arrived | SUBACK granted (0x01) yet nothing delivered, shown by a later message to the same device; forbidden PUBLISHes get PUBACK 0x87; a barrier from the same client; connection alive [DOCKER, measured] |
| T4 | accepted any `OSError` | broker reachable with a valid certificate; `SSLV3_ALERT_CERTIFICATE_EXPIRED`; one new "certificate verify failed" in the broker log |
| N3 | "handshake failure" **or** "alert" | classical group → alert 40 "handshake failure"; TLS 1.2 → alert 70 "protocol version"; no negotiated protocol |
| F2 | "signature invalid **or** malformed" | exactly `manifest signature invalid`, for a flip in the signature and in a signed field, directly and via parts |
| A5 | checked a locally sealed buffer | the bytes the broker forwarded (captured at the utility) and wrote to `mosquitto.db` for an offline utility contain no plaintext; the destination decrypts both |
| Negative delivery | sleep-then-assert, and sleeps used as synchronisation | PUBACK codes, same-topic ordering, alert-ACK barriers, SUBACK tracking, `UtilityMqtt.flush()`; the ACL reload wait (SIGHUP) remains a precondition sleep in the harness, never the basis of an assertion |
| FOTA mutations | cleared the staging area before the genuine artifact | staging is not cleared; every mutation refused; staging bounded (`MAX_ASSEMBLIES = 4`, LRU); poisoning detected (`manifest signature invalid`) and the genuine artifact installs by its next re-delivery at the latest |

### 13.3 Independent oracles

- **X-Wing KAT:** the first vector of draft-connolly-cfrg-xwing-kem-11 Appendix C (`tests/vectors/`), read
  verbatim from the IETF text; key expansion by `hashlib.shake_256`. Our key loading reproduces the 1,216-byte
  pk and our decapsulation the published shared secret.
- **Byte fixtures** written by hand from the Master layouts: CMD, GRANT, SETPOINT, ZONEKEY, ticket plaintext and
  blob layout (opened with `cryptography`'s ChaCha20-Poly1305 directly), FOTA manifest (167 B), a one-class
  policy and POLICY_INFO; signature inputs recomputed with `hashlib` (`tests/unit/test_vectors.py`).
- **Sizes:** the DR event (3,488 B) and the manifest (167 B) are hand-derived in the tests.

### 13.4 Hygiene

`repr=False` on `Session.k_master`, `MasterKeys`, `_Pending.kc_d` (all secret fields now hidden, tested);
`EVP_MD_CTX_new` NULL → explicit `CryptoError` (fail closed, tested); `_DupCache` bounded by count (4,096);
`Installer._parts` bounded; node logs bounded (`BoundedLog`, 1,000). Internal alarms carry the exception type and
code locations only.

### 13.5 Production callers (M9 inventory)

Every step M9 listed now runs from a main loop: reconnect with back-off, (re)establishment, policy installation
and activation (both sides), firmware trial boot and commit, firmware-version update, republish request,
publisher cleanup, weekly and policy-change zone rotation, ACL recompile after revocation and policy
activation, the DR-049 scrub, intent reclamation, chain sweep. Methods with no internal caller **by design**:
the application/operator API (`DeviceMqtt.send_alert`, `send_telemetry`; `UtilityMqtt.command`, `grant`,
`setpoint`, `join_zone`, `revoke_device`, `publish_artifact`, `schedule_policy`, `dr_event`;
`ZoneManager.create`, `rotate`) and diagnostics (`DeviceMqtt.tls_resumed`).

### 13.6 Final remediation pass (2026-09-30)

The remaining items of the audit, each fixed, tested and mutation-checked (the fix removed one at a time, with a
clean baseline first).

| Item | Root cause | Fix | Tests | Result |
|---|---|---|---|---|
| Device flash capacity | The outbox charged 24 B per entry while its flash record costs 40 B; no start-up check; unbounded pending bodies, zones per device, chunk count, alert size | True-bytes outbox; `budget()` of every coexisting record at its largest; `require_capacity()` at start-up and before a policy is committed (`CapacityError`); at most one PENDING body (an older one becomes INTERRUPTED, E37); ≤ 16 zones (utility and device), ≤ 1,024 chunks, alert ≤ 1,024 B / kind ≤ 16 B; simulated store 8 × 4 KiB | `tests/security/test_flash_capacity.py` (10): the worst case built from real records fits item by item; power cut at every step of compacting it, reboot recovers everything; impossible flash refused; a policy needing more refused before commit; each bound; DF size bound | Worst case **7,927 B** measured; budget **10,758 B** (9,678 + 1,080 in flight); a 4-page bank holds **≥ 12,068 B**; two 8 KiB banks (6,034 B) refused [SIM]. 9/9 mutations caught |
| C2 DF with a full outbox (found with the above) | DF carried the whole outbox: > 64 envelopes could not be encoded, and its NT/FIN (69 B per ACK) could exceed the 4 KiB packet limit, so establishment never completed | DF carries `min(64, (max_packet − 420) ÷ 69)` of the oldest entries (**C2: 53**); the rest go live after NT/FIN | Full-outbox and lost-ACK broker tests; DF size bound | 53 alerts → reply **4,008 B** ≤ 4,096; largest C2 DF **6,109 B** (upstream); lost live ACKs → next DF, flagged duplicate [DOCKER]. 2/2 mutations caught |
| Reconnect back-off | `connect_with_backoff` counted attempts per call, so each tick restarted at the base window | `_reconnect_step`: attempt count and next-attempt time kept by the device loop across ticks; jittered wait before every attempt; reset on CONNACK; the loop never sleeps | `test_M9_reconnect_back_off_grows_across_ticks_and_resets_on_success` (production loop, broker stopped/restarted) | Windows 2, 4, 8 … 256, 300 s; ≥ 3 ticks per attempt; back to 2 s after a success [DOCKER]. 3/3 mutations caught (one redundant reset removed) |
| E-2 cross-topic ordering | An event could overtake its new ZONEKEY; recovery waited for the next establishment | ZONESYNC (`0x08`, own key label `key|SYNC|up`, replay guard; ≤ 1 outstanding per zone; utility ≤ 1 per 5 s per device and zone): the current key first, then the still-valid events under it, same σ and bseq | `tests/security/test_zone_sync.py` (4); `test_E2_*` (2) with the key held back | Two overtaking events → one sync, each accepted once, original copy rejected as a replay; expired event not republished [SIM, DOCKER]. 9/9 mutations caught |
| E-3 SETPOINT ACK | "Class interval" undefined | Cumulative OK for the newest SETPOINT every 30 s (inclusive); final ACK at once when its GRANT expires or is replaced; nothing after expiry | `tests/unit/test_setpoint_ack.py` (4); `test_E3_*` through the loop | 29.999 s no, 30.000 s yes; final ACK once [SIM, DOCKER]. 5/5 mutations caught |
| E-4 republish trigger | Depended on the persisted time floor | Device: a stalled verified download (600 s, once per period); utility: newest POLICY on a POLICY_INFO-mismatched CH, newest FIRMWARE newer than the session's and not retained; hourly per device (an empty offer costs nothing); newest valid only (signer not revoked, in role; POLICY not older than active) | `tests/security/test_republish.py` (4); three `test_E4_*` loop tests; retention test updated | Missing valid artifact republished; stale, revoked, superseded never; rate limit [SIM, DOCKER]. 9/9 mutations caught (one test strengthened) |

### 13.7 Validation (final remediation run, 2026-09-30)

| Check | Result |
|---|---|
| Full Docker suite | **464 passed** (Debian trixie, Python 3.13, OpenSSL 3.5, Mosquitto 2.x) |
| Local `.venv` | 423 passed, 41 skipped (the broker tests; they run in Docker) |
| v2.1 `validate.py` in Docker | **80/80 as expected** (CORE 47, EDGE 31, RISK 2) |
| Broker tests, three consecutive runs | 41 / 41 / 41 passed |
| Groups (FOTA fuzz and labels, crash/reboot, duplicates, lifecycle, DR-048, DR-050, policy race, revocation, interrupted commands, callback faults, scrub, mixed zones, vectors, chain expiry, reconnect loop, flash worst case, DF limit, E-2, E-3, E-4, orchestration, hygiene) | all passed |
| FOTA code mutations in the container | **34 run, 33 caught**; the survivor is the known equivalent mutant (the early revoked-anchor check, repeated in `check_signer`; kept to skip an SLH-DSA verify). Includes the H4 roles, part-label binding, staging and chunk bounds, E-4 validity |

**Message sizes [DOCKER, v2.2 code, pinned by tests]:** CH 2,493 · SH 2,411 · DF alone 46 · DF + ALERT 193 ·
ALERT 137 · CMD 3,466 · GRANT 3,477 · SETPOINT 97 · ZONEKEY 138 · status ACK 83 · DR event 3,488 (64-byte event,
ChaCha group) · ZONESYNC 83 (2-character zone; 113 at 32) · signed manifest 8,031 · E2E full / PSK / PSK+KEM
5,221 / 761 / 3,097 · C2: NT with 53 ACKs 4,008, largest DF 6,109.

**Evidence labels:** [SIM] in process with the FlashSim power-loss model; [DOCKER] the real broker with hybrid TLS
1.3 in the test container; [LIT] / [ANALYTICAL] unchanged from Master. **Nothing is [HW].**

### 13.8 Remaining after the final pass

- **[HW] not done:** MCU timing and memory, real flash (geometry, wear, power-fail behaviour), actuators, radio
  links, bootloader swap safety, secure storage. The simulated device store (2 × 4 × 4 KiB) is a requirement
  to check against the real part, not a measurement of it.
- **E-1 (kept interpretation):** the chain cap applies to every live session; a new full handshake starts a new
  chain.
- **Broker behaviour relied on [DOCKER, Mosquitto 2.x]:** SUBACK granted but delivery filtered for an
  unauthorised SUBSCRIBE; PUBACK 0x87 for an unauthorised PUBLISH. Cross-topic ordering is no longer relied on.
- **Prototype limits:** the nodes' application sinks (`alerts`, `telemetry`, `statuses`, `events`) are
  unbounded lists used for observation; logs are bounded. The ACL-reload wait in the test harness is a
  precondition sleep, never the basis of an assertion. Python cannot zeroise memory (`close()` drops
  references).
- **Status:** implemented and validated in simulation and Docker only. Not complete: hardware validation is
  outstanding, and the final read-only audit decides the status.

## 14. Continuous audit (2026-09-30 onward)

Iterative review after the final remediation pass. Every entry was first shown by a test that fails on the code
before the fix (the "before" run is recorded in the commit message), then fixed, then checked with the focused
tests, the full Docker suite and the frozen v2.1 `validate.py` (80/80). Evidence labels as in §13. Nothing is [HW].

**Test environment note (corrected, §15).** The canonical images are built from `design-validation/Dockerfile`
(Debian trixie). It could not be built in this environment (Debian mirrors 403, later Docker Hub 429), so **every
number of this section was produced in a SUBSTITUTE base** (Ubuntu 25.10: OpenSSL 3.5.3, Mosquitto 2.0.22,
Python 3.13.7, the same pinned `cryptography`/`paho-mqtt`/`pytest`; recipe now in `docker/substitute-ubuntu.Dockerfile`).
It reproduced the 464-test baseline and v2.1 80/80 before any change; equivalence with the canonical image is not
demonstrated (an earlier wording called it "equivalent").

| # | Area | Defect (how it was shown) | Fix | Regression test | Label |
|---|---|---|---|---|---|
| C1-1 | Device flash record store | A power cut right after the **type byte** of a record starting in the last 267 B of a page left `key_len` = 0xFF; the boot scan stopped there without marking the page torn, so the next small write programmed over the non-erased byte and every later small write failed ("store bug"): the store was unusable. The §16 power-loss test never wrote after recovering, so it could not see this | `_scan_bank` treats a header that runs past its page as a tear (rest of the page abandoned), like a bad CRC | `test_torn_header_near_the_end_of_a_page_does_not_block_later_writes`; `test_power_loss_at_every_point_leaves_before_or_after_state` now also writes (and reboots) after every recovery | [SIM] |
| C1-2 | Identifier grammars (I-21) | The device-ID, policy-ID, class-name and zone/target-token checks used `re.match` with `^…$`; `$` also matches before a final `\n`, so `meter-0001\n`, `nitk-grid\n`, `smart_meter\n` and `f7\n` were accepted. These strings become ACL lines, topic levels, POLICY_INFO and CNs: a newline splits an ACL line. No pqgrid test covered the grammars | `fullmatch` in `registry.valid_device_id`, `commands.codec.valid_token` and the two validator checks | `tests/unit/test_identifiers.py` (45 hand-written accept/reject cases: registry, validator, zone creation, ZONEKEY and GRANT decoding) | [SIM] |
| C1-3 | Utility main loop (M9, §12) | A scheduled policy that is refused when it falls due (e.g. v2 scheduled, then an urgent v3 activated directly; v2 now fails rule 5) raised out of `UtilityMqtt.tick()` **before** its housekeeping and stayed scheduled, so on every tick for ever: no weekly zone-key rotation, no artifact clean-up, no chain sweep. `schedule_policy` also accepted a policy that was already not newer than the installed one | `tick()` drops a scheduled policy refused at activation (recorded in `refused`) and continues; `schedule_policy` validates the version against the installed policy at once | `tests/unit/test_utility_loop.py` (2): refused at scheduling; refused at activation → dropped once, housekeeping in the same and the next tick | [SIM] |
| C1-4 | Utility GRANT memory (§13.4, resources) | `CommandService._grants` (sid → GRANTs, each with its 3,309-B σ) was never pruned: every GRANT of every session ever stayed in RAM (hourly GRANTs ≈ 570 KB per device per week; ≈ 5.7 GB for 10k DERs). Shown by five sessions with one GRANT each: six sids held | When a device is granted in a session, its GRANTs of the previous session are dropped (they died with it) and GRANTs expired beyond the 60-s device-clock slack (E56) are dropped; replaced-but-unexpired GRANTs stay usable, so what the device decides is unchanged | `test_utility_grant_memory_is_bounded_by_live_grants` (`tests/security/test_control.py`) | [SIM] |
| C1-5 | Test quality | Three assertions accepted any exception: `pytest.raises(Exception, …)` for a command to a revoked device (`test_mqtt.py`), a class missing from the policy in the ACL compiler (`test_transport_units.py`) and a replayed broadcast (`test_restart.py`); an unrelated error (e.g. a crash) would have passed them | Test-only | Now `CommandError`, `PolicyError` (naming the class) and `ReplayError` | — |
| C1-6 | Test race (T4, [DOCKER]) | `test_T4_…`: in TLS 1.3 the broker refuses an expired client certificate **after** the client's handshake has completed, then closes with handshake records unread, which resets the connection. The test wrote the MQTT CONNECT before reading, so when the reset had already arrived `sendall` failed with ECONNRESET and the queued `certificate_expired` alert was never read: it failed 5 of 6 runs under CPU load on unchanged code | Test-only: a `_tls_refused` helper reads (never writes) first; the alert is queued ahead of the reset. The assertion is unchanged (`SSLV3_ALERT_CERTIFICATE_EXPIRED` + one new broker log line) | 12 of 12 runs under the same load | [DOCKER] |
| C1-7 | FOTA commit crash window (§15.12) | A commit writes the protected record, then drops the staging record. A power cut in between left a staged FIRMWARE whose version was already committed; at the next boot the bootloader model re-hashed the other slot, which is now the **old** image, and reported a false "refused: staged image modified" (a tamper alarm) | At boot, a staged or downloading artifact whose version is already committed is dropped (the commit is finished), generalising the existing KEYREVOKE recovery | `test_power_loss_between_the_commit_and_dropping_the_staged_record` (`tests/security/test_fota.py`) | [SIM] |
| C1-8 | Installed policy (Master §4.1, §12, §15.1) — **lock-out** | (a) Nothing persisted the device's installed policy (Master §4.1 requires it in flash): after a reboot following a policy update the device ran its factory policy, the utility refused its CH (old POLICY_INFO) and the current policy it re-sent (E-4) was refused as a rollback (`version ≤ committed`): **permanently locked out**. Every reboot test booted with the factory policy, so it never showed. (b) `activate_policy` decoded the staged policy without re-checking its SHA-256: a staging area modified after its download checks (§15.1 external-flash threat) was committed, e.g. with a command key nobody signed. Both shown by in-process scripts with real SLH-DSA artifacts | Two policy areas used alternately like the firmware slots (staging never touches the installed policy); the one protected record now also holds the installed policy's area, length and SHA-256, so version and installed copy commit atomically; `Installer.installed_policy()` reads it back and verifies the digest (explicit `FotaError` if damaged; `None`: factory policy); `activate_policy` re-hashes the staged policy; the harness boots devices with `installed_policy() or factory` | `tests/security/test_fota.py`: `…installed_policy_is_kept_in_flash_across_reboots_and_updates` (incl. factory reset), `…modified_policy_area_is_refused_at_activation_and_at_boot`, `…device_rebooted_after_a_policy_update_establishes_under_it`; `test_M9_scheduled_policy_rollout_end_to_end` now power-cycles the device after the rollout over the broker | [SIM, DOCKER] |
| C1-9 | Test strength (mutation analysis) | 117 mutants, each disabling one security or correctness check in `pqgrid` (handshake, tickets, envelopes, commands, zones, policy, wire, persistence, FOTA, ACL), run against the in-process suite (`tests/unit`, `tests/security`): 94 killed, 22 survived. 17 survivors were real gaps: the CH class vs the registry; revocation recorded in the registry alone (sessions, status ACKs, GRANTs); half-open state kept on revocation; the device's SH checks of POLICY_INFO and resume mode; a forged FIN; a ticket for a class that never resumes; CONTROL topic ownership and tier (masked by the AEAD's topic binding); an unknown status token under a valid MAC; a SETPOINT for a GRANT-only class; an oversized signed command; an idempotent intent past its expiry at recovery; the utility's SETPOINT bounds; a non-POLICY or E57-inconsistent artifact on the utility/ACL path. 5 are equivalent by construction: ticket chain check (expiry ≤ chain), ticket mode vs current policy (implied by checks 4 and 6), ZONESYNC phase-1 check (phase 2 refuses the replay), last-anchor guard (unreachable under DR-050 roles), Merkle `sn == 0` (a short path cannot hash to the root without a collision) | Test-only | 17 tests in `test_handshake.py`, `test_revocation.py`, `test_control.py`, `test_fota.py` (one uses a fully authenticated SH built with the utility's E2E key, RISK-2, to reach the device's own checks); each kills its mutant (re-run: 17/17 killed). Result: 112 of 117 killed, 5 equivalent (re-classified in §15.9) | [SIM] |
| C1-10 | Device follows a policy change (§12, E61, §16) | Class values cached at construction ignored a newly activated policy: (a) the FOTA installer kept its factory `max_packet` for the E61 chunk check, so after a policy raising it (the device then declares 8 KiB and the publisher builds for 8 KiB) every new artifact was refused, also after a reboot; (b) the outbox kept its factory `outbox_cap`; (c) `activate_policy` committed a policy that does not define the device's own class (only the loop's optional `admit` hook looked), leaving an installed policy nothing could run | The installer takes its limit from the installed policy (at boot and at each commit); the device loop's policy activation also updates the outbox cap; `activate_policy` refuses, before committing, a policy without the device's class | `tests/security/test_fota.py`: `…installer_follows_the_packet_limit_of_the_policy_it_commits` (incl. reboot), `…policy_without_the_devices_own_class_is_refused_before_commit`, `…device_loop_applies_every_class_value_of_a_newly_activated_policy` (through `DeviceMqtt.housekeeping`) | [SIM] |
| C1-11 | Test fidelity (reboot after a firmware update) | The broker harness booted every device as firmware 1, so no test modelled a reboot after a committed update: the rebooted model device would claim its old image (and the utility's E-4 trigger would offer the committed image again). `pqgrid` leaves the running version to the device's boot code, so the defect was in the harness | Harness: a device boots with `committed(FIRMWARE)` (1 from the factory) | `test_M9_firmware_is_committed_…` now power-cycles after the commit: fw 2 on both sides, nothing republished; it fails with the old harness (fw 1) | [DOCKER] |
| C1-12 | Utility rollout state (Master §4.4, U-4) — **fleet refusal after a restart** | The utility's active and scheduled policy lived only in RAM (`open_utility` took the policy as a start argument; `UtilityMqtt._scheduled`). A restart after a rollout put the utility back on its bootstrap policy, and a restart between scheduling and `activate_at` lost the activation, while the devices switch at `activate_at` regardless: every switched device is then refused for its POLICY_INFO | The database keeps the active and the scheduled POLICY artifact with the anchors and revocations they were verified against (`policy_state`), each written before it takes effect or is promised (P8); `open_utility` resumes a newer active policy after re-verifying it; `UtilityMqtt` reloads the scheduled one and forgets it once activated or refused | `tests/unit/test_utility_loop.py`: `…restarted_utility_keeps_the_policy_it_activated` (a v2 device is served), `…policy_scheduled_before_a_restart_is_still_activated_at_its_time`; `test_M9_scheduled_policy_rollout_end_to_end` now also restarts the utility over the broker (fails before the fix: back on v1) | [SIM, DOCKER] |
| C1-13 | Publisher rollout state (Master §4.4 "Artifact publisher: rollout state", U-4, E-4) | The publisher's state (newest artifact per class and type, what is retained since when, anchors revoked by published KEYREVOKEs) lived only in RAM, and the harness reused one `Publisher` object across utility restarts, which hid it. After a real restart the utility could republish nothing (E-4 triggers found no artifact), never removed what it had retained before (the retention clock was lost) and forgot its revocations | `Publisher` persistence hooks, written before the broker is told; `SqlPublisher` (tables `artifacts`, `revoked_anchors`) reloads it; the publisher also refuses an artifact with more chunks than any device accepts (1,024); the harness builds the publisher from the reopened database at each restart | `test_the_publishers_rollout_state_survives_a_utility_restart` (`tests/security/test_republish.py`): revocation kept (A's firmware not republished), retained topics removed after the window, B's release republished after a second restart | [SIM] |
| C1-14 | Dead code (Phase 1) | Proven unused by a search of all code, tests and documents: `mqtt.tls.CLASS_SUITE` (the per-class TLS suite map; Python cannot restrict TLS 1.3 suites, E53, and nothing read it, so it suggested an enforcement that does not exist), `fota.installer.TYPES` (an alias nobody imported) and, by pyflakes, unused imports in `installer.py`, `commands/utility.py`, `tools/mutation_check.py` and three test files | Removed | Full suite unchanged; `pyflakes pqgrid tools` clean (tests: only pytest's fixture-import idiom remains) | — |

### 14.1 Remaining after cycle 1 (classified)

- **Accepted, DoS out of scope (Master L13, §23.14):** a compromised broker can grow two device-side structures:
  the handshake reply queue (`DeviceMqtt._replies`, drained only while establishing) and the zone-sync bookkeeping
  (`_sync_pending`, keyed by the zone name of a forged re-sent event, which also makes the device send one ZONESYNC
  per forged zone: 1:1, no amplification). A broker can drop all traffic anyway.
- **Implementation bound (I-18 under load):** the utility's duplicate cache keeps at most 4,096 replies (§13.4).
  I-18 (identical replies to identical requests within the DUP window) therefore holds while at most 4,096 distinct
  CH/RH/DF arrive within one window; in a larger restoration storm a QoS 1 duplicate may get a fresh reply and cost
  that device one more attempt. Not a safety issue; sizing it to the fleet is a deployment choice.
- **Latent path:** `DeviceRecord.max_packet` (a per-device limit in the registry) is honoured by the
  utility's publish check, but `pqgrid` devices declare and size everything (MQTT Maximum Packet Size, DF) from their
  class. A per-device value below the class value would make the NT/FIN answering a full DF unpublishable. No
  production caller sets it. *Release audit (§15):* kept (Master §10.2 has the device report its maximum), now
  exercised by the L-4 test and recorded as Master §25 L22.
- ~~**Minor ordering:** `on_finished` recorded the bundled alerts as seen before NT/FIN was built~~ — fixed in C2-6.
- **Installed policy damaged in flash:** `Installer.installed_policy()` raises; re-installing the same version to
  repair it is not implemented [HW: flash integrity].
- **Mutation analysis:** 5 equivalent mutants (listed in C1-9) remain by construction; `tools/mutation_check.py`
  re-runs the analysis. *Release audit (§15.9):* two of them (ticket checks 5 and 8) now have direct tests and are
  killed; the other three are classified there (one equivalent, one unreachable by invariant, one equivalent under
  SHA-256 second-preimage resistance).
- **[HW]:** unchanged from §13.8.
- ~~**ACL recompilation (optional hardening):** the ACL hook runs once after a revocation or an activation; if it
  fails (e.g. the broker is restarting when it is signalled) the failure is visible (it raises to the caller or is
  an internal alarm of the loop) but is not retried.~~ Retried by every tick since the release audit (§15, L-1). Since C2-4 and C2-7 a stale ACL gives a revoked device nothing
  beyond a broker connection (unreadable events, refused messages, public signed artifacts).
- **DR re-send cost (by design, M4):** each (re)establishment re-sends every still-valid event of the device's zones;
  the device drops what it already accepted. Recorded in Master §22.6; changing it needs a decision record.
- **Not implemented in the Python device (Master D-2):** pipelining CONNECT with the first PUBLISH (`DeviceMqtt.connect`
  waits for CONNACK) and MQTT 5 topic aliases for high-rate TELEMETRY. *Corrected by the independent release audit
  (§15):* this is a choice of the prototype, not a paho limit. paho-mqtt 2.1.0 can do both (`publish()` and
  `subscribe()` need only the socket, which the synchronous `connect()` has once CONNECT is sent; under MQTT 5 it
  accepts a zero-length topic with a TopicAlias property), and the cited experiment's own recorded result
  (`design-validation/constrained-audit/results/transport.txt`) shows an aliased publish of 94 B sent through paho.
  Both are byte and latency optimisations, measured in the design-validation T5/T6 experiments, not security
  properties (Master §25 L17).


**Cycle 2 (fresh scan of the updated tree).** Regression review of cycle 1's changes: none found. Broker tests
under contention: three concurrent full integration runs, 41/41 each [DOCKER].

| # | Area | Finding | Change | Test | Label |
|---|---|---|---|---|---|
| C2-1 | Fuzz coverage (I-21) | The fuzz tests covered the 12 slice-1 to slice-3 message types but none added later: ZONESYNC (E-2), the re-sent DR event, SETPOINT, ZONEKEY, the ALERT ACK and FIN. Result: no defect; every corruption of them is refused with a controlled error | Test-only | `test_corrupted_later_message_types_are_refused_cleanly` (6 × 300 mutations; the genuine message still works afterwards) | [SIM] |
| C2-2 | Test strength of cycle 1's own fixes | 23 new mutants (117–139 in `tools/mutation_check.py`), one per check added in cycle 1: 22 killed at once; the survivor showed that the C1-13 test never restarted **after** a retention clean-up, so a clean-up that was not persisted went unseen (a restarted utility would believe an artifact still retained and skip the E-4 "no longer retained" republish) | Test-only: the C1-13 test now restarts after the clean-up and checks nothing is believed retained | 23 of 23 killed; overall 135 of 140, the 5 equivalent ones unchanged | [SIM] |
| C2-3 | Documentation (Phase 8) | Code docstrings described finished work in the future tense ("Slice 4 moves it to SQLite", "Flash storage arrives with slice 4", …) and the package docstring described slice 1 only; the roadmap did not say that Master D-2's CONNECT pipelining and topic aliases are not in the Python device | Docstrings name the class that now does it; package map; §14.1 records the D-2 gap and why | Docs only (suite re-run) | — |
| C2-4 | Revocation crash window (H1, §4.7, Phase 6) | `revoke_device` makes the registry revocation durable, then removes the device from its zones with new keys. A utility crash in between left the revoked device a zone member holding the **current** zone key after the restart: it could read every DR event published until the weekly rotation (the E2E refusals do not cover broadcast confidentiality). Shown with a real SQLite restart: still a member, key epoch unchanged | At start the zone manager finishes it: a member the registry says is revoked leaves its zones, with new group keys (once) | `test_a_crash_between_revocation_and_zone_removal_still_locks_the_device_out_of_the_zone` (`tests/security/test_revocation.py`) | [SIM] |
| C2-5 | Policy activation crash window (§4.7, Phase 6) | Zone keys rotate at a policy change. `activate_policy` persisted the new policy, then rotated: a crash in between (injected as a failure of the rotation) left the restarted utility running the new policy on the old zone keys. Low severity (the members are the same, so nobody gains access; the weekly rotation bounds it) | The rotation runs before the policy is persisted (still durable before it takes effect): a crash leaves the old policy active and the scheduled activation runs again, rotation included | `test_a_crash_while_activating_never_leaves_the_new_policy_on_the_old_zone_keys` (`tests/unit/test_utility_loop.py`) | [SIM] |
| C2-6 | Authentication succeeded, persistence failed (Phase 6) | `on_finished` recorded the DF's bundled alerts as seen (alert-ID dedup) before building NT/FIN, which may write to the database (a new STEK). When that failed, the application never received the alerts, yet the device's resend in its next DF arrived flagged as duplicates. Shown with an injected failure of the ticket issue | The bundle is recorded as seen only after NT/FIN has been built | `test_alerts_of_a_df_whose_reply_failed_to_persist_arrive_as_new_next_time` (`tests/security/test_handshake.py`) | [SIM] |
| C2-7 | Revoked device's TELEMETRY (H1, K-5) | H1 requires a revoked device to be refused everywhere whatever the broker ACL says. TELEMETRY is hop-only, and `UtilityMqtt` accepted any device's reading without consulting the registry: until the ACL was recompiled (the hook is optional and runs after the revocation, so a crash skips it) a revoked device's readings were still accepted, and billed from. Shown over the broker with no ACL change | The utility accepts TELEMETRY only from an active device on its own class's topic, as it already did for republish requests | `test_H1_live_revocation_over_the_broker_without_any_acl_change` now sends a reading after the revocation (refused, not in the sink) | [DOCKER] |
| C2-8 | Test strength of cycle 2's fixes | Mutants 140–143 (one per cycle-2 fix) plus #129, whose pattern the C2-5 reorder had changed; the telemetry check had only a broker test, which the in-process mutation run does not execute | Test-only: a telemetry test through paho's callback without a broker | 5 of 5 killed. Overall: 144 mutants, 139 killed, 5 equivalent | [SIM] |

**Cycle 2 result.** Found and fixed: a revoked device keeping the current zone key after a crash (C2-4), the new
policy on old zone keys after a crash (C2-5), a DF's alerts flagged as duplicates after a failed persist (C2-6), a
revoked device's TELEMETRY accepted until the ACL changes (C2-7); one weak test of cycle 1 (C2-2); fuzzing of the
later message types found nothing (C2-1). Full suite 535 → 545, v2.1 80/80 throughout. What remains is in §14.1.

**Cycle 3 (fresh scan).** Secrets at rest checked: SQLite gives the WAL and SHM files of the utility database (which
holds the STEK) the database's 0600 mode [DOCKER]; no change.

| # | Area | Finding | Change | Test | Label |
|---|---|---|---|---|---|
| C3-1 | ACL compiler (§10.1, K-5) | One registry record whose class the policy does not define (e.g. a class dropped by a new policy while its devices are still registered) made `render_acl` raise for the whole fleet. The broker then kept its **previous** ACL: fail-stale, not fail-closed, including the rights of devices revoked since the last compile; the activation's ACL hook also raised after the policy was already active. The test pinned the raise | Such a device gets no block (a comment line says why); every other device's rights are still written | `test_acl_gives_no_rights_to_a_device_whose_class_is_not_in_the_policy` (replaces the test that expected the raise) | [SIM] |
| C3-2 | Documentation (Phase 8) | Two costs were not written down anywhere: the M4 re-send of every still-valid DR event at each establishment (absent from the Master's bandwidth figures) and the unretried ACL hook | Master §22.6 note [ANALYTICAL]; §14.1 entries | Docs only | — |
| C3-3 | DR subscription after an AEAD change (DR-047) | A device subscribed to a zone's crypto-group topic only when a ZONEKEY for a **new zone name** arrived. A policy moving its class to another AEAD moves it to another group, same zone name: it never subscribed to the new group's topic, stayed on the old one (kept by the persistent broker session) and silently missed every live DR event (nothing arrived, so no zone sync either); until the ACL was recompiled, old-group events it could not open would each have triggered a pointless zone sync | The device tracks its subscribed event topics for its current group: when a ZONEKEY arrives it subscribes to the current group's topic if missing and unsubscribes from a group it left | `test_a_device_whose_class_changes_aead_follows_its_new_groups_event_topic` (`tests/security/test_zones_logical.py`, through paho's callback, no broker) | [SIM] |
| C3-4 | Final regression gate | Full mutation run on the committed tree (144 mutants): 139 killed, the 5 survivors exactly the 5 equivalent ones; mutants 144–146 for cycle 3's fixes (one re-creates the old "new zone name only" subscription rule): 3 of 3 killed | Tooling only | 147 mutants: 142 killed, 5 equivalent | [SIM] |

**Cycle 3 result.** Found and fixed: one registry record of an undefined class stopping the whole fleet's ACL
recompile (C3-1), a device missing every live DR event after a policy moved its class to another AEAD (C3-3).
Recorded: the M4 re-send cost and the unretried ACL hook (C3-2). Final fresh audit: the whole change set against
`main` reviewed again; `pyflakes` clean; nothing new found.

### 14.2 State after the continuous audit (cycles 1–3)

| Measure | Value |
|---|---|
| Cycles | 3, each ending with a fresh scan and a regression review of the previous cycle's own changes |
| Production defects found and fixed | 18, each shown by a failing test or script first: C1-1, C1-2, C1-3, C1-4, C1-7, C1-8 (2: lock-out; unverified staged policy), C1-10 (3: installer limit, outbox cap, own class), C1-12, C1-13, C2-4, C2-5, C2-6, C2-7, C3-1, C3-3 |
| Test and harness defects fixed | a TLS 1.3 race in T4 (C1-6), harness fidelity (C1-11), 3 any-exception assertions (C1-5), 18 test gaps from mutation analysis (C1-9: 17; C2-2: 1) |
| Tests | 464 → 546 collected ([DOCKER, substitute]); 40 new test functions, 1 replaced; ≈ 10 existing tests strengthened |
| Mutation analysis | 147 mutants over every security/correctness check, including those added here: 142 killed, 5 equivalent by construction (`tools/mutation_check.py`; re-run and re-classified after the release audit: §15.9) |
| Dead code | `mqtt.tls.CLASS_SUITE`, `fota.installer.TYPES`, 7 unused imports |
| Evidence | v2.1 `validate.py` 80/80 at every stage (it tests the v2.1 reference prototype, not `pqgrid`); broker tests 41/41 in 3 concurrent runs; [SIM] and [DOCKER, substitute] only |
| Not claimed | hardware validation, formal verification, exactly-once actuation, production readiness, completeness: what remains is in §14.1 |

## 15. Independent release audit and remediation (2026-09-30)

An independent, read-only release audit of `main` at `197ef40` (the merge of PR #1) reported 2 high and 5 medium
findings, 10 low ones, 6 design ambiguities, and lists of requirement gaps, validation gaps, stale material and weak
tests. They were remediated on the branch `claude/release-remediation`, created from `origin/main` at `197ef40` and
not merged. For each code fix the steps were: reproduce it (a test that fails on the code before the fix, run in a
scratch copy); fix it; add a regression test; run the focused tests, the broker tests and the full suite; review the
diff; commit; push.

Evidence labels as in §13. [SIM] means in-process, on the production code paths. [DOCKER, substitute] means the real
Mosquitto 2.0.22 in the substitute image (§15.10). Nothing here is [HW].

### 15.1 Stage 1: release blockers

| # | Issue (audit) | Root cause | Fix | Files | Regression tests | Broker validation | Commit | Status |
|---|---|---|---|---|---|---|---|---|
| H-1 | Utility key rotation through the policy did not work. Activating a policy that names new `utility_kem_pk` / `utility_cmd_pk` succeeded, but the utility kept its old private keys: every device on the new policy was refused and commands stayed signed with the old key | The utility took its private keys once, at start, and never read the keys named by the policy | A keyring (`pqgrid/keyring.py`, `SqlKeyring` in the utility database). The utility always uses the pair its **active** policy names. Scheduling or activating a policy whose keys are not held is refused before any state changes. `open_utility` selects keys by the active policy. Queued commands and retained DR events are re-signed under the active key with the same sequence numbers. The two most recent retired E2E keys are used only to recognise and refuse an old-policy hello (E-4 republish); such a hello never yields a session. Master §12, §13.1, §23.7, DR-051 | `keyring.py`, `errors.py`, `suite/sig.py`, `persistence/utility_db.py`, `commands/utility.py`, `commands/zones.py`, `e2e/handshake.py`, `mqtt/utility_node.py` | `tests/security/test_key_rotation.py` (13): KEM key, command key, both; missing and mismatched keys; a crash before and after the activation write; restarts; commands and events queued across a rotation; old-key hellos; no key material in reprs | `test_utility_key_rotation_rollout_over_the_broker` (both production loops, device power cycle, utility restart) [DOCKER, substitute] | `3ba7195` | FIXED |
| H-2 | CONNECT properties stayed stale after a policy change. A policy raising `max_packet` left the live connection on the old declared limit; the broker silently dropped the NT answering a DF with an alert backlog, and the device could not re-establish | New class values reached only the client's properties object; nothing reconnected, while the utility, the installer and DF sizing switched at once. The C1-10 test inspected that object | `DeviceMqtt` declares the **installed** policy's values at CONNECT and records what the live connection declared. When they differ it makes one planned reconnect (flush, DISCONNECT, CONNECT) at the §12 re-handshake point. After a raise it re-subscribes to the retained FOTA topics. The publisher sizes POLICY/KEYREVOKE to the class **delivery floor** (the smallest `max_packet` any activated policy gave the class, persisted); FIRMWARE follows the current policy. Master §12, §15.9, DR-052 | `mqtt/device_node.py`, `fota/publisher.py`, `persistence/utility_db.py` | C1-10 unit test now asserts what the next CONNECT declares; publisher floor unit test (`test_fota.py`) | `tests/integration/test_connect_properties.py` (5), observed at the broker (its CONNECT log, what it forwards, whether it kept the session): raise with a 60-alert backlog, lower + 3 s session expiry, broker outage + reboot, no-change policy (no reconnect), FIRMWARE and a DR event above the old limit. With the pre-fix device code 3 of the 5 fail (raise with backlog, with the audit's symptom; lower + expiry; outage + reboot). The other 2 (no reconnect without a CONNECT change; FOTA/DR at the boundary) guard behaviour that must not regress | `f400bdd` | FIXED |
| M-1 | A policy scheduled while anchor A was valid was still activated after KEYREVOKE(A); every device refuses it, so the utility and the fleet diverged | The scheduled policy was verified against the caller's revocation snapshot, taken at scheduling time | The database's `revoked_anchors` table is the single authoritative set. It is consulted at scheduling, at every activation attempt, at restart (a scheduled policy is re-verified), for a new policy's ACL and for republication. The policy already in force is not re-judged. DR-050 amended | `mqtt/utility_node.py`, `persistence/utility_db.py`, `fota/publisher.py` | `tests/security/test_revocation_authority.py` (6): real utility, SqlPublisher, anchors A/B and a device installer | Covered in-process with the production loop (`UtilityMqtt.tick`); no broker behaviour involved | `52b1394` | FIXED |
| M-2 | A stale but authentic `utility_time` could roll the device clock back: an SH withheld for 6 h set the clock 6 h back | A hello was resent identically, and any authentic reply to it accepted, for ever | Attempt lifetime = `max(DUP_WINDOW, PENDING_TTL)` on the device's clock. Past it the hello (an RH with its ticket) is abandoned, a reply to it is refused before its time is believed, and a persisted PSK RH carries its build time. Master §9.4, §16 (budget 10,774 B), DR-053 | `e2e/handshake.py`, `persistence/device.py`, `mqtt/device_node.py` | `tests/security/test_time_freshness.py` (12, 11 of which fail on the pre-fix code); `test_flash_capacity.py` budget | [SIM] only: the delay is on the utility→device path and is modelled by holding the reply | `c513584` | FIXED |
| M-3 | CA roll-over through the policy's `ca_set` was not implemented: `ca_set` was parsed and never used | The device TLS context came from provisioning files | The device's TLS trust is the installed policy's `ca_set` (no time checks, §8.8), rebuilt when a new policy changes it (next connection; the TLS session is dropped). Rule 10 requires DER X.509 CA certificates. Master §4.5, §12 rule 10, K-4 | `mqtt/tls.py`, `mqtt/device_node.py`, `policy/validator.py` | `tests/unit/test_ca_trust.py` (rule 10 cases, >2 refused by the codec, the context trusts exactly `ca_set`) | `tests/integration/test_ca_rollover.py`: v2 with {current, next} rolled out, the broker switches to the next CA, the v2 device re-establishes (also after a power cycle), a v1 device is refused by TLS [DOCKER, substitute] | `136982b` | FIXED |

### 15.2 Stage 2: the other findings

| # | Finding | Decision / fix | Tests / evidence | Commit | Status |
|---|---|---|---|---|---|
| M-4 | Contradictions between the Master and the code | Reconciled: §4.4, §4.6, §4.7 (anchor roles, key rotation), §12 (`tls_max_record`, rule 10), §13.5 (V-G5), §14.10, §15.14 (the last-anchor guard is unreachable), §17.3 (substitute label), §22.2 (utility bounds), §23.7, §24 (statuses of S1, S2a, S2b, S3, S4, S5, T1, T4, V-D3, V-G5 and I1 set from the tests that exist, each with its test name), §25 (L16–L22), §27.2 (D-1, D-2, U-2 prototype notes), §28 (I1), §31, Appendix F | Documentation; every status names its test | `435a5b6` | FIXED |
| M-5 | The final evidence came from a substitute environment that was not in Git | `docker/substitute-ubuntu.Dockerfile`: labelled SUBSTITUTE, pinned by digest, versions recorded; `docker/pqgrid-tests.Dockerfile` takes `BASE`. The canonical build was retried and failed again (§15.10). All figures are labelled [DOCKER, substitute]; equivalence is not claimed | §15.10 | `d460e3a` | FIXED (reproducibility); canonical run: VALIDATION GAP |
| L-1 | An ACL hook failure was reported as "policy refused" and never retried | `recompile_acl()`: the activation result stands on its own; a failure is recorded in `acl_failures` and retried by every tick until it succeeds. A zone join now also owes a recompile. `broker.acl_installer()` is the production hook (compile, atomic write, SIGHUP) | `test_an_acl_hook_failure_is_retried_and_never_reported_as_a_refused_activation`; the broker rollout test uses `acl_installer` and checks the file the broker reloads | `16f0ced` | FIXED |
| L-2 | The last-anchor guard cannot be reached under DR-050 | Kept as defence in depth (hardware with more anchors). The installer docstring, its comment and the V-F3 test comment now say it is unreachable; no scenario was manufactured to reach it. Master §15.14 | Mutant 110 classified as unreachable (§15.9) | `d460e3a`, `435a5b6` | VERIFIED LIMITATION (intentional dead branch) |
| L-3 | A DR event can be lost between the `bseq` write and application delivery if power fails | Chosen semantics: **at most once** (Master §11, L19), as for commands (L9). No durable pending-delivery record was added: the device cannot tell whether the application acted before the cut, so re-delivery after a reboot would make it at least once (a possible double action), and a broadcast has no ACK to report the loss | `tests/security/test_dr_power_loss.py` (27): a cut at each of the 26 bytes of the `bseq` record (torn: the re-send is accepted after reboot) and after it is durable (the re-send is refused as a replay: lost, never delivered twice) | `7736bf6` | VERIFIED LIMITATION (L19) |
| L-4 | DF alerts could be marked seen before the application got them, when the NT publish failed | The alerts are handed to the application before the reply is published | `test_df_alerts_reach_the_application_even_when_the_reply_cannot_be_published` (delivered once; a retransmitted DF adds nothing) | `16f0ced` | FIXED |
| L-5 | `max_fragment_length` (`tls_max_record`) is parsed and validated but never applied | Python's `ssl` has no API for it. It stays in the signed policy format for an MCU TLS stack (D-1). Code comment, Master §12 table and L18 say the prototype does not apply it | — | `435a5b6` | NOT IMPLEMENTED AND EXPLICITLY DOCUMENTED |
| L-6 | No separation of duties or HSM in the prototype | Master §4.4 (command service row), §27.2 U-2 and L16 separate the production requirement from the prototype, which runs one process and keeps the keys in SQLite | — | `435a5b6` | NOT IMPLEMENTED AND EXPLICITLY DOCUMENTED |
| L-7 | Broker user and queue limits were left to defaults | `render_config` writes `user mosquitto` and `max_queued_messages 1000`; `validate_config` requires both and refuses `user root` unless it is explicitly allowed (throwaway test containers only). `max_inflight_messages`, persistence paths and listener addresses stay operator-controlled | `test_transport_units.py` (render and validate cases) | `7736bf6` | FIXED |
| L-8 | RAM and storage bounds were not sized | Master §22.2 table [ANALYTICAL; Python object sizes measured with `sys.getsizeof`]: duplicate cache 10.6–17.1 MiB; seen alert IDs 230 KiB per device; `commands` table ~108 MB a day at 3 commands a day for 10,000 devices (L21); the device's `_replies` and `_sync_pending` grow only under a malicious broker (DoS, out of scope) | `test_duplicate_reply_cache_is_bounded_by_count`; new `test_a_duplicate_hello_beyond_the_cache_bound_costs_one_more_attempt_and_nothing_else` (the §14.1 claim, now tested) | `435a5b6` | VERIFIED LIMITATION (L21 retention is an operator task) |
| L-9 | Clone monitoring missed used-ticket events | "Ticket already used" raises `ticket_reuse_alarms` (Master §27.8 M-1), not only a refusal-log line | `test_a_reused_ticket_raises_the_clone_alarm` | `16f0ced` | FIXED |
| L-10 | A stale roadmap sentence ("the ACL compiler does not yet verify the policy signature") | Struck through (§11.6); stale §14.1 entries now point here | — | `435a5b6` | FIXED |

### 15.3 Design ambiguities (one definition each now)

| # | Ambiguity | Decision (Master) | Tests |
|---|---|---|---|
| 1 | V-G5: SUPERSEDED or a replay drop? | A replayed or older SETPOINT is dropped by the envelope replay guard, with no status. SUPERSEDED is the status of a redelivered discrete command older than the last applied one, or of a replaced GRANT (§13.5) | `test_VG5_replayed_setpoint_is_dropped`; the SUPERSEDED cases in `test_control.py` |
| 2 | "Takes effect at the next connection" | The next CONNECT declares the installed policy's values, and a policy that changes them causes exactly one planned reconnect (DR-052) | `test_connect_properties.py` |
| 3 | Who owns anchor revocation state, and when is it checked? | The utility database's set is authoritative and is checked at scheduling, activation, restart, new-policy ACL compilation and republication. The policy in force is not re-judged (DR-050 amended) | `test_revocation_authority.py` |
| 4 | `utility_time` adopted before key confirmation | Kept, but only from a reply to a hello younger than the attempt lifetime. Adopting after NT/FIN was rejected because the NT can be held back the same way (DR-053) | `test_time_freshness.py` |
| 5 | DR-event delivery across a power loss | At most once (§11, L19) | `test_dr_power_loss.py` |
| 6 | Two definitions of I1 | §24.4 defines it: a composed attack during a rollout. The §28 lifecycle test that carried the name is renamed `test_lifecycle_over_the_broker` | `test_composed_attack.py::test_I1_…` over the broker |

### 15.4 Requirement gaps named by the audit

| Item | Status |
|---|---|
| Utility key rotation through the policy | FIXED (H-1) |
| CA roll-over through `ca_set` | FIXED (M-3) |
| D-1 `max_fragment_length` | NOT IMPLEMENTED AND EXPLICITLY DOCUMENTED (L18; Python `ssl` has no API) |
| D-2 pipelining and topic aliases | NOT IMPLEMENTED AND EXPLICITLY DOCUMENTED (L17). The earlier "paho cannot" reason was wrong and is corrected in §14.1 and the Master |
| U-2 separation of duties / HSM | NOT IMPLEMENTED AND EXPLICITLY DOCUMENTED (L16) |
| B-6 broker queue limit, B-1 user | FIXED (L-7) |

### 15.5 Validation gaps named by the audit

| Item | Status |
|---|---|
| Utility SQLite durability is tested against SIGKILL only | VALIDATION GAP (L20; SQLite's guarantee is [LIT]) |
| Composed I1 attack | FIXED: `test_composed_attack.py` over the broker (`7736bf6`) |
| Timing and side channels | VALIDATION GAP (L12) |
| Latency and byte figures modelled, not measured on hardware or networks | VALIDATION GAP, labelled [SIM]/[ANALYTICAL]/[DOCKER] (L17, §22) |
| ACL wiring through operator hooks | `broker.acl_installer` is the production hook and runs in the broker rollout test. Running it in a deployment (broker PID, file path, permissions) is operator configuration: VALIDATION GAP for a real deployment |
| Latent `max_packet` paths | FIXED for the class value (H-2 broker tests); the per-device registry value is documented (Master §25 L22) and exercised by the L-4 test |
| Duplicate cache beyond 4,096 | VERIFIED LIMITATION: bound tested; the effect past it (one more attempt, nothing else) is now tested |
| Canonical environment not run | VALIDATION GAP (§15.10) |
| MCU resource claims analytical or from literature | VALIDATION GAP [HW] (§15.12) |
| Mutation analysis excludes integration tests | Partly addressed: 3 mutants also run the broker test that exercises them. The in-process score is reported separately (§15.9) |
| Tests use private attributes | Reviewed (§15.8) |
| Tests stub paho or call callbacks directly | The C3-3 AEAD move (`16f0ced`) and revoked-device TELEMETRY (C2-7) also have broker tests now. The callback-level unit tests stay as fast checks of the same production callback |
| The SH-forgery helper re-implements SH generation | Cross-checked against the production SH layout (`d460e3a`) |
| Survivor classifications rely on untested invariants | Survivors 24 and 28 now have direct tests (`d460e3a`); 40, 110 and 112 are classified in §15.9 |

### 15.6 Stale, dead or conflicting material

| Item | Decision |
|---|---|
| The last-anchor guard and a comment claiming it is tested | Guard kept (defence in depth); the comments are corrected (L-2) |
| `Policy.ca_set` parsed but unused | Now the device's TLS trust (M-3) |
| `ClassProfile.tls_max_record` parsed but unused | Kept. It is a field of the signed v2.2 policy encoding, and removing it would change the format every device verifies. Marked as not applied by the prototype (L-5) |
| `DeviceRecord.max_packet` latent path | Kept (Master §10.2); commented; Master §25 L22; exercised by the L-4 test |
| Redundant ticket checks 5 (chain) and 8 (mode) | Kept as defence in depth; each now has a direct test with a ticket sealed by the real STEK in a state `issue()` never produces |
| Stale validation numbers and statuses | Master §24 and §31 updated from the tests that exist; counts in §15.11 come from test discovery |
| Stale anchor-revocation wording | Master §4.6, §4.7 and §23.7 now state DR-050 as amended |

### 15.7 Weak or misleading tests (audit list)

| Test | Change |
|---|---|
| C1-10 `max_packet` | Asserts what the next CONNECT declares. The property itself is asserted at the real broker (`test_connect_properties.py`) |
| V-F3 comment | No longer claims the guard is exercised |
| I1 | A real composed attack over the broker (§15.3 item 6) |
| S3 | The Master row says "killed process"; a power cut is L20 |
| ACL wiring | The rollout test runs the production `acl_installer` and reads the ACL file the broker reloads |
| C3-3, telemetry | Broker tests added or already present (§15.5) |
| SH-forgery helper | Cross-checked against the production SH |
| Mutation tool | A mutant counts as KILLED only when a test **fails** (pytest exit 1). A crash or collection error is ERROR, not a kill |

### 15.8 Private attributes in tests

`grep` finds 85 references to underscore attributes in 23 test files.

| Kind | References | Examples | Decision |
|---|---|---|---|
| Fault-injection and setup seams: wrap or replace a private method to inject a failure or count calls, or set up a state | 33 | `_publish`, `_zone_sync`, `_handshake`, `_connection_step`, `_on_control`, `_lib` (OpenSSL NULL), `pasr._keys` (65,535 rotations) | Kept: there is no public way to inject these faults, and each test asserts public behaviour |
| Checks that secret, half-open or bounded state is gone or bounded, where no public view exists | 40 | `_pending`, `_ch`, `_rh` after revocation; `_grants` (C1-4 memory bound); `_parts` (assembly bound); `_d` (duplicate cache); zone `_keys` epochs; the `_online` / `_conn_attempt` heuristics | Kept: these are the properties themselves |
| Flash-model internals in the flash unit tests | 10 | `_pos`, `_wseq`, `_live` | Kept: they are white-box tests of the storage model |
| CONNECT properties the next connection will declare | 1 | `_connect_props` | Kept as a fast check; the behaviour is asserted at the broker |
| Harness | 1 | `_listening` | — |

Replaced where a public equivalent existed: `test_utility_loop.py` read `UtilityMqtt._scheduled` (now the persisted state, `db.load_policy("scheduled")`). The C1-10 test read `_props` (now what the next CONNECT declares, plus the broker tests).

### 15.9 Mutation analysis (re-run)

`tools/mutation_check.py` now has 173 mutants: the 147 of §14, 25 for the remediation's checks (147–171) and
one for the §15.11 join fix (172). Each disables one security or correctness check. A mutant counts as KILLED only
when a test **fails** (pytest exit 1); a crash or collection error would be ERROR, and none occurred. Every mutant
runs the in-process suite (`tests/unit`, `tests/security`). Mutants 154, 155 and 166 also run the broker test that
exercises them.

| Run | Code | Result |
|---|---|---|
| Full run, 4 slices (substitute image) | `d460e3a` (the production code of the final tree is identical apart from comments and docstrings, checked by AST comparison, except `UtilityMqtt.join_zone`) | 172 mutants (0–171): **168 KILLED**, each by a failing test (the run stops at the first failure, `pytest -x`, so every result line shows 1 failed: that is the tool, not a measure of how many tests catch the mutant); **4 SURVIVED** (40, 110, 112, 155); 0 ERROR |
| Re-run of every mutant in `pqgrid/mqtt/utility_node.py`, plus 155 and 172 | final code, `a55a227` | **17 of 17 KILLED** (the 15 in `utility_node.py`, 155 with its new test, 172) |

**Scores, kept apart.** In-process (unit and security suites): 170 mutants on the final code (169 of the full run plus 172), 167 KILLED; the 3 survivors are classified below. Broker-assisted (154, 155, 166): 3 of 3 KILLED on the final code (155 only since the test added in `a55a227`). Overall: 173 mutants, 170 killed by test failures, 3 classified survivors, 0 errors.
Integration coverage is not a mutation score: 51 broker tests run in every full suite (§15.11).

**Survivors, classified:**

| # | Mutant | Class | Why |
|---|---|---|---|
| 40 | ZONESYNC phase-1 replay check (`guard.validate` before the MAC) | Equivalent (security) | Phase 2, `guard.accept`, runs the same check after the MAC (`replay.py`), so a replayed ZONESYNC is still refused and nothing is accepted twice. Without phase 1 a replay costs one HMAC before its refusal. No test was written to kill it: it would test that cost, not a security property |
| 110 | Last-anchor guard in KEYREVOKE | Unreachable by invariant | Under DR-050 only B revokes, and only A. With anchors {A, B} the guard's condition cannot hold (Master §15.14). The invariant is tested directly (`test_only_B_may_revoke_and_only_A`); the guard is kept as defence in depth (L-2) |
| 112 | Merkle: final `sn == 0` in `verify` | Equivalent under SHA-256 second-preimage resistance | It refuses an authentication path that is too short for the tree. Without it such a path is accepted only if an interior node's hash equals the signed root, which needs a second preimage of SHA-256 (paths that are too long are refused before the loop) |
| 155 | H-2: re-subscribe to the retained FOTA topics after a CONNECT that raised the limit | Insufficiently tested (**now killed**) | Every broker test published the large artifact after the reconnect, so the re-subscription was never needed. New test `test_a_retained_artifact_dropped_under_the_old_limit_arrives_after_the_reconnect` (`a55a227`): FIRMWARE published for 16 KiB while the live connection declares 4 KiB arrives after the one planned reconnect. It kills the mutant; 18 of 18 loaded runs pass |

Survivors 24 (ticket check 5: chain) and 28 (ticket check 8: mode) of §14 are now killed by direct tests
(`test_resume.py`: tickets sealed with the real STEK in states `issue()` never produces).

### 15.10 Environment (canonical vs substitute)

| | Canonical | Substitute (used for every figure in §14 and §15) |
|---|---|---|
| Recipe | `design-validation/Dockerfile` (`debian:trixie-slim`) | `docker/substitute-ubuntu.Dockerfile` (Ubuntu 25.10, base pinned by digest `sha256:7cc5e35f…7092`) |
| Built here? | **No.** 2026-09-30 12:41Z: Docker Hub 429 for `debian:trixie-slim`. 13:25Z: the base image pulled, but every Debian mirror (`deb.debian.org`, `security.debian.org`, `ftp.*.debian.org`, `mirrors.kernel.org`, `cdn-aws.deb.debian.org`) answered 403 under this environment's network policy (no host networking used) | **Yes, rebuilt from Git** on 2026-09-30 (bridge network; the sandbox's TLS-proxy CA supplied through the recipe's `extra-ca` build context, as the audit image had it). Its 126 dpkg and pip packages are identical to those of the image the audit evidence came from (`pqgrid-validation-audit`) |
| Versions | Recorded in Master §17.3: OpenSSL 3.5.7, Mosquitto 2.0.21, Python 3.13.5 | Ubuntu 25.10; openssl/libssl3t64 3.5.3-1ubuntu3.4; mosquitto 2.0.22-2; python3.13 3.13.7-1ubuntu0.4; SQLite 3.46.1; cryptography 50.0.1; paho-mqtt 2.1.0; pytest 9.1.1 |
| Equivalence | — | **Not demonstrated.** A different distribution and different OpenSSL/Mosquitto builds. Every substitute result is labelled [DOCKER, substitute] |

Unblocking the canonical run needs the Debian mirrors allowed in the environment's network settings. Evidence from
before this work that was produced canonically (§13.7: 464 passed, v2.1 80/80) is the project's own record and is
not re-labelled.

### 15.11 Final validation (2026-09-30)

**Found by the final concurrent broker runs, and fixed before the final audit.** Three concurrent integration runs,
while the 4-slice mutation run also ran, each had one failure: two different tests.

| # | Finding | Root cause | Fix | Evidence | Status |
|---|---|---|---|---|---|
| F-1 | Under load, the first DR event after a live zone join was lost for the new member: the C3-3 broker test failed in 1 of 3 runs. A diagnostic variant (scratch, not committed) lost the event in 18 of 36 loaded runs, and it never arrived later | `join_zone` published the new ZONEKEY, then ran the ACL hook. The device subscribes when its key arrives, and Mosquitto grants the SUBACK without a read right and filters at delivery. So an event the broker processed before its reload was dropped for that member, and nothing re-sends it while the member stays connected | `UtilityMqtt.join_zone` compiles the ACL naming the new member and signals the broker **before** the key goes out. The residual window (events before the member's subscription) is documented in Master §11 and §25 L23 | `test_a_joining_member_gets_its_read_right_before_its_new_zone_key` fails on the old code (key published first); mutant 172 (the old order) is KILLED; the diagnostic variant lost the event in 0 of 36 loaded runs after the fix [DOCKER, substitute] | FIXED (residual window: VERIFIED LIMITATION L23) |
| F-2 | `test_E2_event_before_its_zonekey_is_recovered_by_a_zone_sync_over_the_broker` failed in 2 of 3 runs ("both refused": 1 refusal instead of 2) | Test-only. Under load the whole zone sync (refusal → ZONESYNC → ZONEKEY + re-send) finished between the test's two `dr_event` calls, so the second event opened with the recovered key. That is correct protocol behaviour; a scratch variant that waits for the sync between the events shows it deterministically (1 refusal, 1 sync, both events once, in order). The scenario's "both refused" assumed an interleaving it did not enforce | Both events are published while the test holds the utility's lock, which answering a zone sync needs, so the scenario's interleaving is enforced. The assertions are unchanged | 36 of 36 loaded runs pass | FIXED (test precondition) |

**Results on the final code (`a55a227`)**, in the substitute image rebuilt from Git (§15.10):

| Check | Result |
|---|---|
| Tests collected | 629: 578 in-process, 51 broker. At `main` (`197ef40`): 546, counted from a `git archive` of it, so the remediation added 83 |
| Full suite | **629 passed**, 0 failed, 0 skipped |
| Broker tests, 3 concurrent runs | **51 / 51 / 51 passed**. Before F-1/F-2, under the mutation load: 49 of 50 in each run. At `c8db56c`, under the same load: 50 / 50 / 50 |
| Stress runs (scratch variants, not committed; loaded host) | First event after a live join: lost in 0 of 36 runs (18 of 36 before F-1). E2: 36 of 36 pass. The #155 test: 18 of 18 pass |
| Groups (within the full suite; the file groups overlap) | fuzz 19, persistence/recovery 83, policy lifecycle 81, FOTA 96, command/replay/zone 127, TLS/handshake 148, broker 51: all passed |
| Fuzz | `test_fuzz.py`: 19 tests of 300 corruptions each; the seeds vary per process. Passed in the full suite and in 3 extra runs |
| Mutation | §15.9: 173 mutants, 170 killed by test failures, 3 classified survivors, 0 errors |
| pyflakes 4.0.0 (throwaway container) | `pqgrid`, `tools`: clean. `tests`: only the pytest fixture-import idiom |
| v2.1 `validate.py` | 80/80 as expected (CORE 47, EDGE 31, RISK 2) on the Git-rebuilt substitute base. It tests the v2.1 reference, not `pqgrid` |
| Documentation numbers | Per-file counts in §15.1–§15.2 and the 546 → 629 totals checked against test discovery. Every test name cited in the Master and in this roadmap exists (script check) |
| Canonical environment | Not buildable here (§15.10) |

### 15.12 Hardware limitations (unchanged: nothing here is [HW])

MCU cycles, whole-application RAM and stack, energy per wake, NOR flash geometry, wear and power-cut behaviour, the
bootloader's power-fail-safe swap, external-slot tamper (V-F4), watchdog budget, TRNG/DRBG seeding (D-8), the MCU
TLS implementation (hybrid groups, max_fragment_length, suite restriction), and radio/NAT/operator-network
behaviour. All of them are open in Master §29, the Hardware Validation Plan, which now has rows for NOR flash, the
bootloader swap and TRNG/DRBG. The Master's device figures are [ANALYTICAL] or [LIT] (with the source's hardware
named) and are never presented as measurements; the prototype's device is Python on a Linux container.

## 16. Codex audit (2026-10-03)

An independent read-only audit (OpenAI Codex) of `main` at `65f0f80` reported 1 P0 and 3 P1 findings and 3
improvements. Each was reproduced or checked against `main` before anything changed (branch
`fix/p1-2-utility-publish` onward). Severities below are this project's, after reproduction; the audit's own label is
given with each.

### 16.1 Triage

| # | Audit claim (audit severity) | Reproduced on `65f0f80` | Verdict | Status |
|---|---|---|---|---|
| P0-1 | A forged staged FOTA artifact activates after a reboot without re-verifying SLH-DSA (P0) | Yes [SIM]: the staged manifest record and the slot rewritten, reboot → `committed`, version 99 | The code re-reads the staged manifest from the normal record store without its signature (only the manifest bytes are stored). The attack needs write access to that store (internal flash); §15.1's attacker is on EXTERNAL flash, which V-F4 covers. The Master never states that the record store is inside the trust boundary | **Fixed in code** (§16.5): the signed manifest is kept in the artifact's area and re-verified; validation pending (§16.6) |
| P1-1 | A class or key change leaves the old session and its commands active (P1) | Yes [SIM]: after `Registry.add` of a changed record, `current_session` still returns the old session and a queued command is still sent | Real. `Registry.add` silently replaces a record; nothing invalidates what the old record authorised. The Master's clone procedure ("revoke and re-provision", §23.11) is safe only because revoking comes first | **Fixed in code** (§16.5); validation pending |
| P1-2 | Failed utility-side publishes lose commands and FOTA state (P1) | The claimed mechanism no; a related defect yes [DOCKER] | §16.2 | **Fixed** (§16.2) |
| P1-3 | SQLite backups are world-readable (P1) | Yes [SIM]: `backup_to()` → 0644 (umask 022); the database itself 0600 | Real; the backup holds the utility's private keys and STEKs. Only a test calls it today | **Fixed in code** (§16.5); validation pending |
| A | A client could negotiate a classical-only TLS group | n/a | Not a defect: the broker's OpenSSL configuration offers and accepts only hybrid groups and TLS 1.3, proven by `test_N3_T7_only_hybrid_tls13_is_accepted`; Python cannot pin groups on the client (E53) | Unchanged |
| B | The installer accepts one anchor | From the code | Real, minor: the Master requires ≥ 2 anchors (O7); `Installer` accepts any number, duplicates and wrong sizes (a provisioning check) | **Fixed in code** (§16.5); validation pending |
| C | Unbounded utility collections | From the code | Real, minor: `UtilityMqtt.alerts`, `telemetry`, `statuses`, `takeover_alarms` are plain lists that grow with valid traffic | **Fixed in code** (§16.5); validation pending |

### 16.2 P1-2: utility-side publishes

**What the audit got wrong.** A QoS 1 publish made while paho is disconnected returns `MQTT_ERR_NO_CONN` (rc 4), but
paho 2.1.0 keeps the message and sends it after reconnecting: it reached a persistent subscriber after a Mosquitto
restart [DOCKER, scratch check against the canonical image]. A utility command is also never recorded as *successful*
without the device's status ACK, so a lost publish could not make the utility believe a command succeeded.

**The defect found while reproducing it.** The `MQTTMessageInfo` of that message keeps rc 4 for good, and
`is_published()` then raises `RuntimeError`. The utility's bookkeeping (`_track`) asked every tracked info that
question on each publish, so ONE publish during a broker outage made every later utility publish raise until a
restart. The message itself still went out, but everything after the raising publish was skipped: after an
establishment, the device's queued commands (already recorded as sent in that session, so not sent again until its
next session), zone keys and DR re-sends; `flush()` (graceful stop) returned at once. Two smaller gaps in the same
place: a publish paho did not queue at all (rc ≠ 0, 4) went unnoticed and its command stayed recorded as sent; and the
publisher recorded an artifact as retained before the broker had it, so an artifact that existed only in paho's memory
when the utility restarted, or that the broker refused (PUBACK 0x87, e.g. a stale ACL), was never published again
(the E-4 offer at establishment skips an artifact it believes retained) for the whole 30-day window.

**Fix** (no new queue: the commands table and the publisher's rollout state are the durable records):

| Part | Change |
|---|---|
| Tracking | `UtilityMqtt._send`: rc 4 is reset to 0 (paho keeps the message), so the info reports the PUBACK like any other; any other rc raises `TransportError` (not queued). Every utility publish goes through it |
| Commands | `CommandService.outgoing(send=…)`: each command is still recorded as sent BEFORE its envelope leaves (a crash can only make its outcome UNKNOWN, never a false EXPIRED); if `send` raises (not handed over), the record is undone (`unmark_sent`) so the next flush of the session sends it, and a command that expires first is EXPIRED |
| Broker refusals | `on_publish` records PUBACKs with a failure reason code (`publish_refusals`) |
| Artifacts | `Published.confirmed` (durable column, default 0 for databases from before §16): set by `Publisher.settle()` only when the broker accepted every message; `Publisher.retry()` (each tick) publishes an unconfirmed, still-valid publication again when nothing is in flight, at most once per `retry_every_s` (60 s): after a restart, or after a refusal |

**Regression tests** (each fails on `65f0f80`):

| Test | Failure on `65f0f80` |
|---|---|
| `tests/integration/test_publish_outage.py::…command_issued_during_a_broker_outage…` | `RuntimeError: Message publish failed: The client is not currently connected` on the next command [DOCKER] |
| `…::…artifact_published_during_an_outage_reaches_the_device_although_the_utility_restarted` | the device never stages the firmware (30 s) [DOCKER] |
| `…::…artifact_the_broker_refused_is_published_again_once_the_broker_accepts_it` | the device never stages the firmware after the ACL is corrected (30 s) [DOCKER] |
| `tests/security/test_utility_publish.py` (7 tests: tracking, not-queued commands incl. EXPIRED vs UNKNOWN, zone key and DR event, confirmation, restart, refusal, no resurrection of an invalid artifact) | `RuntimeError` (2), `DID NOT RAISE TransportError`, nothing published after the restart, and the confirmation API absent (2) [SIM]; the validity test passes on `65f0f80` because nothing was ever published again there |

One existing test changed: `test_a_joining_member_gets_its_read_right_before_its_new_zone_key` stubbed paho's
`publish()` with an object without `rc`; it now returns paho's own `MQTTMessageInfo` (its assertions are unchanged).
Mutants 173–182 cover the new checks (§16.4).

Not changed: the device side already treats any rc ≠ 0 as a failed publish (`DeviceMqtt._publish`), so it never
tracks such an info; an artifact *removal* (empty retained publish after the retention window) is not confirmed, so a
removal lost to a restart leaves a valid, signed, older artifact retained (devices refuse it as a rollback or install
the newest they see).

### 16.3 Validation of the P1-2 fix (2026-10-03)

Canonical image (Debian trixie, OpenSSL 3.5.7, Mosquitto 2.0.21, paho-mqtt 2.1.0), rebuilt from the branch:

| Check | Result |
|---|---|
| Before the fix (`65f0f80` code, new tests) | 3 broker tests and 6 of the 7 in-process tests FAIL as listed in §16.2 [DOCKER] |
| Full suite | **639 passed** (629 + 10 new) [DOCKER] |
| Broker tests | **54 / 54** in 2 runs; the 3 new outage tests alone 3 / 3 in 3 further runs [DOCKER] |
| In-process suite on macOS (`.venv`) | 585 passed, 54 skipped (the broker tests) [SIM] |
| Mutants 173–182 | **10 of 10 KILLED** (canonical image; also locally in the `.venv`) |
| v2.1 `validate.py` | 80/80 as expected (unchanged reference) |
| pyflakes 4.0.1 (throwaway container) | `pqgrid`, `tools`: clean; new test files: only the pytest fixture-import idiom |

### 16.4 Mutation analysis for P1-2

| # | Check disabled | Killed by |
|---|---|---|
| 173 | rc 4 reset (a publish kept for the reconnect) | `…does_not_break_every_later_publish` |
| 174 | a publish the client did not queue raises | `…the_client_did_not_queue_is_not_counted_as_sent` |
| 175 | the sent record of a command that never left is undone | same |
| 176 | confirmed only when EVERY message was acknowledged | `…counts_as_retained_only_once_the_broker_acknowledged_every_message` |
| 177 | a refused message un-does the publication | `…the_broker_refused_is_published_again` |
| 178 | a refusing PUBACK is recorded | same |
| 179 | tick() publishes an unconfirmed artifact again | `…never_reached_the_broker_is_published_again_after_a_utility_restart` |
| 180 | confirmation is durable | `…counts_as_retained_only_once…` (reopened database) |
| 181 | retries rate-limited to retry_every_s | `…the_broker_refused_is_published_again` |
| 182 | a retry never resurrects an invalid artifact | `…no_longer_valid_is_not_published_again` |

### 16.5 The other findings: fixes (2026-10-04, code and tests written; not yet run)

| # | Fix | Regression tests (written; expected to fail on `65f0f80`) |
|---|---|---|
| P0-1 | The device keeps the signed manifest (manifest + SLH-DSA signature, 8,042 B at 128s) in the last `SIGNED_RESERVE` = 8,704 B of the artifact's own area (inactive slot, inactive policy area, KEYREVOKE area); the record store keeps only an index. At boot every recovered download or staged artifact is believed only if that copy verifies now (anchor, signature, DR-050 role with the revocations of now, type and class) and is the very manifest its record names; otherwise it is dropped (`recovery_refused`). Firmware and policy activation verify it once more. Payload capacity is the area minus the reserve (V-F5). The signature needs no trusted storage, so the external slot (C2) is covered too; protected storage (committed versions, revocations) stays the trusted part. The record-store flash budget is unchanged | `tests/security/test_fota_recovery.py` (9): Codex's forged record + slot; a modified kept signature; another artifact's genuine signed manifest; a forged download record (and the genuine one still resumes); the copy modified while running; policy; interrupted KEYREVOKE; the new capacity. `test_power_loss_between_the_commit_and_dropping_the_staged_record` now also requires that the finished commit raises no refusal |
| P1-1 | `Registry.add` refuses to change a registered device's class, key or revocation; `Registry.reprovision` is the only way and stamps `provisioned_at` (durable column, migrated). Ticket check 4 refuses a ticket issued at or before it. `UtilityNode.reprovision`: the device's zone keys rotate first (alone, a crash leaves an extra rotation); then ONE transaction closes its open commands (UNKNOWN if ever sent, CANCELLED if not) and writes the new record; then its sessions, half-open state and GRANTs go (RAM). `UtilityMqtt.reprovision_device` sends the remaining members their new keys and recompiles the ACL. `current_session` also requires the record's class (defence in depth, unreachable through the public API: no mutant) | `tests/security/test_reprovision.py` (6): class change, key change, restart after the change, the record and its commands in one transaction, no overwrite through `add`, zone keys and ACL at the MQTT level; `tests/integration/test_reprovision_mqtt.py` (2, broker): a replaced key (its old ticket refused, full handshake from flash) and a class change with the production ACL hook |
| P1-3 | `backup_to()` creates the copy 0600 whatever the umask and narrows an existing target before writing. `require_owner_only()`: the database and its -wal/-shm/-journal must belong to this user and be closed to group and others; checked on open (also of a restored backup) and before a backup is written | `tests/security/test_db_permissions.py` (5) |
| B | `check_anchors()`: exactly A and B, 32-byte SLH-DSA-SHA2-128s keys, distinct; whenever an `Installer` is built | `tests/security/test_anchors.py` (6) |
| C | `UtilityMqtt.alerts`, `telemetry`, `statuses`, `takeover_alarms`: `BoundedLog(1000)`; overflow counted in `dropped`; `drain()` for the application. `BoundedLog` now bounds `extend()` and `+=` too (the utility added a DF's alerts with `+=`, which bypassed the cap) | `tests/unit/test_utility_inbox.py` (3) |
| Notes | `DeviceMqtt._unacked` updated under a small lock (two threads publish); §15.9 wording corrected ("by a failing test", not "exactly one"). The audit-time note that `policy/validator.py` imported `x509` mid-file was wrong: the import is at the top | — |

Mutants 183–200 cover these checks; mutants 9, 124 and 133 were re-pointed at the rewritten lines (same check disabled).

### 16.6 Validation still to run (next iteration)

Before the fix (`65f0f80` code, new tests) and after it, on the canonical image: the new tests; the full suite; the
broker tests repeatedly; mutants 183–200 and a full mutation run; v2.1 `validate.py`; pyflakes; then a final
read-only security review of the branch. Nothing in §16.5 is claimed fixed until those runs pass.
