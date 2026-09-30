# BalaMP-Rationale — Why Every Design Choice, and What Happens When Things Go Wrong

**Companion to [BalaMP.md](BalaMP.md).** BalaMP.md says *what* we build. This document says:

- **why** each choice beats its alternatives, and what it costs (Part B)
- **what really happens** to a message on the network and when a device reconnects (Parts A and C)
- **what happens when something goes wrong**: duplicates, losses, crashes, restarts, clones, stolen keys,
  malformed input (Parts D and E)

**Team 14** · 2026-09-22 · Every claim below is either a design argument or has an evidence tag pointing to a
test you can re-run with `design-validation/run_all.sh` (inside Docker).

| Evidence tag | Where it lives |
|---|---|
| `[broker T#/F#]` | `design-validation/results/broker.txt`: real Mosquitto experiments |
| `[net N#]` | `design-validation/results/network.txt`: interception proxy between a real meter and the broker |
| `[core]` · `[edge]` · `[risk]` | `design-validation/results/validate.txt`: 47 core, 31 edge-case and 2 documented-risk scenarios |
| `[bench]` · `[sig]` · `[hyb]` | `results/bench.txt`, `signature_speed.txt`, `hybrid_cost.txt` |

All numbers are laptop measurements inside a Linux container, not smart-meter hardware.

---

## Contents

- **Part A — How a message really travels**
  - A1. Two different things called "MAC"
  - A2. The journey of one alert, layer by layer
  - A3. What an attacker can do with a captured message
- **Part B — Every design decision, with alternatives and trade-offs** (B1–B34)
- **Part C — Establishing and re-establishing a session, step by step** (C1–C14)
- **Part D — Edge-case catalogue** (D-NET, D-HS, D-SESS, D-PASR, D-FOTA, D-OPS)
- **Part E — Stolen keys: what each one gives an attacker**
- **Part F — What this analysis changed in the design**

---

# Part A — How a message really travels

## A1. Two different things called "MAC"

The handshake in BalaMP.md §5.2 uses `MAC_U` and `MAC_D`. Those are **not** network addresses.

| | MAC **address** | MAC = **Message Authentication Code** |
|---|---|---|
| What it is | The hardware address of a network interface, e.g. `3c:22:fb:10:4e:9a` | A short cryptographic checksum computed **with a secret key** (we use HMAC-SHA-256) |
| Where it lives | In the outer frame header (Ethernet / Wi-Fi) | Inside our own messages, deep in the payload |
| Changes in transit? | **Yes, at every hop.** Each router strips the frame and builds a new one with new MAC addresses. On a cellular link (NB-IoT / LTE-M) there is no Ethernet MAC at all: the device is identified by radio-level identities, and its IP packets are carried through the operator's core network | **Never.** The sender computes it once; only the receiver checks it |
| Who can produce a valid one | Anyone; addresses are just labels and can be set to anything | Only someone holding the key |
| Role in our design | **None.** Nothing in our security depends on MAC addresses or IP addresses | Proves the other side derived the same keys (`MAC_U`, `MAC_D`); proves ticket possession (binder); authenticates ACKs. TLS uses the same idea in every record (the AEAD tag) |

**So when a packet's MAC address changes on its way to the broker, nothing breaks, and an attacker gains
nothing by forging one.** Identity comes only from secret keys: the certificate private key at the broker
hop, and the static KEM keys end to end. An attacker can claim any MAC or IP address it likes. It still
cannot produce a valid TLS handshake or a valid `MAC_D`.

## A2. The journey of one alert, layer by layer

A meter sends the alert `VOLTAGE_SAG 182V`. Each layer wraps the one above it:

```
 "VOLTAGE_SAG 182V"                                               the alert itself
 └─ end-to-end envelope   0x02 ‖ sid ‖ seq ‖ ChaCha20-Poly1305(K_ALERT|up)   ← sealed ONCE by the meter,
    └─ MQTT PUBLISH       topic grid/smart_meter/meter-0001/alert, QoS 1        opened ONLY by the utility
       └─ TLS 1.3 record  AES-256-GCM with this hop's keys (implicit per-record sequence number)
          └─ TCP segment  ports, sequence numbers, checksum (not security)
             └─ IP packet source address (carrier NAT may rewrite it) → broker's address
                └─ link frame   radio identities / MAC addresses: rebuilt at every hop
```

What happens at each point of the path:

| Point | What is visible | What changes there | What an attacker at that point can do | What stops them |
|---|---|---|---|---|
| Radio link, operator network, routers | Frame and IP headers; TLS ciphertext; packet sizes and timing | Link addresses at every hop; IP address/port at carrier NAT | Record, drop, delay, reorder, inject, flip bits, replay | TLS record authentication with per-connection keys `[net N1, N2]`; hybrid key exchange against later decryption |
| **Broker** (TLS ends here) | MQTT topic, QoS, client identity, **telemetry in plaintext**; alerts and commands only as opaque sealed bytes | TLS removed and re-applied for the next hop; MQTT re-framed (new packet id) | Read telemetry and topic names; drop, delay, replay or inject messages; serve stale retained messages | End-to-end AEAD `[core: curious broker]`; sequence checks; ownership check; utility signatures on commands; station signatures on firmware and policy |
| Broker → utility hop | Same as the first hop | New TLS keys | Same as the first hop | TLS |
| Utility | Everything (it's the endpoint) | — | — (trusted) | — |

**The key idea: the end-to-end envelope is byte-for-byte identical at the meter and at the utility.** Every
layer around it changes along the way, but nobody in the middle can open or alter it without detection.

## A3. What an attacker can do with a captured message

This answers "what if an attacker records a message and uses it to connect?" for every message in the
system.

| Captured item | Replaying it | Modifying it | Using it somewhere else | Evidence |
|---|---|---|---|---|
| **An entire TLS session** (every byte the meter sent) | Replayed to the broker on a new connection: **0 messages delivered**. The broker picks fresh randomness and a fresh key share every time, so the recorded client messages no longer decrypt or verify. The log shows `record layer failure`, and the replayer never even gets an identity (`Client <unknown>`) | — | — | `[net N1]` |
| **One TLS record** | Inside the same connection its sequence number no longer fits, so the connection is dropped | **One flipped bit:** not delivered, connection dropped | Another connection has different keys, so it cannot decrypt | `[net N2]` |
| The device's **certificate** | Public information. In TLS 1.3 it is also encrypted on the wire. Without the private key it proves nothing | — | — | design |
| **MQTT CONNECT** | Only visible inside TLS, or to the broker itself. Contains no password (identity comes from the certificate), so it is worthless | — | — | design |
| End-to-end **client hello** | The utility answers (identically within 120 s), but nobody can finish without the device's ephemeral and static secrets. The live session is untouched | "client hello failed authentication" | Another device's topic: "identity does not match" | `[core]`, `[edge]` |
| **Server hello / finished** | Bound to that device's ephemeral key and pending state; useless elsewhere; duplicates get the same answer | Rejected | Rejected | `[core]`, `[edge]` |
| **Resume hello** | Within 120 s: identical answer, nothing new. Later: "ticket already used". Without the PSK, no keys can be derived | Binder invalid | Another device's channel: "identity mismatch" | `[core]` |
| **Ticket blob** (from the network or from flash) | Without the PSK: "binder invalid", and the genuine ticket still works. With the PSK (device captured): a clone, detected as "ticket already used" | — | — | `[core]`, `[edge]` |
| **Alert envelope** | Sequence rejected | Authentication fails | On another device's topic: ownership check. After the session changes: unknown session | `[core]`, `[edge]` |
| **Command envelope** | Acknowledged as DUP, **never re-applied** | Signature or authentication fails | Another session cannot decrypt it | `[core]` |
| **Demand-response broadcast** | Replay rejected | Signature fails, even for a zone member who has the zone key | — | `[core]` |
| **Firmware manifest / chunk** | Public by design; old version: rollback rejected | Signature / Merkle check fails | Another device class: rejected | `[core]` |
| **Signed policy** | Old version: rollback rejected | Signature fails | — | `[core]` |

---

# Part B — Every design decision, with alternatives and trade-offs

Each decision has the same shape: the **question**, the **options** with their trade-offs, the
**decision**, **why**, and **what would make us change it**.

## Cryptographic foundations

### B1. Key exchange on the broker hop: classical, pure post-quantum, or hybrid?

| Option | Pros | Cons |
|---|---|---|
| Classical X25519 only | Smallest and fastest | Recorded traffic breaks once quantum computers exist: fails the report's core requirement (§1.2) |
| Pure ML-KEM-768 | Quantum-safe; 64 B smaller; no X25519 computation; our base paper (Kim & Seo) uses pure Kyber | One new algorithm protects recordings **forever**. A classical break of ML-KEM (as happened in 2022 to SIKE and Rainbow, two serious post-quantum candidates) would expose everything ever recorded. Default clients also fail to connect unless configured (verified) |
| **Hybrid X25519MLKEM768** | Secure if **either** algorithm holds; OpenSSL's default; what Chrome and Cloudflare deploy; recommended by Germany's BSI and France's ANSSI (reported in Malina et al. [2]) | +64 B per handshake; **about +120% key-exchange computation** (94 µs vs 77 µs `[hyb]`), roughly 0.1 ms on a laptop |

**Decision:** hybrid.

**Why:** what it protects, recorded traffic, can never be re-protected after the fact. The extra cost is
about 0.1 ms and 64 bytes, and resumption removes it from most reconnections.

**Change it if** ML-KEM builds a long, clean record and the targets become 8-bit-class devices, where X25519
is expensive (Kim & Seo, Table 6). Then use pure ML-KEM, as the base paper does.

### B2. Accept any key exchange the client offers, or pin hybrid-only?

| Option | Pros | Cons |
|---|---|---|
| OpenSSL defaults | Zero configuration | **A client offering only classical X25519 is silently accepted** (`Peer Temp Key: X25519` `[net N3]`). A device with an old TLS library, or a downgrade on its side, loses quantum safety and nobody notices |
| **Pin hybrid groups** (`X25519MLKEM768:SecP256r1MLKEM768`) on broker and devices | Fails closed: classical-only clients get a handshake failure `[net N3]` | One OpenSSL config file per process (`OPENSSL_CONF`), because Mosquitto has no groups setting and Python cannot set groups in code |

**Decision:** pin.

**Why:** "post-quantum" must be a guarantee, not a default that can quietly change.

### B3. Where does the protected session live?

| Option | Pros | Cons |
|---|---|---|
| Device ↔ broker only (base paper's KEM-MQTT; report eq. 3.2) | One handshake | The broker reads everything, so "alerts are end-to-end" would be false |
| **Device ↔ utility** (ours) | The broker relays sealed bytes it cannot read or forge | A second handshake per device (5.2 KB), which PASR amortises |
| Encrypt every message to the utility's public key (HPKE-style, no session) | No session state | About 1.1 KB of ciphertext and one KEM operation **per message**; no forward secrecy per message; nothing to resume |
| Broker decrypts and re-encrypts per subscriber (Malina et al. SL2) | Fits pub/sub fan-out | The broker sees plaintext |
| Separate keys for every subscriber | True multi-party end to end | Heavy key distribution; we have exactly one consumer (the utility) |

**Decision:** device ↔ utility.

**Why:** it is the only placement where "the broker cannot read or forge alerts and commands" is true, at 73
bytes and a few microseconds per alert `[bench]`.

**Change it if** several independent parties need to read alerts; then add group keys.

### B4. How does the end-to-end session authenticate each side?

| Option | Pros | Cons |
|---|---|---|
| **KEM-based implicit authentication** (KEMTLS-PDK; Kim & Seo Fig. 4) + ephemeral KEM | No signatures on the device; mutual authentication; forward secrecy; continuity with the base paper | Static public keys must be registered in advance (the utility registry) |
| Signed handshake (TLS-like, with ML-DSA) | Standard pattern; works with certificates | +2 × 3.3 KB signatures plus certificates per handshake; the device must sign with ML-DSA |
| Pre-shared symmetric key per device | Cheapest | A leak of the utility database exposes every device; no forward secrecy unless combined with a KEM |
| Noise-style post-quantum patterns | Elegant | No Python implementation to build on; departs from the base paper |

**Decision:** KEM-based authentication with an ephemeral KEM.

**Why:** the smallest post-quantum mutual authentication, with no post-quantum signing on the device.
Measured at 0.28 ms on the device and 5.2 KB in total `[bench]`.

**Change it if** devices must talk to many utilities they don't know in advance; certificates would then be
needed.

### B5. Hybrid inside the end-to-end handshake too?

The broker relays, and can record, every end-to-end handshake. So the same record-now-break-later argument
as B1 applies. **Decision:** hybrid (X25519 + ML-KEM-768) for all three KEMs in the handshake. The cost is
included in the 0.27 ms above.

### B6. How are the two shared secrets combined?

| Option | Pros | Cons |
|---|---|---|
| Plain concatenation into HKDF | Simplest; safe **when** the transcript (all public keys and ciphertexts) also goes into the KDF, which ours does | Relies on that transcript binding |
| **X-Wing combiner**: `SHA3-256(ss_ML-KEM ‖ ss_X25519 ‖ ct_X25519 ‖ pk_X25519 ‖ label)` | Secure on its own, independent of transcript binding; one extra hash | An IETF CFRG draft. We use its combiner; we do not claim full X-Wing conformance |

**Decision:** X-Wing combiner. Belt and braces for the price of one hash.

### B7. Which cipher encrypts alerts and commands?

| Option | Pros | Cons |
|---|---|---|
| AES-256-GCM | Fastest where AES hardware exists (servers; TLS uses it) | Constant-time software AES is slow on MCUs without AES instructions |
| AES-CCM | Common in IoT radio standards | Two passes; slower |
| **ChaCha20-Poly1305** (RFC 8439) | Fast and constant-time in plain software; 256-bit key | Same catastrophic failure as GCM if a nonce repeats (handled in B8) |
| Ascon-AEAD128 (NIST SP 800-232) | Designed for tiny devices | 128-bit key; we keep 256-bit keys everywhere for quantum margin |

**Decision:** ChaCha20-Poly1305 end to end; AES-256-GCM stays inside TLS.

**Change it if** the targets become 8-bit devices; Ascon then becomes attractive.

### B8. Where do the nonces come from?

| Option | Pros | Cons |
|---|---|---|
| Random 96-bit nonces | Simple | Needs a good random-number generator on every device, and cheap devices have had broken ones |
| **Counter nonces** (direction ‖ sequence) | No randomness needed; cannot collide while the key is fresh | Requires one rule: **a session key and its counter live and die together** |

**Decision:** counter nonces, with separate keys per tier and per direction.

**The rule that keeps this safe:** session keys exist only in RAM, and so do their counters. After a reboot
the device resumes and gets new keys (§C5). We never save a session key to flash, because that could bring
back an old key with a reset counter, which is nonce reuse.

### B9. How are control commands authenticated?

| Option | Pros | Cons |
|---|---|---|
| Session encryption (AEAD) only | No extra bytes | Anyone holding the session key (a device memory dump, or a leak from the utility's session store) can forge commands; no non-repudiation; unusable for broadcast |
| **ML-DSA-65 signature + AEAD** | Only the utility's signing key can create commands; works for broadcast; auditable; key rotatable through the policy | +3.3 KB per command `[bench]`; 0.1 ms to verify `[sig]` |
| ML-DSA-44 | 2.4 KB | Category 2 (the rest of the system is Category 3) |
| FN-DSA (Falcon) | About 0.7 KB | Floating-point arithmetic makes constant-time MCU code hard; not in our Python stack |
| SLH-DSA | Most conservative | 168–324 ms to sign `[sig]`: too slow for live commands |

**Decision:** ML-DSA-65 plus AEAD. Commands are rare, so 3.3 KB each is acceptable.

**Change it if** bandwidth dominates and FN-DSA becomes usable.

### B10. How are firmware and policy signed?

| Option | Pros | Cons |
|---|---|---|
| ML-DSA-65 (the report's original) | 3.3 KB; fast | Relies on new lattice mathematics, for a key that can **never** be replaced |
| ML-DSA + Ed25519 dual signature | Hybrid | Once quantum computers exist, it reduces to ML-DSA alone |
| LMS / XMSS (stateful, hash-based) | Small signatures; the NSA's CNSA 2.0 choice for firmware | **Stateful**: reusing one internal key even once breaks security. Too risky for a student-run signing station |
| SLH-DSA-SHA2-128s | Stateless, hash-based; 7.9 KB; 32 B public key; 0.16 ms to verify | Category 1 |
| **SLH-DSA-SHA2-192s** | Stateless; security rests only on hash functions; 48 B anchor; 0.28 ms to verify `[sig]`; Category 3 like the rest | 16.2 KB per manifest; 0.32 s to sign (offline, once per release) |

**Decision:** SLH-DSA-SHA2-192s.

**Change it if** manifest bandwidth matters more than keeping one security category; then 128s.

### B11. Which certificates on the broker hop?

| Option (both sides) | Full handshake | Resumed | Notes |
|---|---|---|---|
| **ECDSA P-256** | **4,695 B** | 3,613 B | Classical, but authentication can't be attacked after the fact; replaceable at any time `[broker]` |
| ML-DSA-44 | 23,809 B | 7,213 B | Post-quantum; 5× larger |
| ML-DSA-65 | 31,702 B | 8,749 B | Post-quantum; 7× larger. OpenSSL also stores the client certificate inside TLS tickets, so even resumption stays large |
| Composite (hybrid) certificates | — | — | Still IETF drafts; not tested here |
| Raw public keys | — | — | Mosquitto has no configuration option for them (checked its man page) |
| TLS pre-shared keys | small | small | The broker stores a secret per device: one broker breach leaks every credential |

**Decision:** ECDSA P-256 now, with a ready migration to ML-DSA-44 certificates.

**Why:** hop authentication only protects telemetry and topic access. Even if these certificates were forged
someday, alerts and commands stay protected by end-to-end keys and signatures. A quantum computer cannot
attack a connection that already happened.

**Change it** before quantum computers become plausible. The switch is a configuration change.

## What protection goes where

### B12. How many tiers, and why isn't telemetry end-to-end?

| Option | Pros | Cons |
|---|---|---|
| Everything end-to-end and signed | One simple story | +3.4 KB **per reading**. At 96 readings a day that's about 330 KB/day per meter instead of about 6 KB, which is exactly the waste the report calls gap 1 |
| Two tiers | Simpler | Alerts would carry signatures they don't need |
| **Three tiers** (telemetry / alert / control) | Each traffic type gets exactly what it needs | Needs the policy engine (which is objective 1) |
| Per-message flags | Maximum flexibility | Hard to audit; easy to misuse |

**Why telemetry stays readable by the broker:** the utility runs the broker and bills from these readings.
**Caveat:** meter data can reveal occupancy patterns. **Useful property:** a topic's tier is a *policy*
setting. If a third party ever runs the broker, telemetry can move to ALERT-style protection by publishing a
new signed policy, with no code change.

### B13. What if several policy rules match one topic?

| Rule | Pros | Cons |
|---|---|---|
| First match (firewall style) | Familiar | A broad rule placed too early silently weakens specific topics |
| Most specific wins | Intuitive | A careless specific rule can deliberately weaken a topic |
| **Strongest wins; no match → CONTROL** | Adding a rule can only strengthen protection; a forgotten topic gets maximum protection | You cannot carve out a weaker exception under a stronger wildcard (restructure the topics instead) |

**Decision:** strongest wins.

### B14. Who enforces what?

| Where | Enforces | Why there |
|---|---|---|
| Broker | Who may publish or subscribe where (access list compiled from the signed policy, hot-reloaded `[broker]`) | The only place that can keep one device off another device's topics `[broker T3, F1]` |
| Device and utility | The cryptographic tier of every message | Only they hold the keys |

**Rejected:** crypto enforcement in the broker. It cannot check end-to-end cryptography without keys, and a
plugin would add C code with no security gain.

### B15. How does the policy reach devices?

| Option | Pros | Cons |
|---|---|---|
| **Signed artifact through PQC-FOTA** | Offline signature; rollback-proof; works even when no session can be established (bootstrap) | Slower to change (goes through the signing station) |
| Command signed by the utility | Fast | The policy carries the utility's own keys, which it cannot certify itself; a compromised utility could downgrade the policy |
| Broker configuration only | Easy | Devices would trust the broker: exactly the downgrade we want to prevent |

**Decision:** signed artifact through PQC-FOTA.

## Session lifecycle

### B16. How does a device recover its session cheaply?

| Option | Pros | Cons |
|---|---|---|
| Never resume | Simplest | Full handshake every time: 5.2 KB and 0.28 ms on a laptop; seconds on 8-bit hardware |
| Keep sessions forever | No handshakes | Key exposure grows over time; lost at reboot anyway |
| Utility stores a session cache | No ticket cryptography | Per-device state, shared across utility servers; a database leak exposes every PSK |
| **Stateless tickets** (ours) | The utility keeps only the STEK and a small used-ticket list; the device carries its own state; survives utility restarts `[edge]` | A stolen STEK allows forged tickets `[risk]`, so it needs an HSM |
| TLS resumption only | Standard | Cannot bind policy, firmware or tier; does not check revocation; covers the hop, not end to end |

**Decision:** stateless tickets for the end-to-end session, plus standard TLS resumption on the hop.

### B17. Who issues tickets: broker or utility?

A ticket resumes a session, so its issuer must hold that session's secret. The broker is deliberately
excluded from the session, so **the utility issues tickets**. A bonus: a compromised broker cannot mint
tickets.

### B18. Single-use or reusable tickets?

| Option | Pros | Cons |
|---|---|---|
| Reusable | Fewer ticket messages | Clones are invisible; wider replay window |
| **Single-use** | Clone detection (the second user gets "ticket already used" `[edge]`); replay closed `[core]` | +266 B per resumption for the replacement ticket; a small used-ticket list, bounded by ticket expiry |

**Decision:** single-use.

### B19. Resume modes, and the rule for devices that receive commands

| Mode | Device cost | Forward secrecy | Used for |
|---|---|---|---|
| PSK | 0.021 ms, 755 B `[bench]` | No | Meters (low-sensitivity traffic, the most constrained devices) |
| PSK+KEM | 0.144 ms, 3,103 B | Yes | Classes that receive unicast commands |

**Rule, enforced when the policy is validated:** a class with `unicast_control` must use PSK+KEM, or not
resume at all.

**Why not always PSK+KEM?** On constrained hardware the ML-KEM step *is* the expensive part. Meters gain the
most from skipping it.

### B20. How is replay stopped?

| Option | Pros | Cons |
|---|---|---|
| Timestamps | Stateless | Needs synchronised clocks, which are fragile after outages (B21) |
| Random nonces + a cache | Handles reordering | Memory grows |
| **Strict counters + the two-phase rule** | O(1) memory; a forged message never burns a valid number `[core]` | An older message arriving late is dropped. Alerts are resent under new numbers; for commands, the newest wins `[edge]` |
| Sliding window (IPsec-style) | Tolerates reordering | More complexity |

**Decision:** strict counters. MQTT keeps per-topic order on one connection.

**Change it if** reordering is observed in testing; then use a 64-message window.

### B21. Where does a device get the time? (added by this analysis)

| Option | Pros | Cons |
|---|---|---|
| Device's own clock | No dependency | **Resets after power loss.** In v1, a device at "1970" was refused as "stale client hello" (verified in the v1 code). A device clock running ahead rejects fresh commands as expired |
| NTP | Standard | Unauthenticated: an attacker can shift time so expired commands look fresh |
| Authenticated NTP (NTS) / cellular network time | Better | Extra dependency; not end-to-end authenticated |
| **Utility time inside the authenticated handshake** | Free; authenticated; available on every handshake and resume | Accurate only to network delay (seconds), which is fine for command expiries measured in minutes |

**Decision:** utility-authenticated time. The device's own time is informational only.

**Evidence:** a device at 1970 connects and corrects its clock; a device a day ahead still accepts fresh
commands `[edge]`.

### B22. How do we know an alert or command actually arrived? (added by this analysis)

| Option | Pros | Cons |
|---|---|---|
| MQTT QoS 1 only | Built in | The acknowledgement comes from the **broker**, not the utility. If the utility restarts, alerts are silently lost `[edge]` |
| QoS 2 | Exactly-once per hop | Still not end to end; more round trips |
| **End-to-end ACKs** | Real delivery confirmation. Alerts carry an ID, so resends are recognised as duplicates `[edge]`. Command ACKs carry a status (OK / DUP / EXPIRED), and commands are applied at most once `[edge]` | About 70 B per ACK |

**Decision:** end-to-end ACKs.

### B23. How are duplicate messages handled? (added by this analysis)

MQTT QoS 1 is "at least once", so **duplicates are normal, not an attack**. In v1, a duplicated client hello
broke the handshake, a duplicated finished crashed the utility (`KeyError`), and a duplicated resume hello
killed a valid ticket. All three were verified in the v1 code.

**Decision:** idempotent handlers. The same request within 120 s gets the same stored answer `[edge]`;
alert IDs and command sequence numbers de-duplicate at the application level.

**Rejected:** QoS 2. It is per-hop only and costs extra round trips.

## Updates

### B24. How are firmware chunks protected?

| Option (1 MiB image, 4 KiB chunks) | Signed manifest | Extra per chunk | Total | Arrival order |
|---|---|---|---|---|
| Flat hash list | 8 KB, growing with the image (128 KB at 16 MiB) | 0 | 8 KB | Any |
| Hash chain | 32 B | 32 B | 8 KB | **Must be in order** |
| Signature per chunk | — | 16 KB | 4 MB | Any |
| **Merkle tree** (RFC 6962) | **32 B, always** | 256 B | 64 KB (6%) | Any |

**Decision:** Merkle tree, with chunk size set per class in the policy. At 64 KiB chunks the overhead drops
to 2 KB.

**Honest trade-off:** Merkle costs more bandwidth than a flat list, and saves device memory.

### B25. How is firmware delivered?

| Option | Pros | Cons |
|---|---|---|
| **Retained MQTT messages** | A device collects the update whenever it connects | The broker stores images (needs `persistence true`: without it retained artifacts vanish on restart `[net N5]`); needs cleanup after rollout |
| Device requests missing chunks | Efficient on lossy links | More utility logic |
| HTTP or CoAP file server | Standard for big images | A second protocol and port on every device |

**Decision:** retained messages with broker persistence; on-demand re-requests are future work.

### B26. How is rollback prevented?

| Option | Pros | Cons |
|---|---|---|
| Timestamps | — | Needs trusted time |
| Allow / deny lists | Flexible | Must be maintained; complex |
| **Monotonic counter + A/B slots, committed after a successful boot** | Simple; a failed boot reverts safely `[edge]` | The counter must live in storage that a factory reset cannot erase |

**Why the commit timing matters (added by this analysis):** if the counter moved forward *before* the new
firmware proved it boots, a bad image would strand the device. It couldn't go back (counter), and the new
image doesn't work.

## Engineering

### B27. How are messages encoded?

| Option | Pros | Cons |
|---|---|---|
| JSON | Readable | Not byte-identical across implementations (the Semester 1 problem); large |
| CBOR / COSE (what IETF SUIT uses) | Standard; compact; interoperable | Needs a library and deterministic-encoding rules |
| Protocol Buffers | Compact | Not deterministic by specification |
| **Length-prefixed binary** | Trivial, deterministic, strict; survived 19,800 corrupted inputs `[edge: fuzz]` | Not a standard |

**Decision:** our format for the prototype; SUIT / COSE encoding is the natural production upgrade.

### B28. How do handshake messages travel?

| Option | Pros | Cons |
|---|---|---|
| MQTT 5 enhanced authentication (the report's idea) | Built into CONNECT | Makes the **broker** the other party, which is wrong for end to end; Mosquitto needs a C plugin for custom methods |
| A separate HTTPS channel to the utility | Familiar | A second protocol, port and firewall path |
| **Ordinary MQTT topics** with response topic + correlation data | Verified to pass through the broker intact `[broker T5]` | Asynchronous: needs duplicate and loss handling (done: B23, C1) |

**Decision:** ordinary MQTT topics.

### B29. Which broker?

Mosquitto 2.0:
- small C broker, and the report's choice
- OpenSSL-based, so hybrid key exchange works
- access list hot-reloads on SIGHUP `[broker]`

EMQX and HiveMQ bring clustering and plugins we don't need. Python brokers are easy to change but have
immature MQTT 5 support. **Decision:** Mosquitto, using the verified Debian image.

### B30. Which implementation language?

Python: the team knows it, and `cryptography` provides ML-KEM, ML-DSA and X25519. The trade-off is that
numbers are laptop-class. Constrained-hardware measurements (C on an ESP32 or ARM board) are future work,
said openly.

### B31. How does a device prove its identity to the broker?

| Option | Pros | Cons |
|---|---|---|
| Username and password | Simple | Stored at the broker; can be phished and reused |
| TLS pre-shared key | Small | The broker stores secrets |
| **Certificate; CN = device ID** | The private key never leaves the device; the broker stores nothing secret | Needs a CA. IDs must use a safe character set (see D-OPS-4) |

### B32. Where are keys stored?

| Key | Prototype | Production |
|---|---|---|
| Device keys | Files | Secure element |
| Utility STEK and command key | Files | HSM (the STEK especially: see Part E) |
| Station signing key | Files | Offline HSM or smart card |

### B33. Where do we develop and measure?

Docker only. The host stays untouched, and every result is reproducible from one script.

### B34. One live session per device, or many?

One. A new session replaces the old one. That simplifies replay tracking and makes clones visible, because
the clone's session is evicted `[edge]`.

---

# Part C — Establishing and re-establishing a session, step by step

Sizes are measured `[bench]`/`[broker]`. Times are laptop-in-container figures.

### C1. First connection after installation

```
Meter                             Broker (Mosquitto)                         Utility
 1  TCP handshake ─────────────────▶
 2  TLS 1.3 ClientHello  (X25519MLKEM768 key share, hybrid-only)  ──▶
      ◀── ServerHello (ML-KEM ciphertext) + broker certificate + signature + Finished
    client certificate + signature + Finished ──▶        ≈ 4.7 KB total with ECDSA certificates
      ◀── TLS NewSessionTicket (hop-level, standard)
 3  MQTT CONNECT (client id = device id; identity from certificate CN) ──▶  ◀── CONNACK
 4  SUBSCRIBE: own control topic, pqgrid/hs/{id}/down, firmware and policy topics
 5  End-to-end hybrid KEM-MQTT handshake (the broker only relays):
    CH  2,493 B ─────────────────────▶ ─────────────────────────────────────▶ checks id, registry, class, POLICY_INFO
                                       ◀──────────────────────────────────── SH  2,411 B (carries authenticated time)
    device verifies MAC_U, sets its clock
    DF     42 B ─────────────────────▶ ─────────────────────────────────────▶ verifies MAC_D → session
                                       ◀──────────────────────────────────── NT 266 B (ticket) or FIN
 6  device marks the session CONFIRMED only now, then sends any queued alerts
```

- **End-to-end part:** 5.2 KB; 0.28 ms on the device and 0.23 ms on the utility `[bench]`.
- **Hop part:** 4.7 KB.
- **If a message is lost:** the device retries the same step. Duplicates get identical answers (C-rules in
  D-HS).

### C2. Normal operation

| Traffic | What happens |
|---|---|
| **Telemetry** | Plain MQTT publish inside TLS |
| **Alert** | Sealed with an alert ID (+73 B). The utility answers with an end-to-end ACK. Unacknowledged alerts stay in the flash outbox |
| **Command** | Signed and sealed by the utility (+3.4 KB). The device checks the signature, expiry and sequence, applies it once, and returns a signed-status ACK. The utility re-sends unacknowledged commands on the next session |

### C3. The link drops (cellular dead spot, broker keep-alive timeout); RAM intact

1. New TCP connection.
2. **TLS 1.3 resumption:** 0.53 ms instead of 1.9 ms `[broker F2]`.
3. MQTT CONNECT.
4. **The end-to-end session simply continues.** It lives in the device and the utility, not in the
   broker, so there is no handshake.
5. Anything unacknowledged is resent.

Commands the broker queued for the device are still readable, because the session keys didn't change.

### C4. The device's IP address changes (carrier NAT, cell handover)

Same as C3. TLS resumption does not depend on the IP address: verified from `127.0.0.1` to `172.17.0.2`
`[net N7]`. Identity comes from keys, never from addresses (A1).

### C5. Power outage: the device reboots (RAM lost, flash kept)

1. Full TLS. Python cannot save TLS sessions across restarts; real firmware could.
2. MQTT CONNECT.
3. **PASR resume** using the ticket stored in flash:

| Mode | Size | Device time | Utility time |
|---|---|---|---|
| PSK | 755 B | 0.021 ms | 0.030 ms |
| PSK+KEM | 3,103 B | 0.144 ms | 0.103 ms |

4. The resume reply carries authenticated time, which fixes the clock that the outage reset.
5. The replacement ticket arrives.
6. The flash outbox (alerts sent but never acknowledged) is resent with the **same alert IDs**, so the
   utility can recognise duplicates `[edge]`.
7. The utility re-sends unacknowledged, unexpired commands **with the same sequence number and signature**,
   re-encrypted under the new keys. The device applies each at most once `[edge]`.

### C6. Outage restoration: thousands of meters reboot together

Every meter does C5. Per device, the utility spends 0.030 ms on a PSK resume versus 0.23 ms on a full
handshake, and 755 B versus 5.2 KB. The broker still performs full TLS for each one; that is the E4
experiment's broker-CPU measurement. Reconnections should use random jitter.

### C7. The utility restarts

1. Sessions are lost. The STEK and the used-ticket list are **persisted**.
2. The next alert from a device fails with "unknown session", and the utility sends a **resync hint**.
3. The device resumes with its ticket, and the unacknowledged alert is resent and acknowledged `[edge]`.

Without persistence, every ticket in the fleet would die and every device would need a full handshake at
once `[edge: counterfactual]`. The hint is unauthenticated, so a forged one only triggers one cheap
resumption; further hints are rate-limited to one per 30 s `[edge]`.

### C8. The broker restarts

- Devices do a full TLS handshake, because the broker has new ticket keys.
- **End-to-end sessions are unaffected.**
- Retained firmware and policy survive **only with `persistence true`** `[net N5]`.

### C9. A ticket expires, or the chain reaches its age limit (≤ 7 days)

The device does a full handshake (C1 step 5), which re-checks its static keys, the registry and the current
policy.

### C10. New firmware is installed

1. Download to the inactive slot.
2. Verify SLH-DSA and every Merkle chunk.
3. Reboot into the new image.
4. The self-test passes, so **commit**: the version counter moves forward.
5. The new firmware version means old tickets are refused, so the device does a full handshake.

If the self-test fails: revert, and the counter stays unchanged `[edge]`.

### C11. The policy changes

1. The utility publishes signed policy v(n+1) with an `activate_at` time. Devices download it early.
2. At `activate_at`, the utility refuses old-policy sessions and tickets.
3. Devices re-handshake after a random 0–60 s delay.
4. The broker access list is regenerated from the new policy and reloaded with SIGHUP.

A device that missed the policy fails closed until it installs it `[core]`.

### C12. A device is revoked

1. The registry marks it inactive, so every full handshake and every resumption is refused `[core]`.
   Plain TLS resumption would not check this.
2. The access list removes its topics.
3. The CA revokes its certificate.

### C13. A device comes back after months offline

1. It connects; the TLS certificate and CA must still be valid (see D-OPS-1).
2. It fetches the latest retained policy, installing v(n) directly and skipping missed versions `[edge]`.
3. It does a full handshake. Its commands have long expired and are never redelivered `[edge]`.

### C14. A clone appears (device keys extracted and copied)

**Broker hop:** the clone connects with the same identity and the genuine device is kicked off ("already
connected, closing old connection" `[net N4]`).

**End to end:** whoever uses the ticket second gets "ticket already used" `[edge]`. That is an alarm the
utility must act on (revoke and re-provision).

---

# Part D — Edge-case catalogue

**Residual risk** means what remains after our design.

## D-NET — The network

| # | Situation | What could go wrong | What the design does | Evidence | Residual risk |
|---|---|---|---|---|---|
| NET-1 | MAC addresses rewritten at every hop | Someone thinks identity or integrity breaks | Identity and integrity never use addresses (A1) | design | None |
| NET-2 | Carrier NAT / IP address changes | The session breaks | TLS resumes across IP changes; the end-to-end session is independent of addresses | `[net N7]` | None |
| NET-3 | Attacker records and replays the whole TLS session | Unauthorised connection | New randomness and keys per connection; 0 messages delivered | `[net N1]` | None |
| NET-4 | Bit flipped in a TLS record | Modified message accepted | Record authentication fails; connection dropped | `[net N2]` | Denial of service only |
| NET-5 | Client offers only classical key exchange | Silent loss of quantum safety | Hybrid-only pinning; handshake refused | `[net N3]` | None when pinned |
| NET-6 | MQTT QoS 1 duplicates | Handshakes break, commands apply twice | Idempotent handlers; alert IDs; command sequence numbers | `[edge]` | None |
| NET-7 | Message lost | Stuck handshake; lost alert or command | Step retries; end-to-end ACKs; outbox; redelivery | `[edge]` | Delay |
| NET-8 | Packet larger than the limit | Broker memory exhaustion | `max_packet_size` (300 KB); chunk size set below it | `[net N6]` | None |
| NET-9 | Nagle's algorithm with delayed ACK | Misleading ~90 ms latency measurements | `set_tcp_nodelay true` + client `TCP_NODELAY` | `[broker F2]` | None |
| NET-10 | Half-open TCP (dead link) | Device believes it's connected | MQTT keep-alive; the broker publishes a Last Will "offline" status (informational) | design | Detection delay ≈ 1.5 × keep-alive |
| NET-11 | Broker restart | Lost retained updates | `persistence true`; the end-to-end session is unaffected | `[net N5]` | None |
| NET-12 | Traffic analysis (who, when, how big) | Metadata leaks | — | — | **Out of scope** (stated) |

## D-HS — Handshakes

| # | Situation | What could go wrong | What the design does | Evidence |
|---|---|---|---|---|
| HS-1 | Duplicate client hello | v1: handshake broke | Identical answer from the duplicate cache | `[edge]` |
| HS-2 | Duplicate finished | v1: utility crashed (`KeyError`) | Identical final message; exactly one session | `[edge]` |
| HS-3 | Server hello lost | Stuck | Device retries with a fresh hello; the late original reply is rejected | `[edge]` |
| HS-4 | Finished lost | Device thinks it's connected, utility doesn't, alerts vanish | Device waits for NT/FIN before sending anything; resends finished | `[edge]` |
| HS-5 | Final (ticket) lost | Device never confirmed | Resent finished returns the same stored final | `[edge]` |
| HS-6 | Device clock reset (1970) or ahead | v1: locked out; fresh commands "expired" | Utility-authenticated time | `[edge]` |
| HS-7 | Old client hello replayed by the broker | Hijack or disruption | Cannot be completed; live session unaffected | `[edge]` |
| HS-8 | Client hello on another device's topic | Impersonation | Identity must equal the topic ID | `[core]` |
| HS-9 | POLICY_INFO tampered, either direction | Silent downgrade | Authentication fails; handshake aborts | `[core]` |
| HS-10 | Device and utility on different policy versions | Mismatched rules | Fail closed until the device installs the current policy | `[core]` |
| HS-11 | Handshake flood from one device | Utility memory exhaustion | At most one half-open handshake per device, forgotten after 60 s | `[edge]` |
| HS-12 | Corrupted or malformed messages | Crash, or acceptance | Strict parser, 1 MiB field cap, constant-time comparisons; **19,800 corrupted messages across 6 random seeds, all rejected cleanly** | `[edge: fuzz]` |
| HS-13 | Two handshakes race for one device | Two live sessions | The newest completed session replaces the old one; the old one gets resync | `[edge: clone]` |

## D-SESS — Messages inside a session

| # | Situation | What could go wrong | What the design does | Evidence |
|---|---|---|---|---|
| SESS-1 | Utility restarts | Alerts silently lost | Resync hint → resume → outbox resent → ACK | `[edge]` |
| SESS-2 | Device reboots | Session lost | Resume from the flash ticket; outbox resent | `[edge]` |
| SESS-3 | Alert ACK lost | The utility processes the alert twice | Alert ID de-duplication | `[edge]` |
| SESS-4 | Command sent while the device is offline | Command lost | Redelivered on the next session; applied once | `[edge]` |
| SESS-5 | Command ACK lost (also when the device reboots before the redelivery) | Endless retries, or a double apply | Device answers DUP without re-applying; the applied counter is in flash | `[edge]` |
| SESS-6 | Command expires in transit | Stale command applied | Not redelivered; refused as EXPIRED if it arrives late | `[edge]` |
| SESS-7 | Commands arrive out of order | An old setpoint overrides a newer one | Newest wins; the older one is acknowledged but not applied | `[edge]` |
| SESS-8 | Forged resync hint | Forced re-handshakes | One cheap resumption; further hints rate-limited | `[edge]` |
| SESS-9 | Captured meter re-publishes another meter's alert as its own | Spoofed alert | Ownership check: the topic's device must match the session | `[edge]` |
| SESS-10 | Plaintext message on an ALERT topic | Tier stripped | Refused | `[core]` |
| SESS-11 | Session keys saved to flash with a reset counter | **Nonce reuse, which is catastrophic** | Rule: keys and counters live only in RAM; reboot means new keys (B8) | design |
| SESS-12 | Sequence counter overflow | Wraparound | 64-bit counters; re-key long before (sessions last ≤ 7 days) | design |

## D-PASR — Resumption

| # | Situation | What the design does | Evidence |
|---|---|---|---|
| PASR-1 | Ticket replayed later | "ticket already used" | `[core]` |
| PASR-2 | Same ticket, fresh request (a clone) | "ticket already used" → alarm | `[core]`, `[edge]` |
| PASR-3 | Duplicate resume request | Identical answer (v1: killed the ticket) | `[edge]` |
| PASR-4 | Stolen blob without the PSK | "binder invalid"; the genuine ticket survives | `[core]` |
| PASR-5 | Expired ticket or chain | Refused → full handshake | `[core]` |
| PASR-6 | Policy / firmware change, or revocation | Refused | `[core]` |
| PASR-7 | Mode downgrade (fresh KEM stripped) | Refused | `[core]` |
| PASR-8 | Ticket key retired | Refused | `[core]` |
| PASR-9 | Utility restart without a persisted STEK | Every ticket dies → avoided by persisting it | `[edge]` |
| PASR-10 | Consumed ticket replayed after a utility restart | Refused (used list persisted) | `[edge]` |
| PASR-11 | **STEK stolen** | ⚠ Tickets can be forged for any device: **shown working** `[risk]` → the STEK belongs in an HSM, rotated daily | `[risk]` |

## D-FOTA — Updates

| # | Situation | What the design does | Evidence |
|---|---|---|---|
| FOTA-1 | Tampered chunk or manifest | Merkle / signature failure | `[core]` |
| FOTA-2 | Forged artifact | Signature failure | `[core]` |
| FOTA-3 | Rollback or replay of an old version | Counter refuses it | `[core]` |
| FOTA-4 | Wrong device class | Refused | `[core]` |
| FOTA-5 | Chunks from two versions mixed | Refused | `[edge]` |
| FOTA-6 | Power loss mid-download | Restart from the retained chunks | `[edge]` |
| FOTA-7 | New firmware fails to boot | Revert; counter unchanged; retry possible | `[edge]` |
| FOTA-8 | Device offline across several policy versions | Installs the newest directly; older ones refused | `[edge]` |
| FOTA-9 | Broker restart | Retained artifacts survive with persistence | `[net N5]` |
| FOTA-10 | Retained chunks cleared while a slow device is still downloading | Keep a retention window (e.g. 30 days); re-request is future work | design |
| FOTA-11 | Broker **withholds** updates | Cannot be prevented, only detected (stretch goal: signed freshness heartbeat) | design |
| FOTA-12 | Factory reset erases version counters | Counters must sit in protected storage (production requirement) | design |

## D-OPS — Operations

| # | Situation | What the design does |
|---|---|---|
| OPS-1 | TLS CA replaced while devices are offline | Overlap: deliver the new CA certificate through a signed update **before** switching the broker's certificate |
| OPS-2 | Utility keys rotated | New signed policy carrying the new keys → all devices re-handshake at `activate_at` |
| OPS-3 | Policy rollout causes a reconnection storm | `activate_at` + random 0–60 s jitter |
| OPS-4 | Device IDs with `+`, `#`, `/`, uppercase, spaces or unicode | Rejected at provisioning (`^[a-z0-9][a-z0-9-]{0,31}$`), otherwise they could inject rules into the broker's access list `[edge]` |
| OPS-5 | Flash wear from writing the command counter every time | Write counters in reserved blocks (e.g. every 100) |
| OPS-6 | Detailed error messages help attackers probe | The utility answers failures with nothing, or at most a resync hint; details only in its own log |
| OPS-7 | Several utility servers (high availability) | Share the STEK and the used list (HSM + database); out of prototype scope |
| OPS-8 | Mosquitto running as root | Test configurations only (labelled). The build runs it as the `mosquitto` user with correct file ownership |

---

# Part E — Stolen keys: what each one gives an attacker

| Stolen | Attacker gains | Still safe | Recovery | Evidence |
|---|---|---|---|---|
| One **device's** keys (captured device) | Acts as that one device: its telemetry, alerts, and its own tickets | Every other device; commands (needs the utility's signing key); past sessions (forward secrecy) | Revoke in the registry, access list and CA; re-provision | `[core]` revocation |
| One device's **TLS key** only | Can connect as it at the hop (and kick the genuine device off); can fake its telemetry | Alerts and commands (no end-to-end keys) | Revoke the certificate | `[net N4]` |
| **Utility end-to-end key** | Can impersonate the utility in **new** handshakes and read those alerts | **Commands**: a forged command is still rejected (separate ML-DSA key); past sessions | New policy with a new key | `[risk]` shown |
| **Utility command key** | Can sign commands; with a session or zone key, can send them | Firmware and policy (the station key) | New policy with a new key | design |
| **STEK** | Can forge tickets → impersonate devices by resumption; read PSK-mode resumed sessions | Full-handshake and PSK+KEM sessions' confidentiality; commands | Rotate the STEK; HSM | `[risk]` shown |
| **Station key** | Can sign firmware and policy for the whole fleet: **catastrophic** | — | Physical re-provisioning. Hence offline storage, the hash-only algorithm (B10), and optionally a second backup anchor in the bootloader | design |
| **TLS CA** | Can impersonate the broker or devices at the hop | Everything end to end | New CA via a signed update (OPS-1) | design |
| **The broker itself** | Read telemetry; drop, delay or replay messages; withhold updates | Alerts, commands, firmware and policy authenticity | Rebuild the broker; nothing on devices needs to change | `[core]`, `[net]` |

This is why the design uses **separate keys for separate jobs**: an end-to-end key, a command key, a
station key, a STEK, and a TLS CA. Stealing one never gives everything.

---

# Part F — What this analysis changed in the design

## Bugs found and fixed (each reproduced on the v1 code before fixing)

| # | Bug | How it was found |
|---|---|---|
| 1 | A duplicated client hello broke the handshake ("device key confirmation failed") | QoS 1 duplicate test |
| 2 | A duplicated finished crashed the utility (`KeyError`) | Probe of v1 |
| 3 | A duplicated resume hello killed a valid ticket ("ticket already used") | Probe of v1 |
| 4 | A device whose clock was reset by an outage was refused ("stale client hello") | Probe of v1 |
| 5 | A final message with an unknown type label was accepted | Fuzz test |
| 6 | MAC comparisons were not constant-time | Code review |

## Design gaps closed

- **Explicit confirmation.** The device waits for NT or FIN before trusting a session.
- **End-to-end ACKs.** Alert IDs, command statuses, redelivery, and apply-at-most-once.
- **Utility-authenticated time.** The device clock is no longer a gate.
- **Persistence and resync.** The STEK and the used-ticket list are saved, and a resync hint follows a
  utility restart.
- **A/B firmware slots.** The counter commits only after a successful boot.
- **Input limits.** Device-ID character rules, a cap on parser field size, and a bound on half-open
  handshake state.
- **Ownership check.** An envelope must belong to the device that owns its topic.
- **Broker configuration.** Hybrid-only key exchange pinned; `persistence true`; `max_packet_size`.

## Risks shown honestly, not hidden

- Stolen STEK (needs an HSM).
- Stolen utility end-to-end key (commands still safe).
- Stolen station key (catastrophic; physical recovery).
- A clone can kick the genuine device off the broker (denial of service plus a detection signal).
- Traffic analysis and denial of service in general.
