# Objective 1: PCHC-MQTT, Results Report

**Per-topic Cryptographic Hierarchy Control for MQTT in the smart grid.** Team 14, NITK. Results from the final
`pqgrid` code (`main`), measured on 2026-10-06.

Raw evidence this report is built from:

| File | What it is | Produced by |
|---|---|---|
| `results/objective1-scenarios.md` | Every scenario run live over the real broker (S1–S8), with the bytes on the wire | `tools/demo_objective1.py` |
| `results/objective1.md` | Tier table, per-tier sizes and compute, handshake cost, attack table | `tools/bench_objective1.py` |
| `IMPLEMENTATION-ROADMAP.md` §16 | Test, mutation and review history | the validation runs |

---

## 1. Summary

- **Every scenario works end to end over a real MQTT broker:** telemetry, alert, command, GRANT and set-point,
  broadcast event, and a policy change (**11 of 11 checks passed**).
- **Every downgrade, tampering, replay and forgery attempt is refused**, each with a precise reason: 10 in-process
  attacks (A1–A10) and 5 over the real broker (plaintext injection, a forged command, a replayed command, a
  classical-only TLS client, a TLS 1.2 client).
- **Protection matches importance:** a meter reading costs nothing extra (TLS only); an alert costs **+73 bytes** (end-
  to-end encryption); a command costs **+3,402 bytes** (encryption plus a post-quantum signature). Heavy cryptography
  is spent only where it is needed.
- **The full post-quantum handshake** costs **5,221 bytes** and **0.30 ms** (device) / **0.23 ms** (utility) on a laptop.
- **Quality:** 701 automated tests pass, including 57 against the real broker (three runs); 229 of 232 mutants are
  caught (the 3 survivors are proven harmless); three independent code reviews were fixed and re-verified.

---

## 2. What Objective 1 does

A smart grid sends three kinds of message. Objective 1 gives each the protection it needs, decided by a **signed
policy** that nobody can quietly weaken.

| Tier | Example | Protection | Who can read it | Who can forge it |
|---|---|---|---|---|
| **TELEMETRY** | Meter reading | Hybrid post-quantum TLS on every hop | Broker, utility | Broker |
| **ALERT** | "Tamper detected" | + end-to-end encryption, numbered, acknowledged | **Only the utility** | **Only the device** |
| **CONTROL** | "Curtail solar to 50%" | + end-to-end encryption + **ML-DSA-65 signature** | Only the target device | **Nobody without the utility's command key** |

The policy's identity (POLICY_INFO = name and version) is **bound into the session keys**: changing it, or using an
older policy, makes the handshake fail.

---

## 3. How the evaluation was done

### 3.1 An emulation testbed, not hardware and not a simulation

| | What it means here |
|---|---|
| **Real** | The Mosquitto MQTT broker; hybrid TLS 1.3 (X25519MLKEM768) from OpenSSL 3.5; the NIST post-quantum algorithms ML-KEM-768, ML-DSA-65 and SLH-DSA; the complete protocol code (handshake, tiers, commands, policy). Real encrypted messages over real TCP sockets |
| **Emulated** | The devices: a smart meter and a solar/battery (DER) controller run as Python programs instead of microcontrollers; their flash memory is simulated in software |
| **Why** | No smart-meter hardware was available. Emulation runs the real protocol and the real cryptography, so correctness, security and **message sizes** are genuine; only device speed, memory and energy are not |

Environment: Docker container (Debian trixie, Linux aarch64), Python 3.13.5, `cryptography` 50.0.1, OpenSSL 3.5.7,
Mosquitto 2.0.21, paho-mqtt 2.1.0, on a laptop. Labels used: **[DOCKER]** measured in this testbed;
**[LIT]** from published microcontroller measurements; **[ANALYTICAL]** calculated.

### 3.2 How the programs run

```
 ┌──────────────┐  TLS 1.3 (X25519MLKEM768)   ┌────────────────┐   TLS 1.3 (X25519MLKEM768)  ┌──────────────┐
 │ Device        │ ──── TCP socket ──────────▶ │ Mosquitto      │ ◀──── TCP socket ───────── │ Utility       │
 │ (meter / DER) │                             │ broker         │                            │ (control      │
 │ main loop     │ ◀─────────────────────────── │ (server        │ ─────────────────────────▶ │  centre)      │
 │ tick every 1 s│     MQTT publish/subscribe   │  process)      │     MQTT publish/subscribe  │ main loop     │
 └──────────────┘                              └────────────────┘                            └──────────────┘
        ▲                       end-to-end handshake and messages (the broker only relays)          ▲
        └──────────────────────────────────────────────────────────────────────────────────────────┘
```

- **The broker** is a real server process listening on a TCP port.
- **Each device and the utility** run a **main loop**, `run()`: it calls `tick()` (reconnect if needed, handshake if
  needed, housekeeping), waits one second, and repeats **until it is told to stop**. A separate network thread
  (paho) keeps the TLS socket to the broker open and handles incoming messages as they arrive.
- **So the system runs continuously, like real devices**, until it is stopped. `tools/demo_objective1.py --forever`
  shows this: after the scenarios, the meter keeps sending a reading every 5 seconds and the utility keeps receiving
  them, until Ctrl+C.

---

## 4. Algorithms used in Objective 1

| Layer | Algorithm | Job |
|---|---|---|
| Every hop (all tiers) | TLS 1.3 with **X25519MLKEM768** (hybrid), ECDSA P-256 certificates, AES-256-GCM or ChaCha20-Poly1305 | Encrypts each connection; post-quantum key exchange; mutual identity |
| End-to-end handshake (ALERT, CONTROL) | **Hybrid KEM** (ML-KEM-768 + X25519, X-Wing combiner), used 3 times; SHA-256 transcript; HKDF-SHA-256; HMAC-SHA-256 | Device and utility agree on keys the broker cannot know; mutual authentication without signatures; POLICY_INFO bound into the keys |
| Message protection (ALERT, CONTROL) | AES-256-GCM or ChaCha20-Poly1305 with sequence numbers | Encrypts each message end to end; blocks replays |
| Commands (CONTROL) | **ML-DSA-65** (NIST FIPS 204) | Only the utility's command key can create a command |
| The policy | **SLH-DSA-SHA2-128s** (NIST FIPS 205), offline | Nobody can install a weaker or forged policy |

---

## 5. Scenario results (live, over the real broker)

Two emulated devices: `meter-0001` (smart meter: telemetry and alerts) and `der-0001` (DER controller: also takes
commands). Sizes are the bytes each program handed to MQTT; TLS adds its own record overhead on top.
Source: `results/objective1-scenarios.md` [DOCKER].

### S1. Connect and establish the end-to-end session

| | |
|---|---|
| **Input** | Each device's certificate and key pair; the utility's public key from the signed policy |
| **What happens** | Hybrid TLS 1.3 to the broker, then the end-to-end handshake with the utility: CH → SH → DF → NT |
| **Observed** | meter: CH 2,493 B → SH 2,411 B → DF 46 B → NT 271 B; DER: 2,488 → 2,415 → 46 → 270 B. Both sessions established, bound to policy *nitk-grid v1* |
| **Result** | **PASS** |
| **Why it matters** | Keys the broker cannot learn; both sides authenticated; the policy locked into the keys |

### S2. TELEMETRY: a meter reading

| | |
|---|---|
| **Input** | `kWh=1234.5;V=230.1;A=4.2` (24 B) |
| **What happens** | Published over the TLS connection; no end-to-end layer |
| **Observed** | 24 B sent as is; the utility received the reading |
| **Result** | **PASS** |
| **Why it matters** | Frequent, low-risk data stays cheap; it is still post-quantum protected on every hop |

### S3. ALERT: "TAMPER: cover opened"

| | |
|---|---|
| **Input** | Alert kind `TAMPER`, text `cover opened` (12 B) |
| **What happens** | Encrypted end to end with the session's alert key, numbered, kept in the device's flash outbox; the utility opens it and replies with an ACK; the device then deletes it |
| **Observed** | Envelope 85 B (12 B text + 73 B protection); **the text does not appear in the bytes the broker carries**; ACK 65 B; outbox empty |
| **Result** | **PASS** |
| **Why it matters** | The broker can neither read nor alter alerts; alerts survive outages (outbox until ACK) |

### S4. CONTROL: a discrete command

| | |
|---|---|
| **Input** | `CURTAIL 50%`, valid for 300 s |
| **What happens** | The utility gives it a never-repeating command number, **signs it with ML-DSA-65**, encrypts it end to end; the device decrypts, verifies the signature, checks it is new and unexpired, applies it, replies `OK` |
| **Observed** | Envelope 3,413 B (11 B command + 3,402 B protection, including the 3,309 B signature); status 83 B; applied once |
| **Result** | **PASS** |
| **Why it matters** | Even a hacked broker, or someone who stole a session key, cannot create a command |

### S5. CONTROL: one GRANT, then a SETPOINT

| | |
|---|---|
| **Input** | GRANT: target `P_ACTIVE_W` between −5,000 and +5,000 W, at most 12 changes a minute, for 1 hour; then SETPOINT 2,500 W |
| **What happens** | The GRANT is signed once (ML-DSA-65) and bound to this session; each SETPOINT is only encrypted and is applied only within the GRANT's limits |
| **Observed** | GRANT 3,477 B; SETPOINT 97 B (no signature); the device applied 2,500 W |
| **Result** | **PASS** |
| **Why it matters** | Fast control without a 3.3 KB signature per update: for a set-point every 5 s, radio airtime drops from about 7 hours to about 35 minutes a day at 20 kbit/s (Master §13.3, [ANALYTICAL]) |

### S6. CONTROL broadcast: a demand-response event

| | |
|---|---|
| **Input** | Zone `f7` with the DER as member; event `SHED 20% 14:00-16:00`, valid 600 s |
| **What happens** | The device receives the zone key (134 B); the event is encrypted with the zone key and signed with ML-DSA-65 |
| **Observed** | Event 3,440 B; the device verified and accepted it |
| **Result** | **PASS** |
| **Why it matters** | One message reaches a whole zone, and members cannot forge events for each other |

### S7. Attacks over the broker

| # | Attack | Observed | Result |
|---|---|---|---|
| S7a | Plaintext (tier-stripped) message published on an ALERT topic | Utility refused it: not an end-to-end envelope | **PASS** |
| S7b | A command sealed with a valid session key but signed with the wrong key | Device answered `REJECTED:signature`; not applied | **PASS** |
| S7c | S4's command envelope sent again (replay) | Device refused it as a replay; applied only once | **PASS** |
| S7d | A client offering only classical X25519 key exchange | Broker refused the TLS handshake (alert 40, handshake failure) | **PASS** |

### S8. Policy change

| | |
|---|---|
| **Input** | A new signed policy, version 2, active 6 seconds later |
| **What happens** | Delivered ahead of time (through Objective 2's pipeline); at the activation time the utility closes every v1 session; both devices re-handshake under v2 |
| **Observed** | Policy *nitk-grid v1* → *nitk-grid v2*; both sessions now bound to v2 |
| **Result** | **PASS** |
| **Why it matters** | The whole fleet moves to new rules together; nobody can keep using old, weaker rules |

**Total: 11 of 11 checks passed.**

---

## 6. Cost per tier (64-byte payload)

Median of 180 runs after 20 warm-up runs, on a laptop [DOCKER]. Source: `results/objective1.md`.

| Tier | End-to-end envelope | Overhead | MQTT packet | Device (ms) | Utility (ms) |
|---|---|---|---|---|---|
| TELEMETRY | none (64 B as is) | **0** | 108 B | — | — |
| ALERT | 137 B | **+73 B** | 178 B | seal 0.0056 | open 0.0100 |
| CONTROL: command | 3,466 B | **+3,402 B** | 3,504 B | open + verify + apply 0.1125 | sign + seal 0.5572 |
| CONTROL: GRANT | 3,477 B | — | 3,515 B | open + verify 0.1126 | sign + seal 0.4399 |
| CONTROL: SETPOINT | 97 B | — | 135 B | 0.0077 | 0.0071 |
| CONTROL: broadcast event | 3,484 B | +3,420 B | 3,525 B | — | — |

**Reading the table:**
- **The overhead is fixed, whatever the payload:** an alert always adds 73 B and a command always adds 3,402 B. The
  live run confirms it: a 12-byte alert became 85 B, an 11-byte command became 3,413 B.
- **A command is about 54 times the size of the same 64-byte content sent as telemetry** (3,466 B against 64 B;
  about 32 times counting the full MQTT packets, 3,504 B against 108 B). That is exactly why signatures are used only
  for CONTROL, and why GRANT + SETPOINT exists for frequent control.

### Full end-to-end handshake

| Device class | CH | SH | DF | NT | Total | Device | Utility |
|---|---|---|---|---|---|---|---|
| smart_meter | 2,493 B | 2,411 B | 46 B | 271 B | **5,221 B** | 0.299 ms | 0.229 ms |
| der_ctrl | 2,488 B | 2,415 B | 46 B | 270 B | **5,219 B** | 0.296 ms | 0.226 ms |

### On a real microcontroller (not measured here)

Laptop times say nothing about a smart meter. From published Cortex-M4 measurements [ANALYTICAL from LIT: pqm4 and
others, Master §22.1]: the end-to-end handshake needs about **5.8 M cycles (91 ms at 64 MHz)**; a cold start (TLS +
end-to-end) about **308 ms**; verifying one ML-DSA-65 command about **38–90 ms**. These are estimates from other
researchers' hardware, not our measurements.

---

## 7. Which tier a topic gets

The signed policy's rules decide; **the strongest matching rule wins; a topic no rule matches gets CONTROL**.

| Topic | Tier | Why |
|---|---|---|
| `grid/smart_meter/meter-0001/telemetry` | TELEMETRY | rule |
| `grid/smart_meter/meter-0001/alert` | ALERT | rule |
| `grid/der_ctrl/der-0001/control` | CONTROL | rule |
| `grid/dr/f7/AES256GCM/event` | CONTROL | rule (broadcast) |
| `grid/smart_meter/meter-0001/debug` | CONTROL | no rule matches: fail-safe default |
| `grid/smart_meter/meter-0001/alert` with an extra careless rule `grid/#` → TELEMETRY | ALERT | strongest rule wins |
| `grid/+/meter-0001/alert` (not a valid topic) | CONTROL | fail-safe default |

---

## 8. Security results

All attempts are refused [DOCKER]. Sources: `results/objective1.md` (A1–A10, N3) and
`results/objective1-scenarios.md` (S7).

| ID | Attack | Refused because |
|---|---|---|
| A1 | Broker changes POLICY_INFO in the client hello | client hello failed authentication |
| A2 | Broker changes POLICY_INFO in the server hello | server hello failed authentication |
| A2b | Broker changes the utility's key confirmation | utility key confirmation failed |
| A4 | Device still on an older, weaker policy | POLICY_INFO mismatch: device must install the current policy |
| A5 | Broker looks for an alert's text | not present: the alert is encrypted end to end |
| A6 | Plaintext message on an ALERT topic | malformed alert envelope |
| A7 | Device asked to send an alert on a TELEMETRY topic | topic is not ALERT tier under the installed policy |
| A8 | Replayed alert | sequence number not newer |
| A9 | Replayed command | sequence number not newer |
| A10 | Command forged with a session key but not the command key | REJECTED:signature, not applied |
| N3 | Classical-only TLS client; TLS 1.2 client | broker: handshake failure; protocol version |
| S7a–d | The same kinds of attack, live over the broker | see §5, S7 |

**What this shows:** the broker cannot read alerts or commands, cannot forge or replay them, cannot downgrade a
device's policy or tier, and cannot force classical-only cryptography.

---

## 9. Verification of the implementation

| Check | Result |
|---|---|
| Automated tests (canonical Docker image) | **701 passed** |
| Tests against the real broker | **57 / 57**, in three runs |
| Mutation testing (a security check deliberately disabled; a test must fail) | **229 of 232 caught**; the 3 survivors are proven harmless (a check that a later step repeats, a case the rules make impossible, and one that would need a SHA-256 break) |
| Independent code reviews | Three reviews (OpenAI Codex); every finding fixed, with a test that fails on the old code and passes on the new |
| Design checks (reference prototype) | 80 / 80 |

---

## 10. What these results do and do not show

**They show:**
- the protocol works correctly, end to end, over a real broker;
- every tested attack is refused, for the right reason;
- the exact message sizes per tier (the same on any hardware).

**They do not show:**
- speed, memory or energy on a real smart meter (estimates from published measurements are in §6);
- behaviour on real radio networks (NB-IoT, LTE-M);
- a formal proof of security (we rely on NIST-standard algorithms in hybrid mode, plus attack and mutation testing).

**Known limitations (documented):**
- TELEMETRY is readable by the broker by design (the utility runs the broker); sensitive data belongs on ALERT topics;
- TLS certificates are classical ECDSA (post-quantum certificates would make each handshake about 23.8 KB instead of
  4.7 KB); they can be switched later through the signed policy;
- hardware validation is future work (Master §29: an nRF9160 DK and a Cortex-M board).

---

## 11. How to reproduce

```bash
docker build -t pqgrid-validation design-validation
docker build -f docker/pqgrid-tests.Dockerfile -t pqgrid-tests .
docker run --rm pqgrid-tests python tools/demo_objective1.py            # the scenarios, live over the broker
docker run --rm -it pqgrid-tests python tools/demo_objective1.py --forever   # keeps running until Ctrl+C
docker run --rm pqgrid-tests python tools/bench_objective1.py           # sizes, costs, attacks
docker run --rm pqgrid-tests                                            # the full test suite
```

---

## 12. For the final presentation

**How to describe the setup (say this):**

> "We built a working software prototype and evaluated it on a Docker-based emulation testbed. The broker, the hybrid
> TLS and the NIST post-quantum algorithms are real, and real encrypted messages travel over real sockets. Only the
> devices are emulated: because we had no smart-meter hardware, we wrote Python programs that behave like a meter and
> a solar controller, running continuous loops just like device firmware. So we can prove the protocol is correct and
> secure, and the message sizes are exact; device speed and energy we take from published microcontroller
> measurements, and hardware testing is our future work."

**Suggested demo (about 2 minutes):** run `tools/demo_objective1.py` and walk through S1 → S8; finish with the attack
step (S7) and the summary table. Optionally start it with `--forever` to show the system keeps running.

**Likely questions:**

| Question | Answer |
|---|---|
| Is this a simulation? | No. The real code, broker and cryptography run; only the device hardware is replaced, like testing an app in a phone emulator |
| Why no hardware? | No devices were available. Correctness, security and message sizes do not depend on the hardware; speed and energy do, and we quote published measurements for those |
| Why hybrid cryptography? | ML-KEM is new; if a flaw is found, X25519 still protects the data, and if a quantum computer breaks X25519, ML-KEM still does |
| Why is telemetry only TLS? | It is frequent and low risk, and the utility runs the broker; the per-message cost of more protection is not justified |
| Why sign commands if they are already encrypted? | Encryption keeps the broker out; the signature means only the utility's command key can create a command, even if a session key is stolen |
| Can the broker downgrade a device? | No. The policy identity is inside the handshake and the keys; any change makes the handshake fail (A1, A2, A4) |
| How do you know the tests are good? | Mutation testing: we deliberately disabled each security check, and the tests caught 229 of 232; the 3 others are proven harmless |
