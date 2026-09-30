# BalaMP Audit — Constrained-IoT and Smart-Grid Review of Design v2.1

**Project:** Post-Quantum Secure MQTT for Smart Grid Communication (Team 14, NITK)
**Audits:** [BalaMP.md](BalaMP.md) v2.1 and [BalaMP-Rationale.md](BalaMP-Rationale.md), dated 2026-09-22
**Date:** 2026-09-22
**Status:** **audit only.** Neither BalaMP.md nor BalaMP-Rationale.md has been changed. Part 16 lists the
proposed changes; nothing is applied until you approve.

**New evidence, all reproducible inside Docker:** [`design-validation/constrained-audit/`](design-validation/constrained-audit/)

| File | Contents |
|---|---|
| `run_audit.sh` | One command runs every audit experiment |
| `results/state.txt` | Crash and restart behaviour of the reference implementation |
| `results/tls_time.txt` | TLS ticket lifetime, small TLS records, clocks and certificates, PSK hop |
| `results/transport.txt` | MQTT packet limits, bytes on the wire, simulated NB-IoT and LTE-M links |
| `results/analysis.txt` | Budgets calculated from cited inputs |

---

## 0. How to read this

**Why this audit exists.** The 80/80 validation shows that the protocol logic is correct on a laptop. It does
not show that a smart meter can run it. This audit keeps those two questions apart:

- *security validation*: does the design stop the attacks?
- *hardware feasibility*: can the target device afford it in RAM, flash, CPU, radio time and energy?

**Evidence labels.** Every number carries one of these:

| Label | Meaning |
|---|---|
| **[DOCKER]** | Measured in this project's Docker container (Debian trixie, OpenSSL 3.5, Mosquitto 2.0.21, Python 3.13) on an Apple-silicon laptop. It is **not** a device measurement. |
| **[SIM]** | Resource-constrained simulation: Docker plus a modelled link (delay and rate). Not NB-IoT, not an MCU. |
| **[LIT]** | Taken from a named paper, standard or datasheet. The source's hardware is always stated. |
| **[ANALYTICAL]** | Calculated from [LIT] or [DOCKER] inputs; the formula lives in `constrained-audit/analysis.py`. |
| **[HW]** | Cannot be settled without real hardware. Stated as an open question, never as a number. |

**Rules followed**
- A Docker process with CPU or memory limits is never treated as an MCU.
- One MCU's benchmark is never presented as "all IoT".
- A laptop number is never presented as an MCU number.
- No energy number was invented. Energy appears only where a source measured it, and each one is marked
  measured or estimated.

**Colours used in the decision matrix (Part 14)**

| Colour | Meaning |
|---|---|
| **GREEN** | Keep as is |
| **YELLOW** | Keep, but add a requirement or fix an explanation |
| **ORANGE** | Change needed for some device classes or traffic profiles |
| **RED** | A defect, or infeasible for a stated target; must change before implementation |

---

## 1. Verdict

**The v2.1 security logic holds.** No attack from §9 of BalaMP.md becomes possible because of anything
found here.

**But v2.1 as written is a design for gateways and well-resourced cellular devices.** Tested against the
devices the report names as targets (NB-IoT/LTE-M smart meters, DER controllers, EV chargers, gateways),
the audit found:

- 7 **RED** issues:
  - three state bugs in the reference code, which Semester 2 would inherit because §8.5 promotes that code;
  - one clock deadlock;
  - one silent delivery failure;
  - two feasibility limits: which device classes are in scope, and high-rate control.
- 7 **ORANGE** issues that depend on traffic profile or device class.
- 14 **YELLOW** items.

Almost every fix is a change to a state machine, a configuration setting or a class profile. None needs a
new algorithm or a new architecture.

| # | Finding | Evidence | Colour |
|---|---|---|---|
| 1 | **Clock deadlock.** A device whose clock resets to 1970, or runs years ahead, is refused by TLS ("certificate is not yet valid" / "has expired"). The E2E layer's utility-time repair never runs, because it needs TLS first. The v2.1 "1970 device reconnects" test only exercised the E2E layer | T4 [DOCKER] | **RED** |
| 2 | **Commands silently lost after a utility restart.** The utility's per-device command counter lives only in RAM. After a restart it starts again at 1, the device answers DUP, and the utility deletes the command | S1 [DOCKER] | **RED** |
| 3 | **Command applied at most once, possibly never, and wrongly confirmed.** The flash counter is written before actuation. A power cut in between loses the command, sometimes after an "OK" was already sent | S2 [DOCKER] | **RED** |
| 4 | **Utility persistence is not crash-safe and does not scale.** `open(path, "w")` truncates first, so a torn write stops the utility restarting. The whole used-ticket file is rewritten per resume: about 480 GB/day at 100,000 devices | S3, S4 [DOCKER] | **RED** |
| 5 | **Silent manifest non-delivery.** A device that declares an MQTT 5 Maximum Packet Size of 16,384 B or less never receives the 16,405 B signed manifest. No error reaches it | T1 [DOCKER] | **RED** |
| 6 | **v2.1 cannot run on RFC 7228 Class 0/1 devices.** The report's "hardware-independent" claim is false. Peak RAM is about 50 KB with default TLS buffers, before any application code | Parts 5, 10 [ANALYTICAL] | **RED (scope)** |
| 7 | **Per-command ML-DSA-65 at the report's own traffic source rate** (Alghawli: a DER set-point every 5 s) costs about 61 MB/day and 7 h/day of airtime at 20 kbit/s | Part 6 [ANALYTICAL] | **RED for that profile; GREEN at IEEE 2030.5 rates** |
| 8 | **Reconnection dominates meter traffic.** For a meter waking every 15 min, security handshakes are 97–98% of its bytes (0.44–0.62 MB/day). The broker's TLS ticket lasts only 2 h | T2 [DOCKER], Part 6 [ANALYTICAL] | ORANGE |
| 9 | **PASR saves bytes and CPU, but not round trips.** Over high-latency links, time is dominated by round trips | T6 [SIM], Part 7 | ORANGE |
| 10 | **Device RAM is dominated by TLS record buffers (16 KB), not post-quantum crypto.** Small-record negotiation works with this broker (MFL 512 → 529 B records) | T3 [DOCKER] | ORANGE |
| 11 | **On a Cortex-M4, the classical parts cost the most.** ECDSA and X25519 are 79% of a cold start's public-key cycles; ML-KEM is 21% | Part 3 [ANALYTICAL from LIT] | YELLOW |
| 12 | **A per-device PSK on the hop is not available as a quantum-safe option with Mosquitto 2.0.** PSK works only on TLS 1.2, with classical FFDHE-3072. The hybrid-only pin does not stop it | T7 [DOCKER] | YELLOW |

**What survives unchanged:** ML-KEM-768; hybrid key exchange at both layers; the Merkle tree; A/B slots with
commit after boot; the strongest-rule policy engine; counter nonces; end-to-end ACKs; the duplicate cache;
hybrid-only pinning on TLS 1.3 listeners.

---

## 2. Evidence base

### 2.1 The six reference papers, re-read for hardware facts

| Paper | Hardware actually used | Algorithm and level | RAM / flash | Time | Energy | Sizes | Network | What it really supports | Corrections |
|---|---|---|---|---|---|---|---|---|---|
| **Kim & Seo, ASIA CCS 2025** (base paper) | ATmega4808: 8-bit AVR, 6 KB SRAM, 48 KB flash, clocked at 7.37 MHz. Kyber-768/1024 were run on an ATmega1280p (8 KB SRAM) | Kyber-512 (Cat. 1) KEM-MQTT; no signatures | Stack: Kyber ~3 KB; MQTT request 5,726 B; response 5,184 B. OpenSSL needs ≥ 16 KB | Client total 31.83 M cycles = 4.32 s | ~71.75 mJ **calculated** from an assumed 5 mA at 3 V, **not measured** | Kyber-512 pk 800 B, ct 768 B | None: MQTT exchange simulated on the chip; "excluding the physical transmission time" | A **pure** Kyber-512 handshake fits an 8-bit node. TLS does not | The report's "4.32 s handshake with only 3 KB stack" mixes two numbers: 3 KB is the Kyber code; the handshake phases used about 5.7 KB |
| **Malina et al., ARES 2024** | Raspberry Pi Zero (1 GHz, 512 MB) plus two phones; **5 repetitions** on the Pi | Falcon-1024 and Kyber-1024 (**Level 5**) | — | Pi: Falcon-1024 sign 145 ms, verify 3.96 ms; Kyber-1024 encaps 17.17 ms, decaps 14.99 ms | None | Falcon-1024 sig 1,330 B (max); Kyber-1024 ct 1,568 B | LAN | Level-5 PQC is usable on a Linux-class board. Their **broker decrypts and re-encrypts** (it is semi-trusted). Group keys are Kyber-encrypted and **Falcon-signed per subscriber** | The report quotes 145 ms and 17 ms without saying they are Level-5 values from 5 runs. The paper says "Cortex-A53" for a 1-core Pi Zero; the original Pi Zero is an ARM11. Treat its hardware description with care |
| **Setyowati et al., ICCED 2025** | 3 virtual machines; Node-RED; Mosquitto | **TLS 1.2 with ECDHE**, plus a **separate ML-KEM-768 microservice over HTTP** (liboqs) | — | 108.80 ms vs 95.6 ms baseline (~13%); CPU 1–5% | None | — | Virtualised | Application-layer ML-KEM added to classical TLS costs a small latency increase on servers | **Not a TLS 1.3 hybrid group.** The report's "hybrid TLS with ML-KEM-768 for MQTT" overstates it. It does not support X25519MLKEM768 performance claims; our Docker tests and Tasopoulos do |
| **Alghawli et al., Frontiers 2026** | NS-3 simulation of IEEE 802.15.4 (250 kbit/s), 6LoWPAN, RPL, CoAP/UDP. Crypto timed on a **Raspberry Pi 4B** (liboqs 0.10.1; INA219 at 1 kHz) | ML-KEM-512/768/1024; ML-DSA-44/65/87 (they deploy ML-KEM-1024 + ML-DSA-87) | Pi process peak memory 96–224 KB | Pi: ML-KEM-768 enc 0.27 / dec 0.34 ms; ML-DSA-65 sign 1.21 / verify 0.47 ms | Pi, INA219: ML-KEM-768 0.61 mJ; ML-DSA-65 1.88 mJ. Radio energy is **simulated** (TX 17.4 mA, RX 19.7 mA at 3 V) | 802.15.4 fragments: ML-KEM-768 14, ML-DSA-65 42 | Simulated mesh | Traffic model: meter 128 B every **15 s**, DER set-point 96 B every **5 s**, substation 160 B every 10 s | **Not MQTT, not cellular.** A meter reading every 15 s contradicts the report's own AMI description (5–15 **min**). Use it only as a stress profile |
| **Domingo Martín et al., ITASEC 2025** | **2012 Intel Core i5-3427U laptop** (SUPERCOP); the authors warn it is not a meter | Signature survey: ML-DSA, Falcon, SLH-DSA 'f' variants | — | Laptop cycles only | None | Table 6 mislabels ML-DSA-87 with ML-DSA-44 sizes. SLH-DSA sizes listed are 'f' variants. Table 2 calls a ciphertext a "Signature" and gives ML-KEM-1024 pk 1,586 B (actual 1,568 B) | — | Falcon is judged the best fit for meters. Meters get firmware through **data concentrators over DLMS/COSEM**, about **once a year** | The report's "sub-millisecond ML-DSA verification … weekly firmware updates" uses **laptop** numbers, and the paper says updates are yearly, not weekly |
| **Suleiman & Javeed, ICEEE 2025** | Orange Pi Zero 2W (Cortex-A7, 1.2 GHz) and Raspberry Pi Zero 2 W (Cortex-A53, 1 GHz), both 512 MB; broker on Windows 10; QoS 0 | ASCON-128 + Kyber-768 | ~1.7–1.9 MB process memory | ASCON 6–91 µs; Kyber-768 encaps 1.66 / 6.12 ms | Supply current only (0.15–0.24 A at 5 V) | — | LAN | Kyber plus a lightweight AEAD is fast on Linux-class boards | The text **swaps** the two boards' Kyber numbers relative to Table I(b). It says a "256-byte" shared secret truncated to a "128-byte" key (these are **bits**: 32 B and 16 B). Its AES-GCM baseline of 1.2 ms per 256 B is implausibly slow. Do not rely on its figures |

**What the six papers do not contain:** any measurement on a cellular smart meter or MCU-class device running
TLS plus MQTT. Only Kim & Seo measure an MCU, and they avoid TLS entirely.

### 2.2 Outside evidence used in this audit

| Source | Hardware | Algorithms and level | RAM / flash | Time | Energy | Sizes | Network | What it supports |
|---|---|---|---|---|---|---|---|---|
| **pqm4 (mupq), benchmarks.md** | NUCLEO-L4R5ZI, **Cortex-M4F at 24 MHz** (no flash wait states), gcc 11.3 | ML-KEM-512/768/1024; ML-DSA-44/65/87; SPHINCS+ (= SLH-DSA) SHA-2 s/f | Stack excludes key, ct and sig buffers. ML-KEM-768 stack: 2.8 KB (small) or 6.5 KB (fast). ML-DSA-65 verify stack: 2.7 KB (small) or 9.9 KB (fast). Code 13–25 KB, excluding hashing | ML-KEM-768 keygen / encaps / decaps: 0.64 / 0.66 / 0.71 M cycles. ML-DSA-65 verify 2.42 M. SLH-192s verify 13.5 M; SLH-128s verify 7.47 M | — | — | — | MCU cost of every PQ primitive in the design |
| **pqm4, tag Round3** | STM32F4DISCOVERY, Cortex-M4 at 24 MHz | Falcon-512/1024 | Falcon-512 sign stack 2.6 KB, but 81 KB code + 40 KB RAM tables | Falcon-512 verify 0.47 M; sign 39 M cycles | — | — | — | FN-DSA verification is very cheap; signing is expensive and needs floating point |
| **Haase & Labrique, TCHES 2019** | STM32F407, Cortex-M4 | X25519 | — | 625,358 cycles per scalar multiplication | — | 32 B | — | Cost of the classical half of the hybrids |
| **Düll et al., Des. Codes Cryptogr. 2015** | AVR ATmega; MSP430X; Cortex-M0 | X25519 | — | AVR 13.9 M; MSP430X 5.3 M (32-bit multiplier); M0 3.59 M cycles | — | — | — | X25519 cost on 8-bit, 16-bit and M0 parts |
| **Chhetri et al., arXiv 2603.19340 (preprint, 2026)** | RP2040, **Cortex-M0+ at 125 MHz**, 264 KB SRAM; PQClean reference C | ML-KEM-512/768/1024; ML-DSA-44/65/87; mbedTLS P-256 | ML-KEM-768 decaps 18.9 KB total; **ML-DSA-65 sign 86.7 KB**; code 5–9 KB | ML-KEM-768 total 56.6 ms; ML-DSA-65 verify 72.2 ms; sign mean 256.6 ms (p99 952.8 ms); P-256 ECDSA verify 321.4 ms | **Estimated** from a datasheet, **not measured** | FIPS sizes | — | M0+ is ~2× slower than M4 per cycle; ML-DSA **signing** does not fit Class 2 in reference C |
| **Tasopoulos et al., ISPEC 2022** | NUCLEO-F439ZI, **Cortex-M4 at 180 MHz**, 192 KB SRAM, 2 MB flash; wolfSSL + lwIP; Ethernet RTT 0.49 ms | PQ TLS 1.3, mutual auth; Kyber and Dilithium/Falcon/SPHINCS+ at L1/L3/L5 | Static memory: Dil2+Kyb1 49.6 KB; Dil3+Kyb3 69.1 KB; ECDSA+ECDHE 2.4 KB | Client handshake: Dil2+Kyb1 96 ms; **ECDSA+ECDHE 109 ms**; Dil3+Kyb3 157 ms; Sph1s+Kyb1 67 s. ECDSA sign 12.3 ms, verify 25.2 ms | — | Handshake bytes: Dil2+Kyb1 14,748; ECDSA+ECDHE 2,353; Dil3+Kyb3 20,224 | Ethernet LAN | On an M4, **PQ TLS is not slower than classical TLS**; the cost is **bytes and RAM** |
| **Tasopoulos et al., CF'23 (MalHIoT)** | Same board; **PicoScope measurement across a shunt, whole board at 3.3 V** (including ~100 mW idle) | Same | — | — | **Measured**: Kyber-768 keygen / enc / dec 1.89 / 1.80 / 1.24 mJ; ECDSA verify 4.78 mJ; Dilithium3 verify 2.59 mJ; SPHINCS+-128s verify 12.0 mJ; TLS client Dil2+Kyb1 15.0 mJ; ECDSA+ECDHE 18.2 mJ | — | LAN | Crypto energy per handshake is tens of mJ on a board-level measurement |
| **Anastasova et al., eprint 2024/2083** | STM32F413, Cortex-M4 at 76.6 MHz; wolfSSL | Fully hybrid TLS 1.3 (X448 + Kyber1024; Ed448 + Dilithium5) | — | 114 M cycles hybrid handshake vs 44.4 M classical (×2.77 wolfSSL) | — | — | UART at 115,200 bit/s | An upper-end hybrid (Level 5) data point on an M4 |
| **Lukic et al., arXiv 2005.13648** | Quectel BC68 NB-IoT module, **live operator network** (Serbia); on-board current sensing | — | — | Default inactivity timer 5 s | **Measured charge** per UDP echo: ~275 / 282 / 318 / 415 mAs for 16 / 64 / 256 / 1,024 B (read from their Fig. 6). "Active waiting" is ~64% of it | Minimum header: MQTT/TCP/IPv4 74 B vs MQTT-SN/UDP 37 B | NB-IoT, urban | **Radio fixed costs dominate** per-message energy |
| **3GPP NB-IoT primer (Wang et al., arXiv 1606.04171)** | — | — | — | Rel-13 latency target ≤ 10 s at 164 dB MCL; peak ~26 kbit/s DL, ~62–66 kbit/s UL (multi-tone) | — | — | NB-IoT | Round trips of seconds, rates of tens of kbit/s |
| **Standards** | — | FIPS 203/204/205 (final, Aug 2024). **FIPS 206 (FN-DSA) is a draft**, submitted for approval Aug 2025 and not final in the sources found. SP 800-232 Ascon (final, 13 Aug 2025). SP 800-208 / RFC 8554 LMS. RFC 7228 device classes. MQTT 5.0 [MQTT-3.1.2-25]. RFC 6066 max_fragment_length. RFC 5280 §4.1.2.5 notAfter 99991231235959Z. CNSA 2.0 (LMS/XMSS for firmware; constrained devices by 2033) | — | — | — | — | — | Standard status and sizes |
| **Vendor docs** | nRF9160 SiP (Cortex-M33, 1 MB flash, 256 KB RAM, CryptoCell 310). Its modem's offloaded TLS is documented as TLS 1.2 / DTLS 1.2 client. SAM4CM metering SoC (dual Cortex-M4, 120 MHz, up to 2 MB flash and 304 KB SRAM; AES-GCM, SHA-256, ECC accelerators, TRNG, battery-backed RTC). MSP430F6765A metering SoC (16 KB RAM, 128 KB flash). wolfSSL 5.8.0 (hybrid ML-KEM groups including X25519). Mbed TLS / TF-PSA-Crypto roadmap (ML-KEM "future") | — | As listed | — | — | — | — | What real target parts provide |

---

## Part 1 — Realistic device classes

The report names the MQTT clients: cellular smart meters (NB-IoT/LTE-M), DER inverter and battery
controllers, EV chargers with cellular modems, and field gateways (report §1.3). Real parts fall into five
classes. RFC 7228 sizes are given where they apply.

| Class | Example parts [LIT] | CPU | RAM | Flash | Link | Power | Typical role | v2.1 as written |
|---|---|---|---|---|---|---|---|---|
| **C0/C1 · metrology MCU** | ATmega4808 (6 KB / 48 KB) (Kim & Seo); MSP430F6765A metering SoC (16 KB / 128 KB); RFC 7228 Class 0 (≪10 KiB RAM) and Class 1 (~10 KiB) | 8/16-bit, ≤ 25 MHz | 6–16 KB | 48–128 KB | Usually none of its own; talks to a data concentrator over PLC or RF using DLMS/COSEM (Domingo) | Mains | Measures energy | **Not feasible (RED).** TLS alone needs more RAM than the chip has. Such meters belong behind a gateway (C4) |
| **C2 · small comms MCU** | RFC 7228 Class 2 (~50 KiB RAM, ~250 KiB flash); Cortex-M0+/M4 parts with 64–128 KB RAM | 32-bit, 48–120 MHz, often no crypto accelerators | ~50–128 KB | 256–512 KB | NB-IoT/LTE-M through an AT-command modem | Mains (meter) or battery (gas/water) | Low-cost cellular meter module | **ORANGE.** Fits only with small TLS records, stack-optimised PQ code and firmware streamed to flash (Parts 5 and 10) |
| **C3 · cellular SiP / metering SoC** | nRF9160 (Cortex-M33, 256 KB RAM, 1 MB flash, CryptoCell 310); SAM4CM (dual Cortex-M4 at 120 MHz, up to 304 KB SRAM and 2 MB flash, AES-GCM, SHA-256 and ECC hardware, TRNG, battery-backed RTC) | 32-bit, 64–120 MHz | 256–304 KB | 1–2 MB | NB-IoT/LTE-M | Mains or battery | Smart meter with an integrated modem | **YELLOW/GREEN** once the RED items are fixed |
| **C4 · Linux-class** | Raspberry Pi-class boards (as used in Malina, Alghawli, Suleiman); DER gateways; EV-charger controllers; data concentrators | Cortex-A, ≥ 1 GHz | ≥ 256 MB | ≥ GBs | LTE / Ethernet | Mains | Gateway, aggregator, charger or inverter controller | **GREEN** |
| **8-bit gateway-less** | The Kim & Seo device, used directly | AVR at 7–20 MHz | 6–8 KB | 48 KB | Sensor network | Battery | Base-paper scenario | **Out of scope.** Only a pure KEM-MQTT profile would fit (4.32 s per handshake, Kyber-512) |

**Notes that change the story:**

- **Many DER inverters and EV chargers do not speak MQTT natively.** IEEE 2030.5 is a polled REST
  protocol: pollRate defaults to 900 s, and the CSIP guide sets DERControl polling to 10 min. EV chargers are
  usually managed with OCPP over WebSocket. In practice, the MQTT client on a DER or charger is often a
  **C3/C4 gateway**, not the power-electronics MCU.
- **Electricity meters are mains-powered.** Energy is a secondary constraint for them. It is primary for
  battery gas and water meters, and for a comms module's power budget. What matters most for electricity
  meters is **bytes, airtime, latency, and the data plan's cost per MB**.
- **Offloaded modem TLS cannot do post-quantum.** Cellular modules often provide TLS inside the modem, and
  that TLS is not post-quantum: nRF91 modem firmware documents TLS 1.2 and DTLS 1.2 clients. A PQ-hybrid hop
  therefore needs the TLS stack **on the application MCU**, over plain sockets. That moves a whole TLS
  library and its record buffers onto the MCU. Their size depends on the library and its build options
  **[HW]**, and the design currently never mentions this cost.
  - **wolfSSL 5.8** ships hybrid ML-KEM groups, including X25519 + ML-KEM.
  - **Mbed TLS / TF-PSA-Crypto** lists ML-KEM only as "future" on its roadmap.
  - So for C2/C3 firmware the library choice is effectively wolfSSL, or a patched stack. **[LIT: vendor docs] [HW]**

---

## Part 2 — Every cryptographic choice against its alternatives

Cycle counts are Cortex-M4 at 24 MHz (pqm4) unless marked otherwise. "ms @64 MHz" divides cycles by
64 MHz: this is a **lower bound**, because it ignores flash wait states and library overhead.
"Stack" excludes key, ciphertext and signature buffers.

### 2.1 Key exchange

| Option | NIST cat. | pk / ct (B) | M4 keygen / enc / dec (M cycles) | Stack: small / fast | Code (KB, excl. hash) | M0+ total ms [RP2040] | 8/16-bit | Energy [TAS23, measured] | Constant-time notes | HW accel. on target MCUs | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|
| X25519 | classical | 32 / 32 | 0.63 per scalar mult [HL19] | < 1 KB | small | 28.7 ms per mult (M0 [DULL15]) | AVR 13.9 M cycles; MSP430X 5.3 M [DULL15] | (P-256 ECDHE as a proxy: 1.59 + 3.37 mJ) | Ladder is constant-time | Rarely accelerated; P-256 accelerators are more common (e.g. SAM4CM) | RFC 7748 |
| ML-KEM-512 | 1 | 800 / 768 | 0.39 / 0.39 / 0.43 | 2.3 / 5.4 KB | 13.3 | 35.7 | Kim & Seo: Kyber-512 on AVR | 1.23 / 0.97 / 0.53 mJ | KyberSlash (2024) showed timing leaks in some implementations: use patched code | Keccak rarely in hardware | FIPS 203 |
| **ML-KEM-768 (chosen)** | 3 | 1,184 / 1,088 | 0.64 / 0.66 / 0.71 | 2.8 / 6.5 KB | 13.3 | 56.6 | Optimised MSP430 Kyber exists (TCHES 2026); absolute numbers **[HW]** | 1.89 / 1.80 / 1.24 mJ | as above | as above | FIPS 203; NIST's recommended default |
| ML-KEM-1024 | 5 | 1,568 / 1,568 | 1.02 / 1.03 / 1.09 | 3.3 / 7.5 KB | 14.0 | 85.7 | — | — | as above | as above | FIPS 203; CNSA 2.0 requires it (for US national-security systems only) |
| X25519MLKEM768 (TLS) | hybrid | 1,216 / 1,120 | ML-KEM-768 + 2 X25519 mults | — | ML-KEM + X25519 | — | — | — | — | — | IETF draft-ietf-tls-ecdhe-mlkem; OpenSSL 3.5 default (verified) |
| HQC | backup | 2,249 / 4,481 (L1) | 53 / 106 / 160 (hqc-128) | — | — | — | — | — | — | — | Selected in 2025; not final |

**Verdict.** ML-KEM-768 stays (GREEN).

- **Against X25519:** one ML-KEM-768 operation (0.64–0.71 M cycles) costs about the same as one X25519
  scalar multiplication (0.63 M). A hybrid encapsulation needs two of those multiplications.
- **Against ECDSA:** one ECDSA P-256 verification (about 4.5 M cycles, wolfSSL) costs about 7× an ML-KEM
  operation.
- **Against ML-KEM-512:** stepping down saves about 0.3 M cycles per operation and a few hundred bytes per
  handshake. That is not worth reopening a frozen decision.

### 2.2 Signatures

| Option | Cat. | pk / sig (B) | Device verify: M cycles / ms @64 MHz | Verify stack: small / fast | Sign cost (who signs) | Code (KB) | Energy, verify [TAS23] | Implementation risk | Stateful? | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| ECDSA P-256 | classical | 65 / 64 | 4.53 / 71 (wolfSSL at 180 MHz [TAS22]) | small | Device signs its TLS CertificateVerify: 2.2 M cycles | tens of KB (TLS library) | 4.78 mJ | Needs a good nonce (RFC 6979) | No | FIPS 186-5 |
| ML-DSA-44 | 2 | 1,312 / 2,420 | 1.42 / 22 | 2.7 / 8.9 KB | Utility | 19.6–24.8 | 1.54 mJ (Dil2) | Rejection sampling makes signing time variable (M0+ p99 584 ms); verification is constant-time | No | FIPS 204 |
| **ML-DSA-65 (commands)** | 3 | 1,952 / 3,309 | 2.42 / 38 (fast) · 5.73 / 90 (small stack) | 2.7 / 9.9 KB | Utility: 0.56 ms in Docker | 19.3–24.1 | 2.59 mJ (Dil3) | as above | No | FIPS 204 |
| ML-DSA-87 | 5 | 2,592 / 4,627 | 4.19 / 66 | 2.7 / 12.1 KB | Utility | 19.5 | — | as above | No | FIPS 204 |
| FN-DSA-512 (Falcon) | 1 | 897 / 666 | 0.47 / 7.4 | 0.4 KB (+ 40 KB tables when signing) | **Utility** (floating point; hard to make constant-time on an MCU) | 81 (sign + verify) | 0.47 mJ | Signing is the hard part, and the **device never signs** | No | **FIPS 206 draft, not final** |
| SLH-DSA-SHA2-128s | 1 | 32 / 7,856 | 7.47 / 117 | 2.0 KB | Offline station: 168 ms (Docker) | 5.3 | 12.0 mJ (SPHINCS+-128s) | Needs only SHA-256 | No | FIPS 205 |
| SLH-DSA-SHA2-128f | 1 | 32 / 17,088 | 21.9 / 343 | 2.7 KB | Station | 5.0 | 37.8 mJ | 'f' verifies **slower** than 's' | No | FIPS 205 |
| **SLH-DSA-SHA2-192s (firmware)** | 3 | 48 / 16,224 | 13.5 / 211 | 3.7 KB | Station: 324 ms (Docker) | 6.0 | — | Categories 3 and 5 **also need SHA-512** (FIPS 205 §11.2) | No | FIPS 205 |
| SLH-DSA-SHA2-256s | 5 | 64 / 29,792 | 19.6 / 307 | 5.6 KB | Station | 6.1 | — | as above | No | FIPS 205 |
| LMS/HSS (H10–H20, W8) | SHA-256, n = 32 | 56 / 1,456–1,776 | Few hash chains; very fast **[HW]** | small | Station; state must never repeat | small | — | **State reuse is catastrophic.** SP 800-208 expects state held in hardware | **Yes** | SP 800-208; CNSA 2.0's firmware choice |
| XMSS-SHA2_10_256 | ~SHA-256 | 68 / 2,500 | fast **[HW]** | small | Station | small | — | as above | **Yes** | RFC 8391; SP 800-208 |

**Verdicts** (explained in Part 4):

- **Commands.** Keep ML-DSA-65 for discrete commands, and add signed grants for high-rate set-points.
  FN-DSA-512 is the strongest future fit: the utility signs, the device only verifies. Adopt it only when
  FIPS 206 is final.
- **Firmware.** Keep hash-based signatures. Now consider **SLH-DSA-SHA2-128s**: its signature is half the
  size, it needs SHA-256 only, and it fits an 8 KB MQTT packet. This meets the change condition recorded in
  Rationale B10.
- **LMS/HSS** is the production-grade option (CNSA 2.0) once a hardware-backed signing station exists.

### 2.3 Authenticated encryption

| Option | Key | Software speed on MCU | Hardware on target parts | Where the design uses it | Notes |
|---|---|---|---|---|---|
| AES-256-GCM | 256 | Slow and leaky without hardware (table AES) | **Common**: SAM4CM (AES-GCM), nRF9160 CryptoCell 310 (AES) | **TLS hop** (`TLS_AES_256_GCM_SHA384`, negotiated by default, verified) | The device must implement it anyway, for TLS |
| **ChaCha20-Poly1305 (E2E)** | 256 | Fast and constant-time in software | Rare | End-to-end layer | A **second** AEAD on the device, beside the one TLS already needs |
| Ascon-AEAD128 | 128 | Very small and fast on 8/16-bit | Rare | Not used | SP 800-232 final (Aug 2025). No TLS cipher suite, so it would be a third AEAD |

**Two corrections to the v2.1 reasoning:**

1. **Rationale B7 rejects Ascon for its 128-bit key** "for quantum margin". NIST's position is that AES-128
   remains secure against quantum attack (Grover's search does not parallelise usefully). The real reason
   not to use Ascon is that TLS has no Ascon suite, so it would add a second AEAD. **YELLOW**: fix the
   explanation.
2. **The device carries two AEADs** (AES-GCM for TLS, ChaCha20 end to end). That costs code, testing, and
   side-channel surface. On parts with AES hardware, AES-256-GCM end to end is cheaper. On parts without it,
   TLS should negotiate `TLS_CHACHA20_POLY1305_SHA256` so ChaCha20 serves both layers. Either way, choose
   **one AEAD per device class**, set in the policy. **YELLOW.**

### 2.4 Hashes and KDFs

SHA-256, HMAC and HKDF are GREEN, and SHA-256 hardware is common.

Two points to note:
- The X-Wing combiner uses **SHA3-256**. That is free, because ML-KEM already needs Keccak.
- **SLH-DSA-SHA2-192s pulls SHA-512 into the bootloader.** SAM4CM's hash engine offers SHA-1/224/256 only,
  so for 192s the bootloader must run SHA-512 in software. 128s needs only SHA-256. **[LIT: FIPS 205
  §11.2; SAM4CM datasheet]**

---

## Part 3 — Hybrid or pure post-quantum at each layer, and duplicated work

### 3.1 Every public-key operation a device performs

The counts below come from BalaMP.md §5.2/§5.4, plus a TLS 1.3 client with mutual certificates.

| Phase | ML-KEM-768 (keygen / enc / dec) | X25519 scalar mults | ECDSA (sign / verify) | M4 M cycles | ms @64 MHz | M0+ ms [RP2040 + DULL15 + mbedTLS] |
|---|---|---|---|---|---|---|
| TLS full: X25519MLKEM768, mutual ECDSA | 1 / 0 / 1 | 2 | 1 / 2 | 13.9 | 217 | 831 |
| TLS resumed (psk_dhe_ke) | 1 / 0 / 1 | 2 | 0 | 2.6 | 41 | 95 |
| E2E full handshake (3 hybrid KEMs) | 1 / 1 / 2 | 5 | 0 | 5.8 | 91 | 222 |
| E2E PSK+KEM resume | 1 / 0 / 1 | 2 | 0 | 2.6 | 41 | 95 |
| E2E PSK resume | 0 | 0 | 0 | 0 | 0 | 0 |
| **Cold start (TLS full + E2E full)** | **2 / 1 / 3** | **7** | **1 / 2** | **19.7** | **308** | **1,053** |

These figures are [ANALYTICAL], built from [LIT] cycle counts. They are **lower bounds**: flash wait states,
the TLS/MQTT library and interrupts are excluded.

**Where the cold-start cycles go:** ML-KEM 21%, X25519 22%, ECDSA P-256 57%.

That corrects the intuition behind "hybrid doubles the cost" (BalaMP §7.4: +120% measured on the laptop).
On an MCU, the most expensive thing the device does is the **classical certificate authentication on the
hop**, not the post-quantum part.

### 3.2 Layer by layer

| Layer | v2.1 | Pure PQ alternative | What the classical half buys | Cost of the classical half, device | Verdict |
|---|---|---|---|---|---|
| TLS key exchange | X25519MLKEM768, pinned | `MLKEM768` group (one config line) | Protection if ML-KEM is broken by classical cryptanalysis before quantum computers arrive; matches ANSSI/BSI hybrid guidance (Malina §2.2) | 2 mults = 1.25 M cycles (~20 ms @64 MHz); +32 B each way | **GREEN**: keep. The report and slides already argue for hybrid |
| E2E KEMs (×3) | X25519 + ML-KEM-768 (X-Wing combiner) | ML-KEM-768 only | Same, **against the broker as a recorder** | 5 mults = 3.1 M cycles (~49 ms @64 MHz; ~144 ms on M0+); +32 B per key or ct | **GREEN** on C3/C4, **YELLOW** on C2 (affordable; keep for consistency) |
| Hop authentication | ECDSA P-256 certificates | ML-DSA-44/65 certificates | — | ECDSA is 57% of cold-start cycles | **YELLOW**: keep ECDSA (bytes: 4.7 KB vs 23.8–31.7 KB), but see 3.3 |
| Commands | ML-DSA-65 | — (already PQ) | — | — | Part 4 |
| Firmware | SLH-DSA-192s | — (already PQ, hash-based) | — | — | Part 4 |

### 3.3 Duplicated work, and whether profiles are needed

**Two full key exchanges per cold start.** TLS and E2E each run hybrid key exchange: 6 ML-KEM operations and
7 X25519 multiplications on the device. The E2E layer cannot be removed: it is the only thing that protects
alerts and commands from the broker. The TLS layer cannot be removed either: it protects TELEMETRY, the
topic names, and the MQTT framing from the network. So the duplication is **structural and justified**.
What *can* shrink is how often each layer runs:

- **TLS resumption saves much less than expected** [DOCKER T5]: 4,438 B against 6,262 B for a full
  handshake (TCP payload, including MQTT CONNECT). The hybrid key shares (1,216 + 1,120 B) are sent again on
  every resumption (psk_dhe_ke), and OpenSSL sends **two** NewSessionTickets of about 680 B each, which carry
  the client certificate. Options, with their trade-offs:
  - Issue one ticket instead of two: saves ~680 B. OpenSSL supports it; Mosquitto has no setting
    **[HW: needs a broker patch or OpenSSL config]**.
  - `psk_ke` resumption (no fresh key exchange): saves ~2.3 KB, but the resumed hop loses forward secrecy
    against theft of the broker's ticket key. Its confidentiality still descends from the original hybrid
    handshake. **Not recommended by default.**
- **The ticket lifetime is 7,200 s** [DOCKER T2]: resumption was accepted at +7,000 s and refused at
  +7,300 s. A device that sleeps longer than 2 h pays a **full** hybrid TLS handshake (6.3 KB, 13.9 M cycles)
  at every wake. Batch reporting four times a day always misses the ticket.
- **Hop authentication with a PSK was tested as a way to remove ECDSA** [DOCKER T7]. Mosquitto 2.0.21
  accepts a PSK only over **TLS 1.2** (`DHE-PSK-AES256-GCM-SHA384`, **classical FFDHE-3072**). A TLS 1.3 PSK
  is refused ("protocol version"). A PSK hop would therefore **lose post-quantum key exchange**: rejected for
  this broker. The same run shows the hybrid-only `Groups` pin **does not constrain TLS 1.2**. Any listener
  that allows TLS 1.2 silently offers classical DHE, so `tls_version tlsv1.3` must be on every listener.
  **YELLOW** (a new validator check).

**Are profiles needed?** Yes, but only as **per-class settings in the signed policy**, never negotiated on
the wire. A negotiated profile would be a downgrade surface; a signed per-class value is not. The policy
already has per-class fields, so add these:

| Profile field | C2 (constrained) | C3/C4 |
|---|---|---|
| `tls_max_record` (asked for with max_fragment_length) | 512–1,024 B (supported by the broker: T3) | default |
| `aead` (E2E and TLS suite, one per device) | ChaCha20-Poly1305 without AES hardware; AES-256-GCM with it | AES-256-GCM |
| `pq_impl` | stack-optimised (e.g. pqm4 m4fstack) | fast |
| `manifest_delivery` | chunked, streamed to flash | chunked |
| `cmd_auth` | per-command signature; grants for set-point streams | same |
| `reconnect` | persistent MQTT session + 1-RTT resume + jittered back-off | same |

---

## Part 4 — ML-DSA-65 for commands and SLH-DSA-SHA2-192s for firmware

### 4.1 ML-DSA-65 signing each command

**What it costs** [ANALYTICAL from LIT]:

| | Cost |
|---|---|
| Bytes per command | +3,309 B: 96% of the 3,442 B CONTROL envelope |
| Device verification | 2.42 M cycles (38 ms @64 MHz) with 9.9 KB stack, or 5.73 M (90 ms) with 2.7 KB stack |
| On a Cortex-M0+ | 72 ms (reference C) |
| Measured energy | 2.59 mJ (board-level, Dilithium3) [TAS23] |
| Utility signing | 0.56 ms per signature [DOCKER] |

**Where it breaks.** At the report's cited traffic source (Alghawli: a DER set-point every 5 s) a device
receives 17,280 commands a day. That is:
- ~61 MB/day of signatures alone;
- ~7 h/day of airtime at 20 kbit/s;
- ~11 min/day of verification CPU at 64 MHz.

The utility would sign 172.8 M times a day per 10,000 DERs: about 27 CPU-hours a day. If the key sits in an
HSM, as separation of duties requires, the HSM's signing rate becomes the limit **[HW: vendor data]**.

At IEEE 2030.5 rates (control events a few times a day, schedules and curves), the cost is negligible:
about 14 kB/day.

**What the signature actually adds** over the session AEAD:

1. Non-repudiation, and an audit trail per command.
2. Broadcast authenticity: needed, because zone keys are shared.
3. Protection against someone who holds the *session* key but not the *signing* key.

Point 3 is only true if the signing key is **held apart from** the utility's E2E KEM key (HSM or a separate
command service). v2.1 lists both as "utility" keys. If they sit in one process, the RISK test's comfort
("a stolen KEM key cannot forge commands") does not hold in practice. **YELLOW: state separation of duties
as a requirement.**

**Alternatives**

| Option | Bytes per set-point | Device work | Security change | Verdict |
|---|---|---|---|---|
| Keep per-command ML-DSA-65 | 3,442 B | 1 verify each | — | Right for **discrete** commands (trip, curtail, schedule) |
| ML-DSA-44 | 2,553 B (−26%) | −41% cycles | Category 2 instead of 3 | Not enough gain to reopen D5 |
| FN-DSA-512 (Falcon) | ~800 B (−77%) | 0.47 M cycles (−80%) | Category 1. The device only verifies, which is Falcon's easy side | **Best future fit.** Adopt only when FIPS 206 is final and a vetted library exists. Record now as a trigger |
| **Signed grant + AEAD set-points** | 93 B per SETPOINT envelope + one GRANT (3,461 B) per hour | 24 verifies/day | The grant, signed with ML-DSA-65, is **bound to the session id** and carries bounds (min/max set-point, rate, expiry). Set-points inside the grant need only the session AEAD. A forger without the signing key cannot get a grant for its own session. Someone with the live session key can move a set-point **only within the signed bounds** | **Proposed for high-rate classes** (P3 profile). It also gives the device local safety limits, which partly answers "compromised utility" (BalaMP §6, out of scope) |

**Zone keys.** v2.1 sends each member its zone key as a **signed** unicast CONTROL message:
3.4 KB × members × daily rotation. The session AEAD already authenticates the utility to that device, so the
signature adds only non-repudiation, which is not needed for key transport. Deliver zone keys under the
session AEAD, and rotate them on membership change (plus weekly). **YELLOW.**

### 4.2 SLH-DSA-SHA2-192s signing firmware and policy

**What it costs** [ANALYTICAL from LIT; DOCKER]:

| | Cost |
|---|---|
| Device verification | 13.5 M cycles: 211 ms @64 MHz, 562 ms @24 MHz |
| Verification stack | 3.7 KB, plus SHA-256 **and SHA-512** code |
| Signed manifest | 16,405 B |
| Offline signing | 324 ms per release [DOCKER] |

**"The trust anchor can never be replaced": is the argument sound?**

- **Algorithm risk** (a future break of lattice maths) **is correctly addressed**. SLH-DSA rests only on hash
  functions.
- **Key-management risk is not addressed, and it is far more likely.** With a single burned-in anchor, one
  lost or stolen station key leaves the whole fleet unable to update, or permanently forgeable. Real secure
  bootloaders provision **several** anchor keys and allow revocation. The design should provision **at least
  two independent anchor keys**, held in separate stations or escrow. A signed "revoke key k" update is
  honoured only if it is signed by a *different*, non-revoked anchor, and it is recorded with a revocation
  counter in protected storage. **YELLOW → ORANGE for production.**

**Parameter set** (192s against the alternatives):

| Criterion | 128s | 192s | 128f / 192f | LMS/HSS |
|---|---|---|---|---|
| Signature | 7,856 B | 16,224 B | 17–36 KB | ~1.5–1.8 KB |
| Signed manifest fits an 8 KiB MQTT max packet | **yes** (~8.0 KB) | no (T1: needs ≥ 16,445 B) | no | yes |
| Verify cycles (M4) | 7.47 M | 13.5 M | 21.9 M / 35.5 M (**slower**) | small **[HW]** |
| Hash functions needed on the device | SHA-256 only (often in hardware) | SHA-256 + SHA-512 | as for 's' | SHA-256 |
| Category | 1 | 3 | 1 / 3 | ~SHA-256/192 |
| Stateless | yes | yes | yes | **no** |

**Recommendation.** Rationale B10 already recorded the trigger: *"Change it if manifest bandwidth matters
more than keeping one security category; then 128s."* The audit supplies the evidence that meets it:
- the silent drop at the MQTT packet limit (T1);
- the RAM budget of C2 devices (Part 10);
- the SHA-512 requirement on SHA-256-only hash engines.

Propose **SLH-DSA-SHA2-128s for firmware and policy on all classes**. One station algorithm keeps the station
simple. Keep 's' (never 'f'). Keep LMS/HSS as the documented production option for a hardware-backed station.
**ORANGE: needs your approval.** It changes D6.

Independently of the parameter set, **deliver the manifest in chunks and verify it from flash**. Then the
signature size never has to fit in RAM or in one MQTT packet (Part 8).

---

## Part 5 — Is end-to-end protection feasible on constrained devices?

| Class | Compute, cold start (TLS + E2E) | RAM for E2E on top of TLS | E2E verdict |
|---|---|---|---|
| C0/C1 | X25519 alone: 0.87 s on AVR at 16 MHz; ML-KEM-768 needs 18.9 KB total RAM in reference C | Does not fit (6–16 KB total) | **RED.** Behind a gateway, or a pure KEM-MQTT profile (Kim & Seo), outside this design |
| C2 (M0+/M4, ~64 KB) | ~0.3 s (M4 @64 MHz) to ~1.05 s (M0+ @125 MHz), lower bounds | +~7–13 KB transient (ML-KEM stack 2.8–6.5 KB, ephemeral secret key 2.4 KB, CH/SH buffers 2.5 + 2.4 KB) | **ORANGE.** Fits only with 1 KiB TLS records and small-stack code (Part 10) |
| C3 (nRF9160, SAM4CM) | ~0.16–0.31 s | comfortable in 256–304 KB | **GREEN** |
| C4 | negligible | — | **GREEN** |

**The E2E layer is cheap next to the hop.** An E2E full handshake is 5.8 M cycles and 5.2 KB. A TLS full
handshake is 13.9 M cycles and 6.3 KB.

What makes E2E expensive on C2 is **latency**: the two extra round trips through the broker (Part 7). E2E is
therefore feasible wherever TLS is feasible. Nowhere does E2E fail while TLS succeeds.

---

## Part 6 — The three tiers under realistic traffic

Per-message bytes are **measured** [DOCKER T5]: TCP payload through TLS 1.3, excluding IP/TCP headers.

| Message (QoS 1 unless noted) | Payload | On the wire, up + down | Overhead |
|---|---|---|---|
| TELEMETRY, QoS 0 | 64 B | 128 B | 64 B (TLS 22 + MQTT header + 37-byte topic) |
| TELEMETRY, QoS 0, **MQTT 5 topic alias** | 64 B | 94 B | 30 B (**−27%**) |
| TELEMETRY | 64 B | 157 B | 93 B (includes PUBACK) |
| ALERT envelope | 137 B | 231 B | 94 B |
| CONTROL envelope (ML-DSA-65) | 3,442 B | 3,536 B | 94 B |
| Full TLS handshake + CONNECT/CONNACK | — | **6,262 B** | — |
| Resumed TLS handshake + CONNECT/CONNACK | — | **4,438 B** | — |
| SUBSCRIBE/SUBACK | — | 83 B | — |

**Three traffic profiles** [ANALYTICAL; bytes per device per day; formulas in `analysis.py`]:

| Profile | Source | Data bytes/day | Connection handling | Security bytes/day | Total | Security share | Airtime @20 kbit/s |
|---|---|---|---|---|---|---|---|
| **P1 AMI meter**: a 64 B reading every 15 min, 1 alert/day, no commands | AMI 15-min interval data; report §1.1 "5 to 15 minutes" | 15.3 kB | Reconnect every 15 min, full TLS (ticket expired) | 602 kB | 0.62 MB | **98%** | 4.1 min |
| | | | Reconnect every 15 min, TLS resumed | 427 kB | 0.44 MB | **97%** | 2.9 min |
| | | | **Batched: reconnect 4×/day** | 18.5 kB | 0.03 MB | 55% | 0.2 min |
| | | | Always connected, 5-min keepalive | 20.8 kB | 0.04 MB | 58% | 0.2 min |
| **P2 DER, IEEE 2030.5-style**: 128 B monitoring every 5 min, 4 control events/day | 2030.5 pollRate 900 s; CSIP 10 min | 78.2 kB | Always connected | 20.8 kB | 0.10 MB | 21% | 0.7 min |
| **P3 "Alghawli nominal"**: 128 B every 10 s, set-point every 5 s | Alghawli Tables 3/10 (**SIMULATED**, 802.15.4) | 63.0 MB (61.1 MB of it command signatures) | Always connected | 20.8 kB | 63.0 MB | ~0% | **7.0 h** |
| P3 with **hourly signed grants** + AEAD set-points | — | 5.2 MB (control 3.3 MB + telemetry 1.9 MB) | Always connected | 20.8 kB | 5.2 MB | ~0% | 35 min |

**Crypto operations per day on the device** [ANALYTICAL]:

| Profile | Operations |
|---|---|
| P1 | 96 TLS resumptions (or full handshakes), each ML-KEM keygen + decaps + 2 X25519 (+ 3 ECDSA when full). ~250–1,330 M cycles/day at M4 cycle counts: **4–21 s of CPU per day at 64 MHz** |
| P2 | Negligible: a handful of verifications and one full handshake per day |
| P3 | 17,280 ML-DSA-65 verifications: **652 s/day at 64 MHz**. With grants: 24 |

**Energy per day:** not stated as a number. The only measured sources are:
- board-level crypto energy [TAS23];
- NB-IoT radio charge per exchange [LUK20].

Their ratio is informative (Part 11). An absolute daily energy figure for the full design needs real
hardware **[HW]**.

**Findings**

1. **The tier model works as intended.** TELEMETRY pays only the hop. ALERT adds 73 B per message. The
   cost of CONTROL is entirely the signature.
2. **For meters, the tiers do not decide the bytes; reconnection does.** A meter that reconnects every
   15 minutes spends 97–98% of its bytes on handshakes. That is about 13–19 MB/month per meter on a
   cellular plan. The biggest saving available is **operational**:
   - batch readings (4×/day), **or**
   - keep the connection open where the radio allows it (LTE-M/eDRX; PSM kills TCP sessions).

   **ORANGE.** The reconnect strategy must be a per-class policy field, and E4/E3 must measure it.
3. **The report's traffic source (Alghawli) is a stress case, not an AMI model.** It is simulated 802.15.4,
   with 15-second meter reads. Using it as "realistic AMI" contradicts the report's own 5–15-minute AMI
   statement. Evaluate P1 and P2 as realistic profiles and P3 as a stress bound. Label all of them
   **SIMULATED**.

---

## Part 7 — PASR as a mechanism for constrained IoT

### 7.1 What PASR saves, and what it does not

**Simulated time until the device can send its first E2E-protected message** [SIM T6]. The link model is a
one-way delay plus a serialisation rate, and one RTT for the TCP handshake. The proxy terminates TCP, and
there is no radio scheduling or loss. Link parameters are **assumptions**, inside the 3GPP NB-IoT ranges.

| Scenario | LTE-M-like: RTT 0.2 s, 200 kbit/s | NB-IoT-good: RTT 1 s, 20 kbit/s | NB-IoT-poor: RTT 4 s, 2 kbit/s | Bytes |
|---|---|---|---|---|
| A · cold start: full TLS + SUBSCRIBE + full E2E | 1.72 s | 10.77 s | 71.2 s | 11,870 |
| B · reboot (v2.1 §4.6): full TLS + SUBSCRIBE + PSK resume | 1.53 s | 8.98 s | 53.4 s | 7,414 |
| C · wake: TLS resumed + SUBSCRIBE + PSK resume | 1.46 s | 8.25 s | 46.1 s | 5,590 |
| C′ · wake: TLS resumed + SUBSCRIBE + PSK+KEM resume | 1.55 s | 9.18 s | 55.5 s | 7,933 |
| **D · proposal**: TLS resumed + persistent MQTT session + 1-RTT PSK resume | **1.02 s** | **6.02 s** | **35.9 s** | 5,866 (includes the first alert and its ACK) |
| E · floor: telemetry-only wake (no E2E) | 1.00 s | 5.84 s | 34.2 s | 4,579 |

n = 3 for the first two links; n = 1 for NB-IoT-poor.

**What this shows**
- PASR cuts **bytes** by 37–53% against a full E2E handshake (7,414 or 5,590 against 11,870 B), and device
  public-key work to zero in PSK mode.
- But on NB-IoT, **time** falls only 17–23% (10.8 → 9.0 / 8.3 s). Both the full and the resumed E2E
  exchange take **2 round trips** (CH/SH + DF/NT against RH/RS + DF/NT). TCP, TLS, CONNECT and SUBSCRIBE add
  4 more.
- The report's promise of "60–70% lower reconnection latency" cannot come from PASR alone on high-latency
  links. On the LAN, its compute and byte savings are real (92% / 86%).

**Proposal D removes 2 round trips**: 8.25 → 6.02 s on NB-IoT-good (−27%) and 46.1 → 35.9 s on NB-IoT-poor (−22%).
Against a cold start it is −44% and −50%. It lands within 3–5% of the floor (E), the cost of a bare telemetry wake.
The proposal has three parts:

1. **Persistent MQTT session** (`clean_start = false` plus a Session Expiry Interval). The broker keeps the
   subscription, so SUBSCRIBE disappears on every wake. The broker also **queues commands** for sleeping
   devices. Cost: per-device state on the broker (Mosquitto `max_queued_messages`).
2. **1-RTT resume.** After RS the device is already sure it is talking to the utility (MAC_U), so it sends
   DF **with its first envelopes inside the same message**, as the TLS 1.3 client does after its Finished.
   NT returns with the ACK.
   - The rule "confirm before use" (D17) was added so a lost DF could not lose alerts. The flash outbox plus
     end-to-end ACKs already cover that: a lost DF only means the alerts are resent.
   - Carrying the envelopes **inside** the DF publish matters. A separate alert publish on another topic has
     no ordering guarantee against DF in MQTT, and could reach the utility before the session exists.
3. **Optional: pipeline CONNECT and the first PUBLISH/SUBSCRIBE** without waiting for CONNACK. MQTT allows
   this. It saves one more round trip for telemetry-only wakes (E).

### 7.2 Single-use tickets, persistent state and crashes

**Utility state**

| State | Written when | v2.1 reference behaviour | Failure | Evidence | Fix |
|---|---|---|---|---|---|
| Used-ticket list | Every resume | `json.dump(…, open(path, "w"))`: truncate, then write; no fsync; the **whole file** each time | A torn write makes the next start fail (JSONDecodeError). Without fsync, a power loss after RS can forget a consumed ticket, reopening replay. At 100k devices, 4.8 MB is rewritten per resume: ~480 GB/day | S3, S4 [DOCKER] | Append-only log or SQLite (WAL, `synchronous = FULL`). Rule: **persist, then respond**. Records expire with the ticket |
| STEK set | Every rotation | Same pattern | A torn write means no restart, or, if caught, every ticket in the fleet dies at once | S3 [DOCKER] | Write to a temporary file, fsync, rename, fsync the directory (or use an HSM, per B32). Retire keys automatically. The key id is 8 bits (mod 256): it must be rotated and retired together |
| **Per-device command sequence** | Every command | **RAM only** | After a restart, sequences start at 1: the device answers DUP and the utility drops the command. Silent loss | **S1 [DOCKER]** | Persist the sequence before sending, or use seq = (persisted utility epoch ‖ counter), with one write per restart. The device must answer **STALE** (not DUP) for `seq < last_applied` that it never saw, and the utility must alarm on it |
| Unacknowledged commands (redelivery queue) | Every command | RAM only | Lost on restart: commands never redelivered | Code review | Persist together with the sequence |

**Device state**

| State | Written when | Failure | Evidence | Fix |
|---|---|---|---|---|
| **`last_cmd_seq`** | Before the command is applied | A power cut between the flash write and the actuator loses the command; if "OK" was already sent, the utility believes it was applied | **S2 [DOCKER]** | Intent log: write PENDING(seq); actuate; write APPLIED(seq); **then** ACK "OK". After a reboot a PENDING record becomes status **INTERRUPTED**, and the utility decides. Command types carry an `idempotent` flag, so absolute set-points may be re-applied safely |
| Ticket and psk | On NT | A reboot between RS and NT means no ticket, so the next wake is a full handshake. Graceful | [DOCKER validate] | Double-buffered record with CRC |
| Resume hello | On RH | A **rebuilt** RH after the first one was processed gives "ticket already used", so a full handshake. Only a byte-identical retransmission gets the cached RS | **S5 [DOCKER]** | Keep the RH bytes (and, for PSK+KEM, the ephemeral secret key) until RS or a timeout, and retransmit them identically. After a reboot, accept the full handshake |
| Alert outbox | Per alert (append, then delete on ACK) | **Unbounded**: a device offline for days can fill flash | Code review | Cap the outbox; merge repeats per alert type; keep a "dropped N" counter that is sent as an alert |
| Time floor (proposed) | Once a day and after each authenticated time | — | T4 | See Part 12, row 1 |

**Flash endurance** [ANALYTICAL]:
- Assumes 10,000 erase cycles (a typical embedded NOR figure; **use the actual part's datasheet**),
  4 KiB pages and 16-byte log records.
- Meter (~100 writes/day): one page lasts about 70 years.
- DER with per-set-point counters every 5 s (17,280 writes/day): one page lasts about 0.4 years. It needs
  about 37 pages (148 KiB) for 15 years.

**Rationale OPS-5 is wrong for the device counter.** Its advice, "reserve counters every 100", works on the
**utility** side, which skips ahead after a restart. On the **device** it breaks liveness: after a reboot the
device would jump `last_applied` ahead and refuse the utility's next 100 commands. The device must use a
**wear-levelled append log**, or avoid persisting per set-point (grants are session-bound, so set-points
inside a grant need no cross-session persistence).

### 7.3 PASR failure cases (summary; full list in Part 12)

**Handled well by v2.1:**
- stolen ticket without psk: binder fails, and the genuine ticket survives;
- ticket replay: "already used";
- expired ticket or chain;
- policy or firmware change: invalidated;
- revoked device;
- retired STEK;
- duplicate RH within 120 s: identical RS.

**Not handled before this audit:**
- torn or unsynced persistence (S3);
- write amplification (S4);
- rebuilt RH after a crash (S5);
- the hop ticket expiring after 2 h (T2), which makes "cheap resume" still pay a full hybrid TLS handshake
  on every sleep longer than 2 h.

---

## Part 8 — FOTA storage: what the smallest device must hold

**Minimum flash** for v2.1 FOTA with revert (A/B, commit after boot):

`flash ≥ bootloader + 2 × max_image + manifest staging + persistent data (+ one scratch sector if the slots swap)`

- An overwrite-only bootloader cannot **revert**, so v2.1's revert rule needs two full slots, or dual-bank
  execute-in-place.
- The manifest is **16,405 B** with 192s, or about **8,037 B** with 128s.
- Merkle state is small: a received-chunk bitmap (256 chunks → 32 B) plus one proof in RAM (8 × 32 B).

**What must fit inside the image just for this design's crypto** [LIT pqm4 code sizes, excluding hashing and
the C library]:

| Component | Code size |
|---|---|
| ML-KEM-768 | 13.3 KB |
| ML-DSA-65 (the whole scheme; a verify-only build is smaller **[HW]**) | 19.3–24.1 KB |
| SLH-DSA verify | 5.3–6.0 KB |
| Keccak/SHA-3, SHA-256 (+ SHA-512 for 192s) | not included above |
| X25519 | not included above |
| AEAD(s) | not included above |
| TLS library with hybrid groups (wolfSSL-class) | not included above |
| MQTT client | not included above |

The last five rows depend on library and build **[HW]**. The crypto code alone is roughly **40–45 KB before
TLS**.

| Flash size | Two in-chip slots? | Verdict |
|---|---|---|
| 48–128 KB (C0/C1: ATmega4808, MSP430F6765A) | No: the crypto alone takes a third of the chip | **RED** (behind a gateway) |
| 256–512 KB (C2) | Only if image ≤ ~(flash − bootloader − data)/2, i.e. < ~120–240 KB | **ORANGE.** Usually needs an **external SPI flash** for slot B |
| 1–2 MB (C3: nRF9160, SAM4CM) | Yes | **GREEN** |
| C4 | Filesystem | **GREEN** |

**Gaps in the FOTA text** (all YELLOW):

1. **External flash is outside the trust boundary.** If slot B is external, the image can be modified
   physically after installation checks. The bootloader must **re-check the image hash** (from the committed
   manifest) when it copies or boots from slot B, not only at download time.
2. **Size limits must be the device's own.** The limits 64 MiB / 65,536 chunks (reference `fota.py`) are
   generic. Each device must refuse a manifest whose payload length exceeds **its own slot size**.
3. **The policy artifact is JSON with hex-encoded keys** (reference `policy.py`: canonical JSON). That
   contradicts D14 ("length-prefixed binary everywhere") and §3.3 (canonical JSON rejected). On an MCU it
   needs a JSON parser plus hex decoding, and doubles the key bytes (1,216 + 1,952 B become 6,336
   characters). Use the same binary codec as every other message.
4. **The manifest must be delivered in chunks and verified from flash.** See T1 in Part 9 for why.

---

## Part 9 — MQTT, TLS and cellular overhead

| Item | Finding | Evidence |
|---|---|---|
| **MQTT 5 Maximum Packet Size vs the signed manifest** | A device declaring 8,192 or 16,384 B **never receives** the 16,405 B manifest: the broker drops it silently, the device stays connected and still receives the 4,352 B chunk. It needs ≥ 16,445 B (the MQTT spec requires the broker to discard silently: [MQTT-3.1.2-25]) | T1 [DOCKER] |
| Fix | (a) Every artifact, **including the manifest**, travels as chunks no larger than the class limit (manifest part 0..k, reassembled into flash); (b) each device reports its maximum in its handshake and registry, and the utility refuses to publish anything larger to that class; (c) with 128s the whole manifest fits in 8 KiB | — |
| TLS record size | By default the broker sends **16,401 B records** (ciphertext). A device must buffer a whole record before the AEAD can authenticate it: ≥ 16 KB of RAM just to receive | T3 [DOCKER] |
| Small records | With RFC 6066 **max_fragment_length** the broker honours 512 → records ≤ 529 B, and 1024 → ≤ 1,041 B. The device's receive buffer drops to ~1 KB | T3 [DOCKER] |
| Handshake flights | ClientHello: one 1,528 B record (hybrid key share 1,216 B). The server's first flight: ServerHello 1,210 B, then certificates and more. Plus **two NewSessionTickets of about 680 B each** | T5 [DOCKER] |
| Resumed handshake | 4,438 B: still carries both hybrid key shares and two new tickets | T5 [DOCKER] |
| Per-publish overhead | 64 B (QoS 0) or 93–94 B (QoS 1 with PUBACK) for a 37-byte topic; **topic alias** cuts a 64 B QoS 0 publish from 128 to 94 B | T5 [DOCKER] |
| IP/TCP headers | Not included above. At least 40 B per segment, plus ACK segments | [ANALYTICAL] |
| TCP on NB-IoT | Minimum header: MQTT/TCP/IPv4 74 B vs MQTT-SN/UDP 37 B. Measured studies report CoAP/UDP performing better than MQTT/TCP on NB-IoT. MQTT is fixed by the report, so state this as a **limitation**; MQTT-SN or DTLS is future work | [LIT LUK20 Table I; NB-IoT smart-meter study] |
| NAT and keep-alive | Carrier NAT idle timeouts are operator-specific. A PSM device cannot keep a TCP connection alive across sleep, so every wake reconnects | **[HW: operator data]** |
| Fragmentation on 802.15.4 | ML-KEM-768 ≈ 14 fragments; ML-DSA-65 ≈ 42 (Alghawli). This matters only if a C2 device reaches the gateway over a mesh | [LIT] |

---

## Part 10 — RAM, flash and persistent-storage budgets (peak, per class)

**Peak simultaneous RAM for the security path** [ANALYTICAL]. Crypto figures come from pqm4 and RP2040. TLS
buffers: 2 × (16 KiB + 29 B) by default (Mbed TLS default content length), or 2 × (1 KiB + 29 B) with
max_fragment_length. **Application, RTOS, IP stack and modem driver are excluded [HW].**

| Moment of peak | Default settings | Constrained profile |
|---|---|---|
| Full connection (TLS buffers live during the E2E handshake) | **50.2 KB** (fast PQ code) | **16.7 KB** (1 KiB records, small-stack PQ code) |
| Manifest receive + SLH-DSA verify | **51.8 KB** (manifest in RAM, 192s) | **10.1 KB** (streamed to flash, verified from flash) |
| CONTROL receive + ML-DSA-65 verify | **45.1 KB** | **8.1 KB** |
| Reference C (M0+) for comparison | ML-KEM-768 decaps 18.9 KB total; ML-DSA-65 **signing** 86.7 KB (the device never signs) | — |

| Class | RAM | Verdict |
|---|---|---|
| C0/C1 (6–16 KB) | smaller than even the constrained profile before the application | **RED** |
| C2 (~50–128 KB) | fits **only** with the constrained profile; the default settings consume the whole RAM | **ORANGE** |
| C3 (256–304 KB) | comfortable | **GREEN** |

**Persistent storage per device** (bytes; sizes from FIPS and [DOCKER]):

| Item | Size | Changes when |
|---|---|---|
| Device E2E key: ML-KEM-768 dk + X25519 sk | 2,400 + 32 | Re-provisioning |
| TLS key + certificate (ECDSA) | 32 + ~426 (measured) | CA re-issue |
| CA certificate(s) | ~450 each (2 during a CA roll-over) | OPS-1 |
| Firmware anchors (SLH-DSA, ≥ 2 proposed) | 32–48 each | Never (revocable) |
| Installed policy (binary, proposed) | ~3.5 KB (keys 1,216 + 1,952 + rules) | Policy update |
| Ticket + psk + expiry + mode | ~300 | Every resume |
| Committed version counters, revocation counter | tens of bytes | Updates |
| Command intent log | 16 B per record | Every command |
| Alert outbox (bounded, proposed) | e.g. 4 KiB | Every alert and ACK |
| Time floor | 8 | Daily |

---

## Part 11 — Energy (no invented numbers)

**Every measured source available:**

| What | Value | Measured? | Hardware |
|---|---|---|---|
| Crypto per operation [TAS23] | Kyber-768 keygen / enc / dec 1.89 / 1.80 / 1.24 mJ; ECDSA verify 4.78 mJ; Dilithium3 verify 2.59 mJ; SPHINCS+-128s verify 12.0 mJ | **Measured** (PicoScope, shunt) | Whole NUCLEO-F439ZI board at 180 MHz, 3.3 V, including ~100 mW board idle |
| PQ TLS handshake, client [TAS23] | Dil2+Kyb1 15.0 mJ; ECDSA+ECDHE 18.2 mJ; Dil3+Kyb3 25.4 mJ | **Measured** | Same |
| NB-IoT radio per exchange [LUK20] | ~275–415 mAs per UDP echo, 16–1,024 B; ~64% is the 5-s inactivity timer | **Measured** (on-board current sensor, live network) | Quectel BC68 |
| Kim & Seo 71.75 mJ | — | **Calculated**, not measured | AVR |
| RP2040 energy | — | **Estimated** from a datasheet | M0+ |
| Alghawli radio energy | — | **Simulated** (NS-3) | 802.15.4 |

**What can honestly be said** [ANALYTICAL ratio of two measured sources]:

- A cold start's device crypto adds up to **about 39 mJ** on that dev board. That figure uses P-256 ECDHE as
  a stand-in for X25519, which **over-estimates** it.
- A **single** 64-byte NB-IoT exchange costs about **280 mAs**, which is 0.85–1.0 J at 3.0–3.6 V. The paper
  does not state the voltage.
- A TCP + TLS + MQTT reconnect needs at least that one radio connection and 4–6 round trips.

So the radio costs **at least ~20–25× the crypto** per reconnect.

**Conclusion.** Choosing a cheaper algorithm barely moves energy. What moves it is:
- how often the device wakes;
- how many round trips each wake takes;
- how long the radio stays in active waiting.

Part 7 proposal D, batching, and "release assistance" address exactly these. A per-day energy number for the
whole design **requires hardware [HW]**. Electricity meters are mains-powered, so energy matters most for
battery-powered gas and water meters.

---

## Part 12 — Failure and edge-case catalogue

Columns: **Trigger · State before · Device · Utility · Broker · Security property at stake · Resource cost ·
Persistent state involved · Recovery · How it can still fail.** "v2.1" marks behaviour already correct.
**Bold** marks a gap found by this audit.

| # | Trigger | State before | Device | Utility | Broker | Property | Resource cost | Persistent state | Recovery | Can still fail when… |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | **RTC resets to 1970 after power loss** | Device off; no battery-backed RTC | **TLS refuses the broker certificate ("not yet valid") (T4)** | Never sees the device | Sees a failed handshake | Availability; the E2E time repair (B21) is never reached | Endless reconnect attempts and radio energy | None today | **Proposed:** device TLS skips validity-time checks (pinned private CA; T4-d shows it works); persisted **time floor** = last authenticated utility time; clock = max(RTC, floor) until the E2E handshake sets it | the CA is compromised (a pinned CA is then trusted without expiry); rotate through OPS-1 |
| 2 | **RTC runs years ahead** | Drifted or garbage RTC | **TLS: "certificate has expired" (T4-e)** | — | — | Availability; command expiry (v2.1 is fine at the E2E layer) | as #1 | — | Same fix as #1 | — |
| 3 | **Device certificate expires while the device is offline** | Offline longer than the certificate lifetime | Presents an expired certificate | — | **Broker refuses it: "alert certificate expired" (T4-f)** | Availability; the device cannot even fetch a new certificate | Truck roll | Device certificate | **Proposed:** device certificates with notAfter 99991231235959Z (RFC 5280 §4.1.2.5; verified accepted, T4-g); revoke through registry/ACL (and CRL) | revocation lists are not kept current |
| 4 | Broker or CA certificate replaced while devices are offline | Old CA pinned | Rejects the new broker certificate | — | New certificate | Availability | — | CA set | v2.1 OPS-1: deliver the new CA through a signed update **before** switching; keep both CAs pinned during overlap | a device misses the whole overlap window; keep an out-of-band CA-update path |
| 5 | Power loss during the TLS or E2E handshake | Half-open | Restarts from scratch | Pending entry expires after 60 s (v2.1) | TLS session dropped | — | One more handshake | — | v2.1: retry with back-off | **Timers must scale with the link:** at 4 s RTT and 2 kbit/s, the E2E exchange alone takes ~30 s (2.5 KB each way + 2 RTT), so a 60 s pending TTL has no margin; keep PENDING_TTL ≥ 2× the worst handshake time per class |
| 6 | **Power loss after RH, before RS; device retries with a rebuilt RH** | Ticket consumed at the utility | New nonce, so different bytes | **"ticket already used" (S5)** | — | Replay protection holds | Falls back to a full handshake (E2E 5.2 KB) | Ticket | **Proposed:** keep RH bytes (+ ephemeral key) until RS or timeout; retransmit identically; after a reboot accept the full handshake | reboots loop faster than handshakes complete |
| 7 | Power loss between RS and NT | Session keys in RAM only | Loses session and ticket (single-use) | Session live | — | Forward secrecy, single use | Full handshake next time | Ticket slot empty | v2.1: graceful | — |
| 8 | **Power loss between the counter write and actuation** | Command received | **Counter written, actuator never acted (S2)** | Believes OK (if the ACK left) or redelivers and gets DUP | — | At-most-once becomes "never", with a false confirmation | Grid action silently missing | `last_cmd_seq` | **Proposed:** intent log PENDING → APPLIED; ACK only after APPLIED; INTERRUPTED reported after reboot; `idempotent` flag | the actuator itself has no readable state (must be reported as unknown) |
| 9 | **Utility restarts while commands are in flight** | Sequence counter in RAM | **Answers DUP to the "new" seq 1 (S1)** | **Counter reset; queue lost** | — | Liveness of CONTROL | Silent loss until the counter catches up | Utility sequence counter, pending queue | **Proposed:** persist both (write-ahead) or epoch ‖ counter; device answers STALE; utility alarms | the epoch file is itself torn (use the #11 atomic-write rule) |
| 10 | Utility restarts: sessions lost | Devices hold live sessions | Next envelope gets a resync hint (v2.1) | Resumes through PASR | — | — | One resume per device | STEK and used list persisted | v2.1 C7 | #11 |
| 11 | **Utility crashes during a persistence write** | Writing used.json or stek.json | — | **Cannot restart (JSONDecodeError), or loses every ticket (S3)** | — | Replay protection (used list); availability (STEK) | Fleet-wide full handshakes | Used list, STEK | **Proposed:** SQLite WAL / append log; temp + fsync + rename; persist before responding | the disk lies about fsync (use enterprise storage or an HSM) |
| 12 | **Fleet grows to ~100k devices** | Used list 4.8 MB | — | **Rewrites 4.8 MB per resume: ~480 GB/day, ~1.2 h/day of blocking I/O (S4)** | — | Availability | Disk wear, latency | Used list | Log-structured store keyed by ticket_id with expiry-based compaction | — |
| 13 | Broker restarts | TLS sessions and ticket keys lost; retained messages kept only with `persistence true` (v2.1) | Full TLS handshake | Unaffected | Re-accepts everyone | — | N × 6.3 KB and full handshakes (ECDSA + hybrid) | Broker DB, including persistent MQTT sessions | v2.1 plus jitter (#14) | persistence disabled (verified N5) |
| 14 | **Mass power restoration** | Thousands reboot within seconds | Reconnect at once | Burst of resumes | Burst of full TLS | Availability | Broker CPU and radio-cell congestion | — | v2.1 has jitter **only for policy activation**. **Proposed:** randomised exponential back-off on every reconnect, spread over a class-dependent window; E4 measures it | the cellular cell itself is the bottleneck **[HW]** |
| 15 | Link loss mid-E2E handshake (NB-IoT) | — | MQTT QoS 1 retransmits the same bytes | Duplicate cache: identical reply (v2.1) | Redelivers | — | — | — | v2.1 | **a retransmission later than DUP_WINDOW (120 s) is treated as new: for RH that means "already used", then a full handshake. Set DUP_WINDOW per class ≥ worst reconnect time** |
| 16 | MQTT QoS 1 duplicates | — | Idempotent (v2.1) | Idempotent (v2.1) | — | — | — | — | v2.1 | — |
| 17 | **Manifest larger than the device's Maximum Packet Size** | Device declared, e.g., 8 or 16 KiB | **Never receives it; no error (T1)** | Believes it was published | **Drops it silently (spec-mandated)** | Update availability, which is a security property (patches) | Endless waiting | — | **Proposed:** chunk the manifest; declared maximum in registry; the utility checks | a class limit is set wrongly in the policy (validator must check it against artifact sizes) |
| 18 | Power loss mid-download | Some chunks written | Resumes from the retained chunks (v2.1, tested) | — | Retained | — | Re-fetches missing chunks | Chunk bitmap | v2.1 | retained chunks already cleaned (#19) |
| 19 | Retained artifacts cleaned before a slow device finishes | Rollout ending | Missing chunks | — | Deleted | Availability | — | — | v2.1: retention window (e.g. 30 days) | a device offline longer than the window must re-request (add a "republish" request) |
| 20 | New firmware fails to boot | Slot B staged | Watchdog or self-test fails, then revert (v2.1) | — | — | Rollback protection intact (counter not advanced) | One reboot | Slots, counter | v2.1 | **an external slot B modified after the check: re-verify the hash at swap/boot** |
| 21 | **Watchdog fires during long crypto** | SLH verify 0.21–0.56 s (M4 at 64–24 MHz); TLS full on M0+ ~0.8 s | Reset loop | — | — | Availability | — | — | **Proposed:** watchdog period > the worst crypto time per class, or run crypto in a task that kicks the watchdog between blocks | **[HW]** |
| 22 | **Outbox fills flash** | Offline for days, alerts keep coming | Writes until flash is full | — | — | Availability; alert delivery | Flash wear | Outbox | **Proposed:** bounded outbox, merge per alert type, "dropped N" counter | — |
| 23 | **Counter pages wear out** | High-rate set-points | Flash errors after ~0.4 years for one page | — | — | Apply-once | — | Counter log | **Proposed:** wear-levelled log; grants remove per-set-point persistence; do **not** use OPS-5's "reserve 100" on the device | — |
| 24 | Device offline for months | Ticket, chain, TLS ticket all expired; commands expired | Full TLS + full E2E; installs the newest policy directly (v2.1) | Does not redeliver expired commands (v2.1) | — | — | One cold start | — | v2.1 C13 **plus #1–#3** | certificate or clock issues (#1–#3) |
| 25 | Clone (keys copied) | — | Genuine device kicked off (N4) | "ticket already used" alarm (v2.1) | Takeover logged | Detection only | — | — | Revoke and re-provision (v2.1) | the clone acts first and the genuine device is then the one blocked; needs an operator |
| 26 | Captured meter (keys extracted, including by side-channel) | Physical access | — | — | — | **Per-device keys** limit the damage to that device plus its zone's DR confidentiality (not integrity: signature) | — | — | Revoke; rotate the zone key (v2.1) | — |
| 27 | **Weak RNG at boot** | Cheap part, no TRNG | ML-KEM/X25519 keys and nonces predictable | — | — | Everything | — | — | **Proposed requirement:** hardware TRNG + SP 800-90A DRBG, seeded before the first handshake (SAM4CM and CC310 have TRNGs; the RP2040 ring oscillator is not certified) | **[HW]** |
| 28 | **Command-signing HSM unavailable** | — | — | Cannot sign commands | — | Availability of CONTROL | — | — | **Proposed:** queue with expiry, alarm; grants keep existing set-point streams going until they expire | — |
| 29 | **A TLS 1.2 listener is enabled** (e.g. for PSK or legacy clients) | — | May negotiate classical DHE | — | **`Groups` pin does not apply to TLS 1.2 (T7)** | Post-quantum hop confidentiality | — | — | **Proposed validator:** every listener `tls_version tlsv1.3` | an operator adds a legacy listener |
| 30 | Persistent MQTT session queue overflows while a device sleeps | Many commands queued | — | E2E redelivery covers it (v2.1) | Drops beyond `max_queued_messages` | — | — | Broker DB | v2.1 redelivery + #9 fix | — |
| 31 | IP change / NAT rebinding | — | TLS resumes from a new IP (N7) | Unaffected | — | — | — | — | v2.1 | — |
| 32 | Forged resync hint | — | One cheap resume, then rate limit (v2.1) | — | — | DoS only | 1 resume per 30 s | — | v2.1 | — |

---

## Part 13 — Security gained against resource cost, per choice

Device costs are per event. Bytes are [DOCKER]; cycles are [ANALYTICAL from LIT] Cortex-M4.

| Choice | Security gained, against whom | Device bytes | Device cycles | RAM / flash | Who else pays | Worth it? |
|---|---|---|---|---|---|---|
| Hybrid TLS 1.3 (vs classical) | All traffic, against record-now-decrypt-later | +~2.3 KB per handshake (key shares) | +1.35 M (ML-KEM) | +13 KB code | Broker CPU (small) | **Yes** |
| Hybrid-only pin | Blocks silent classical fallback (N3) | 0 | 0 | 0 | — | **Yes**, and extend it to "no TLS 1.2 listeners" |
| ECDSA P-256 hop certificates | Hop identity (a live-only threat) | ~0.9 KB of certificates | **11.3 M (57% of a cold start)** | small | CA operations | **Yes**, with the time fixes (Part 12 #1–#3). ML-DSA certificates cost 24–32 KB; PSK is not PQ on Mosquitto |
| E2E hybrid KEM-MQTT | Alerts and commands against the broker | 5.2 KB per full handshake; 0.76 KB per PSK resume | 5.8 M full; 0 PSK | ~7–13 KB transient | Utility CPU (small) | **Yes**: the only way to exclude the broker |
| POLICY_INFO bound into keys | Silent downgrade of the policy | tens of bytes | ~0 | 0 | — | **Yes** |
| ALERT: E2E + ACK + outbox | Confidentiality, integrity and delivery against the broker | +73 B per alert | ~0 | Flash writes per alert | — | **Yes**, with a bounded outbox |
| CONTROL: per-command ML-DSA-65 | Forgery by session-key holders (**only with separation of duties**); non-repudiation | +3.3 KB per command | 2.4 M per verify | 2.7–9.9 KB stack | Utility or HSM signing | **Yes for discrete commands; no for 5-s streams** (use grants) |
| Zone keys + broadcast signature | DR confidentiality within a zone; authenticity against captured members | 3.4 KB per member per rotation (signed delivery) | 2.4 M per rotation | — | — | Signature on key delivery: **no** (use session AEAD). Signature on events: **yes** |
| PASR (PSK / PSK+KEM) | Cheap re-keying within policy limits | −86% / −41% bytes | 0 / 2.6 M | Ticket in flash | Utility persistence | **Yes**, with the state fixes. Time saving is modest on NB-IoT |
| STEK rotation + persisted used list | Ticket replay, and blast radius of a stolen STEK | — | — | — | Utility I/O (**a real scaling issue, S4**) | **Yes**, with the storage fix |
| SLH-DSA-192s firmware | Forgery of firmware, even if lattice maths is broken | 16.2 KB per manifest | 13.5 M per verify | 3.7 KB stack; SHA-512 code | Station (offline) | **Yes, but 128s gives the same kind of security for half the bytes** (Part 4) |
| Merkle chunks | Per-chunk integrity with constant memory | +256 B per 4 KiB chunk (6%) | Hashing | ~300 B | — | **Yes** |
| A/B + commit after boot | No bricking; no rollback | — | — | **2× image flash** | — | **Yes**; C2 needs external flash (re-verify it) |
| Utility-authenticated time | Command expiry despite a bad RTC | 16 B | 0 | 8 B (time floor) | — | **Yes**, *but only after TLS is up*: add Part 12 #1 |
| Duplicate cache (120 s) | Correctness under QoS 1 duplicates | 0 | 0 | — | Utility memory | **Yes**; tune the window per class |
| One session per device | Clone detection; simple replay state | 0 | 0 | — | — | **Yes** |
| Binary encoding | Parser robustness; no canonicalisation bugs | smaller | smaller | smaller parser | — | **Yes**; extend it to the policy |

---

## Part 14 — Decision matrix

Colours are defined in §0. "New" rows are decisions the audit adds.

| # | Decision (BalaMP.md §14) | Colour | Why | Proposal (Part 16) |
|---|---|---|---|---|
| D1 | Hybrid TLS 1.3, X25519MLKEM768 | **GREEN** (+Y7) | Correct. Costs about 20 ms of X25519 on an M4 | Y7 |
| D2 | E2E session device ↔ utility | **GREEN** | The only placement where "broker cannot read" is true | — |
| D3 | Hybrid inside E2E | **GREEN** (C2: YELLOW) | Cost 3.1 M cycles; affordable wherever TLS fits | — |
| D4 | ChaCha20-Poly1305 E2E, AES-256-GCM in TLS | **YELLOW** | Two AEADs on one device | Y1 |
| D5 | ML-DSA-65 per command | **YELLOW** / **RED at 5-s set-points** | Separation of duties unstated; bytes at high rate | R7, Y5, Y6 |
| D6 | SLH-DSA-SHA2-192s | **ORANGE** | 16 KB manifest vs packet limits and RAM; SHA-512; single anchor | O4, O7 |
| D7 | ECDSA P-256 hop certificates | **RED** (time handling) → GREEN once fixed | Clock and expiry deadlocks (T4) | R1 |
| D8 | Strongest rule wins, default CONTROL | **GREEN** | — | — |
| D9 | Utility-issued single-use tickets, 24 h STEK | **YELLOW** | 8-bit key id; retirement not automatic | Y14 |
| D10 | Resume modes per class; unicast control ⇒ PSK_KEM/NONE | **GREEN** | — | — |
| D11 | Merkle chunks, chunk size per class | **GREEN** | — | — |
| D12 | Policy via FOTA with activate_at | **GREEN** | — | — |
| D13 | Docker only | **GREEN** | — | — |
| D14 | Binary encoding everywhere | **YELLOW** | The policy is still canonical JSON with hex keys | Y3 |
| D15 | Pin hybrid-only groups | **YELLOW** | Does not cover TLS 1.2 listeners (T7) | Y7 |
| D16 | Idempotent handling, 120 s | **YELLOW** | The window must exceed the worst reconnect time per class | Y8 |
| D17 | Confirm before use (wait for NT/FIN) | **ORANGE** | Costs a round trip that ACK + outbox already cover | O2 |
| D18 | Utility-authenticated time | **RED** | Unreachable when TLS rejects the clock (T4) | R1 |
| D19 | E2E ACKs, redelivery, apply at most once | **RED** | S1 (sequence reset) and S2 (write-before-actuate) | R2, R3 |
| D20 | Persist STEK and used list | **RED** | Non-atomic, no fsync, O(n) rewrite (S3, S4) | R4 |
| D21 | A/B, commit after boot | **GREEN** (+Y13) | External slot B must be re-verified | Y13 |
| D22 | Device-ID rules, parser caps, one half-open per device | **GREEN** | — | — |
| D23 | Broker persistence, `max_packet_size 300000` | **YELLOW** | The broker limit is fine; the *device* limit is the problem | R5 |
| D24 | Resync hint | **GREEN** | — | — |
| New | Scope: which device classes the design targets | **RED** | "Hardware-independent" is false; C0/C1 cannot run it | R6 |
| New | Manifest delivery vs the device's max packet | **RED** | Silent non-delivery (T1) | R5 |
| New | Reconnect strategy per class | **ORANGE** | Handshakes are 97–98% of meter bytes | O1 |
| New | Constrained-class profile (records, stacks, streaming) | **ORANGE** | C2 RAM | O3 |
| New | Counter storage on the device | **ORANGE** | Flash wear; OPS-5 is wrong for the device | O5 |
| New | Reconnect back-off for outage restoration | **ORANGE** | Jitter exists only for policy activation | O6 |
| New | Multiple firmware anchors with revocation | **ORANGE** (production) | Key-loss risk | O7 |

---

## Part 15 — Mid-semester report against v2.1: consistency

**Current** = what v2.1 says today, with the audit's proposal in brackets.
The report's choices are background only; none is copied back into v2.1.

| # | Item | Report (mid-sem, **report claim**) | v2.1 now | Why it changed | Current | Does the old evidence still apply? | Is an old claim now invalid? |
|---|---|---|---|---|---|---|---|
| 1 | Hop key exchange | Hybrid TLS 1.3 X25519MLKEM768; cites Setyowati as "hybrid TLS with ML-KEM-768 for MQTT" | Same, **pinned** hybrid-only | Defaults accept classical-only clients (N3) | v2.1 (+ TLS 1.3-only listeners) | **No.** Setyowati is TLS 1.2 + app-layer ML-KEM over HTTP. Replace with our Docker results and Tasopoulos (PQ TLS on an M4) | **Yes**: the description of Setyowati |
| 2 | Tier key | eq. 3.2 `K_session = KDF(K_TLS, policy_id, tier)` | KDF over E2E KEM secrets and the transcript | The broker holds K_TLS | v2.1 | n/a | **Yes**: "alerts/commands end to end" was false under eq. 3.2 |
| 3 | POLICY_INFO transport | MQTT 5 enhanced authentication | Inside the E2E handshake | Broker is not a party; Mosquitto needs a C plugin | v2.1 | n/a | Yes (mechanism) |
| 4 | Policy engine and ticket manager | Broker | Broker = TLS + ACL; tickets at the utility | The ticket issuer must hold the session secret | v2.1 | n/a | Yes |
| 5 | Firmware signature | ML-DSA-65 ("or SLH-DSA") | SLH-DSA-192s (**proposed 128s**) | Irreplaceable anchor; hash-only assumption | v2.1 → O4 | **No.** Domingo's timings are from a 2012 laptop, not a meter | **Yes**: "sub-millisecond ML-DSA verification … weekly updates" is not a meter figure; Domingo says updates are **yearly** |
| 6 | Chunk integrity | Per-chunk hash list | Merkle root + audit paths | Constant device memory | v2.1 | n/a | No |
| 7 | Control and resumption | "Control-tier topics excluded from resumption" | Unicast-control classes resume only with PSK+KEM or not at all | One connection carries all tiers | v2.1 | n/a | Yes (not implementable) |
| 8 | Resume key | eq. 3.8 `KDF(K_ticket, nonces)` | `KDF(psk [‖ ss_e′], transcript)` + binder | Forward-secrecy option; possession proof | v2.1 | n/a | Yes |
| 9 | Ticket key | Broker-held | Utility STEK, rotated; single-use | Bounded exposure | v2.1 (+ R4 storage) | n/a | Yes |
| 10 | Reconnection benefit | "reduce reconnection latency by 60–70%" (expected) | Measured 92% compute / 86% bytes (PSK, laptop) | Honesty rules | v2.1 + T6 | **Partly.** Laptop compute and bytes still hold | **Yes for latency on cellular:** PASR alone gives −17 to −23% time on simulated NB-IoT. With proposal D, −44 to −50% against a cold start. Quote T6 with its labels |
| 11 | Base paper numbers | "4.32 s handshake … only 3 KB stack" | — | — | — | Partly | **Yes**: 3 KB is the Kyber code; handshake phases used 5.7 KB. It was simulated without transmission time |
| 12 | Malina numbers | "Falcon signing 145 ms, Kyber encaps 17.17 ms on a Pi Zero" | — | — | — | Yes, with the missing context | Add: **Level 5**, 5 repetitions. Their broker re-encrypts |
| 13 | Traffic profiles | From Alghawli (report §4.1, §4.2.5) | E3 labels it SIMULATED | — | Audit: P1/P2 realistic, P3 stress | **Only as a stress case**: 802.15.4 simulation with 15-**second** meter reads | **Yes**: presenting it as realistic AMI contradicts report §1.1 (5–15 **minute** intervals) |
| 14 | Hardware claim | "The framework's design is hardware-independent" (§4.2.5) | v2.1: no smart-meter performance claims | — | Audit: class-dependent | — | **Yes**: feasibility depends on class (C0/C1 infeasible; C2 needs the constrained profile) |
| 15 | Target devices | NB-IoT/LTE-M meters, DER controllers, EV chargers, gateways (§1.3) | Same | — | Same + scope note (R6) | Yes | Needs the note: C0/C1 meters behind gateways; chargers and DER often behind C3/C4 gateways |
| 16 | PQC library | liboqs + oqs-provider | OpenSSL ≥ 3.5 native | Verified | v2.1 | n/a | Yes (not needed). For MCUs: wolfSSL-class, since Mbed TLS lacks ML-KEM |
| 17 | Suleiman figures | "90% speed increase; ASCON 6–21 µs" | — | — | — | **Unreliable** | Avoid citing its numbers (board results swapped; byte/bit confusion) |
| 18 | Tier naming | "Policy-Driven Hybrid Cryptographic Configuration" vs PCHC | PCHC everywhere | Consistency | v2.1 | n/a | Yes (naming only) |
| 19 | Energy | "bandwidth and energy cost matters on cellular AMI links" (qualitative) | No energy numbers | — | Audit Part 11 | Yes | No, but never quote Kim & Seo's 71.75 mJ as measured |

---

## Part 16 — Proposed changes (awaiting your approval)

Format for each: **OLD DESIGN · PROBLEM · EVIDENCE · ALTERNATIVES · TRADE-OFF · PROPOSED CHANGE**. Nothing below
has been applied. After approval, BalaMP.md §3/§5/§12/§13/§14 and the matching Rationale sections would be
updated, and every S/T experiment becomes a regression test in `design-validation`.

### RED — fix before implementation

**R1 · Clock and certificate validity on the TLS hop**
- **OLD:** B21/D18: the device takes time from the authenticated utility handshake; "a device at 1970
  connects". Device certificates carry normal lifetimes.
- **PROBLEM:** TLS runs *before* the E2E layer, and it refuses a 1970 clock ("not yet valid"), a clock years
  ahead ("expired"), and an expired device certificate. The device can never reach the utility that would
  fix its clock.
- **EVIDENCE:** T4 a–g [DOCKER]; validate.py's clock tests only exercised the E2E layer.
- **ALTERNATIVES:**
  1. battery-backed RTC (hardware cost; some meter SoCs have one, e.g. SAM4CM);
  2. unauthenticated NTP or cellular network time (attackable);
  3. device skips certificate validity-time checks, plus long-lived device certificates;
  4. a persisted time floor.
- **TRADE-OFF:** skipping time checks means a compromised CA key is valid forever. It is mitigated by a
  private, pinned, rotatable CA (OPS-1) and by revocation at the broker. Long-lived device certificates move
  revocation onto the registry and ACL, which the utility already controls.
- **PROPOSED:**
  - device TLS verifies the chain with `X509_V_FLAG_NO_CHECK_TIME` (or the embedded-library equivalent);
  - device certificates get `notAfter = 99991231235959Z`;
  - broker certificates rotate under the CA overlap rule (OPS-1);
  - the device persists a monotonic **time floor** (the last authenticated utility time, written daily) and
    uses max(RTC, floor) until the E2E handshake sets its clock;
  - new tests: T4 plus "1970 device completes TLS + E2E and corrects its clock".

**R2 · The utility's command sequence survives restarts**
- **OLD:** `cmd_seq` and `pending_cmds` live in utility RAM; the device answers DUP for `seq ≤ last_applied`.
- **PROBLEM:** after a restart, new commands reuse low sequence numbers. The device answers DUP; the utility
  deletes them. **Silent command loss.**
- **EVIDENCE:** S1 [DOCKER].
- **ALTERNATIVES:**
  1. persist the counter per device before sending;
  2. seq = (utility epoch ‖ counter), with the epoch persisted once per restart;
  3. use a timestamp as seq (needs clock monotonicity).
- **TRADE-OFF:** (1) costs one DB write per command; (2) costs one write per restart. Both are cheap.
- **PROPOSED:**
  - option (2), plus persisting the redelivery queue;
  - the device distinguishes **DUP** (seq equals a recently applied one) from **STALE** (below
    `last_applied` but never seen), and the utility **alarms** on STALE;
  - new test: S1 must fail closed.

**R3 · Apply-at-most-once with honest confirmation**
- **OLD:** the device writes `last_cmd_seq`, then the command is applied, then ACK "OK".
- **PROBLEM:** a power cut between the write and actuation loses the command, and sometimes the ACK already
  claimed success.
- **EVIDENCE:** S2a/S2b [DOCKER].
- **ALTERNATIVES:**
  1. write after apply (at-least-once: duplicates after a crash);
  2. an intent log;
  3. rely on idempotent commands.
- **TRADE-OFF:** exactly-once is impossible across a crash without actuator feedback. Be explicit instead.
- **PROPOSED:**
  - intent log PENDING(seq) → actuate → APPLIED(seq) → ACK "OK";
  - after a reboot, a PENDING record is reported as **INTERRUPTED**;
  - commands carry an `idempotent` flag (absolute set-points may be re-applied; "trip" may not);
  - new test: S2 variants.

**R4 · Crash-safe, scalable utility persistence**
- **OLD:** JSON files rewritten whole with `open(path, "w")`.
- **PROBLEM:** a torn write blocks restart or kills every ticket. There is no fsync, so a consumed ticket can
  be forgotten. The rewrite is O(n) per resume: ~480 GB/day at 100k devices.
- **EVIDENCE:** S3, S4 [DOCKER].
- **ALTERNATIVES:** SQLite (WAL, `synchronous = FULL`); an append-only log plus compaction; an HSM for the
  STEK; a database for high availability (OPS-7).
- **TRADE-OFF:** one more dependency, and fsync latency (~ms) per resume.
- **PROPOSED:**
  - SQLite for the used-ticket set, command sequences and queue; rule: **persist, then respond**;
  - STEK written temp + fsync + rename (HSM in production), retired automatically;
  - tests: S3 and S4 as regression tests.

**R5 · Every artifact fits the device's packet limit**
- **OLD:** the manifest is one retained 16,405 B message; the chunk size per class applies only to data
  chunks.
- **PROBLEM:** a device declaring MQTT 5 Maximum Packet Size ≤ 16,384 **never** receives the manifest, with no
  error (spec-mandated silent drop).
- **EVIDENCE:** T1 [DOCKER].
- **ALTERNATIVES:**
  1. require devices to accept ≥ 17 KB (fails C2);
  2. chunk the manifest;
  3. use 128s so it fits 8 KiB (O4).
- **TRADE-OFF:** chunking adds a few messages and a reassembly step into flash.
- **PROPOSED:**
  - the manifest travels as parts no larger than the class `max_packet`, reassembled into flash and verified
    from flash;
  - each device's declared maximum goes into its registry entry, and the utility/station refuses oversized
    artifacts for that class;
  - the policy validator checks the class chunk size against `max_packet`;
  - test: T1 plus a C2-sized device installing an update.

**R6 · State the device scope**
- **OLD:** the report says the design is "hardware-independent"; v2.1 lists meters, DER, EV and gateways
  without classes.
- **PROBLEM:** C0/C1 (6–16 KB RAM) cannot run TLS at all. C2 fits only with a constrained profile.
- **EVIDENCE:** Parts 5, 8, 10 [ANALYTICAL from LIT].
- **ALTERNATIVES:** (a) claim universality (false); (b) a separate KEM-MQTT-only profile for 8-bit devices
  (Kim & Seo), which is out of project scope; (c) put C0/C1 behind gateways (DLMS/COSEM, as Domingo
  describes).
- **PROPOSED:**
  - adopt (c);
  - add a "Device classes" section (Part 1 table) to BalaMP.md §4;
  - remove "hardware-independent" from any future text;
  - evaluation claims are stated per class.

**R7 · High-rate control**
- **OLD:** every command carries its own ML-DSA-65 signature.
- **PROBLEM:** at the report's own source rate (a set-point every 5 s): ~61 MB/day, ~7 h/day of airtime at
  20 kbit/s, and 17,280 verifies/day. On the utility side: 27 CPU-hours per 10k DERs per day, or an HSM
  bottleneck.
- **EVIDENCE:** Part 6 [ANALYTICAL].
- **ALTERNATIVES:** ML-DSA-44 (−26% bytes); FN-DSA-512 (−77%, **not final**); session AEAD only (loses
  forgery resistance against session-key holders); **signed grants**.
- **TRADE-OFF:** within a grant, a live-session-key holder can move set-points inside the signed bounds.
  Per-set-point non-repudiation becomes per-grant.
- **PROPOSED:**
  - a CONTROL sub-type **GRANT**, signed with ML-DSA-65 over (sid, device, bounds, max rate, expiry), and a
    sub-type **SETPOINT** under session AEAD, checked by the device against the live grant;
  - discrete commands keep per-command signatures;
  - the policy says per class which sub-types are allowed;
  - add P1/P2 as the realistic E3 profiles, P3 as a stress bound.

### ORANGE — class or profile dependent

| # | OLD | PROBLEM | EVIDENCE | ALTERNATIVES | TRADE-OFF | PROPOSED |
|---|---|---|---|---|---|---|
| O1 | Reconnect behaviour unspecified per class | Meters waking every 15 min spend 97–98% of bytes on handshakes; the TLS ticket expires after 2 h | T2, T5 [DOCKER]; Part 6 | Batching; keeping the connection open (LTE-M/eDRX); a longer broker ticket lifetime (not settable in Mosquitto config) | Batching delays data (fine for AMI); an open connection costs keep-alives and needs a non-PSM radio | Policy field `reconnect` per class (batch interval, or persistent connection); E3/E4 measure bytes per day per strategy |
| O2 | D17 confirm-before-use; SUBSCRIBE on every connection | 6 round trips before the first protected message | T6 [SIM] | Keep; or 1-RTT resume + persistent MQTT session + pipelining | Broker keeps per-device session state; a lost DF means alerts are resent (outbox already handles it) | **Proposal D**: −22 to −27% time on simulated NB-IoT against the v2.1 wake; envelopes carried *inside* DF; `clean_start = false` + Session Expiry |
| O3 | No constrained profile | Peak RAM 45–52 KB with default TLS buffers | T3 [DOCKER]; Part 10 | Use a bigger MCU; or the constrained profile | Small records add a little per-record overhead (17 B per record) | C2 profile: max_fragment_length 512–1,024, small-stack PQ code, artifacts streamed to flash, manifest verified from flash |
| O4 | D6: SLH-DSA-SHA2-192s | 16.2 KB signature: packet limits, RAM, SHA-512 on SHA-256-only engines | T1; Part 4 | 128s; LMS/HSS with a hardware station; keep 192s + chunking | Category 1 instead of 3 (still post-quantum, hash-only) | **SLH-DSA-SHA2-128s** for firmware and policy (B10's recorded trigger is met). **Needs your decision** |
| O5 | OPS-5 "reserve counters every 100" | Wrong on the device side (refuses the next 100 commands after a reboot); flash wear at high rate | Part 7 [ANALYTICAL] | Log-structured records; no per-set-point persistence (grants) | A few KiB of flash for the log | Wear-levelled append log for device counters; OPS-5 applies to the utility side only |
| O6 | Jitter only for policy activation | Outage restoration: everyone reconnects at once | Part 12 #14 | Randomised exponential back-off on every reconnect | Slower recovery for some devices | Back-off window per class; E4 measures it |
| O7 | One burned-in SLH-DSA anchor | Key loss or compromise is unrecoverable | Part 4 | ≥ 2 anchors with signed revocation | A second offline key to guard | Two or more anchors; revocation signed by a different anchor; revocation counter in protected storage |

### YELLOW — keep, but add a requirement or fix an explanation

| # | Item | Proposed |
|---|---|---|
| Y1 | Two AEADs per device | One AEAD per class, at both layers: AES-256-GCM where AES hardware exists, otherwise ChaCha20-Poly1305 (and TLS negotiates `TLS_CHACHA20_POLY1305_SHA256`) |
| Y2 | B7's Ascon reason ("128-bit key") | Replace with: no TLS suite exists for it, so it would be an extra AEAD. AES-128-level keys are not a quantum weakness per NIST |
| Y3 | The policy is canonical JSON with hex keys | Use the same length-prefixed binary codec (D14) |
| Y4 | Zone keys delivered as **signed** CONTROL | Deliver under the session AEAD; rotate on membership change + weekly |
| Y5 | Command key vs E2E KEM key both "utility" | Require separation of duties: signing key in an HSM or separate command service |
| Y6 | FN-DSA dismissed | Record a trigger: re-evaluate FN-DSA-512 for utility → device signatures when FIPS 206 is final and a vetted library exists |
| Y7 | Hybrid pin | Validator: every listener `tls_version tlsv1.3`. TLS 1.2 gives classical DHE (T7) |
| Y8 | Fixed 120 s duplicate window, 60 s pending TTL | Per class: ≥ 2× the worst handshake or reconnect time on that link |
| Y9 | Unbounded outbox | Cap, merge, "dropped N" counter |
| Y10 | RNG unstated | Hardware TRNG + SP 800-90A DRBG, required before the first handshake |
| Y11 | Watchdog vs long crypto | Budget the watchdog per class; crypto in a task that kicks it |
| Y12 | Where TLS runs | On the application MCU with a hybrid-capable library (wolfSSL-class); modem-offloaded TLS is not PQ |
| Y13 | FOTA limits and external flash | Device limit = its own slot size; re-verify the hash of an external slot B at swap/boot |
| Y14 | STEK key id and retirement | Retire keys automatically after the maximum ticket lifetime; use a key id wider than 8 bits, or guarantee no wrap inside the retention window |

### What does not change

- The three objectives.
- The hybrid rule.
- ML-KEM-768.
- The E2E placement and the KEM-MQTT structure.
- The policy engine and binding.
- The tiers.
- PASR's checks and invariant.
- The Merkle tree.
- A/B slots with commit after boot.
- The attack suite: all 80 scenarios still pass as they are.

The proposals **add tests**; they never weaken one.

---

## Appendix — Reproduce, and what still needs hardware

```bash
design-validation/constrained-audit/run_audit.sh
```

The runner does four steps, each writing to `results/`:
1. the state audit (S1–S5);
2. TLS/time/PSK (T2, T3, T4, T7);
3. transport (T1, T5, T6: about 15 minutes);
4. the analytical budgets.

Everything runs in Docker, with no host mounts.

**[HW] open questions** (only real hardware can answer):
- ML-KEM/ML-DSA/SLH-DSA timings with flash wait states, on the actual meter MCU.
- TLS library footprint (wolfSSL build) and total RAM, including the application.
- NB-IoT/LTE-M energy per reconnect for the full design.
- Carrier NAT timeouts.
- How much SHA-256 hardware speeds up SLH-DSA.
- The watchdog budget.
- The HSM's ML-DSA signing rate.

A single nRF9160 (C3) or Cortex-M4 development board with a modem would settle most of them. That is the
existing ESP32 stretch goal, redirected to the target class.
