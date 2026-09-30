"""[ANALYTICAL RESULT] budgets for the constrained-IoT audit, computed from CITED inputs only.
Nothing here is a measurement of a meter. Every input carries its source tag; see SOURCES at the bottom.
Cycle counts -> time use the stated clock and are LOWER BOUNDS (flash wait states, interrupts, TLS/MQTT
library overhead and the application are not included)."""

# --------------------------------------------------------------------------------------------- inputs
SZ = {  # bytes; [FIPS203] [FIPS204] [FIPS205] [RFC8554] [RFC8391] [FALCON]
    "mlkem512": dict(pk=800, sk=1632, ct=768), "mlkem768": dict(pk=1184, sk=2400, ct=1088),
    "mlkem1024": dict(pk=1568, sk=3168, ct=1568),
    "mldsa44": dict(pk=1312, sig=2420), "mldsa65": dict(pk=1952, sig=3309), "mldsa87": dict(pk=2592, sig=4627),
    "slh128s": dict(pk=32, sig=7856), "slh128f": dict(pk=32, sig=17088), "slh192s": dict(pk=48, sig=16224),
    "slh192f": dict(pk=48, sig=35664), "slh256s": dict(pk=64, sig=29792),
    "falcon512": dict(pk=897, sig=666), "falcon1024": dict(pk=1793, sig=1280),     # FIPS 206 NOT final
    "lms_h10_w8": dict(pk=56, sig=1456), "lms_h15_w8": dict(pk=56, sig=1616), "lms_h20_w8": dict(pk=56, sig=1776),
    "xmss_sha2_10_256": dict(pk=68, sig=2500),
    "x25519": dict(pk=32), "ecdsa_p256": dict(pk=65, sig=64),
}
M4 = {  # Cortex-M4 cycles. [PQM4] NUCLEO-L4R5ZI @24 MHz (m4f/m4fspeed = fast, m4fstack = small stack)
    "mlkem768_keygen": 642_096, "mlkem768_encaps": 658_754, "mlkem768_decaps": 707_827,
    "mlkem512_keygen": 392_423, "mlkem512_encaps": 390_881, "mlkem512_decaps": 428_167,
    "mldsa44_verify": 1_421_623, "mldsa65_verify": 2_415_944, "mldsa87_verify": 4_193_104,
    "mldsa65_verify_smallstack": 5_732_397, "mldsa44_sign": 3_943_121, "mldsa65_sign": 6_193_171,
    "slh128s_verify": 7_471_794, "slh192s_verify": 13_494_855, "slh128f_verify": 21_923_628, "slh256s_verify": 19_637_153,
    "falcon512_verify": 473_061,                                    # [PQM4-R3] STM32F4DISCOVERY @24 MHz
    "x25519": 625_358,                                              # [HL19] per scalar multiplication
    "ecdsa_p256_sign": round(12.305e-3 * 180e6), "ecdsa_p256_verify": round(25.193e-3 * 180e6),   # [TAS22] wolfSSL @180 MHz
}
M4_STACK = {  # bytes, excluding keys/ct/sig buffers [PQM4]
    "mlkem768_fast": 6_468, "mlkem768_small": 2_860, "mldsa65_verify_fast": 9_888, "mldsa65_verify_small": 2_712,
    "slh192s_verify": 3_700, "slh128s_verify": 1_968,
}
M0 = {  # Cortex-M0+ RP2040 @125 MHz, PQClean reference C [RP2040] (preprint); ms
    "mlkem768_keygen": 16.02, "mlkem768_encaps": 18.58, "mlkem768_decaps": 22.02,
    "mldsa65_verify": 72.2, "mldsa44_verify": 44.0,
    "ecdsa_p256_sign": 92.6, "ecdsa_p256_verify": 321.4,                 # mbedTLS 3.6 on the same board
    "x25519": 3_589_850 / 125e6 * 1e3,                                   # [DULL15] Cortex-M0 cycles at 125 MHz
}
M0_RAM_KB = {"mlkem768_decaps_total": 18.9, "mldsa65_sign_total": 86.7, "mldsa44_sign_total": 56.8}   # [RP2040] Table IX
AVR = {"x25519_cycles": 13_900_397, "kemmqtt_kyber512_client_cycles": 31_833_391, "sram": 6 * 1024}   # [DULL15] [KS25]
ENERGY_MJ = {  # [TAS23] measured, whole NUCLEO-F439ZI board @180 MHz, 3.3 V (includes ~100 mW board idle)
    "kyber768_keygen": 1.891, "kyber768_enc": 1.802, "kyber768_dec": 1.240, "ecdhe_keygen": 1.588, "ecdhe_agree": 3.369,
    "ecdsa_sign": 2.283, "ecdsa_verify": 4.782, "dil3_verify": 2.586, "dil2_verify": 1.541, "falcon512_verify": 0.465,
    "sphincs128s_verify": 12.028, "tls_dil2_kyb1_client": 15.006, "tls_ecdsa_ecdhe_client": 18.242, "tls_dil3_kyb3_client": 25.392,
}
RADIO_MAS_PER_EXCHANGE = {16: 275, 64: 282, 256: 318, 1024: 415}   # [LUK20] mAs per NB-IoT UDP echo, read from Fig. 6 (approx.)
MEAS = {  # measured in this project's Docker environment (results/transport.txt T5; ../results/bench.txt)
    "tls_full_ecdsa": 6262, "tls_resumed_ecdsa": 4438,      # incl. MQTT CONNECT/CONNACK and 2 NewSessionTickets [T5]
    "e2e_full": 5212, "e2e_psk": 755, "e2e_pskkem": 3103, "alert_env": 137, "control_env": 3442, "manifest": 16405,
}
MQTT_TLS_PER_PUBLISH_QOS1 = 93 - 37          # [T5] measured QoS 1 publish overhead 93-94 B incl. a 37-byte topic, PUBACK and
                                              # both TLS records; the topic is added back per profile below

def ms(cycles, mhz): return cycles / (mhz * 1e3)
def hdr(t): print("\n" + "=" * 100 + "\n" + t + "\n" + "=" * 100)

# --------------------------------------------------------------------------------------------- 1. device crypto per connection
hdr("1. Device public-key work per connection in v2.1 (operation counts from BalaMP.md §5.2/§5.4 + TLS 1.3 client, mutual auth)")
OPS = {  # (ML-KEM-768 keygen, encaps, decaps, X25519 scalar mults, ECDSA sign, ECDSA verify)
    "TLS 1.3 full, X25519MLKEM768, ECDSA mutual":        (1, 0, 1, 2, 1, 2),
    "TLS 1.3 resumed (psk_dhe_ke, hybrid group)":        (1, 0, 1, 2, 0, 0),
    "E2E full handshake (3 hybrid KEMs)":                (1, 1, 2, 5, 0, 0),
    "E2E PASR PSK+KEM resume":                           (1, 0, 1, 2, 0, 0),
    "E2E PASR PSK resume":                               (0, 0, 0, 0, 0, 0),
}
def m4_cycles(o):
    kg, en, de, xs, ss, sv = o
    kem = kg * M4["mlkem768_keygen"] + en * M4["mlkem768_encaps"] + de * M4["mlkem768_decaps"]
    return kem, xs * M4["x25519"], ss * M4["ecdsa_p256_sign"] + sv * M4["ecdsa_p256_verify"]
def m0_ms(o):
    kg, en, de, xs, ss, sv = o
    return (kg * M0["mlkem768_keygen"] + en * M0["mlkem768_encaps"] + de * M0["mlkem768_decaps"],
            xs * M0["x25519"], ss * M0["ecdsa_p256_sign"] + sv * M0["ecdsa_p256_verify"])
print(f"{'phase':<46}{'ML-KEM':>10}{'X25519':>10}{'ECDSA':>10}{'total Mcyc':>12}{'@64MHz':>9}{'@24MHz':>9}   M0+@125MHz ms (KEM/X/EC)")
tot = [0, 0, 0]
for k, o in OPS.items():
    a, b, c = m4_cycles(o); t = a + b + c; m = m0_ms(o)
    print(f"{k:<46}{a/1e6:>10.2f}{b/1e6:>10.2f}{c/1e6:>10.2f}{t/1e6:>12.2f}{ms(t,64):>8.0f}ms{ms(t,24):>7.0f}ms   "
          f"{m[0]:.0f}/{m[1]:.0f}/{m[2]:.0f} = {sum(m):.0f}")
for k in ("TLS 1.3 full, X25519MLKEM768, ECDSA mutual", "E2E full handshake (3 hybrid KEMs)"):
    for i, v in enumerate(m4_cycles(OPS[k])): tot[i] += v
T = sum(tot)
print(f"\ncold start (full TLS + full E2E) on Cortex-M4: {T/1e6:.1f} Mcycles = {ms(T,64):.0f} ms @64 MHz, {ms(T,120):.0f} ms @120 MHz (lower bounds)")
print(f"  share: ML-KEM {100*tot[0]/T:.0f}%  X25519 {100*tot[1]/T:.0f}%  ECDSA P-256 {100*tot[2]/T:.0f}%  "
      f"-> the classical halves cost {100*(tot[1]+tot[2])/T:.0f}% of the device's public-key time")
e = (ENERGY_MJ["kyber768_keygen"] * 2 + ENERGY_MJ["kyber768_enc"] + ENERGY_MJ["kyber768_dec"] * 3
     + ENERGY_MJ["ecdhe_keygen"] * 3 + ENERGY_MJ["ecdhe_agree"] * 4 + ENERGY_MJ["ecdsa_sign"] + ENERGY_MJ["ecdsa_verify"] * 2)
print(f"energy proxy [TAS23 board-level, P-256 ECDHE used as a stand-in for X25519]: ~{e:.0f} mJ per cold start")
print(f"radio proxy [LUK20]: ONE 64-byte NB-IoT UDP exchange ~{RADIO_MAS_PER_EXCHANGE[64]} mAs = {RADIO_MAS_PER_EXCHANGE[64]*3.0:.0f}-"
      f"{RADIO_MAS_PER_EXCHANGE[64]*3.6:.0f} mJ at 3.0-3.6 V (voltage not stated in the paper)")
print("AVR (Kim & Seo device class): one X25519 = %.2f s at 16 MHz; the whole Kyber-512 KEM-MQTT client = %.2f s at 7.37 MHz;"
      % (AVR["x25519_cycles"] / 16e6, AVR["kemmqtt_kyber512_client_cycles"] / 7.3728e6))
print("  TLS 1.3 + a second hybrid E2E layer is not feasible in 6 KB SRAM (OpenSSL needs >= 16 KB stack [KS25]).")

# --------------------------------------------------------------------------------------------- 2. per-command signature
hdr("2. CONTROL authenticity: bytes and device verify cost per command")
env_base = MEAS["control_env"] - SZ["mldsa65"]["sig"]     # envelope without the signature (64-byte command)
for name, sig, cyc in [("ML-DSA-65 (v2.1)", SZ["mldsa65"]["sig"], M4["mldsa65_verify"]),
                       ("ML-DSA-44", SZ["mldsa44"]["sig"], M4["mldsa44_verify"]),
                       ("FN-DSA-512 (draft FIPS 206)", SZ["falcon512"]["sig"], M4["falcon512_verify"]),
                       ("LMS H10/W8 (stateful!)", SZ["lms_h10_w8"]["sig"], None),
                       ("session AEAD only (grant model)", 0, 0)]:
    c = f"{ms(cyc,64):6.1f} ms @64MHz" if cyc is not None else "   (not in pqm4)"
    print(f"  {name:<34} envelope {env_base + sig:>5} B   verify {c}")

# --------------------------------------------------------------------------------------------- 3. traffic profiles
hdr("3. Bytes per day per device (payload + E2E + an ANALYTICAL MQTT/TLS per-publish estimate; no TCP/IP headers)")
def per_pub(payload, topic=37): return payload + topic + MQTT_TLS_PER_PUBLISH_QOS1
PROFILES = {
  "P1 AMI meter, 15-min interval reads [AMI]": dict(tele=(96, 64), alert=(1, 137), ctrl=(0, 0)),
  "P2 DER, 2030.5-style: 5-min monitoring, 4 control events/day [IEEE2030.5]": dict(tele=(288, 128), alert=(2, 137), ctrl=(4, 3442)),
  "P3 Alghawli 'nominal' DER set-point every 5 s (SIMULATED profile) [ALG26]": dict(tele=(8640, 128), alert=(10, 137), ctrl=(17280, 3442)),
}
KEEPALIVE = 2 * (2 + 22)            # PINGREQ + PINGRESP, each in one TLS 1.3 record (ANALYTICAL; not measured)
CONN = {  # connection-management bytes per day
  "reconnect every 15 min, full TLS each time (ticket expired)": 96 * MEAS["tls_full_ecdsa"] + MEAS["e2e_psk"],
  "reconnect every 15 min, TLS resumed each time":               96 * MEAS["tls_resumed_ecdsa"] + MEAS["e2e_psk"],
  "reconnect 4x/day (batched reads), TLS resumed":               4 * MEAS["tls_resumed_ecdsa"] + MEAS["e2e_psk"],
  "always connected, keepalive 5 min, daily TLS + weekly E2E":   288 * KEEPALIVE + MEAS["tls_full_ecdsa"] + MEAS["e2e_full"] / 7,
}
for name, p in PROFILES.items():
    b_t = p["tele"][0] * per_pub(p["tele"][1]); b_a = p["alert"][0] * per_pub(p["alert"][1]); b_c = p["ctrl"][0] * per_pub(p["ctrl"][1])
    data = b_t + b_a + b_c
    print(f"  {name}\n     data: telemetry {b_t/1e3:.1f} kB + alerts {b_a/1e3:.1f} kB + control {b_c/1e3:.1f} kB = {data/1e3:.1f} kB/day")
    for cname, cb in CONN.items():
        if name.startswith("P1") or cname.startswith("always"):
            t_ = data + cb
            print(f"       + {cname:<60} {cb/1e3:7.1f} kB -> total {t_/1e6:6.2f} MB/day, security share {100*(t_-b_t-b_a-b_c)/t_:3.0f}%"
                  f", airtime @20 kbit/s {t_*8/20e3/60:6.1f} min/day")
    if p["ctrl"][0] > 100:
        grant = p["ctrl"][0] * per_pub(p["ctrl"][1] - SZ["mldsa65"]["sig"] - 24) + 24 * per_pub(400 + SZ["mldsa65"]["sig"])
        print(f"     per-command ML-DSA-65: {b_c/1e6:.2f} MB/day and {p['ctrl'][0]} verifies ({ms(p['ctrl'][0]*M4['mldsa65_verify'],64)/1e3:.0f} s CPU @64 MHz)"
              f" | hourly signed grant + AEAD set-points: {grant/1e6:.2f} MB/day and 24 verifies")

hdr("3b. Round trips before the first E2E-protected message (ANALYTICAL; T6 simulates the same flows)")
RTT = {"A cold: TCP 1 + TLS 1 + CONNECT 1 + SUBSCRIBE 1 + E2E full 2": 6, "C wake: TCP 1 + TLS(resumed) 1 + CONNECT 1 + SUBSCRIBE 1 + PSK 2": 6,
       "D proposal: TCP 1 + TLS(resumed) 1 + CONNECT 1 (persistent session) + 1-RTT PSK": 4,
       "E telemetry-only wake: TCP 1 + TLS 1 + CONNECT 1 + PUBLISH/PUBACK 1": 4}
for k, n in RTT.items(): print(f"  {k:<84} {n} RTT -> {n*1.0:4.0f} s @1 s RTT, {n*4.0:4.0f} s @4 s RTT (+ serialisation)")

# --------------------------------------------------------------------------------------------- 4. flash wear
hdr("4. Flash wear of per-event persistent writes (log-structured records, 4 KiB erase page, 16 B record)")
ENDURANCE = 10_000   # typical embedded NOR flash spec; MUST be replaced by the actual part's datasheet value
RECS = 4096 // 16
for name, wpd in [("meter (~100 writes/day: tickets, outbox, counters)", 100), ("DER, 4 commands/day", 60),
                  ("DER, 5-s set-points with per-command flash counter", 17_280)]:
    days1 = ENDURANCE * RECS / wpd
    need15 = 15 * 365 * wpd / (ENDURANCE * RECS)
    print(f"  {name:<56} one page lasts {days1/365:8.1f} years; pages needed for 15 years: {max(1, need15):5.1f} ({max(1,need15)*4:.0f} KiB)")

# --------------------------------------------------------------------------------------------- 5. RAM peaks
hdr("5. Device RAM, peak simultaneous (KB); crypto parts from [PQM4]/[RP2040]; application/RTOS/IP stack NOT included")
tls_default = 2 * (16384 + 29) / 1024          # [MBEDTLS] default IN/OUT content length 16 KiB each (+ record header/tag)
tls_small = 2 * (1024 + 29) / 1024             # with a 1 KiB record limit (only if the broker honours it: T3)
kem_hs = (M4_STACK["mlkem768_fast"] + 2432 + 1216 + 2493 + 2411) / 1024   # ML-KEM stack + eph sk + pk_e + CH out + SH in
rows = [
  ("full connection, default TLS buffers, fast PQ code", tls_default + kem_hs + 3.5),
  ("full connection, 1 KiB TLS records, small-stack PQ code", tls_small + (M4_STACK["mlkem768_small"] + 2432 + 1216 + 2493 + 2411) / 1024 + 3.5),
  ("manifest receive + SLH-DSA-192s verify, default TLS, manifest in RAM", tls_default + (MEAS["manifest"] + 64) / 1024 + M4_STACK["slh192s_verify"] / 1024),
  ("manifest streamed to flash + verify from flash, 1 KiB TLS records", tls_small + 4.4 + M4_STACK["slh192s_verify"] / 1024),
  ("CONTROL receive + ML-DSA-65 verify (fast), default TLS", tls_default + MEAS["control_env"] / 1024 + M4_STACK["mldsa65_verify_fast"] / 1024),
  ("CONTROL receive + ML-DSA-65 verify (small stack), 1 KiB TLS records", tls_small + MEAS["control_env"] / 1024 + M4_STACK["mldsa65_verify_small"] / 1024),
]
for n, v in rows: print(f"  {n:<74} {v:6.1f} KB")
print(f"  (M0+ reference-C for comparison: ML-KEM-768 decaps {M0_RAM_KB['mlkem768_decaps_total']} KB; ML-DSA-65 SIGN {M0_RAM_KB['mldsa65_sign_total']} KB)")
print("  RFC 7228: Class 1 ~10 KiB RAM -> RED; Class 2 ~50 KiB -> only the small-buffer rows fit, before the application.")

# --------------------------------------------------------------------------------------------- 6. v2.2 formats
hdr("6. v2.2 message formats (ANALYTICAL): sizes from the length-prefixed codec (4-byte length per field)")
def enc_len(*fields): return sum(4 + f for f in fields)
AEAD_TAG, SIG65, SLH128 = 16, SZ["mldsa65"]["sig"], SZ["slh128s"]["sig"]
def envelope(pt): return enc_len(1, 8, 8, pt + AEAD_TAG)            # type, sid, seq, AEAD ciphertext
cmd_pt = enc_len(3, 64, 8, 1, SIG65)                                  # "CMD", 64-byte command, expires_at, idempotent, sig
grant_pt = enc_len(5, 8, 8, 16, 4, 4, 2, 8, 8, SIG65)                 # "GRANT", id, sid, target, min, max, rate, nbf, exp, sig
setp_pt = enc_len(8, 8, 4, 8)                                         # "SETPOINT", grant id, value, expires_at
zkey_pt = enc_len(7, 8, 8, 32, 8)                                     # "ZONEKEY", zone, epoch, key, expires_at
man_body = MEAS["manifest"] - 8 - SZ["slh192s"]["sig"]                # measured v2.1 manifest body (173 B)
man_v22 = enc_len(man_body + 5, SLH128)                               # + signer anchor id field (1 byte + 4-byte prefix)
df_alone = enc_len(2, 32, 0)                                          # "DF", MAC, empty bundle length
df_alert = enc_len(2, 32, enc_len(2, MEAS["alert_env"]))              # DF + bundle(count, one ALERT envelope)
W = {"CMD envelope (64-byte command, ML-DSA-65)": envelope(cmd_pt), "GRANT envelope (ML-DSA-65)": envelope(grant_pt),
     "SETPOINT envelope (session AEAD only)": envelope(setp_pt), "ZONEKEY envelope (session AEAD only)": envelope(zkey_pt),
     "signed manifest, SLH-DSA-SHA2-128s": man_v22, "DF alone": df_alone, "DF + one piggybacked ALERT": df_alert}
for k, v in W.items(): print(f"  {k:<46} {v:>6} B")
per = lambda env: env + 37 + MQTT_TLS_PER_PUBLISH_QOS1
p3_tele = 8640 * per(128); p3_alert = 10 * per(137)
p3_ctrl_v21 = 17280 * per(MEAS["control_env"])
p3_ctrl_v22 = 17280 * per(W["SETPOINT envelope (session AEAD only)"]) + 24 * per(W["GRANT envelope (ML-DSA-65)"])
ka = 288 * KEEPALIVE + MEAS["tls_full_ecdsa"] + MEAS["e2e_full"] / 7
for name, ctrl in [("v2.1 per-command ML-DSA-65", p3_ctrl_v21), ("v2.2 hourly GRANT + SETPOINTs", p3_ctrl_v22)]:
    tot = p3_tele + p3_alert + ctrl + ka
    print(f"  P3 total/day, {name:<32}: control {ctrl/1e6:6.2f} MB, all traffic {tot/1e6:6.2f} MB, airtime @20 kbit/s {tot*8/20e3/60:6.1f} min")
print(f"  manifest parts at max_packet 4096 B (30 B part header, 37 B topic, ~20 B MQTT): {-(-man_v22 // (4096 - 30 - 37 - 20))} parts")

SOURCES = """
[FIPS203/204/205] NIST FIPS 203, 204, 205 (Aug 2024) parameter-set sizes.  [FALCON] Falcon spec; FIPS 206 not final.
[RFC8554] LMS sizes computed from RFC 8554 (n=32, W8 p=34, HSS L=1).  [RFC8391] XMSS-SHA2_10_256.
[PQM4] mupq/pqm4 benchmarks.md (master), NUCLEO-L4R5ZI Cortex-M4 @24 MHz, arm-none-eabi-gcc 11.3.1; stack excludes key/ct/sig buffers.
[PQM4-R3] pqm4 tag Round3 benchmarks.md, STM32F4DISCOVERY @24 MHz (Falcon; removed from current pqm4).
[HL19] Haase & Labrique, TCHES 2019: X25519 625,358 cycles, STM32F407.
[DULL15] Duell et al., Des. Codes Cryptogr. 2015: X25519 AVR 13,900,397; MSP430X 5,301,792; Cortex-M0 3,589,850 cycles.
[TAS22] Tasopoulos et al., ISPEC 2022: NUCLEO-F439ZI Cortex-M4 @180 MHz, wolfSSL, PQ TLS 1.3 handshake times and bytes.
[TAS23] Tasopoulos et al., CF'23 MalHIoT workshop: measured energy (PicoScope, shunt) on the same board.
[RP2040] Chhetri et al., arXiv 2603.19340 (preprint, 2026): RP2040 Cortex-M0+ @125 MHz, PQClean reference C; energy NOT measured.
[KS25] Kim & Seo, ASIA CCS 2025 (base paper): ATmega4808 6 KB SRAM; KEM-MQTT Kyber-512 31.83M cycles; OpenSSL >= 16 KB stack.
[LUK20] Lukic et al., arXiv 2005.13648: Quectel BC68 on a live NB-IoT network; charge per UDP echo read from Fig. 6.
[AMI] 15-minute interval data is the common AMI configuration (utility/vendor sources; see audit document).
[IEEE2030.5] pollRate default 900 s; CSIP default DERControl polling 10 min (see audit document).
[ALG26] Alghawli et al., Frontiers 2026, Table 3/10: simulated 802.15.4 smart-grid traffic (not cellular, not MQTT).
[MBEDTLS] Mbed TLS default MBEDTLS_SSL_IN/OUT_CONTENT_LEN = 16384.
"""
print(SOURCES)
