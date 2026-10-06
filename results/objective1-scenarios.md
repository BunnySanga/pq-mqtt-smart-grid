# Objective 1 (PCHC-MQTT) live over the real broker
Broker: Mosquitto on 127.0.0.1:38259, TLS 1.3 only, hybrid groups only (X25519MLKEM768). Devices: meter-0001 (smart_meter: TELEMETRY + ALERT) and der-0001 (der_ctrl: also takes commands). Policy nitk-grid v1.

=== S1  Connect over hybrid TLS 1.3, then the end-to-end handshake (device <-> utility)
    meter-0001: CH 2493 B -> SH 2411 B -> DF 46 B -> NT/FIN 271 B
    der-0001: CH 2488 B -> SH 2415 B -> DF 46 B -> NT/FIN 270 B
    OK   both sessions established; policy bound into the keys: nitk-grid v1

=== S2  TELEMETRY: a meter reading, protected by the hybrid TLS hop only
    meter -> broker -> utility: 24 B, the reading as is (no E2E layer)
    OK   utility received 'kWh=1234.5;V=230.1;A=4.2' from meter-0001

=== S3  ALERT: encrypted end to end, numbered, acknowledged; kept in the device outbox until the ACK
    meter -> utility: ALERT envelope 85 B; the text is NOT in the bytes the broker carries
    utility -> meter: ACK 65 B; device outbox now empty
    OK   utility received 'cover opened'; ACK cleared the outbox

=== S4  CONTROL: a discrete command, encrypted end to end AND signed with ML-DSA-65
    utility -> der: CMD envelope 3413 B (includes the 3,309-B signature)
    der -> utility: status 83 B; applied: [b'CURTAIL 50%']
    OK   cmd_seq 0x6ac5363300000001 -> OK; device applied [b'CURTAIL 50%']

=== S5  CONTROL: one signed GRANT, then cheap SETPOINTs within its limits
    utility -> der: GRANT 3477 B (signed: P_ACTIVE_W in [-5000, 5000] W, <= 12/min, 1 h), SETPOINT 97 B (no signature)
    OK   device set-points [('P_ACTIVE_W', 2500)]

=== S6  CONTROL broadcast: a demand-response event for a zone (zone key + ML-DSA-65)
    utility -> der: ZONEKEY 134 B; utility -> zone f7: event 3440 B (one per crypto group)
    OK   device events [('f7', b'SHED 20% 14:00-16:00')]

=== S7  Attacks over the broker
    OK   utility refused it: not an end-to-end envelope (bad tag)
    OK   device answered REJECTED:signature; not applied
    OK   device refused it as a replay; applied once
    OK   broker refused the TLS handshake (alert 40: handshake failure)

=== S8  Policy change: a new signed policy (v2) becomes active; every session moves to it
    policy nitk-grid v1 -> nitk-grid v2; both devices re-handshook under v2
    OK   meter and der sessions now bound to nitk-grid v2

## Summary

| Step | Scenario | Result | Evidence |
|---|---|---|---|
| S1 | Connect + end-to-end handshake | PASS | both sessions established; policy bound into the keys: nitk-grid v1 |
| S2 | TELEMETRY delivered | PASS | utility received 'kWh=1234.5;V=230.1;A=4.2' from meter-0001 |
| S3 | ALERT delivered, ACKed, not readable by the broker | PASS | utility received 'cover opened'; ACK cleared the outbox |
| S4 | Command verified, applied once, status OK | PASS | cmd_seq 0x6ac5363300000001 -> OK; device applied [b'CURTAIL 50%'] |
| S5 | GRANT accepted; SETPOINT applied within its limits | PASS | device set-points [('P_ACTIVE_W', 2500)] |
| S6 | Zone key delivered; broadcast event verified and accepted | PASS | device events [('f7', b'SHED 20% 14:00-16:00')] |
| S7a | Plaintext (tier-stripped) message on an ALERT topic | PASS | utility refused it: not an end-to-end envelope (bad tag) |
| S7b | Forged command (session key, but not the command key) | PASS | device answered REJECTED:signature; not applied |
| S7c | Replayed command (S4's envelope sent again) | PASS | device refused it as a replay; applied once |
| S7d | Client offering only classical X25519 key exchange | PASS | broker refused the TLS handshake (alert 40: handshake failure) |
| S8 | Policy v1 -> v2: old sessions closed, devices re-established under v2 | PASS | meter and der sessions now bound to nitk-grid v2 |

RESULT: all 11 checks passed
