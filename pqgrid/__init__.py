"""pqgrid — implementation of the Post-Quantum Secure MQTT design (BalaMP-Master.md, design v2.2).

    wire, suite, policy, registry   codec, primitives, the signed policy and its validator, the device registry
    e2e, pasr                       the device <-> utility KEM-MQTT session, envelopes and resumption tickets
    commands                        CONTROL: signed commands, GRANT/SETPOINT, zones and DR broadcasts
    persistence                     device flash record store; the utility's SQLite state (incl. rollout state)
    fota                            signed artifacts, installer/bootloader model, station and publisher
    mqtt                            MQTT 5 over hybrid TLS 1.3: broker config and ACL, device and utility nodes
Evidence is [SIM] or [DOCKER] only; see IMPLEMENTATION-ROADMAP.md (§13, §14) for what was validated and how.
"""
