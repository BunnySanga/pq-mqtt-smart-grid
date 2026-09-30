# constrained-audit

Evidence behind [`../../BalaMP-Audit.md`](../../BalaMP-Audit.md): the constrained-IoT and smart-grid review of
design v2.1. Everything runs **inside Docker**, with no host installs, no bind mounts, no `--privileged` and
no host network.

```bash
./run_audit.sh
```

The runner needs the `pqgrid-validation` image; it builds it if it is missing. Then it adds `libfaketime`, so
single processes can be given a false clock without touching the container's or the host's clock.

| Step | Script | What it shows | Output |
|---|---|---|---|
| 1 | `audit_state.py` | S1–S5: crash and restart behaviour of the v2.1 reference implementation (command sequence after a utility restart, counter-before-actuation, torn persistence writes, used-list rewrite cost, rebuilt resume hello) | `results/state.txt` |
| 2 | `test_tls_time.py` | T2 TLS ticket lifetime (broker clock moved with libfaketime); T3 max_fragment_length; T4 device clock and certificate validity; T7 per-device PSK on the hop | `results/tls_time.txt` |
| 3 | `test_transport.py` + `linkproxy.py` | T1 MQTT 5 Maximum Packet Size vs the signed manifest; T5 bytes on the wire; T6 time-to-ready over modelled LTE-M and NB-IoT links (**simulation**: delay and rate only) | `results/transport.txt` |
| 4 | `analysis.py` | Budgets calculated from cited literature inputs: cycles, bytes per day, flash wear, peak RAM | `results/analysis.txt` |

## Honest scope

- Docker numbers come from a laptop container. They are **not** MCU or smart-meter measurements.
- T6 models only one-way delay, serialisation rate and the TCP handshake round trip. The proxy terminates
  TCP. Radio scheduling, repetitions, loss and congestion control are not modelled. The link parameters are
  assumptions.
- `analysis.py` never invents inputs. Every constant carries a source tag, listed at the end of its output.
  Its results are lower bounds, not device performance.
- The `--cpus`/`--memory` limits in `run_audit.sh` only keep resource use tidy. They do not model a
  constrained device.
