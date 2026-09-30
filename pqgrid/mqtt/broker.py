"""Broker configuration, its validator (Master §27.1) and the ACL compiler (Master §10.1; E48).

Validator rules (v2.2): every listener is TLS 1.3 only, requires a client certificate and uses its identity as the
user name; anonymous access is off; persistence is on (retained artifacts and persistent sessions, §10.3); a broker
max_packet_size of at most 300,000 B (§10.2); an explicit per-client queue limit (B-6) and an explicit, non-root
account to run as (B-1; root only for throwaway test containers). The TLS 1.2 case matters: the hybrid group pin does not cover TLS 1.2
[DOCKER T7], so a TLS 1.2 listener would silently fall back to classical key exchange.

The ACL is generated, never hand-edited: one block per active device (its own topics only), zone read rights from
membership, and a least-privilege utility block. A revoked device simply has no block, nor has one whose class
the policy does not define (a comment line says why); one such record never stops the fleet's ACL from being
recompiled. It is written atomically
and the broker reloads it on SIGHUP (verified in v2.1: no restart needed). The compiler accepts the policy only as
a verified POLICY artifact (§10.1 "verifies the policy signature"; E13 closed in slice 6).
"""
from __future__ import annotations

import os
import signal

from ..persistence.atomic import atomic_write
from . import topics
from .tls import HYBRID_GROUPS

MAX_BROKER_PACKET = 300_000
MAX_QUEUED_MESSAGES = 1000     # B-6: per client; sizing in Master §27.1 (a sleeping device's CONTROL + DR queue, and
                               # the utility's own queue while it restarts) [ANALYTICAL]


class ConfigError(ValueError):
    pass


def hybrid_openssl_cnf() -> str:
    """OPENSSL_CONF for the broker process: only hybrid groups are offered or accepted (§8.2, [DOCKER N3])."""
    return ("openssl_conf = openssl_init\n[openssl_init]\nssl_conf = ssl_sect\n[ssl_sect]\n"
            "system_default = system_default_sect\n[system_default_sect]\n"
            f"Groups = {HYBRID_GROUPS}\nMinProtocol = TLSv1.3\n")


def render_config(listeners: list[dict], acl_file: str, persistence_dir: str, log_file: str | None = None,
                  user: str = "mosquitto", allow_root: bool = False) -> str:
    """listeners: [{"port", "cafile", "certfile", "keyfile"}]. `user` is the account Mosquitto drops to (B-1);
    `allow_root` exists only for throwaway test containers."""
    lines = [f"user {user}", "per_listener_settings false", "allow_anonymous false", f"acl_file {acl_file}",
             "persistence true", f"persistence_location {persistence_dir.rstrip('/')}/",
             f"max_packet_size {MAX_BROKER_PACKET}", f"max_queued_messages {MAX_QUEUED_MESSAGES}",
             "set_tcp_nodelay true",
             f"log_dest {'file ' + log_file if log_file else 'stdout'}", "log_type error", "log_type warning",
             "log_type notice"]
    for li in listeners:
        lines += ["", f"listener {li['port']}", f"cafile {li['cafile']}", f"certfile {li['certfile']}",
                  f"keyfile {li['keyfile']}", "tls_version tlsv1.3", "require_certificate true",
                  "use_identity_as_username true"]
    text = "\n".join(lines) + "\n"
    validate_config(text, allow_root=allow_root)
    return text


def validate_config(text: str, allow_root: bool = False) -> None:
    glob: dict[str, str] = {}
    blocks: list[dict[str, str]] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        k, _, v = line.partition(" ")
        if k == "listener":
            blocks.append({"listener": v.strip()})
        elif blocks:
            blocks[-1][k] = v.strip()
        else:
            glob[k] = v.strip()
    bad = []
    if glob.get("per_listener_settings", "false") != "false":
        bad.append("per_listener_settings must be false (one global ACL and anonymous rule)")
    if glob.get("allow_anonymous") != "false":
        bad.append("allow_anonymous must be false")
    if glob.get("persistence") != "true":
        bad.append("persistence must be true (retained artifacts, persistent sessions: §10.3)")
    if "acl_file" not in glob:
        bad.append("acl_file is required")
    mp = glob.get("max_packet_size", "")
    if not (mp.isdigit() and 0 < int(mp) <= MAX_BROKER_PACKET):
        bad.append(f"max_packet_size must be set and at most {MAX_BROKER_PACKET}")
    mq = glob.get("max_queued_messages", "")
    if not (mq.isdigit() and 0 < int(mq)):
        bad.append("max_queued_messages must be set explicitly (B-6: bounded queues for persistent sessions)")
    if not glob.get("user"):
        bad.append("user must be set explicitly (B-1: Mosquitto drops to that account)")
    elif glob["user"] == "root" and not allow_root:
        bad.append("user root is for throwaway test containers only (B-1)")
    if not blocks:
        bad.append("no listener")
    for b in blocks:
        name = f"listener {b['listener']}"
        if b.get("tls_version") != "tlsv1.3":
            bad.append(f"{name}: tls_version tlsv1.3 is required (the hybrid pin does not cover TLS 1.2)")
        for key in ("cafile", "certfile", "keyfile"):
            if key not in b:
                bad.append(f"{name}: {key} is required (no plaintext listeners)")
        if b.get("require_certificate") != "true":
            bad.append(f"{name}: require_certificate true is required")
        if b.get("use_identity_as_username") != "true":
            bad.append(f"{name}: use_identity_as_username true is required")
    if bad:
        raise ConfigError("; ".join(bad))


def compile_acl(signed_policy: bytes, policy_payload: bytes, anchors: dict[int, bytes], registry_records,
                zone_members: dict[str, set[bytes]], revoked=frozenset(), utility_user: str = "utility") -> str:
    """The operator entry point: verify the signed POLICY artifact, then render the ACL from it."""
    from ..fota.policy_artifact import verify_policy_artifact
    policy = verify_policy_artifact(signed_policy, policy_payload, anchors, revoked)
    return render_acl(policy, registry_records, zone_members, utility_user)


def render_acl(policy, registry_records, zone_members: dict[str, set[bytes]], utility_user: str = "utility") -> str:
    """Render from an already verified Policy (compile_acl is the only caller outside tests)."""
    out = [f"# generated for {policy.info()!r}; do not edit", "", f"user {utility_user}",
           "topic read pqgrid/hs/+/up", "topic write pqgrid/hs/+/down",
           "topic read grid/+/+/telemetry", "topic read grid/+/+/alert", "topic read grid/+/+/status",
           "topic write grid/+/+/control", "topic write grid/dr/+/+/event",
           "topic write pqgrid/fota/#", "topic read pqgrid/fota/+/request/+"]
    for rec in sorted(registry_records, key=lambda r: r.device_id):
        if not rec.active:
            continue                                              # revoked: no rights at all
        if rec.dclass not in policy.classes:                      # it could not establish under this policy: no
            out += ["", f"# no rights for {rec.device_id.decode()}: class {rec.dclass!r} is not in the policy"]
            continue                                              # rights, and the rest of the fleet's ACL is still
        alg = policy.profile(rec.dclass).aead                     # written (raising left the broker on a stale ACL)
        did, cls = rec.device_id, rec.dclass
        out += ["", f"user {did.decode()}",
                f"topic write {topics.telemetry(cls, did)}", f"topic write {topics.alert(cls, did)}",
                f"topic write {topics.status(cls, did)}", f"topic read {topics.control(cls, did)}",
                f"topic write {topics.hs_up(did)}", f"topic read {topics.hs_down(did)}",
                f"topic read pqgrid/fota/{cls}/#", f"topic write {topics.fota_request(cls, did)}"]
        out += [f"topic read {topics.dr_event(z, alg)}" for z in sorted(zone_members) if did in zone_members[z]]
    return "\n".join(out) + "\n"


def install_acl(path: str, text: str, broker_pid: int | None = None, owner: tuple[int, int] | None = None) -> None:
    atomic_write(path, text.encode(), mode=0o640)
    if owner:
        os.chown(path, *owner)
    if broker_pid:
        os.kill(broker_pid, signal.SIGHUP)                        # reload without a restart


def acl_installer(utility, path: str, broker_pid, owner: tuple[int, int] | None = None, bootstrap=None):
    """The production ACL hook for UtilityMqtt (U-8, B-4): compile the ACL for the policy in force
    (UtilityMqtt.acl_text: its signed artifact verified, the registry, zone membership), write it atomically and
    make the broker reload it. `broker_pid` is the broker's pid or a callable returning it (it changes on restart);
    `bootstrap` = (signed, payload, anchors) of the bootstrap policy, used until a policy has been activated."""
    def hook() -> None:
        pid = broker_pid() if callable(broker_pid) else broker_pid
        install_acl(path, utility.acl_text(bootstrap), pid, owner)
    return hook
