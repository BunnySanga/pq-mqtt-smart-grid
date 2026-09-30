"""Mutation check (IMPLEMENTATION-ROADMAP §14, C1-9): each mutant disables ONE security or correctness check in pqgrid;
the in-process suite (tests/unit, tests/security) must kill it. A survivor is either a missing test or an equivalent
mutant (a check made redundant by construction: record why).

Run in the test image, against a snapshot of the tree mounted read-only at /src (4 slices in parallel):
    for k in 0 1 2 3; do docker run --rm -v "$PWD":/src:ro -v "$PWD/tools":/t:ro -w /tmp pqgrid-tests \
        python /t/mutation_check.py $k 4 & done; wait
    python tools/mutation_check.py sel 1,9,10 0 1        # only the listed mutants (same docker wrapper)
Last full run (after C1-9): 117 mutants, 112 killed, 5 equivalent (24, 28, 40, 110, 112).
Mutants 117-139 disable the checks added by cycle 1 (C2-2): 23 of 23 killed.
Mutants 140-143: cycle 2's fixes (C2-8).
"""
import shutil
import subprocess
import sys
import tempfile

M = [
    # ---------------------------------------------------------------- handshake (utility)
    ("pqgrid/e2e/handshake.py", "        if not ct_eq(did, topic_id):\n", "        if False:\n", "CH identity = topic"),
    ("pqgrid/e2e/handshake.py", "        if dclass != rec.dclass.encode():\n", "        if False:\n", "CH class = registry"),
    ("pqgrid/e2e/handshake.py", "        if not ct_eq(pinfo, self.policy.info()):\n            raise PolicyMismatchError",
     "        if False:\n            raise PolicyMismatchError", "CH POLICY_INFO current"),
    ("pqgrid/e2e/handshake.py", "        if tag != b\"DF\" or not ct_eq(keys.mac_d(pend.kc_d, pend.th2, pend.mu, bundle), mac_d_rx):",
     "        if tag != b\"DF\":", "DF MAC_D"),
    ("pqgrid/e2e/handshake.py", "        if not ct_eq(s.policy_info, self.policy.info()):                    # M1",
     "        if False:                    # M1", "DF M1 policy race"),
    ("pqgrid/e2e/handshake.py", "        if now >= s.chain_expires:                                            # M2",
     "        if False:                                            # M2", "DF M2 chain end"),
    ("pqgrid/e2e/handshake.py", "        if not self.active(who.encode()):", "        if False:", "alert: revoked device"),
    ("pqgrid/e2e/handshake.py", "        if not ct_eq(s.policy_info, self.policy.info()):\n            raise EnvelopeError(\"session belongs",
     "        if False:\n            raise EnvelopeError(\"session belongs", "alert: old-policy session"),
    ("pqgrid/e2e/handshake.py", "        if self.now() < s.chain_expires:\n            return False\n        if self.sessions",
     "        if True:\n            return False\n        if self.sessions", "utility chain end"),
    ("pqgrid/e2e/handshake.py", "        if (s is None or not self.active(device_id) or not ct_eq(s.policy_info, self.policy.info())",
     "        if (s is None or not ct_eq(s.policy_info, self.policy.info())", "current_session: revoked"),
    ("pqgrid/e2e/handshake.py", "        self._pending.pop(device_id, None)\n        return closed",
     "        return closed", "revoke: half-open kept"),
    # ---------------------------------------------------------------- handshake (device)
    ("pqgrid/e2e/handshake.py", "        if not ct_eq(pinfo_u, self.policy.info()):", "        if False:", "SH POLICY_INFO"),
    ("pqgrid/e2e/handshake.py", "        if mode_b != self.profile.resume.value.encode():", "        if False:", "SH resume mode"),
    ("pqgrid/e2e/handshake.py", "        if not ct_eq(keys.mac_u(mk.kc_u, th2), mu):", "        if False:", "SH MAC_U"),
    ("pqgrid/e2e/handshake.py", "        if not ct_eq(keys.mac_u(mk.kc_u, th), mu):", "        if False:", "RS MAC_U"),
    ("pqgrid/e2e/handshake.py", "            elif ct_e:\n                raise HandshakeError(\"resume reply failed authentication\")",
     "            elif False:\n                raise HandshakeError(\"resume reply failed authentication\")", "RS PSK with ct"),
    ("pqgrid/e2e/handshake.py", "        elif tag != b\"FIN\" or not ct_eq(m, mac(keys.fin_key(s.k_master), s.sid)):",
     "        elif tag != b\"FIN\":", "FIN MAC"),
    ("pqgrid/e2e/handshake.py", "            if s.resume_mode is ResumeMode.NONE:\n                raise HandshakeError(\"unexpected ticket",
     "            if False:\n                raise HandshakeError(\"unexpected ticket", "NT for NONE class"),
    ("pqgrid/e2e/handshake.py", "        if tag != b\"\\x07\" or self.session is None or not ct_eq(sid, self.session.sid):",
     "        if tag != b\"\\x07\" or self.session is None:", "resync hint sid"),
    ("pqgrid/e2e/handshake.py", "        if self.clock() - self._last_resync < self.RESYNC_INTERVAL_S:\n            return False",
     "        if False:\n            return False", "resync hint rate"),
    ("pqgrid/e2e/handshake.py", "        s = self.session\n        if s is None or self.now() < s.chain_expires:",
     "        s = self.session\n        if True:", "device chain end"),
    # ---------------------------------------------------------------- tickets
    ("pqgrid/pasr/tickets.py", "        if not (ct_eq(t.device_id, topic_id) and ct_eq(t.device_id, claimed_id)):",
     "        if not ct_eq(t.device_id, claimed_id):", "ticket check 3 topic"),
    ("pqgrid/pasr/tickets.py", "        if rec is None or not rec.active:\n            raise TicketError(\"device unknown or revoked\")",
     "        if rec is None:\n            raise TicketError(\"device unknown or revoked\")", "ticket check 4 revoked"),
    ("pqgrid/pasr/tickets.py", "        if rec.dclass != t.dclass:", "        if False:", "ticket check 4 class"),
    ("pqgrid/pasr/tickets.py", "        if not (now < t.expires_at and now < t.chain_expires_at):",
     "        if not (now < t.expires_at):", "ticket check 5 chain"),
    ("pqgrid/pasr/tickets.py", "        if not (now < t.expires_at and now < t.chain_expires_at):",
     "        if not (now < t.chain_expires_at):", "ticket check 5 ticket"),
    ("pqgrid/pasr/tickets.py", "        if not (ct_eq(t.policy_info, policy_info) and ct_eq(policy_info, policy.info())):",
     "        if not ct_eq(t.policy_info, policy_info):", "ticket check 6 current"),
    ("pqgrid/pasr/tickets.py", "        if t.fw_version != fw_version:", "        if False:", "ticket check 7 fw"),
    ("pqgrid/pasr/tickets.py", "        if not (mode == t.resume_mode.value.encode() and t.resume_mode is current",
     "        if not (mode == t.resume_mode.value.encode()", "ticket check 8 current mode"),
    ("pqgrid/pasr/tickets.py", "        if len(pk_e) != (hkem.PK_LEN if current is ResumeMode.PSK_KEM else 0):",
     "        if False:", "ticket check 8 fresh key"),
    ("pqgrid/pasr/tickets.py", "        if not ct_eq(mac(keys.binder_key(t.psk), binder_input), binder):",
     "        if False:", "ticket check 9 binder"),
    ("pqgrid/pasr/tickets.py", "        if not self.used.consume(t.ticket_id, t.expires_at, now):",
     "        if not (self.used.consume(t.ticket_id, t.expires_at, now) or True):", "ticket single use"),
    ("pqgrid/pasr/stek.py", "        if k is None or now >= k.retire_at:", "        if k is None:", "STEK retirement"),
    # ---------------------------------------------------------------- envelopes
    ("pqgrid/e2e/envelopes.py", "    if parts[1] != s.dclass or parts[2].encode() != s.device_id:\n        raise EnvelopeError(\"envelope belongs to another device's session\")\n\n\ndef seal_alert",
     "    if False:\n        raise EnvelopeError(\"envelope belongs to another device's session\")\n\n\ndef seal_alert", "alert ownership"),
    ("pqgrid/e2e/envelopes.py", "    if policy.tier(topic) is not Tier.ALERT:", "    if False:", "alert tier"),
    ("pqgrid/e2e/envelopes.py", "    if parts[1] != s.dclass or parts[2].encode() != s.device_id:\n        raise EnvelopeError(\"envelope belongs to another device's session\")\n\n\ndef seal_control",
     "    if False:\n        raise EnvelopeError(\"envelope belongs to another device's session\")\n\n\ndef seal_control", "control ownership"),
    ("pqgrid/e2e/envelopes.py", "    if policy.tier(topic) is not Tier.CONTROL:\n        raise EnvelopeError(\"topic is not CONTROL",
     "    if False:\n        raise EnvelopeError(\"topic is not CONTROL", "control tier"),
    ("pqgrid/e2e/envelopes.py", "    if not ct_eq(m, mac(s.key(\"ACK\", \"down\"), sid + seq_b)):", "    if False:", "alert ACK MAC"),
    ("pqgrid/e2e/envelopes.py", "    if not ct_eq(m, mac(s.key(\"ACK\", \"up\"), sid + mseq_b + cseq_b + status)):", "    if False:", "status ACK MAC"),
    ("pqgrid/e2e/envelopes.py", "    if not ct_eq(m, mac(s.key(\"SYNC\", \"up\"), sid + seq_b + epoch_b + zone_b)):", "    if False:", "zone sync MAC"),
    ("pqgrid/e2e/envelopes.py", "    guard = s.guard(\"SYNC\", \"up\")\n    guard.validate(seq)", "    guard = s.guard(\"SYNC\", \"up\")", "zone sync replay (phase1)"),
    ("pqgrid/e2e/envelopes.py", "    guard.accept(seq)\n    return zone, epoch", "    return zone, epoch", "zone sync replay (accept)"),
    ("pqgrid/e2e/envelopes.py", "    guard.accept(seq)                                     # phase 2: only after authentication",
     "    pass", "alert replay accept"),
    ("pqgrid/e2e/envelopes.py", "    guard.accept(seq)\n    return pt, seq", "    return pt, seq", "control replay accept"),
    ("pqgrid/e2e/envelopes.py", "    guard.validate(seq)                                   # phase 1: before decryption\n",
     "    guard.accept(seq)                                   # MUTANT: burn before auth\n", "alert two-phase (I-7)"),
    ("pqgrid/e2e/envelopes.py", "    guard = s.guard(\"CONTROL\", \"down\")\n    guard.validate(seq)",
     "    guard = s.guard(\"CONTROL\", \"down\")\n    guard.accept(seq)", "control two-phase (I-7)"),
    ("pqgrid/e2e/envelopes.py", "    if not valid_status(status):\n        raise EnvelopeError(\"unknown status\")\n    return mseq",
     "    return mseq", "utility status token"),
    # ---------------------------------------------------------------- commands (device)
    ("pqgrid/commands/device.py", "        if not self._verify(c.sig, cmd_signed_input(", "        if False and not self._verify(c.sig, cmd_signed_input(", "CMD signature"),
    ("pqgrid/commands/device.py", "        if not self._verify(g.sig, grant_signed_input(self.d.id, topic, g)):", "        if False:", "GRANT signature"),
    ("pqgrid/commands/device.py", "        if not ct_eq(g.sid, s.sid):\n            return ack(b\"REJECTED:sid\")", "        if False:\n            return ack(b\"REJECTED:sid\")", "GRANT sid binding"),
    ("pqgrid/commands/device.py", "        if not self._allowed(CmdType.CMD):", "        if False:", "CMD allowed"),
    ("pqgrid/commands/device.py", "        if not self._allowed(CmdType.SETPOINT):", "        if False:", "SETPOINT allowed"),
    ("pqgrid/commands/device.py", "        if st.is_applied(c.cmd_seq):", "        if False:", "CMD DUP"),
    ("pqgrid/commands/device.py", "        if c.cmd_seq <= st.last_applied:", "        if False:", "CMD SUPERSEDED"),
    ("pqgrid/commands/device.py", "        if self.d.now() >= c.expires_at:\n            return ack(b\"EXPIRED\")", "        if False:\n            return ack(b\"EXPIRED\")", "CMD EXPIRED"),
    ("pqgrid/commands/device.py", "        if len(c.command) > MAX_COMMAND:", "        if False:", "CMD size"),
    ("pqgrid/commands/device.py", "        if g.target not in self.targets:", "        if False:", "GRANT target"),
    ("pqgrid/commands/device.py", "        if not (g.min <= g.max and 0 < g.max_rate <= self.d.profile.max_setpoint_rate):", "        if False:", "GRANT bounds"),
    ("pqgrid/commands/device.py", "        if not (g.not_before <= now < g.expires_at and now < sp.expires_at):", "        if not (now < g.expires_at and now < sp.expires_at):", "SETPOINT not_before"),
    ("pqgrid/commands/device.py", "        if not (g.not_before <= now < g.expires_at and now < sp.expires_at):", "        if not (g.not_before <= now < g.expires_at):", "SETPOINT own expiry"),
    ("pqgrid/commands/device.py", "        if not g.min <= sp.value <= g.max:", "        if False:", "SETPOINT bounds"),
    ("pqgrid/commands/device.py", "        if len(win) >= g.max_rate:", "        if False:", "SETPOINT rate"),
    ("pqgrid/commands/device.py", "        g = next((g for g in self._grants.values() if g.grant_id == sp.grant_id and ct_eq(g.sid, s.sid)), None)",
     "        g = next((g for g in self._grants.values() if g.grant_id == sp.grant_id), None)", "SETPOINT grant sid"),
    ("pqgrid/commands/device.py", "        if z.aead is not self.d.profile.aead:", "        if False:", "ZONEKEY aead"),
    ("pqgrid/commands/device.py", "        st.write_applied(c.cmd_seq)                               # APPLIED durable before \"OK\"\n        return ack(b\"OK\")",
     "        return ack(b\"OK\")", "CMD APPLIED durable"),
    ("pqgrid/commands/device.py", "        if r.idempotent and self.d.now() < r.expires_at and r.cmd_seq > self.state.last_applied:",
     "        if r.idempotent and r.cmd_seq > self.state.last_applied:", "recover: expiry"),
    ("pqgrid/commands/device.py", "        if r.idempotent and self.d.now() < r.expires_at and r.cmd_seq > self.state.last_applied:",
     "        if self.d.now() < r.expires_at and r.cmd_seq > self.state.last_applied:", "recover: idempotent"),
    # ---------------------------------------------------------------- commands (utility)
    ("pqgrid/commands/utility.py", "        if not self.u.active(s.device_id):", "        if False:", "status from revoked"),
    ("pqgrid/commands/utility.py", "        if not ct_eq(s.policy_info, self.u.policy.info()):               # P10", "        if False:  # P10", "status old policy"),
    ("pqgrid/commands/utility.py", "            if status in (b\"DUP\", b\"SUPERSEDED\") and q.sends == 1 and msg_seq != 0:",
     "            if False:", "regression alarm"),
    ("pqgrid/commands/utility.py", "        if not g.min <= value <= g.max:", "        if False:", "utility setpoint bounds"),
    ("pqgrid/commands/utility.py", "        if not (valid_token(target) and lo <= hi and 0 < max_rate <= prof.max_setpoint_rate):",
     "        if not (valid_token(target) and lo <= hi):", "utility grant rate cap"),
    ("pqgrid/commands/utility.py", "            if q.last_sid == s.sid:\n                continue", "            pass", "redeliver once per session"),
    # ---------------------------------------------------------------- zones
    ("pqgrid/commands/zones.py", "        if bseq <= self.state.zone_bseq.get(zone, 0):", "        if False:", "bcast bseq replay"),
    ("pqgrid/commands/zones.py", "        if self.d.now() >= exp:\n            raise EnvelopeError(\"broadcast expired\")", "        if False:\n            raise EnvelopeError(\"broadcast expired\")", "bcast expiry"),
    ("pqgrid/commands/zones.py", "        if not mldsa_verify(self.d.policy.utility_cmd_pk, sig, bcast_signed_input(zone, bseq, exp, event)):", "        if False:", "bcast signature"),
    ("pqgrid/commands/zones.py", "        if t != T_BCAST or topic != event_topic(zone, alg) or self.d.policy.tier(topic) is not Tier.CONTROL:",
     "        if t != T_BCAST:", "bcast topic binding"),
    ("pqgrid/commands/zones.py", "        if z is None or device_id not in z.members:\n            raise CommandError(\"zone sync from a device that is not a member\")",
     "        if z is None:\n            raise CommandError(\"zone sync from a device that is not a member\")", "zone sync membership"),
    ("pqgrid/commands/zones.py", "        if now - self._last_sync.get((device_id, name), -ZONE_SYNC_MIN_S) < ZONE_SYNC_MIN_S:", "        if False:", "zone sync rate"),
    ("pqgrid/commands/zones.py", "            out += [self._seal(z, alg, ev) for ev in z.events if ev.bseq > joined]",
     "            out += [self._seal(z, alg, ev) for ev in z.events]", "resend join point"),
    ("pqgrid/commands/zones.py", "        self._rotate(z, [alg])\n\n    def remove_member", "        self._save(z)\n\n    def remove_member", "join rotates"),
    ("pqgrid/commands/zones.py", "        z.members.pop(device_id, None)\n        self._rotate(z, list(z.groups))", "        z.members.pop(device_id, None)\n        self._save(z)", "removal rotates"),
    # ---------------------------------------------------------------- policy
    ("pqgrid/policy/validator.py", "    if p.default_tier is not Tier.CONTROL:", "    if False:", "rule 1"),
    ("pqgrid/policy/validator.py", "        if c.unicast_control and c.resume not in (ResumeMode.PSK_KEM, ResumeMode.NONE):", "        if False:", "rule 3"),
    ("pqgrid/policy/validator.py", "        if not 0 < c.ticket_lifetime_s <= c.max_chain_age_s <= SEVEN_DAYS:", "        if not 0 < c.ticket_lifetime_s <= c.max_chain_age_s:", "rule 4 cap"),
    ("pqgrid/policy/validator.py", "    if installed_version is not None and p.version <= installed_version:", "    if False:", "rule 5"),
    ("pqgrid/policy/validator.py", "        if CmdType.SETPOINT in c.cmd_types and CmdType.GRANT not in c.cmd_types:", "        if False:", "rule 6"),
    ("pqgrid/policy/validator.py", "        if c.fota_chunk_size <= 0 or c.fota_chunk_size + CHUNK_OVERHEAD > c.max_packet:", "        if c.fota_chunk_size <= 0:", "rule 7"),
    ("pqgrid/policy/validator.py", "        if c.dup_window_s < MIN_DUP_WINDOW_S or c.pending_ttl_s < MIN_PENDING_TTL_S:", "        if False:", "rule 9"),
    ("pqgrid/policy/validator.py", "    if not 1 <= len(p.ca_set) <= 2:", "    if False:", "rule 10"),
    ("pqgrid/policy/engine.py", "    return max(hits) if hits else Tier.CONTROL", "    return max(hits) if hits else Tier.TELEMETRY", "fail-safe default"),
    ("pqgrid/policy/engine.py", "    return max(hits) if hits else Tier.CONTROL", "    return hits[0] if hits else Tier.CONTROL", "strongest wins"),
    ("pqgrid/policy/codec.py", "    if len(class_list) != len(policy.classes) or encode_policy(policy) != bytes(raw):", "    if len(class_list) != len(policy.classes):", "canonical policy"),
    # ---------------------------------------------------------------- wire / crypto
    ("pqgrid/wire.py", "    if i != len(buf):\n        raise WireError(\"trailing bytes\")", "    pass", "no trailing bytes"),
    ("pqgrid/wire.py", "        if length > MAX_FIELD:\n            raise WireError(\"field too large\")\n        if i + length", "        if i + length", "field cap"),
    ("pqgrid/suite/hkem.py", "    return sha3_256(ss_m + ss_x + ct_x + pk_x + XWING_LABEL)", "    return sha3_256(ss_m + ss_x + XWING_LABEL)", "X-Wing binds ct/pk"),
    ("pqgrid/e2e/keys.py", "    return mac(kc_d, b\"D-finished\" + h(th2, mac_u_, h(bundle)))", "    return mac(kc_d, b\"D-finished\" + h(th2, mac_u_))", "DR-044 bundle in MAC_D"),
    ("pqgrid/registry.py", "            self._store(rec)                                   # revocation is durable before it takes effect\n",
     "", "revocation durable"),
    # ---------------------------------------------------------------- persistence
    ("pqgrid/persistence/flash.py", "                if crc_at + 4 > len(data) or zlib.crc32(data[off:crc_at]) != struct.unpack_from(\">I\", data, crc_at)[0]:",
     "                if crc_at + 4 > len(data):", "record CRC"),
    ("pqgrid/persistence/device.py", "            if self.is_applied(seq):\n                store.delete(T_INTENT, key)", "            if False:\n                store.delete(T_INTENT, key)", "boot reconciliation"),
    ("pqgrid/persistence/device.py", "    def write_pending(self, c) -> None:\n        super().write_pending(c)\n        self._s.put(",
     "    def write_pending(self, c) -> None:\n        super().write_pending(c)\n        return\n        self._s.put(", "PENDING durable"),
    ("pqgrid/persistence/utility_db.py", "        c.execute(\"INSERT OR REPLACE INTO device_seq VALUES (?, ?)\", (device_id, n))", "        pass", "cmd counter persisted"),
    ("pqgrid/persistence/utility_db.py", "            self.db.execute(\"INSERT INTO used_tickets VALUES (?, ?)\", (ticket_id, expires_at))",
     "            pass", "used ticket persisted"),
    # ---------------------------------------------------------------- FOTA
    ("pqgrid/fota/installer.py", "        if not slh_verify(self.anchors[m.signer_anchor_id], sig, raw):", "        if False:", "manifest signature"),
    ("pqgrid/fota/installer.py", "        if m.device_class != self.cls:", "        if False:", "F7 class"),
    ("pqgrid/fota/installer.py", "        if m.version <= self.prot.committed[m.type]:\n            raise FotaError(\"rollback: version not newer than installed\")",
     "        if False:\n            raise FotaError(\"rollback: version not newer than installed\")", "anti-rollback (signed)"),
    ("pqgrid/fota/installer.py", "        if not merkle.verify(i, m.chunk_count, data, path, m.merkle_root):", "        if False:", "chunk Merkle"),
    ("pqgrid/fota/installer.py", "        if hashlib.sha256(image).digest() != m.payload_sha256:", "        if False:", "boot re-hash"),
    ("pqgrid/fota/installer.py", "        if not self_test(image):", "        if False:", "self-test"),
    ("pqgrid/fota/installer.py", "        if self.clock() < m.activate_at:\n            return \"waiting for activate_at\"", "        if False:\n            return \"waiting for activate_at\"", "fw activate_at"),
    ("pqgrid/fota/installer.py", "        if not (set(self.anchors) - self.prot.revoked - {rid}):", "        if False:", "last anchor"),
    ("pqgrid/fota/artifact.py", "    elif signer != release_anchor(revoked):", "    elif False:", "DR-050 release role"),
    ("pqgrid/fota/merkle.py", "    return sn == 0 and r == expected_root", "    return r == expected_root", "merkle sn==0"),
    ("pqgrid/fota/policy_artifact.py", "    if m.type != POLICY:", "    if False:", "policy artifact type"),
    ("pqgrid/fota/policy_artifact.py", "    if p.version != m.version or p.activate_at != m.activate_at:", "    if False:", "policy/manifest agree"),
    # ---------------------------------------------------------------- broker / ACL
    ("pqgrid/mqtt/broker.py", "        if not rec.active:\n            continue", "        if False:\n            continue", "ACL revoked"),
    ("pqgrid/mqtt/broker.py", "    if glob.get(\"allow_anonymous\") != \"false\":", "    if False:", "config anonymous"),
    # ---------------------------------------------------------------- checks added by cycle 1 (C1-x)
    ("pqgrid/fota/installer.py", "        if hashlib.sha256(payload).digest() != m.payload_sha256:          # as V-F4",
     "        if False:          # as V-F4", "C1-8 staged policy re-hash"),
    ("pqgrid/fota/installer.py", "        if hashlib.sha256(raw).digest() != digest:", "        if False:", "C1-8 installed policy digest"),
    ("pqgrid/fota/installer.py", "            return self.flash.policy_areas[1 - self.prot.policy[0]]",
     "            return self.flash.policy_areas[self.prot.policy[0]]", "C1-8 stage beside the installed policy"),
    ("pqgrid/fota/installer.py", "        self.prot.commit(POLICY, m.version, policy=(1 - self.prot.policy[0], m.payload_length, m.payload_sha256))",
     "        self.prot.commit(POLICY, m.version)", "C1-8 commit records the installed policy"),
    ("pqgrid/fota/installer.py", "            p.profile(self.cls)                                            # it must",
     "            pass                                            # it must", "C1-10 policy defines own class"),
    ("pqgrid/fota/installer.py", "        self.max_packet = p.profile(self.cls).max_packet                   # E61 now",
     "        pass                   # E61 now", "C1-10 installer limit follows commit"),
    ("pqgrid/fota/installer.py", "            self.max_packet = installed.profile(self.cls).max_packet\n",
     "            pass\n", "C1-10 installer limit at boot"),
    ("pqgrid/fota/installer.py", "        self._finish_interrupted_commits()\n", "", "C1-7 boot reconciliation"),
    ("pqgrid/mqtt/device_node.py", "            self.outbox.cap = prof.outbox_cap                 # the budget",
     "            pass                 # the budget", "C1-10 outbox cap follows policy"),
    ("pqgrid/commands/utility.py", "        self._forget_grants(device_id, s.sid, now)\n", "", "C1-4 GRANT pruning"),
    ("pqgrid/mqtt/utility_node.py", "                self._forget_scheduled()\n                self.refused.append",
     "                self.refused.append", "C1-3 refused schedule dropped"),
    ("pqgrid/mqtt/utility_node.py", "        validate(p, installed_version=self.n.endpoint.policy.version)  # … and so is one that is not newer",
     "        pass  # … and so is one that is not newer", "C1-3 schedule validates version"),
    ("pqgrid/mqtt/utility_node.py", "            self.n.db.save_policy(\"active\", signed, payload, anchors, revoked)   # active; durable",
     "            pass   # active; durable", "C1-12 active policy persisted"),
    ("pqgrid/mqtt/utility_node.py", "        self.n.db.save_policy(\"scheduled\", signed, payload, anchors, revoked)   # survives",
     "        pass   # survives", "C1-12 scheduled policy persisted"),
    ("pqgrid/persistence/utility_db.py", "        if active.version > policy.version:\n            policy = active",
     "        if False:\n            policy = active", "C1-12 active policy resumed"),
    ("pqgrid/fota/publisher.py", "        self._store(key, art, pub)                                 # the rollout state first",
     "        pass                                 # the rollout state first", "C1-13 publish persisted"),
    ("pqgrid/fota/publisher.py", "            self._store_revoked(rid)\n", "            pass\n", "C1-13 revocation persisted"),
    ("pqgrid/fota/publisher.py", "                self._store(key, pub.artifact, None)               # still the newest",
     "                pass               # still the newest", "C1-13 cleanup persisted"),
    ("pqgrid/persistence/flash.py", "                    end = (i + 1, 0)                           # after its type byte",
     "                    pass                           # after its type byte", "C1-1 torn header"),
    ("pqgrid/registry.py", "    return bool(_DEVICE_ID.fullmatch(device_id))", "    return bool(_DEVICE_ID.match(device_id))",
     "C1-2 device id fullmatch"),
    ("pqgrid/commands/codec.py", "    return bool(_TOKEN.fullmatch(s))", "    return bool(_TOKEN.match(s))", "C1-2 token fullmatch"),
    ("pqgrid/policy/validator.py", "    if not _POLICY_ID.fullmatch(p.policy_id):", "    if not _POLICY_ID.match(p.policy_id):",
     "C1-2 policy id fullmatch"),
    ("pqgrid/policy/validator.py", "        if not _CLASS_NAME.fullmatch(name) or c.name != name:",
     "        if not _CLASS_NAME.match(name) or c.name != name:", "C1-2 class name fullmatch"),
    # ---------------------------------------------------------------- checks added by cycle 2 (C2-x)
    ("pqgrid/commands/zones.py", "        self._finish_revocations()\n", "", "C2-4 revoked members leave at start"),
    ("pqgrid/mqtt/utility_node.py",
     "            self.n.zones.rotate_all()                                # first: a crash then leaves the old policy\n"
     "            self.n.db.save_policy(\"active\", signed, payload, anchors, revoked)   # active; durable before effect\n",
     "            self.n.db.save_policy(\"active\", signed, payload, anchors, revoked)   # active; durable before effect\n"
     "            self.n.zones.rotate_all()                                # first: a crash then leaves the old policy\n",
     "C2-5 rotate before persisting"),
    ("pqgrid/e2e/handshake.py",
     "            opened.append((aid, payload))\n",
     "            opened.append((aid, payload)); self._dedup(s.device_id, aid)\n", "C2-6 dedup after the reply"),
    ("pqgrid/mqtt/utility_node.py", "                    if rec is None or not rec.active or rec.dclass != cls:   # not wait",
     "                    if rec is None:   # not wait", "C2-7 telemetry from revoked devices"),
]


def run(i, mut):
    path, old, new, name = mut
    work = tempfile.mkdtemp()
    for d in ("pqgrid", "tests"):
        shutil.copytree(f"/src/{d}", f"{work}/{d}")
    shutil.copy("/src/pytest.ini", work)
    src = open(f"{work}/{path}").read()
    n = src.count(old)
    if n != 1:
        return f"{i:3d} BADPATTERN({n}) {name}"
    open(f"{work}/{path}", "w").write(src.replace(old, new))
    r = subprocess.run([sys.executable, "-m", "pytest", "-o", "addopts=", "-q", "-x", "-p", "no:cacheprovider",
                        "tests/unit", "tests/security"], cwd=work, capture_output=True, text=True, timeout=1200)
    shutil.rmtree(work)
    last = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.stderr[-200:]
    return f"{i:3d} {'KILLED  ' if r.returncode else 'SURVIVED'} {name}   [{last}]"


if __name__ == "__main__":
    if sys.argv[1] == "sel":                      # python mutate.py sel 1,9,10 <slice> <nslices>
        chosen = [int(x) for x in sys.argv[2].split(",")]
        k, n = int(sys.argv[3]), int(sys.argv[4])
        for j, i in enumerate(chosen):
            if j % n == k:
                print(run(i, M[i]), flush=True)
    else:
        k, n = int(sys.argv[1]), int(sys.argv[2])
        for i, mut in enumerate(M):
            if i % n == k:
                print(run(i, mut), flush=True)
