"""A real broker for integration tests: Mosquitto with the rendered, validated config, a fresh ECDSA P-256 PKI,
the hybrid-only group pin and a compiled ACL. Available only where Mosquitto and OpenSSL >= 3.5 exist, i.e. in
the Docker test image; elsewhere the tests are skipped with that reason (nothing is installed on the host)."""
from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field

import pytest

import conftest
from pqgrid.commands import CommandProcessor
from pqgrid.e2e.handshake import DeviceEndpoint
from pqgrid.mqtt import pki, tls
from pqgrid.fota.artifact import FIRMWARE, POLICY
from pqgrid.fota.installer import FotaFlash, Installer
from pqgrid.fota.publisher import part_payload_budget
from pqgrid.fota.station import Station
from pqgrid.mqtt.broker import compile_acl, hybrid_openssl_cnf, install_acl, render_config
from pqgrid.persistence.flash import RecordStore
from pqgrid.policy import encode_policy
from pqgrid.mqtt.device_node import DeviceMqtt
from pqgrid.mqtt.utility_node import UtilityMqtt
from pqgrid.mqtt import topics
from pqgrid.persistence.device import DeviceFlash
from pqgrid.persistence.flash import FlashSim
from pqgrid.persistence.utility_db import SqlPublisher, open_utility
from pqgrid.policy import validate
from pqgrid.registry import DeviceRecord
from pqgrid.suite.hkem import HybridKeyPair
from pqgrid.suite.sig import mldsa_keygen, mldsa_public_bytes

MOSQUITTO, OPENSSL = shutil.which("mosquitto"), shutil.which("openssl")


def _openssl_ok() -> bool:
    if not OPENSSL:
        return False
    v = subprocess.run([OPENSSL, "version"], capture_output=True, text=True).stdout
    m = re.search(r"OpenSSL (\d+)\.(\d+)", v)
    return bool(m) and (int(m.group(1)), int(m.group(2))) >= (3, 5)


requires_broker = pytest.mark.skipif(
    not (MOSQUITTO and _openssl_ok()),
    reason="needs Mosquitto and OpenSSL >= 3.5: runs in the Docker test image (docker run --rm pqgrid-tests)")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(cond, timeout: float = 10.0, step: float = 0.02) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(step)
    return cond()


class Broker:
    def __init__(self, tmp):
        self.dir = str(tmp)
        os.makedirs(f"{self.dir}/pki", exist_ok=True)
        os.makedirs(f"{self.dir}/db", exist_ok=True)
        P = f"{self.dir}/pki"
        self.ca = pki.make_ca(P)
        self.cert = pki.issue(self.ca, P, "broker", "broker", "serverAuth", san="DNS:localhost,IP:127.0.0.1")
        self.future = pki.issue(self.ca, P, "broker-future", "broker", "serverAuth", san="DNS:localhost",
                                not_before="20400101000000Z", not_after="20410101000000Z")
        self.utility = pki.issue(self.ca, P, "utility", "utility", "clientAuth")
        self.port, self.port_future = free_port(), free_port()
        self.acl, self.log = f"{self.dir}/acl", f"{self.dir}/mosquitto.log"
        with open(self.acl, "w") as f:
            f.write("user utility\n")
        conf = render_config([
            {"port": self.port, "cafile": self.ca.crt, "certfile": self.cert.crt, "keyfile": self.cert.key},
            {"port": self.port_future, "cafile": self.ca.crt, "certfile": self.future.crt, "keyfile": self.future.key},
        ], self.acl, f"{self.dir}/db", log_file=self.log)
        self.conf, self.cnf = f"{self.dir}/mosquitto.conf", f"{self.dir}/hybrid.cnf"
        with open(self.conf, "w") as f:
            f.write(conf + "user root\n")                       # test container only: no privilege drop
        with open(self.cnf, "w") as f:
            f.write(hybrid_openssl_cnf())
        self.proc = None
        self.start()

    def start(self) -> None:
        self.proc = subprocess.Popen([MOSQUITTO, "-c", self.conf], env=dict(os.environ, OPENSSL_CONF=self.cnf),
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        assert wait_for(self._listening, 10), "broker did not start"

    def _listening(self) -> bool:
        try:
            socket.create_connection(("127.0.0.1", self.port), 0.2).close()
            return True
        except OSError:
            return False

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()                                # SIGTERM: Mosquitto saves persistence on exit
            self.proc.wait(10)

    def restart(self) -> None:
        self.stop()
        self.start()

    def load_acl(self, text: str) -> None:
        install_acl(self.acl, text, broker_pid=self.proc.pid)
        time.sleep(0.3)                                          # the broker re-reads it on SIGHUP

    def device_ctx(self, cert: pki.Cert):
        return tls.device_context([self.ca.crt], cert.crt, cert.key)

    def utility_ctx(self):
        return tls.utility_context([self.ca.crt], self.utility.crt, self.utility.key)

    def s_client(self, *args: str, port: int | None = None, cert: pki.Cert | None = None) -> str:
        cert = cert or self.utility
        r = subprocess.run([OPENSSL, "s_client", "-connect", f"127.0.0.1:{port or self.port}", "-CAfile", self.ca.crt,
                            "-cert", cert.crt, "-key", cert.key, "-brief", *args],
                           input=b"Q\n", capture_output=True, timeout=15)
        return (r.stdout + r.stderr).decode(errors="replace")


@dataclass
class Dev:
    did: bytes
    dclass: str
    kp: HybridKeyPair
    cert: pki.Cert
    flash: FlashSim = field(default_factory=FlashSim)
    protected: FlashSim = field(default_factory=FlashSim)          # FOTA counters: survive a factory reset
    fota_flash: FotaFlash = field(default_factory=lambda: FotaFlash(64 * 1024))
    fota: Installer = None
    applied: list = field(default_factory=list)
    setpoints: list = field(default_factory=list)
    d: DeviceEndpoint = None
    proc: CommandProcessor = None
    outbox: object = None
    mq: DeviceMqtt = None


class Plant:
    """Utility (SQLite + MQTT) and devices (flash + MQTT) on one real broker; real time throughout."""

    def __init__(self, broker: Broker, tmp):
        self.b, self.db_path = broker, f"{tmp}/utility.db"
        self.u_static, self.cmd_sk = HybridKeyPair.generate(), mldsa_keygen()
        self.policy = conftest.make_policy(self.u_static.pk, mldsa_public_bytes(self.cmd_sk))
        validate(self.policy)
        self.node = open_utility(self.db_path, self.policy, self.u_static, self.cmd_sk, time.time)
        self.station = Station(f"{tmp}")
        self.policy_art = self.sign_policy(self.policy)
        self.publisher = SqlPublisher(self.node.db, self.policy)
        self.u = UtilityMqtt(self.node, broker.utility_ctx(), "localhost", broker.port, publisher=self.publisher)
        self.devs: dict[bytes, Dev] = {}

    def sign_policy(self, policy, device_class: str = "smart_meter"):
        prof = policy.profile(device_class)
        return self.station.build(POLICY, device_class, policy.version, encode_policy(policy), prof.fota_chunk_size,
                                  part_payload_budget(prof.max_packet, device_class, POLICY, policy.version),
                                  activate_at=policy.activate_at)

    def artifact(self, type_, dclass: str, version: int, payload: bytes, **kw):
        prof = self.policy.profile(dclass)
        return self.station.build(type_, dclass, version, payload, prof.fota_chunk_size,
                                  part_payload_budget(prof.max_packet, dclass, type_, version), **kw)

    def add(self, did: bytes, dclass: str) -> Dev:
        dev = Dev(did, dclass, HybridKeyPair.generate(), pki.device_cert(self.b.ca, f"{self.b.dir}/pki", did))
        self.node.endpoint.registry.add(DeviceRecord(did, dclass, dev.kp.pk))
        self.devs[did] = dev
        self.boot(dev)
        return dev

    def boot(self, dev: Dev) -> Dev:
        """Power-on: every object rebuilt from flash; a new MQTT connection. The device runs its committed firmware
        (version 1 from the factory) and its installed policy, kept in flash (Master §4.1), or its factory policy if
        none was ever installed over the air."""
        df = DeviceFlash(dev.flash, clock=time.time)
        dev.fota = Installer(self.station.anchors, dev.dclass, self.policy.profile(dev.dclass).max_packet,
                             dev.fota_flash, RecordStore(dev.protected, clock=time.time), df.store,
                             clock=lambda: dev.d.now())
        policy = dev.fota.installed_policy() or self.policy
        dev.d = DeviceEndpoint(dev.did, dev.dclass, policy, dev.fota.committed(FIRMWARE) or 1, dev.kp, flash=df)
        dev.proc = CommandProcessor(dev.d, dev.applied.append, lambda t, v: dev.setpoints.append((t, v)),
                                    targets={"P_ACTIVE_W"}, state=df.command_state())
        dev.outbox = df.outbox(topics.alert(dev.dclass, dev.did), policy.profile(dev.dclass).outbox_cap)
        dev.mq = DeviceMqtt(dev.d, dev.proc, dev.outbox, self.b.device_ctx(dev.cert), "localhost", self.b.port,
                            reply_timeout=2.0, fota=dev.fota)
        return dev

    def publish_acl(self) -> None:
        members = {name: set(z.members) for name, z in self.node.zones.zones.items()}
        self.b.load_acl(compile_acl(self.policy_art.signed, self.policy_art.payload, self.station.anchors,
                                    self.node.endpoint.registry.records(), members))

    def restart_utility(self) -> None:
        self.u.stop()
        self.node.db.close()
        self.node = open_utility(self.db_path, self.policy, self.u_static, self.cmd_sk, time.time)
        self.publisher = SqlPublisher(self.node.db, self.node.endpoint.policy)   # only what the database kept
        self.u = UtilityMqtt(self.node, self.b.utility_ctx(), "localhost", self.b.port, publisher=self.publisher)
        self.u.start()

    def close(self) -> None:
        for dev in self.devs.values():
            try:
                dev.mq.disconnect()
            except Exception:
                pass
        try:
            self.u.stop()
        except Exception:
            pass
        self.node.db.close()


@pytest.fixture
def broker(tmp_path):
    b = Broker(tmp_path)
    yield b
    b.stop()


@pytest.fixture
def plant(broker, tmp_path):
    p = Plant(broker, tmp_path)
    yield p
    p.close()
