#!/usr/bin/env python3
"""Bounded Linux smoke test of a built miner using only local mock servers.

Usage: python3 tools/test-vu9p-smoke.py /path/to/suprminer-fpga
Requires a C compiler for an LD_PRELOAD guard which forbids USB initialization
and non-loopback connections. This tests real miner startup, work generation,
CPU share checking/submission, reconnect STOP, and process-exit socket closure.
All bridge counters, telemetry, FPGA behavior and pool acceptance are simulated.
It does not test a bitstream, physical performance, or real-pool acceptance.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import tempfile
import threading
import time

RATE = 298_600_000
USER = "smoke.worker"
JOB = "local-smoke-job"
XNONCE1 = bytes.fromhex("01020304")
COINB1 = bytes.fromhex("01000000")
COINB2 = bytes.fromhex("00000000")
VERSION = bytes.fromhex("20000000")
PREVHASH = bytes.fromhex("12345678" * 8)
NTIME = bytes.fromhex("65000000")
NBITS = bytes.fromhex("1d00ffff")
NONCE = 17

GUARD = r'''
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>
static const unsigned short ports[] = {MOCK_PORTS};
__attribute__((constructor)) static void active(void) {
    static const char message[] = "SMOKE_GUARD_ACTIVE\n";
    write(2, message, sizeof(message)-1);
}
static void denied(void) {
    static const char message[] = "SMOKE_GUARD_DENIED\n";
    write(2, message, sizeof(message)-1); _exit(97);
}
int libusb_init(void **ctx) { (void)ctx; denied(); return -1; }
ssize_t libusb_get_device_list(void *ctx, void ***list) {
    (void)ctx; (void)list; denied(); return -1;
}
int connect(int fd, const struct sockaddr *address, socklen_t size) {
    static int (*real_connect)(int,const struct sockaddr*,socklen_t);
    if (!real_connect) real_connect = dlsym(RTLD_NEXT, "connect");
    if (!real_connect || !address || address->sa_family != AF_INET ||
        size < sizeof(struct sockaddr_in) ||
        ntohl(((const struct sockaddr_in *)address)->sin_addr.s_addr) != INADDR_LOOPBACK)
        denied();
    unsigned short port = ntohs(((const struct sockaddr_in *)address)->sin_port);
    unsigned int i;
    for (i = 0; i < sizeof(ports)/sizeof(ports[0]); i++)
        if (port == ports[i]) return real_connect(fd, address, size);
    denied(); return -1;
}
'''


def sha3t(message):
    for _ in range(3):
        message = hashlib.sha3_256(message).digest()
    return message


def expected_header(xnonce2):
    coinbase = COINB1 + XNONCE1 + xnonce2 + COINB2
    merkle = hashlib.sha256(hashlib.sha256(coinbase).digest()).digest()
    prev = b"".join(PREVHASH[i:i + 4][::-1] for i in range(0, 32, 4))
    return VERSION[::-1] + prev + merkle + NTIME[::-1] + NBITS[::-1]


class Server:
    def __init__(self, handler):
        self.handler = handler
        self.errors = []
        self.stop = threading.Event()
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen()
        self.socket.settimeout(0.2)
        self.port = self.socket.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def start(self):
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                connection, peer = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                assert peer[0] == "127.0.0.1"
                connection.settimeout(0.2)
                with connection:
                    self.handler(connection, self)
            except (BrokenPipeError, ConnectionResetError):
                pass  # The miner deliberately closes transport during cleanup.
            except Exception as exc:
                self.errors.append(str(exc))
                break

    def lines(self, connection):
        pending = b""
        while not self.stop.is_set():
            try:
                data = connection.recv(4096)
            except socket.timeout:
                continue
            if not data:
                return
            pending += data
            assert len(pending) < 65536, "unbounded mock request"
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                yield line.rstrip(b"\r").decode("ascii")

    def close(self):
        self.stop.set()
        self.socket.close()
        if self.thread.ident is not None:
            self.thread.join(2)
            assert not self.thread.is_alive(), "mock server did not stop"


class Bridge:
    def __init__(self, index):
        self.index = index
        self.events = []
        self.works = []
        self.connections = 0
        self.active = False
        self.injected_eof = False
        self.exit_eof = 0
        self.polls = 0

    def handle(self, connection, server):
        self.connections += 1
        number = self.connections
        header = None
        started = 0
        sent_found = False
        try:
            for line in server.lines(connection):
                command = line.split(" ", 1)[0]
                self.events.append((number, command))
                if line == "PING":
                    response = "PONG 5a3d0001"
                elif line == "TEMP":
                    assert not self.active, "TEMP occurred during a live epoch"
                    response = "TEMP MASTER_SLR_ONLY C=40.000 VCCINT=0.8000 VCCAUX=1.8000 VCCBRAM=0.8000"
                elif line == "STOP":
                    self.active = False
                    response = "OK"
                elif command == "WORK":
                    match = re.fullmatch(r"WORK ([0-9a-f]{152}) ([0-9a-f]{8}) ([0-9a-f]{8})", line)
                    assert match, "invalid WORK grammar"
                    header = bytes.fromhex(match[1])
                    assert match.groups()[1:] == ("ffffffff", "00000000"), "unexpected target/base"
                    self.works.append(header)
                    self.active = True
                    started = time.monotonic()
                    sent_found = False
                    response = "OK"
                elif line == "POLL":
                    assert self.active and header is not None, "POLL without a WORK epoch"
                    time.sleep(0.025)
                    self.polls += 1
                    count = max(1000, int((time.monotonic() - started) * RATE))
                    digest = sha3t(header + NONCE.to_bytes(4, "big"))
                    hash7 = int.from_bytes(digest[28:32], "little")
                    if self.index == 0 and self.polls >= 4 and not self.injected_eof:
                        self.injected_eof = True
                        self.active = False  # Models the Tcl owner's EOF STOP.
                        return
                    if not sent_found:
                        response = f"FOUND {NONCE:08x} {hash7:08x} {count} {hash7:08x}"
                        sent_found = True
                    else:
                        response = f"NONE {count} {hash7:08x}"
                else:
                    raise AssertionError(f"unexpected bridge request: {command}")
                connection.sendall((response + "\n").encode())
        finally:
            self.active = False  # Models Tcl STOP on EOF, not physical evidence.
            self.exit_eof += 1


class Pool:
    def __init__(self, bridges):
        self.bridges = bridges
        self.submits = []
        self.ids = set()
        self.methods = []

    @staticmethod
    def send(connection, value):
        connection.sendall((json.dumps(value) + "\n").encode())

    def handle(self, connection, server):
        for line in server.lines(connection):
            request = json.loads(line)
            method, ident = request["method"], request["id"]
            self.methods.append(method)
            if method == "mining.subscribe":
                result = [[["mining.notify", "smoke-session"]], XNONCE1.hex(), 4]
            elif method == "mining.authorize":
                assert request["params"] == [USER, "test-only"]
                self.send(connection, {"id": ident, "result": True, "error": None})
                self.send(connection, {"id": None, "method": "mining.set_difficulty", "params": [1e-12]})
                self.send(connection, {"id": None, "method": "mining.notify", "params": [
                    JOB, PREVHASH.hex(), COINB1.hex(), COINB2.hex(), [],
                    VERSION.hex(), NBITS.hex(), NTIME.hex(), True]})
                continue
            elif method == "mining.submit":
                assert isinstance(ident, int) and ident >= 4 and ident not in self.ids
                self.ids.add(ident)
                user, job, extra, ntime, nonce_text = request["params"]
                assert user == USER and job == JOB and ntime == NTIME.hex()
                assert len(extra) == 8
                nonce = int.from_bytes(bytes.fromhex(nonce_text), "little")
                assert nonce == NONCE
                header = expected_header(bytes.fromhex(extra))
                owners = [b.index for b in self.bridges if header in b.works]
                assert len(owners) == 1, "submit header must belong to exactly one card"
                # Independent CPU digest uses the actual generated header.
                digest = sha3t(header + nonce.to_bytes(4, "big"))
                assert len(digest) == 32
                self.submits.append((ident, owners[0], header.hex(), nonce))
                result = True  # Deliberately trivial mock target; not a real share.
            else:
                raise AssertionError(f"unexpected Stratum method: {method}")
            self.send(connection, {"id": ident, "result": result, "error": None})


def run(binary):
    binary = binary.resolve(strict=True)
    started = time.monotonic()
    bridges = [Bridge(i) for i in range(3)]
    pool = Pool(bridges)
    servers = [Server(b.handle) for b in bridges] + [Server(pool.handle)]
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="vu9p-smoke-") as temp:
            temp = Path(temp)
            (temp / "guard.c").write_text(GUARD.replace("MOCK_PORTS", ",".join(str(s.port) for s in servers)))
            subprocess.run(["cc", "-shared", "-fPIC", "-O2", "-o", str(temp / "guard.so"),
                            str(temp / "guard.c"), "-ldl"], check=True, timeout=15,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for server in servers:
                server.start()
            command = [str(binary), "-a", "sha3t", "-o", f"stratum+tcp://127.0.0.1:{servers[-1].port}",
                       "-u", USER, "-p", "test-only", "--no-extranonce", "--no-color", "--no-redirect",
                       "--vu9p", ",".join(f"127.0.0.1:{s.port}" for s in servers[:-1]),
                       "--vu9p-build-id", "5a3d0001", "--vu9p-active-lanes", "1",
                       "--vu9p-rate-hps", "300000000", "--vu9p-poll-work-ms", "1000",
                       "--api-bind", "127.0.0.1:0", "-R", "1", "-r", "0"]
            environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                           "LC_ALL": "C", "LD_PRELOAD": str(temp / "guard.so")}
            with (temp / "miner.log").open("w+") as log:
                process = subprocess.Popen(command, cwd=temp, env=environment, stdin=subprocess.DEVNULL,
                                           stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                deadline = time.monotonic() + 25
                while time.monotonic() < deadline:
                    errors = [error for s in servers for error in s.errors]
                    if errors:
                        raise AssertionError(str(errors) + "\n" + (temp / "miner.log").read_text()[-8000:])
                    if process.poll() is not None:
                        raise AssertionError(f"miner exited early: {process.returncode}\n" + (temp / "miner.log").read_text()[-8000:])
                    # Three independent workers plus STOP/re-WORK after card0 EOF.
                    if (len(bridges[0].works) >= 2 and all(b.polls >= 5 for b in bridges) and
                            {entry[1] for entry in pool.submits} == {0, 1, 2} and len(pool.submits) >= 4):
                        break
                    time.sleep(0.05)
                else:
                    raise AssertionError("startup/share/reconnect deadline expired\n" + (temp / "miner.log").read_text()[-8000:])
                time.sleep(0.15)  # Let the miner consume mock acceptance responses.
                assert all(b.active for b in bridges), "expected live mock owners before SIGINT"
                os.killpg(process.pid, signal.SIGINT)
                process.wait(timeout=5)
                assert process.returncode == 0, "SIGINT did not exit successfully"
                until = time.monotonic() + 2
                while time.monotonic() < until and any(b.active for b in bridges):
                    time.sleep(0.02)
                assert not any(b.active for b in bridges), "mock owner remained active after exit"
                log.seek(0)
                output = log.read()
                assert "SMOKE_GUARD_ACTIVE" in output, "LD_PRELOAD guard was not loaded"
                assert "SMOKE_GUARD_DENIED" not in output
                assert "3 VU9P miner threads started" in output
                allocated = re.findall(r"VU9P ([0-2]): miner thread ([0-9]+) started", output)
                assert len(allocated) == 3
                assert {card for card, _ in allocated} == {"0", "1", "2"}
                assert len({thread for _, thread in allocated}) == 3
                assert "checkNonce FAILED" not in output
                assert re.search(r"accepted:\s*[1-9]", output), "mock true response not accounted as accepted"
                rates = [float(v) for v in re.findall(r"VU9P [0-2]: ([0-9.]+) MH/s", output)]
                assert len(rates) >= 3 and all(math.isfinite(v) and 0 < v <= 300.1 for v in rates)
                assert bridges[0].injected_eof
                assert (2, "STOP") in bridges[0].events
                assert next(cmd for conn, cmd in bridges[0].events if conn == 2) == "STOP"
                assert all(b.exit_eof >= 1 for b in bridges)
                assert len({h for b in bridges for h in b.works}) == sum(len(b.works) for b in bridges)
                print(json.dumps({"status": "PASS", "scope": "local mocks only", "cards": 3,
                                  "mock_accepted_submits": len(pool.submits),
                                  "work_epochs": [len(b.works) for b in bridges],
                                  "bridge_eof_stop_reconnect": True, "sigint_exit_and_peer_eof": True,
                                  "usb_guard_loaded": True, "usb_guard_tripped": False, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                                  "elapsed_seconds": round(time.monotonic() - started, 3)}))
    except Exception:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGINT)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
        raise
    finally:
        for server in servers:
            server.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    run(parser.parse_args().binary)
