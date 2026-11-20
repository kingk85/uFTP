#!/usr/bin/env python3
"""Load scenarios that load_test.py does not cover. Not part of the test suite (slow, measures).

  python3 test/load_scenarios.py transfers --steps 50,100,200,400,800 --size-mb 10
      N clients transfer a big file at the same time (half download, half upload), while a probe
      checks that the control channel still answers. Reports throughput, threads, memory, descriptors,
      errors, and whether the server gives back its threads and descriptors afterwards (leaks).

  python3 test/load_scenarios.py abuse
      Normal clients keep working while others misbehave: idle connections, a command sent one byte
      per second, readers that never read, uploads cut with a reset, a PASV that is never used,
      garbage. Then everyone goes away and the server must be back to its baseline.

  python3 test/load_scenarios.py soak --minutes 60 --connections 2000
      Constant load for a long time; samples memory, threads and descriptors, reports the drift.

UFTP_BIN selects the binary. --tls puts the control connections in TLS.
"""

import argparse
import os
import random
import socket
import statistics
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from uftp_test_server import UFTPTestServer                       # noqa: E402
from ftp_test_client import FtpControl                             # noqa: E402
from load_test import process_info, percentile, work, open_connection, SHARED_TLS_CONTEXT  # noqa: E402


def start_server(args, clients, login_timeout=0):
    server = UFTPTestServer(port=args.port, idle_timeout=3600, max_connections=clients + 300, max_per_ip=clients + 300,
                            extra_config={"MAXIMUM_LOG_FILES": 1, "MAX_CONNECTION_TRY_PER_IP": 0,
                                          "MAX_CONNECTION_RATE_PER_IP": 0, "LOGIN_TIMEOUT": login_timeout,
                                          "RANDOM_PORT_START": 20000, "RANDOM_PORT_END": 60000})
    server.start()
    return server


def new_control(args, server, timeout=120):
    control = FtpControl(args.port, server.user, server.password, login=not args.tls, timeout=timeout)
    if args.tls:
        control.start_tls()
        control.cmd("PBSZ 0")
        control.cmd("PROT C")
        control.login(server.user, server.password)
    return control


class Sampler(threading.Thread):
    """Samples threads, memory and descriptors of the server every `period` seconds."""

    def __init__(self, pid, period=0.5):
        super().__init__(daemon=True)
        self.pid, self.period, self.samples = pid, period, []
        self.stop_flag = threading.Event()

    def run(self):
        while not self.stop_flag.is_set():
            try:
                info = process_info(self.pid)
                self.samples.append((time.monotonic(), info["threads"], info["rss"], info["fds"], info["cpu"]))
            except OSError:
                return
            time.sleep(self.period)

    def finish(self):
        self.stop_flag.set()
        self.join(timeout=5)
        return self.samples


def alive(server):
    return server.process.poll() is None


def baseline(server):
    time.sleep(1)
    return process_info(server.process.pid)


def settle(server, base, seconds=8):
    """After the clients are gone: do the threads and descriptors come back? Returns (ok, text)."""
    deadline = time.monotonic() + seconds
    info = None
    while time.monotonic() < deadline:
        info = process_info(server.process.pid)
        if info["threads"] <= base["threads"] + 1 and info["fds"] <= base["fds"] + 3:
            return True, "threads %d (base %d), descriptors %d (base %d)" % (info["threads"], base["threads"], info["fds"], base["fds"])
        time.sleep(0.5)
    return False, "LEAK? threads %d (base %d), descriptors %d (base %d)" % (info["threads"], base["threads"], info["fds"], base["fds"])


# ---------------------------------------------------------------------------------- transfers
def scenario_transfers(args):
    size = args.size_mb << 20
    steps = [int(s) for s in args.steps.split(",")]
    server = start_server(args, max(steps) + 50)
    chunk = b"z" * (1 << 20)
    with open(os.path.join(server.home, "big.bin"), "wb") as f:
        for _ in range(args.size_mb):
            f.write(chunk)
    base = baseline(server)
    print("file of %d MB; server at rest: %.0f MB, %d threads, %d descriptors; TLS control %s" % (
        args.size_mb, base["rss"], base["threads"], base["fds"], args.tls))
    print("%6s %6s %6s %9s %8s %8s %8s %8s %10s %10s  %s" % (
        "step", "done", "failed", "seconds", "MB/s", "threads", "RSS MB", "fds", "probe max", "probe p99", "after"))
    passed = 0
    exit_code = 0
    try:
        for step in steps:
            result = {"done": 0, "bytes": 0}
            errors = {}
            lock = threading.Lock()
            ready = [0]
            go = threading.Event()
            controls = []

            def client(number):
                try:
                    control = new_control(args, server)
                    data = control.pasv()
                    data.settimeout(args.data_timeout)      # pasv() gives 5 s: too little for a client with thousands of threads
                except Exception as error:
                    with lock:
                        errors["setup " + type(error).__name__] = errors.get("setup " + type(error).__name__, 0) + 1
                        ready[0] += 1
                    return
                with lock:
                    controls.append(control)
                    ready[0] += 1
                go.wait(timeout=300)
                try:
                    if number % 2 == 0:
                        code = control.cmd("RETR big.bin")[0]
                        if code != 150:
                            raise RuntimeError("RETR %s" % code)
                        got = 0
                        while True:
                            piece = data.recv(1 << 18)
                            if not piece:
                                break
                            got += len(piece)
                        data.close()
                        final = control.read_reply()[0]
                        if final != 226 or got != size:
                            raise RuntimeError("RETR end %s, %d of %d bytes" % (final, got, size))
                    else:
                        code = control.cmd("STOR up%d.bin" % number)[0]
                        if code != 150:
                            raise RuntimeError("STOR %s" % code)
                        for _ in range(args.size_mb):
                            data.sendall(chunk)
                        data.close()
                        final = control.read_reply()[0]
                        if final != 226:
                            raise RuntimeError("STOR end %s" % final)
                    with lock:
                        result["done"] += 1
                        result["bytes"] += size
                except Exception as error:
                    key = "%s: %s" % (type(error).__name__, str(error)[:60])
                    with lock:
                        errors[key] = errors.get(key, 0) + 1

            threads = [threading.Thread(target=client, args=(n,)) for n in range(step)]
            for t in threads:
                t.start()
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                with lock:
                    if ready[0] >= step:
                        break
                time.sleep(0.1)

            # the probe is another process: in this one the thousands of client threads would starve it (GIL)
            probe_code = (
                "import sys,time,signal,statistics\nsys.path.insert(0,%r)\nfrom ftp_test_client import FtpControl\n"
                "c=FtpControl(%d,%r,%r,login=%s,timeout=60)\n"
                "%s"
                "t=[]\nstop=[0]\nsignal.signal(signal.SIGTERM,lambda *a: stop.__setitem__(0,1))\n"
                "while not stop[0]:\n s=time.monotonic()\n try:\n  c.cmd('NOOP');t.append((time.monotonic()-s)*1000)\n except Exception:\n  t.append(60000.0)\n time.sleep(0.2)\n"
                "t.sort();print(max(t) if t else 0, t[min(len(t)-1,int(len(t)*0.99))] if t else 0, len(t))\n"
            ) % (os.path.dirname(os.path.abspath(__file__)), args.port, server.user, server.password, "False" if args.tls else "True",
                 ("c.start_tls();c.cmd('PBSZ 0');c.cmd('PROT C');c.login(%r,%r)\n" % (server.user, server.password)) if args.tls else "")
            import subprocess
            probe_process = subprocess.Popen([sys.executable, "-c", probe_code], stdout=subprocess.PIPE, text=True)
            time.sleep(1)

            sampler = Sampler(server.process.pid)
            sampler.start()
            started = time.monotonic()
            go.set()
            for t in threads:
                t.join(timeout=300)
            seconds = time.monotonic() - started
            probe_process.terminate()
            try:
                probe_output = probe_process.communicate(timeout=70)[0].split()
                probe_max, probe_p99 = float(probe_output[0]), float(probe_output[1])
            except Exception:
                probe_max, probe_p99 = 60000.0, 60000.0
            probe_times = [probe_max]
            samples = sampler.finish()
            for control in controls:
                control.close()
            failed = step - result["done"]
            ok_settle, text = settle(server, base)
            top_threads = max([s[1] for s in samples] or [0])
            top_rss = max([s[2] for s in samples] or [0])
            top_fds = max([s[3] for s in samples] or [0])
            print("%6d %6d %6d %9.1f %8.0f %8d %8.0f %8d %9.0fms %9.0fms  %s" % (
                step, result["done"], failed, seconds, result["bytes"] / (1 << 20) / seconds if seconds else 0,
                top_threads, top_rss, top_fds, probe_max, probe_p99, text))
            for why, count in sorted(errors.items(), key=lambda item: -item[1])[:5]:
                print("         %5d x %s" % (count, why))
            sys.stdout.flush()
            for name in os.listdir(server.home):
                if name.startswith("up"):
                    os.unlink(os.path.join(server.home, name))
            step_ok = alive(server) and failed <= step * 0.01 and ok_settle and probe_max < 5000
            print("       step %d: %s" % (step, "PASSED" if step_ok else "FAILED" + ("" if alive(server) else " (SERVER DIED)")))
            if step_ok:
                passed = step
            else:
                exit_code = 1
                break
    finally:
        print("largest step that passed: %d simultaneous transfers" % passed)
        if not alive(server):
            print("--- end of the log ---\n" + server.read_log()[-1500:])
        server.stop()
    return exit_code


# ---------------------------------------------------------------------------------- abuse
def scenario_abuse(args):
    server = start_server(args, 2500, login_timeout=args.login_timeout)
    chunk = b"z" * (1 << 20)
    with open(os.path.join(server.home, "big.bin"), "wb") as f:
        for _ in range(20):
            f.write(chunk)
    base = baseline(server)
    print("server at rest: %.0f MB, %d threads, %d descriptors; LOGIN_TIMEOUT %d s" % (
        base["rss"], base["threads"], base["fds"], args.login_timeout))
    stop = threading.Event()
    held = []
    lock = threading.Lock()
    counts = {}

    def keep(sock):
        with lock:
            held.append(sock)

    def count(name):
        with lock:
            counts[name] = counts.get(name, 0) + 1

    def raw():
        sock = socket.create_connection(("127.0.0.1", args.port), timeout=30)
        sock.recv(200)
        return sock

    def idle():                                     # connects and says nothing
        try:
            keep(raw()); count("idle")
        except OSError:
            count("idle refused")

    def slowloris():                                # a command, one byte per second, never finished
        try:
            sock = raw(); keep(sock); count("slowloris")
            for ch in b"USER abcdefghijklmnopqrstuvwxyz":
                if stop.is_set():
                    return
                sock.sendall(bytes([ch])); time.sleep(1)
        except OSError:
            pass

    def slow_reader():                              # starts a download and reads 1 KB per second
        try:
            control = new_control(args, server); data = control.pasv()
            control.cmd("RETR big.bin"); keep(data); count("slow reader")
            while not stop.is_set():
                data.recv(1024); time.sleep(1)
        except OSError:
            pass

    def cut_upload():                               # starts an upload, sends a little, resets the connection
        try:
            control = new_control(args, server); data = control.pasv()
            control.cmd("STOR cut%d.bin" % random.randrange(10**9)); data.sendall(b"x" * 5000)
            data.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)); data.close()
            control.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)); control.sock.close()
            count("cut upload")
        except (OSError, AttributeError):
            count("cut upload (error)")

    def unused_pasv():                              # PASV that is never used
        try:
            control = new_control(args, server); control.pasv(); keep(control.sock); count("unused PASV")
        except OSError:
            pass

    def garbage():                                  # a long line with no end, and binary
        try:
            sock = raw(); keep(sock); count("garbage")
            sock.sendall(b"A" * 200000)
            sock.sendall(os.urandom(5000))
        except OSError:
            count("garbage closed")

    kinds = [(idle, args.abusers * 3), (slowloris, args.abusers), (slow_reader, args.abusers // 2),
             (cut_upload, args.abusers), (unused_pasv, args.abusers // 2), (garbage, args.abusers // 2)]
    threads = []
    for function, number in kinds:
        for _ in range(number):
            threads.append(threading.Thread(target=function, daemon=True))
    sampler = Sampler(server.process.pid)
    sampler.start()
    for t in threads:
        t.start()
    time.sleep(3)
    print("abusers started: %s" % ", ".join("%s %d" % (k, v) for k, v in sorted(counts.items())))
    operations, errors, latencies = work(args.workers, args.work_seconds, args.port, server.user, server.password, args.tls)
    every = [v for values in latencies.values() for v in values]
    error_count = sum(errors.values())
    print("normal clients during the abuse: %d operations (%.0f/s), %d errors, latency p50 %.1f ms p95 %.1f ms max %.1f ms" % (
        operations, operations / args.work_seconds, error_count, percentile(every, 0.5), percentile(every, 0.95), max(every or [0])))
    for why, number in sorted(errors.items(), key=lambda item: -item[1])[:4]:
        print("         %5d x %s" % (number, why))
    during = process_info(server.process.pid)
    print("server during the abuse: %.0f MB, %d threads, %d descriptors" % (during["rss"], during["threads"], during["fds"]))
    stop.set()
    for sock in held:
        try:
            sock.close()
        except (OSError, AttributeError):
            pass
    for t in threads:
        t.join(timeout=5)
    sampler.finish()
    ok_settle, text = settle(server, base, seconds=args.login_timeout + 20)
    print("after everybody left:", text)
    is_alive = alive(server)
    log = server.read_log()
    sanitizer = "AddressSanitizer" in log or "runtime error" in log or "SIGSEGV" in log
    verdict = is_alive and ok_settle and not sanitizer and error_count <= max(1, operations * 0.01) and percentile(every, 0.95) < 2000
    print("abuse: %s%s%s" % ("PASSED" if verdict else "FAILED", "" if is_alive else " (SERVER DIED)", " (sanitizer/crash in the log)" if sanitizer else ""))
    server.stop()
    return 0 if verdict else 1


# ---------------------------------------------------------------------------------- soak
def scenario_soak(args):
    server = start_server(args, args.connections + 100)
    base = baseline(server)
    print("server at rest: %.0f MB; %d connections held, %d workers, %d minutes" % (base["rss"], args.connections, args.workers, args.minutes))
    held = []
    for n in range(args.connections):
        try:
            held.append(open_connection(n, args.port, args.tls, True, server.user, server.password))
        except Exception as error:
            print("connection %d failed: %s" % (n, error)); break
    sampler = Sampler(server.process.pid, period=1)
    sampler.start()
    end = time.monotonic() + args.minutes * 60
    totals = [0, 0]
    rows = []
    print("%8s %8s %8s %8s %8s %10s %8s" % ("minute", "ops/s", "errors", "RSS MB", "fds", "threads", "p95 ms"))
    minute = 0
    while time.monotonic() < end and alive(server):
        operations, errors, latencies = work(args.workers, 60, args.port, server.user, server.password, args.tls)
        minute += 1
        every = [v for values in latencies.values() for v in values]
        info = process_info(server.process.pid)
        totals[0] += operations
        totals[1] += sum(errors.values())
        rows.append((minute, info["rss"], info["fds"], info["threads"]))
        print("%8d %8.0f %8d %8.1f %8d %10d %8.1f" % (minute, operations / 60, sum(errors.values()), info["rss"], info["fds"], info["threads"], percentile(every, 0.95)))
        sys.stdout.flush()
    sampler.finish()
    for sock in held:
        try:
            sock.close()
        except OSError:
            pass
    ok_settle, text = settle(server, base, seconds=15)
    first = rows[min(2, len(rows) - 1)] if rows else (0, 0, 0, 0)       # after the warm up
    last = rows[-1] if rows else (0, 0, 0, 0)
    growth = (last[1] - first[1]) / first[1] * 100 if first[1] else 0
    print("memory from minute %d to minute %d: %+.1f%% (%.0f -> %.0f MB); descriptors %d -> %d; threads %d -> %d" % (
        first[0], last[0], growth, first[1], last[1], first[2], last[2], first[3], last[3]))
    print("%d operations, %d errors; after the clients left: %s" % (totals[0], totals[1], text))
    verdict = alive(server) and totals[1] <= totals[0] * 0.001 and growth < 5 and ok_settle and last[2] <= first[2] + 5
    print("soak: %s" % ("PASSED" if verdict else "FAILED"))
    server.stop()
    return 0 if verdict else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scenario", choices=["transfers", "abuse", "soak"])
    parser.add_argument("--port", type=int, default=2162)
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--steps", default="50,100,200,400,800")
    parser.add_argument("--size-mb", type=int, default=10)
    parser.add_argument("--workers", type=int, default=20)
    parser.add_argument("--data-timeout", type=int, default=120)
    parser.add_argument("--abusers", type=int, default=100)
    parser.add_argument("--work-seconds", type=int, default=30)
    parser.add_argument("--login-timeout", type=int, default=20)
    parser.add_argument("--minutes", type=int, default=60)
    parser.add_argument("--connections", type=int, default=2000)
    args = parser.parse_args()
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, 200000), hard))
    return {"transfers": scenario_transfers, "abuse": scenario_abuse, "soak": scenario_soak}[args.scenario](args)


if __name__ == "__main__":
    sys.exit(main())
