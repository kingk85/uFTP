#!/usr/bin/env python3
"""Load test: how uFTP behaves with many connections open at the same time.

Not part of the test suite (it is slow, and it measures instead of checking). Starts a server,
opens connections in steps (100, 500, 1000, ...), and at every step prints:

  * how many connections were accepted, and how long opening them took;
  * the memory (RSS), threads and file descriptors of the server, and the memory per connection;
  * the latency of a command (NOOP) on a logged in connection while all the others are open;
  * the CPU that the server uses while the connections are only open (should be near 0);
  * whether the server is still alive and whether it wrote a sanitizer report.

Optionally (--transfers N) it also runs N uploads at the same time at the last step.

  python3 test/load_test.py                       steps up to 3000, plain
  python3 test/load_test.py --tls --steps 100,500,1000
  python3 test/load_test.py --login               every connection logs in (an authenticated session is bigger)
  python3 test/load_test.py --transfers 50
  python3 test/load_test.py --steps 100,500,1000,2000,3000,4000,5000 --workers 40 --login
                                                  clients that work while the others stay connected

--workers N: at every step N logged in clients run a mix of commands (NOOP, PWD, CWD, LIST, STOR, RETR,
SIZE, MKD/RMD, DELE) for --work-seconds seconds. It reports operations per second, errors and the latency
of the operations. A step FAILS if the server dies, more than 1% of the connections or of the operations
fail, or the 95th percentile of the latency is over 2 seconds; the largest step that passes is the limit.

UFTP_BIN selects the binary. The connections come from 127.0.0.2, 127.0.0.3, ... so that the
limits per address do not apply (500 per address). Needs the limit of file descriptors of the
shell to be high (ulimit -n 20000).
"""

import argparse
import os
import resource
import socket
import statistics
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from uftp_test_server import UFTPTestServer          # noqa: E402
from ftp_test_client import FtpControl, tls_client_context  # noqa: E402

PER_ADDRESS = 500
# one context for all the connections: a context per connection (with the system certificates) used
# about 670 KB each in the client, and 20000 of them made the kernel kill the test
SHARED_TLS_CONTEXT = tls_client_context()
CLOCK = os.sysconf("SC_CLK_TCK")


def process_info(pid):
    """RSS in MB, threads, descriptors and CPU seconds of a process, from /proc."""
    info = {}
    with open("/proc/%d/status" % pid) as f:
        for line in f:
            if line.startswith("VmRSS:"):
                info["rss"] = int(line.split()[1]) / 1024.0
            elif line.startswith("Threads:"):
                info["threads"] = int(line.split()[1])
    info["fds"] = len(os.listdir("/proc/%d/fd" % pid))
    with open("/proc/%d/stat" % pid) as f:
        fields = f.read().rsplit(")", 1)[1].split()
    info["cpu"] = (int(fields[11]) + int(fields[12])) / CLOCK
    return info


def server_pid(server):
    """The server process (the test server starts it in its own group)."""
    return server.process.pid


def open_connection(index, port, use_tls, login, user, password):
    source = "127.0.0.%d" % (2 + index // PER_ADDRESS)
    sock = socket.socket()
    sock.bind((source, 0))
    sock.settimeout(10)
    sock.connect(("127.0.0.1", port))
    banner = sock.recv(200)
    if not banner.startswith(b"220"):
        sock.close()
        raise OSError("refused: %r" % banner[:60])
    if use_tls:
        sock.sendall(b"AUTH TLS\r\n")
        if not sock.recv(200).startswith(b"234"):
            raise OSError("AUTH TLS refused")
        sock = SHARED_TLS_CONTEXT.wrap_socket(sock, server_hostname="uftp")
    if login:
        sock.sendall(("USER %s\r\n" % user).encode())
        sock.recv(200)
        sock.sendall(("PASS %s\r\n" % password).encode())
        if not sock.recv(200).startswith(b"230"):
            raise OSError("login refused")
    return sock


def latency(port, user, password, count=20):
    """Median and worst time of NOOP on a new logged in connection (milliseconds)."""
    try:
        control = FtpControl(port, user, password, timeout=15)
    except Exception as error:
        return None, None, "probe could not log in: %s" % error
    times = []
    try:
        for _ in range(count):
            start = time.monotonic()
            code, _ = control.cmd("NOOP")
            times.append((time.monotonic() - start) * 1000)
            if code != 200:
                return None, None, "NOOP answered %s" % code
    finally:
        control.close()
    return statistics.median(times), max(times), ""


def work(workers, seconds, port, user, password, use_tls):
    """workers logged in clients run a mix of commands for `seconds`.
    Returns (operations, errors by kind, latencies by command in milliseconds)."""
    import random
    stop = threading.Event()
    lock = threading.Lock()
    latencies = {}
    errors = {}
    operations = [0]
    samples = []

    def record(name, started, ok, why="", history=None):
        elapsed = (time.monotonic() - started) * 1000
        with lock:
            operations[0] += 1
            latencies.setdefault(name, []).append(elapsed)
            if not ok:
                errors[name + ": " + why[:50]] = errors.get(name + ": " + why[:50], 0) + 1
                if history is not None and len(samples) < 3:
                    samples.append((name, why, list(history)))

    def client(number):
        rng = random.Random(number)
        try:
            control = FtpControl(port, user, password, login=not use_tls, timeout=30)
            if use_tls:
                control.start_tls()          # AUTH TLS clears the login: the login comes after it
                control.cmd("PBSZ 0")
                control.cmd("PROT C")
                control.login(user, password)
        except Exception as error:
            with lock:
                errors["login: " + str(error)[:50]] = errors.get("login: " + str(error)[:50], 0) + 1
            return
        mine = "w%d_" % number
        history = []
        original_cmd, original_read = control.cmd, control.read_reply

        def traced_cmd(line):
            result = original_cmd(line)
            history.append("%s -> %s" % (line, result[0]))
            del history[:-10]
            return result

        def traced_read():
            result = original_read()
            history.append("(reply) %s" % result[0])
            del history[:-10]
            return result

        control.cmd, control.read_reply = traced_cmd, traced_read
        try:
            while not stop.is_set():
                action = rng.choice(["NOOP", "PWD", "CWD", "LIST", "STOR", "RETR", "SIZE", "MKD", "DELE"])
                started = time.monotonic()
                try:
                    if action in ("NOOP", "PWD"):
                        code, _ = control.cmd(action)
                        record(action, started, code in (200, 257), str(code), history)
                    elif action == "CWD":
                        code, _ = control.cmd("CWD /")
                        record(action, started, code == 250, str(code), history)
                    elif action == "LIST":
                        code, _ = control.download("LIST", control.pasv())
                        record(action, started, code == 226, str(code), history)
                    elif action == "STOR":
                        code = control.upload("STOR " + mine + str(rng.randrange(5)), control.pasv(), os.urandom(rng.choice([100, 5000, 200000])))
                        record(action, started, code == 226, str(code), history)
                    elif action == "RETR":
                        code, _ = control.download("RETR " + mine + str(rng.randrange(5)), control.pasv())
                        record(action, started, code in (226, 550), str(code), history)
                    elif action == "SIZE":
                        code, _ = control.cmd("SIZE " + mine + str(rng.randrange(5)))
                        record(action, started, code in (213, 550), str(code), history)
                    elif action == "MKD":
                        code, _ = control.cmd("MKD " + mine + "d")
                        record(action, started, code in (257, 550), str(code), history)
                        control.cmd("RMD " + mine + "d")
                    else:
                        code, _ = control.cmd("DELE " + mine + str(rng.randrange(5)))
                        record(action, started, code in (250, 550), str(code), history)
                except Exception as error:
                    record(action, started, False, type(error).__name__, history)
                    return
        finally:
            control.close()

    threads = [threading.Thread(target=client, args=(n,)) for n in range(workers)]
    for t in threads:
        t.start()
    time.sleep(seconds)
    stop.set()
    for t in threads:
        t.join(timeout=60)
    work.samples = samples
    return operations[0], errors, latencies


def percentile(values, fraction):
    values = sorted(values)
    return values[min(len(values) - 1, int(len(values) * fraction))] if values else 0.0


def uploads(count, port, user, password):
    """count uploads of 2 MB at the same time: (finished, seconds)."""
    done = []
    lock = threading.Lock()

    def one(number):
        try:
            control = FtpControl(port, user, password, timeout=30)
            data = control.pasv()
            control.cmd("STOR load-%d.bin" % number)
            data.sendall(b"x" * (2 << 20))
            data.close()
            code, _ = control.read_reply()
            control.close()
            if code == 226:
                with lock:
                    done.append(number)
        except Exception:
            pass

    start = time.monotonic()
    threads = [threading.Thread(target=one, args=(n,)) for n in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=90)
    return len(done), time.monotonic() - start


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--steps", default="100,500,1000,2000,3000")
    parser.add_argument("--port", type=int, default=2160)
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--login", action="store_true")
    parser.add_argument("--transfers", type=int, default=0)
    parser.add_argument("--workers", type=int, default=0)
    parser.add_argument("--open-threads", type=int, default=32)
    parser.add_argument("--work-seconds", type=int, default=15)
    args = parser.parse_args()
    steps = [int(s) for s in args.steps.split(",")]

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    wanted = max(steps) * 2 + 500
    if soft < wanted:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (min(wanted, hard), hard))
        except (ValueError, OSError):
            pass
    print("descriptors of the client: %d, TLS %s, login %s" % (resource.getrlimit(resource.RLIMIT_NOFILE)[0], args.tls, args.login))

    top = max(steps) + args.workers + 300
    server = UFTPTestServer(port=args.port, idle_timeout=3600, max_connections=top, max_per_ip=top,
                            extra_config={"MAXIMUM_LOG_FILES": 1, "MAX_CONNECTION_TRY_PER_IP": 0,
                                          "MAX_CONNECTION_RATE_PER_IP": 0, "LOGIN_TIMEOUT": 0,
                                          "RANDOM_PORT_START": 20000, "RANDOM_PORT_END": 60000})
    server.start()
    if args.tls and not server.tls_available:
        print("TLS is not available in this build")
        server.stop()
        return 2
    pid = server_pid(server)
    base = process_info(pid)
    print("server pid %d at rest: %.1f MB, %d threads, %d descriptors" % (pid, base["rss"], base["threads"], base["fds"]))
    print("%6s %6s %7s %8s %8s %7s %7s %9s %9s %7s" % (
        "step", "open", "failed", "open s", "RSS MB", "KB/conn", "fds", "NOOP ms", "worst ms", "idle CPU"))

    held = []
    failed_total = 0
    exit_code = 0
    passed = 0
    try:
        for step in steps:
            failed = 0
            start = time.monotonic()
            # the connections are opened by several threads at once, as many clients would
            first_new = len(held)
            results = {}

            def opener(number):
                try:
                    results[number] = open_connection(number, args.port, args.tls, args.login, server.user, server.password)
                except Exception as error:
                    results[number] = error

            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=args.open_threads) as pool:
                list(pool.map(opener, range(first_new, step)))
            for number in range(first_new, step):
                outcome = results.get(number)
                if isinstance(outcome, Exception) or outcome is None:
                    failed += 1
                    if failed == 1:
                        print("   first failure at connection %d: %s" % (number, outcome))
                else:
                    held.append(outcome)
            failed_total += failed
            opened_in = time.monotonic() - start
            if server.process.poll() is not None:
                print("THE SERVER DIED at step %d (exit status %s)" % (step, server.process.poll()))
                tail = server.read_log()[-2500:]
                print("--- the end of the log of the server ---\n" + tail)
                exit_code = 1
                break
            time.sleep(1)
            cpu_before = process_info(pid)["cpu"]
            time.sleep(5)
            info = process_info(pid)
            idle_cpu = (info["cpu"] - cpu_before) / 5 * 100
            median, worst, problem = latency(args.port, server.user, server.password)
            per_connection = (info["rss"] - base["rss"]) * 1024 / max(1, len(held))
            print("%6d %6d %7d %8.1f %8.1f %7.1f %7d %9s %9s %6.1f%%  %s" % (
                step, len(held), failed, opened_in, info["rss"], per_connection, info["fds"],
                "-" if median is None else "%.1f" % median, "-" if worst is None else "%.1f" % worst, idle_cpu, problem))
            sys.stdout.flush()
            step_ok = failed <= step * 0.01 and median is not None
            if args.workers:
                cpu_start = process_info(pid)["cpu"]
                started = time.monotonic()
                done, errors, latencies = work(args.workers, args.work_seconds, args.port, server.user, server.password, args.tls)
                seconds = time.monotonic() - started
                after = process_info(pid)
                every = [v for values in latencies.values() for v in values]
                p95 = percentile(every, 0.95)
                error_count = sum(errors.values())
                alive = server.process.poll() is None
                print("       work: %d operations in %.0f s (%.0f/s), %d errors, latency p50 %.1f ms p95 %.1f ms max %.1f ms, "
                      "server CPU %.0f%%, %.1f MB, %d threads%s" % (
                          done, seconds, done / seconds, error_count, percentile(every, 0.5), p95, max(every or [0]),
                          (after["cpu"] - cpu_start) / seconds * 100, after["rss"], after["threads"], "" if alive else "  SERVER DIED"))
                for why, count in sorted(errors.items(), key=lambda item: -item[1])[:4]:
                    print("         %5d x %s" % (count, why))
                for name, why, history in getattr(work, "samples", []):
                    print("         example, %s %s: %s" % (name, why, " | ".join(history)))
                step_ok = step_ok and alive and done > 0 and error_count <= done * 0.01 and p95 < 2000
            print("       step %d: %s" % (step, "PASSED" if step_ok else "FAILED"))
            if step_ok:
                passed = step
            else:
                exit_code = 1
                break
        if args.transfers and exit_code == 0:
            finished, seconds = uploads(args.transfers, args.port, server.user, server.password)
            info = process_info(pid)
            print("%d uploads at the same time with %d connections open: %d finished in %.1f s, server %.1f MB, %d threads at the end"
                  % (args.transfers, len(held), finished, seconds, info["rss"], info["threads"]))
        print("largest step that passed: %d connections" % passed)
        log = server.read_log() if hasattr(server, "read_log") else ""
        if "AddressSanitizer" in log or "runtime error" in log:
            print("A SANITIZER REPORT is in the log of the server")
            exit_code = 1
    finally:
        for sock in held:
            try:
                sock.close()
            except OSError:
                pass
        server.stop()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
