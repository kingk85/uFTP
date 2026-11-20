#!/usr/bin/env python3
"""Random FTP commands against a throw-away uFTP, to find crashes and memory errors.

Not part of run_tests.sh (it runs for as long as it is told). The useful run is on a build with
AddressSanitizer, which turns an out-of-bounds access or a use after free into a report:

  make OPTIMIZATION="-O1 -g -fsanitize=address" \\
       LIBS="-lpthread -lssl -lcrypto -fsanitize=address" ENABLE_OPENSSL_SUPPORT="-D OPENSSL_ENABLED"
  ASAN_OPTIONS=detect_leaks=0 UFTP_BIN=build/uFTP python3 test/fuzz_commands.py --seconds 600

Every session opens a connection (clear text or TLS), logs in most of the time, sends random lines
(random commands, random arguments, cut in pieces or sent together) and sometimes opens a data
connection. After every session the server must still be alive and must not have written a sanitizer
report. On a failure the commands of the last sessions are saved in fuzz-failure-<seed>.txt and the
run can be repeated with --seed.

Several workers run at the same time (--threads, default 4), on the same files:
  * random workers: random commands with random arguments, as above;
  * chaos workers: STOR, APPE, DELE, RNFR/RNTO, MKD, RMD, SIZE, MDTM, RETR, LIST, CWD, SITE CHMOD on a small
    set of names, so that sessions meet each other (a file removed while another session asks its size);
  * a local thread that, from outside, creates, removes, renames, truncates and takes the permissions away
    from the same files (what another process, or a user with another session, would do).
That is the kind of failure that one session alone does not find (SIZE of a file that disappears).

  --seconds N   how long to run (default 60)      --seed N   to repeat a run (the threads make a run
  --port N      control port (default 2150)                  only approximately repeatable)
  --no-tls      do not use TLS                    --threads N   workers (default 4)
"""

import argparse
import os
import random
import socket
import ssl
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from uftp_test_server import UFTPTestServer, HOST  # noqa: E402
from ftp_test_client import tls_client_context, empty_directory  # noqa: E402

COMMANDS = ["USER", "PASS", "ACCT", "CWD", "CDUP", "XCUP", "PWD", "XPWD", "MKD", "XMKD", "RMD", "XRMD",
            "DELE", "RNFR", "RNTO", "SIZE", "MDTM", "TYPE", "STRU", "MODE", "PASV", "EPSV", "PORT", "EPRT",
            "REST", "RETR", "STOR", "APPE", "LIST", "NLST", "STAT", "ABOR", "NOOP", "SYST", "FEAT", "HELP",
            "OPTS", "ALLO", "SITE", "AUTH", "PBSZ", "PROT", "CCC", "QUIT", "REIN", "STOU", "SMNT", "MLSD"]
SHAPES = ["short", "path", "long", "bytes", "number", "format", "traversal", "deep", "empty", "name", "port"]
LENGTHS = [100, 255, 256, 1000, 1023, 1024, 1025, 2047, 2048, 4095, 4096, 4097, 8000]
NAMES = ["a.txt", "dir", "dir/inner.txt", "link", "dangling", "big.bin", "deep", "ünï.txt"]
POOL = ["c1", "c2", "c3", "cd", "cd/c1", "cd/c2"]
CHAOS = ["STOR {a}", "APPE {a}", "DELE {a}", "RNFR {a}", "RNTO {b}", "MKD {a}", "RMD {a}", "SIZE {a}", "MDTM {a}",
         "RETR {a}", "LIST {a}", "NLST {a}", "CWD {a}", "CDUP", "SITE CHMOD 644 {a}", "SITE CHMOD 000 {a}",
         "STAT {a}", "REST 3", "TYPE I", "PWD"]


def junk(rng, names):
    shape = rng.choice(SHAPES)
    if shape == "short":
        return "".join(rng.choice("abcXYZ019 ._-/") for _ in range(rng.randint(1, 12)))
    if shape == "path":
        parts = [rng.choice(names + ["..", ".", "", "a", "b"]) for _ in range(rng.randint(1, 8))]
        return rng.choice(["", "/", "//", "./"]) + "/".join(parts)
    if shape == "long":
        return rng.choice("aA/.%") * rng.choice(LENGTHS)
    if shape == "bytes":
        return bytes(rng.choice([b for b in range(1, 256) if b not in (10, 13)]) for _ in range(rng.randint(1, 60))).decode("latin-1")
    if shape == "number":
        return rng.choice(["-1", "0", "1", "65535", "65536", "2147483647", "2147483648", "9223372036854775807",
                           "99999999999999999999", "0x41", "1e9", "+5", "007", "-0"])
    if shape == "format":
        return rng.choice(["%s%s%s%s", "%n%n", "%x.%x.%x", "%99999999d", "{}{}", "$(id)", "`id`", "%00"])
    if shape == "traversal":
        return rng.choice(["../" * rng.randint(1, 30) + "etc/passwd", "/..", "/../..", "....//", "..\\..",
                           "a/../../..", "/etc/passwd", "~root", "//" * 40])
    if shape == "deep":
        return "a/" * rng.randint(20, 1500)
    if shape == "name":
        return rng.choice(names)
    if shape == "port":
        return "%s,%d,%d,%d,%d,%d" % (rng.choice(["127,0,0,1", "1,2,3,4", "255,255,255,255", "0,0,0,0", "127,0,0"]),
                                       *(rng.randint(-1, 300) for _ in range(4)))
    return ""


def make_line(rng, names, chaos=False):
    if chaos:
        return rng.choice(CHAOS).format(a=rng.choice(POOL), b=rng.choice(POOL))
    command = rng.choice(COMMANDS)
    if command == "EPRT":
        delimiter = rng.choice("|!#,.:")
        argument = delimiter.join(["", rng.choice(["1", "2", "3", "x", ""]),
                                   rng.choice(["127.0.0.1", "::1", "::ffff:1.2.3.4", "999.1.1.1", "a" * 300, ""]),
                                   str(rng.choice([0, 80, 1024, 2049, 65535, 99999, -1])), ""])
    elif command in ("USER", "PASS") and rng.random() < 0.5:
        argument = rng.choice(["username", "password", "tester2", "Tester2Password"])
    else:
        argument = " ".join(junk(rng, names) for _ in range(rng.choice([0, 1, 1, 1, 2, 3])))
    separator = rng.choice([" ", " ", " ", "  ", "\t", ""])
    return (command if rng.random() > 0.05 else command.lower()) + (separator + argument if argument else "")


class Session:
    def __init__(self, rng, port, use_tls, names, chaos=False):
        self.rng, self.port, self.names, self.chaos = rng, port, names, chaos
        self.use_tls = use_tls
        self.log = []                       # what was sent, for the failure report
        self.sock = socket.create_connection((HOST, port), timeout=5)
        self.sock.settimeout(1)
        self.tls = False
        self.read(first=True)
        self.sock.settimeout(0.05)

    def read(self, first=False):
        data = b""
        try:
            while True:
                chunk = self.sock.recv(65536)
                if not chunk:
                    break
                data += chunk
                if first or len(data) > 1_000_000:
                    break
        except (socket.timeout, ssl.SSLError, OSError):
            pass
        return data

    def send(self, data):
        self.log.append(data)
        try:
            self.sock.sendall(data)
        except (OSError, ssl.SSLError):
            return False
        return True

    def command(self, line):
        return self.send(line.encode("latin-1", "replace") + self.rng.choice([b"\r\n", b"\r\n", b"\r\n", b"\n"]))

    def start_tls(self):
        self.send(b"AUTH TLS\r\n")
        if b"234" in self.read():
            try:
                self.sock.settimeout(3)
                self.sock = tls_client_context().wrap_socket(self.sock, server_hostname=HOST)
                self.sock.settimeout(0.05)
                self.tls = True
            except (OSError, ssl.SSLError):
                pass

    def login(self):
        self.command("USER username")
        self.read()
        self.command("PASS password")
        self.read()

    def data_connection(self):
        """PASV or EPSV, then a transfer command, then random bytes in or out of the data connection."""
        self.command(self.rng.choice(["PASV", "EPSV"]))
        reply = self.read().decode("latin-1")
        port = None
        if "(|||" in reply:
            port = int(reply.split("(|||")[1].split("|")[0])
        elif "(" in reply and "," in reply:
            numbers = reply.split("(")[1].split(")")[0].split(",")
            if len(numbers) == 6:
                port = int(numbers[4]) * 256 + int(numbers[5])
        if port is None:
            return
        try:
            data = socket.create_connection((HOST, port), timeout=2)
        except OSError:
            return
        data.settimeout(0.1)
        if self.use_tls and self.tls and self.rng.random() < 0.5:
            self.command("PBSZ 0")
            self.read()
            self.command("PROT P")
            self.read()
            try:
                data = tls_client_context().wrap_socket(data, server_hostname=HOST)
            except (OSError, ssl.SSLError):
                data.close()
                return
        self.command(self.rng.choice(["LIST", "NLST", "RETR ", "STOR ", "APPE ", "LIST ", "STAT "]) +
                     self.rng.choice(self.names + ([junk(self.rng, self.names)] if not self.chaos else [])))
        try:
            if self.rng.random() < 0.5:
                data.sendall(os.urandom(self.rng.choice([0, 1, 100, 5000, 70000])))
            else:
                data.recv(65536)
        except (OSError, ssl.SSLError):
            pass
        if self.rng.random() < 0.7:
            data.close()
        self.read()

    def run(self, lines):
        if self.use_tls and self.rng.random() < 0.6:
            self.start_tls()
        if self.rng.random() < 0.85:
            self.login()
        pending = []
        for _ in range(lines):
            roll = self.rng.random()
            if roll < 0.08:
                self.data_connection()
            elif roll < 0.18:
                pending.append(make_line(self.rng, self.names, self.chaos))     # pipelined: sent together
            else:
                if pending:
                    self.send(b"".join(p.encode("latin-1", "replace") + b"\r\n" for p in pending))
                    pending = []
                line = make_line(self.rng, self.names, self.chaos).encode("latin-1", "replace") + b"\r\n"
                if self.rng.random() < 0.15 and len(line) > 3:       # cut in two, with a pause
                    cut = self.rng.randint(1, len(line) - 1)
                    self.send(line[:cut])
                    time.sleep(0.02)
                    self.send(line[cut:])
                else:
                    self.send(line)
            self.read()
            if self.rng.random() < 0.02:                              # vanishes in the middle
                break
        if pending:
            self.send(b"".join(p.encode("latin-1", "replace") + b"\r\n" for p in pending))
        self.read()
        if self.rng.random() < 0.5:
            self.send(b"QUIT\r\n")
        try:
            self.sock.close()
        except OSError:
            pass


def prepare_home(home):
    os.makedirs(os.path.join(home, "dir"), exist_ok=True)
    for name, size in (("a.txt", 10), ("dir/inner.txt", 100), ("big.bin", 300000), ("ünï.txt", 5)):
        with open(os.path.join(home, name), "wb") as f:
            f.write(os.urandom(size))
    for name, target in (("link", "a.txt"), ("dangling", "/nonexistent/target")):
        try:
            os.symlink(target, os.path.join(home, name))
        except FileExistsError:
            pass
    deep = os.path.join(home, "deep")
    os.makedirs(deep, exist_ok=True)


def alive(server, port):
    if server.process.poll() is not None:
        return False
    try:
        with socket.create_connection((HOST, port), timeout=5) as s:
            return s.recv(100).startswith(b"220")
    except OSError:
        return False


def sanitizer_report(server):
    log = server.read_log()
    for marker in ("AddressSanitizer", "runtime error:", "Segmentation fault", "LeakSanitizer: detected"):
        if marker in log:
            return marker
    return None


def local_chaos(stop, home, rng):
    """What another process does in the home of the user, all the time, on the names that the chaos
    sessions use: create, write, remove, rename, truncate, make unreadable and readable again."""
    names = [os.path.join(home, n) for n in POOL]
    while not stop.is_set():
        path = rng.choice(names)
        other = rng.choice(names)
        try:
            action = rng.randrange(8)
            if action == 0:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o666)
                os.write(fd, os.urandom(rng.choice([0, 10, 5000])))
                os.close(fd)
            elif action == 1:
                os.unlink(path)
            elif action == 2:
                os.rename(path, other)
            elif action == 3:
                os.truncate(path, rng.choice([0, 3, 100000]))
            elif action == 4:
                os.chmod(path, 0)
            elif action == 5:
                os.chmod(path, 0o666)
            elif action == 6:
                os.mkdir(path)
            else:
                os.rmdir(path)
        except OSError:
            pass


def worker(index, seed, port, use_tls, stop, recent, counter):
    rng = random.Random(seed)
    chaos = index % 2 == 1
    while not stop.is_set():
        session = Session(rng, port, use_tls, POOL if chaos else NAMES, chaos)
        try:
            session.run(rng.randint(1, 40))
        except Exception as error:                                # the fuzzer itself must not stop
            session.log.append(("fuzzer exception: %r" % error).encode())
        recent[index] = (recent.get(index, []) + [session.log])[-6:]
        counter[index] = counter.get(index, 0) + 1


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--port", type=int, default=2150)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--no-tls", action="store_true")
    args = parser.parse_args()

    seed = args.seed if args.seed is not None else random.randrange(1 << 30)
    print("seed", seed, "seconds", args.seconds, "threads", args.threads, "TLS", not args.no_tls)

    server = UFTPTestServer(port=args.port, idle_timeout=60, max_connections=50, max_per_ip=50,
                            extra_config={"MAXIMUM_LOG_FILES": 1, "MAX_CONNECTION_TRY_PER_IP": 0})
    server.start()
    use_tls = server.tls_available and not args.no_tls
    stop = threading.Event()
    recent, counter = {}, {}
    failure = None
    threads = []
    try:
        prepare_home(server.home)
        for index in range(args.threads):
            threads.append(threading.Thread(target=worker, args=(index, seed + index, args.port, use_tls, stop, recent, counter)))
        threads.append(threading.Thread(target=local_chaos, args=(stop, server.home, random.Random(seed + 99))))
        for t in threads:
            t.start()
        deadline = time.monotonic() + args.seconds
        while time.monotonic() < deadline and failure is None:
            time.sleep(1)
            if not alive(server, args.port):
                failure = "the server stopped answering or died (exit status %s)" % server.process.poll()
            elif sanitizer_report(server):
                failure = "a sanitizer report in the log: " + sanitizer_report(server)
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=20)
    sessions = sum(counter.values())
    try:
        if failure is None:
            print("%d sessions (%s), the server is alive and the log has no sanitizer report"
                  % (sessions, ", ".join("%d:%d" % (i, n) for i, n in sorted(counter.items()))))
            return 0
        report = "fuzz-failure-%d.txt" % seed
        with open(report, "wb") as f:
            f.write(("%s\nseed %d, %d sessions\n\n--- log of the server ---\n%s\n--- the last sessions of every worker ---\n"
                     % (failure, seed, sessions, server.read_log()[-6000:])).encode("latin-1", "replace"))
            for index, logs in sorted(recent.items()):
                for number, log in enumerate(logs):
                    f.write(("\n=== worker %d, session -%d\n" % (index, len(logs) - number - 1)).encode())
                    for piece in log:
                        f.write(piece if isinstance(piece, bytes) else repr(piece).encode())
        print("FAILURE:", failure, "- saved in", report)
        return 1
    finally:
        server.stop()


if __name__ == "__main__":
    sys.exit(main())
