"""
Resilience / regression tests for uFTP (denial-of-service class bugs).

These tests start their own throw-away uFTP instance (see uftp_test_server.py)
with a short idle timeout, so they can run as an unprivileged user and never
interfere with a real server.

Normally run through test/run_tests.sh. Standalone:
  python3 test/test_server_resilience.py -v

Requirements: uFTP built with OpenSSL support for the TLS test, the `openssl`
CLI, Linux (/proc is used to measure CPU usage).

Environment overrides:
  UFTP_BIN                 path to the uFTP binary (default: ../build/uFTP)
  UFTP_RESILIENCE_PORT     control port to use      (default: 2122)
"""

import os
import resource
import shutil
import re
import signal
import socket
import ssl
import stat
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from uftp_test_server import UFTPTestServer, HOST, DEFAULT_BIN  # noqa: E402
from ftp_test_client import listening_socket, FtpControl, port_argument, tls_client_context  # noqa: E402


def _server_binary_text():
    """The bytes of the server binary (when UFTP_BIN is a wrapper script, those of the binary it starts)."""
    try:
        with open(DEFAULT_BIN, "rb") as f:
            data = f.read()
        if data.startswith(b"#!"):
            for word in data.split():
                if word.endswith(b"/uFTP") and os.path.isfile(word):
                    with open(word, "rb") as f:
                        return f.read()
        return data
    except OSError:
        return b""


def sanitizer_factor():
    """Slowdown allowed for the timing thresholds: 1 for a normal build, more when the binary is built with a sanitizer
    (AddressSanitizer, UBSan and ThreadSanitizer make the server several times slower)."""
    data = _server_binary_text()
    if b"__tsan_init" in data:
        return 12            # ThreadSanitizer is the slowest: a listing of 100,000 files takes about 105 s (1.2 s normally)
    return 6 if (b"__asan_init" in data or b"__ubsan_handle" in data) else 1


def built_with_tsan():
    """ThreadSanitizer exits with 66 after reporting the (benign) races it found."""
    return b"__tsan_init" in _server_binary_text()


PORT = int(os.environ.get("UFTP_RESILIENCE_PORT", "2122"))
IDLE_TIMEOUT = 3          # seconds, short on purpose


def process_group_stat(pgid):
    """{pid: fields of /proc/<pid>/stat after the command name} of the processes in the group."""
    processes = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat") as f:
                # The command name may contain spaces: split after the closing ')'
                fields = f.read().rsplit(")", 1)[1].split()
        except OSError:
            continue  # process exited meanwhile
        if int(fields[2]) == pgid:                       # pgrp
            processes[int(entry)] = fields
    return processes


def process_group_cpu_seconds(pgid):
    """User+system CPU time consumed so far by every process in the group."""
    ticks = sum(int(fields[11]) + int(fields[12])        # utime + stime
                for fields in process_group_stat(pgid).values())
    return ticks / os.sysconf("SC_CLK_TCK")


def process_group_members(pgid):
    """Pids of the processes that belong to the group, zombies excluded."""
    return sorted(pid for pid, fields in process_group_stat(pgid).items() if fields[0] != "Z")


def recv_line(sock, timeout=5):
    sock.settimeout(timeout)
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(1024)
        if not chunk:
            break
        data += chunk
    return data.decode(errors="replace")


def open_control(timeout=5):
    sock = socket.create_connection((HOST, PORT), timeout=timeout)
    banner = recv_line(sock)
    assert banner.startswith("220"), f"unexpected banner: {banner!r}"
    return sock


def send_cmd(sock, cmd):
    sock.sendall(cmd.encode() + b"\r\n")
    return recv_line(sock)


def wait_closed_by_server(sock, deadline):
    """Return True if the server closes `sock` before `deadline` (time.monotonic)."""
    while time.monotonic() < deadline:
        sock.settimeout(max(0.1, deadline - time.monotonic()))
        try:
            data = sock.recv(1024)
        except socket.timeout:
            return False
        except (ConnectionResetError, BrokenPipeError):
            return True
        if data == b"":
            return True
        # Ignore any data (e.g. a timeout message) and keep waiting for EOF
    return False


class RespawnProcessTests(unittest.TestCase):
    """RESPAWN_PROCESS: the supervisor parent that restarts the server if it dies."""

    def start(self, respawn):
        """respawn: the value of RESPAWN_PROCESS, None = parameter not in the configuration"""
        server = UFTPTestServer(port=PORT, idle_timeout=60, extra_config={"RESPAWN_PROCESS": respawn})
        try:
            server.start()
        except FileNotFoundError as e:
            raise unittest.SkipTest(str(e))
        self.addCleanup(server.stop)
        return server

    def test_respawn_false_runs_a_single_process(self):
        server = self.start("false")
        self.assertEqual(process_group_members(server.pgid), [server.pgid])

    def test_respawn_true_runs_supervisor_and_server(self):
        server = self.start("true")
        self.assertEqual(len(process_group_members(server.pgid)), 2)

    def test_respawn_is_the_default(self):
        server = self.start(None)
        self.assertEqual(len(process_group_members(server.pgid)), 2)

    def test_supervisor_restarts_a_dead_server(self):
        server = self.start("true")
        child = [pid for pid in process_group_members(server.pgid) if pid != server.pgid]
        self.assertEqual(len(child), 1)
        os.kill(child[0], signal.SIGKILL)

        deadline = time.monotonic() + 8
        banner = ""
        while time.monotonic() < deadline and not banner.startswith("220"):
            time.sleep(0.3)
            try:
                with socket.create_connection((HOST, PORT), timeout=1) as sock:
                    banner = recv_line(sock, timeout=1)
            except OSError:
                pass
        self.assertTrue(banner.startswith("220"), "the supervisor did not restart the server")
        new_child = [pid for pid in process_group_members(server.pgid) if pid != server.pgid]
        self.assertEqual(len(new_child), 1)
        self.assertNotEqual(new_child, child)


LOGIN_TIMEOUT = 3          # seconds, for LoginTimeoutTests


def read_until_closed(sock, deadline):
    """Everything the server sends until it closes the connection, or None if it is
    still open at the deadline."""
    data = b""
    while time.monotonic() < deadline:
        sock.settimeout(max(0.1, deadline - time.monotonic()))
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            return None
        except (ConnectionResetError, BrokenPipeError):
            return data
        if not chunk:
            return data
        data += chunk
    return None


class LoginTimeoutTests(unittest.TestCase):
    """LOGIN_TIMEOUT: a client that does not complete the login is disconnected (421),
    whatever it sends meanwhile. It used to hold a slot until IDLE_MAX_TIMEOUT
    (3600 s by default), and NOOP every few seconds kept it forever."""

    def start(self, login_timeout=LOGIN_TIMEOUT):
        server = UFTPTestServer(port=PORT, idle_timeout=60,
                                extra_config={"LOGIN_TIMEOUT": login_timeout})
        try:
            server.start()
        except FileNotFoundError as e:
            raise unittest.SkipTest(str(e))
        self.addCleanup(server.stop)
        return server

    def test_client_that_never_logs_in_is_disconnected(self):
        self.start()
        sock = open_control()
        self.addCleanup(sock.close)
        # with no other traffic select() wakes up every 10 s: allow for it
        data = read_until_closed(sock, time.monotonic() + LOGIN_TIMEOUT + 12)
        self.assertIsNotNone(data, "client never disconnected")
        self.assertIn(b"421", data)

    def keep_sending(self, sock, line, seconds):
        """Send line every 0.5 s; returns the elapsed time when the server closes, or None."""
        start = time.monotonic()
        while time.monotonic() - start < seconds:
            try:
                sock.sendall(line + b"\r\n")
            except (BrokenPipeError, ConnectionResetError):
                return time.monotonic() - start
            if read_until_closed(sock, time.monotonic() + 0.5) is not None:
                return time.monotonic() - start
        return None

    def test_noop_does_not_extend_the_login_time(self):
        self.start()
        sock = open_control()
        self.addCleanup(sock.close)
        elapsed = self.keep_sending(sock, b"NOOP", LOGIN_TIMEOUT + 6)
        self.assertIsNotNone(elapsed, "NOOP kept a not logged in client connected")

    def test_repeated_user_does_not_extend_the_login_time(self):
        server = self.start()
        sock = open_control()
        self.addCleanup(sock.close)
        elapsed = self.keep_sending(sock, b"USER " + server.user.encode(), LOGIN_TIMEOUT + 6)
        self.assertIsNotNone(elapsed, "repeating USER kept the client connected")

    def test_logged_in_client_is_not_affected(self):
        server = self.start()
        sock = open_control()
        self.addCleanup(sock.close)
        self.assertTrue(send_cmd(sock, f"USER {server.user}").startswith("331"))
        self.assertTrue(send_cmd(sock, f"PASS {server.password}").startswith("230"))
        deadline = time.monotonic() + LOGIN_TIMEOUT + 3
        while time.monotonic() < deadline:
            self.assertTrue(send_cmd(sock, "NOOP").startswith("200"))
            time.sleep(0.5)
        self.assertTrue(send_cmd(sock, "PWD").startswith("257"))

    def test_auth_after_login_restarts_the_login_time(self):
        """A user logged in for longer than LOGIN_TIMEOUT who then does AUTH TLS (which
        logs it out) gets a fresh LOGIN_TIMEOUT to log in again, not an immediate close."""
        server = self.start()
        sock = open_control()
        self.assertTrue(send_cmd(sock, f"USER {server.user}").startswith("331"))
        self.assertTrue(send_cmd(sock, f"PASS {server.password}").startswith("230"))
        deadline = time.monotonic() + LOGIN_TIMEOUT + 2
        while time.monotonic() < deadline:
            send_cmd(sock, "NOOP")
            time.sleep(0.5)
        reply = send_cmd(sock, "AUTH TLS")
        if not reply.startswith("234"):
            sock.close()
            self.skipTest("server built without TLS support")
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        tls = context.wrap_socket(sock)
        self.addCleanup(tls.close)
        time.sleep(1.5)                                   # a few timeout checks
        tls.sendall(f"USER {server.user}\r\n".encode())
        self.assertTrue(recv_line(tls).startswith("331"))
        tls.sendall(f"PASS {server.password}\r\n".encode())
        self.assertTrue(recv_line(tls).startswith("230"))

    def test_login_timeout_zero_disables_the_limit(self):
        self.start(login_timeout=0)
        sock = open_control()
        self.addCleanup(sock.close)
        self.assertIsNone(read_until_closed(sock, time.monotonic() + LOGIN_TIMEOUT + 3),
                          "LOGIN_TIMEOUT = 0 must not disconnect")
        self.assertTrue(send_cmd(sock, "NOOP").startswith("200"))   # still connected (NOOP allowed before login)


UNKNOWN_OWNER_SHIM = r"""
/* Makes every file look owned by a user and a group that the system does not know:
   glibc then returns 0 with a null result, as for a uid missing from /etc/passwd. */
#include <pwd.h>
#include <grp.h>
#include <stddef.h>
int getpwuid_r(uid_t uid, struct passwd *pwd, char *buf, size_t len, struct passwd **result)
{ (void)uid; (void)pwd; (void)buf; (void)len; *result = NULL; return 0; }
int getgrgid_r(gid_t gid, struct group *grp, char *buf, size_t len, struct group **result)
{ (void)gid; (void)grp; (void)buf; (void)len; *result = NULL; return 0; }
"""


class UnknownOwnerTests(unittest.TestCase):
    """LIST of a file whose owner is not a known user or group (containers, NFS,
    archives extracted with their owners) crashed the whole server (SIGSEGV)."""

    def setUp(self):
        compiler = shutil.which("cc") or shutil.which("gcc")
        if compiler is None:
            raise unittest.SkipTest("no C compiler to build the test library")
        build = tempfile.mkdtemp(prefix="uftp-shim-")
        self.addCleanup(shutil.rmtree, build, True)
        with open(os.path.join(build, "shim.c"), "w") as f:
            f.write(UNKNOWN_OWNER_SHIM)
        library = os.path.join(build, "shim.so")
        subprocess.run([compiler, "-shared", "-fPIC", "-o", library, os.path.join(build, "shim.c")], check=True)

        self.server = UFTPTestServer(port=PORT, idle_timeout=60)
        os.environ["LD_PRELOAD"] = library             # inherited by the server only
        try:
            self.server.start()
        except FileNotFoundError as e:
            raise unittest.SkipTest(str(e))
        finally:
            del os.environ["LD_PRELOAD"]
        self.addCleanup(self.server.stop)

    def test_list_shows_the_numeric_ids(self):
        with open(os.path.join(self.server.home, "file.txt"), "wb") as f:
            f.write(b"x")
        c = FtpControl(PORT, self.server.user, self.server.password)
        self.addCleanup(c.close)
        code, listing = c.download("LIST", c.pasv())
        self.assertEqual(code, 226)
        self.assertTrue(self.server.is_running(), "the server crashed")
        line = listing.decode().splitlines()[-1].split()
        self.assertEqual(line[2:4], [str(os.getuid()), str(os.getgid())], listing)
        self.assertEqual(line[-1], "file.txt")


ADDRESS_KEY_PROGRAM = r"""
#include <stdio.h>
#include "library/addressKey.h"

int main(int argc, char **argv)
{
    char key[INET6_ADDRSTRLEN];

    for (int i = 1; i < argc; i++)
    {
        addressKey(argv[i], key, sizeof(key));
        printf("%s\n", key);
    }
    return 0;
}
"""


class AddressKeyTests(unittest.TestCase):
    """Failed logins and new connections are counted per address; an IPv6 address is counted as its network (the
    first 64 bits): who has a network has 2^64 addresses and could use a new one for every
    attempt. A test with two real addresses of one network is not possible on this machine
    (loopback has only ::1), so the function that makes the key is tried directly."""

    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("cc") or shutil.which("gcc")
        if compiler is None:
            raise unittest.SkipTest("no C compiler to build the test program")
        cls.build = tempfile.mkdtemp(prefix="uftp-key-")
        source = os.path.join(cls.build, "key.c")
        with open(source, "w") as f:
            f.write(ADDRESS_KEY_PROGRAM)
        cls.program = os.path.join(cls.build, "key")
        root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
        subprocess.run([compiler, "-Wall", "-I", root, "-o", cls.program, source], check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.build, True)

    def keys(self, *addresses):
        output = subprocess.run([self.program, *addresses], capture_output=True, check=True).stdout.decode()
        return output.splitlines()

    def test_addresses_of_one_network_have_the_same_key(self):
        keys = self.keys("2001:db8:1:2::1", "2001:db8:1:2:aaaa:bbbb:cccc:dddd",
                         "2001:0DB8:0001:0002:0000:0000:0000:0001", "2001:db8:1:2:ffff:ffff:ffff:ffff")
        self.assertEqual(len(set(keys)), 1, keys)

    def test_another_network_has_another_key(self):
        a, b, c = self.keys("2001:db8:1:2::1", "2001:db8:1:3::1", "2001:db8:2:2::1")
        self.assertEqual(len({a, b, c}), 3)

    def test_loopback_addresses_are_one_network(self):
        keys = self.keys("::1", "::2", "::ffff:0:1")
        self.assertEqual(keys[0], keys[1])

    def test_ipv4_is_counted_as_it_is_also_when_it_arrives_on_an_ipv6_socket(self):
        self.assertEqual(self.keys("192.0.2.5", "::ffff:192.0.2.5", "::ffff:192.0.2.6"),
                         ["192.0.2.5", "::ffff:192.0.2.5", "::ffff:192.0.2.6"])

    def test_what_is_not_an_address_is_left_alone(self):
        self.assertEqual(self.keys("garbage", ""), ["garbage", ""])


class FreeSpaceTests(unittest.TestCase):
    """MIN_FREE_SPACE_MB: an upload must not fill the disk (the server runs as root and its
    reserved blocks are not safe from it). Below the limit STOR and APPE are refused (452), and an
    upload that is going on is stopped. The limit is set from the space that this machine has,
    so the tests do not fill anything: they only ask for more free space than there is."""

    def setUp(self):
        probe = tempfile.mkdtemp(prefix="uftp-space-")
        self.addCleanup(shutil.rmtree, probe, True)
        stat = os.statvfs(probe)
        self.available_mb = stat.f_bavail * stat.f_frsize // (1 << 20)
        if self.available_mb < 300:
            self.skipTest("less than 300 MB free on this machine")

    def server(self, minimum):
        server = UFTPTestServer(port=PORT, idle_timeout=60,
                                extra_config={"MAXIMUM_LOG_FILES": 1, "MIN_FREE_SPACE_MB": minimum})
        server.start()
        self.addCleanup(server.stop)
        c = FtpControl(PORT, server.user, server.password)
        self.addCleanup(c.close)
        return server, c

    def test_stor_and_appe_are_refused_when_the_free_space_is_below_the_limit(self):
        server, c = self.server(self.available_mb + 100)
        for command in ("STOR full.bin", "APPE full.bin"):
            data = c.pasv()
            self.addCleanup(data.close)
            code, text = c.cmd(command)
            self.assertEqual(code, 452, (command, text))
            self.assertIn("Insufficient storage space", text)
        self.assertFalse(os.path.exists(os.path.join(server.home, "full.bin")))
        self.assertEqual(c.cmd("NOOP")[0], 200)                  # the session goes on
        self.assertEqual(c.cmd("RETR nothing")[0], 550)          # and the other commands answer as always

    def test_the_refusal_is_in_the_log(self):
        server, c = self.server(self.available_mb + 100)
        data = c.pasv()
        self.addCleanup(data.close)
        self.assertEqual(c.cmd("STOR full.bin")[0], 452)
        deadline = time.monotonic() + 5
        log = ""
        while time.monotonic() < deadline and "MIN_FREE_SPACE_MB" not in log:
            time.sleep(0.2)
            log = server.log_folder_text()
        self.assertIn("STOR", log)
        self.assertIn("refused (452)", log)

    def test_below_the_limit_the_upload_is_stopped_and_the_client_is_told(self):
        margin = 25
        server, c = self.server(self.available_mb - margin)
        data = c.pasv()
        self.assertEqual(c.cmd("STOR growing.bin")[0], 150)
        sent = 0
        chunk = b"x" * (1 << 20)
        try:
            for _ in range(120):
                data.sendall(chunk)
                sent += 1
        except OSError:
            pass                                                # the server closed the connection
        data.close()
        code, text = c.read_reply()
        self.assertEqual(code, 452, text)
        stored = os.path.getsize(os.path.join(server.home, "growing.bin")) >> 20
        self.assertLess(stored, margin + 25, "the upload was not stopped: %d MB" % stored)
        self.assertGreater(stored, 0)
        self.assertEqual(c.cmd("NOOP")[0], 200)

    def test_with_enough_space_the_upload_goes_on_as_always(self):
        server, c = self.server(1)
        self.assertEqual(c.upload("STOR fine.bin", c.pasv(), b"y" * 100000), 226)
        self.assertEqual(os.path.getsize(os.path.join(server.home, "fine.bin")), 100000)

    def test_without_the_parameter_nothing_is_checked(self):
        server = UFTPTestServer(port=PORT, idle_timeout=60)
        server.start()
        self.addCleanup(server.stop)
        c = FtpControl(PORT, server.user, server.password)
        self.addCleanup(c.close)
        self.assertEqual(c.upload("STOR fine.bin", c.pasv(), b"z" * 1000), 226)


class ReplyOrderTests(unittest.TestCase):
    """The reply 150 of a transfer must come before its final reply (226). The control thread woke the
    worker and then wrote the 150: a small transfer could finish first, and the worker wrote the 226
    before the 150 (found by test/load_test.py with 40 clients at the same time). The client then
    read the 226 as the answer of the command and every reply after it was one step late."""

    CLIENTS = 40
    TRANSFERS = 500
    USE_TLS = False

    def test_the_150_always_comes_before_the_226(self):
        server = UFTPTestServer(port=PORT, idle_timeout=120, max_connections=60, max_per_ip=60,
                                extra_config={"MAXIMUM_LOG_FILES": 0, "MAX_CONNECTION_TRY_PER_IP": 0, "RANDOM_PORT_START": 20000, "RANDOM_PORT_END": 60000})
        server.start()
        self.addCleanup(server.stop)
        if self.USE_TLS:
            probe = FtpControl(PORT, login=False, timeout=10)      # a build without OpenSSL answers 502
            code = probe.cmd("AUTH TLS")[0]
            probe.close()
            if code == 502:
                self.skipTest("uFTP was built without OpenSSL support")
        with open(os.path.join(server.home, "tiny.txt"), "wb") as f:
            f.write(b"x")
        wrong = []
        lock = threading.Lock()

        def client(number):
            try:
                c = FtpControl(PORT, server.user, server.password, login=not self.USE_TLS, timeout=20)
                if self.USE_TLS:
                    c.start_tls()                   # AUTH TLS clears the login: it comes after
                    c.cmd("PBSZ 0")
                    c.cmd("PROT C")
                    c.login(server.user, server.password)
                for round_ in range(self.TRANSFERS):
                    data = c.pasv()
                    command = ("RETR tiny.txt", "LIST", "STOR up%d" % number)[round_ % 3]
                    first = c.cmd(command)[0]
                    if first != 150:
                        with lock:
                            wrong.append((number, first))
                        data.close()
                        return                      # the replies are out of step: the session is no use
                    if command.startswith("STOR"):
                        data.sendall(b"y" * 100)
                    else:
                        while data.recv(100):
                            pass
                    data.close()
                    last = c.read_reply()[0]
                    if last != 226:
                        with lock:
                            wrong.append((number, last))
                        return
                c.close()
            except Exception as error:
                with lock:
                    wrong.append((number, repr(error)))

        threads = [threading.Thread(target=client, args=(n,)) for n in range(self.CLIENTS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)
        self.assertEqual(wrong, [], "replies out of order in %d of %d sessions" % (len(wrong), self.CLIENTS))


class ReplyOrderTlsTests(ReplyOrderTests):
    """The same with the control connection in TLS, where the worker is slower to run after it has
    written the 227: the client sent its command (STOR, RETR, LIST) before the flag "the data
    connection is ready" was set, and got 425 Use PORT or PASV first."""

    USE_TLS = True


class DataSocketLeakTests(unittest.TestCase):
    """A passive data worker is stopped (pthread_cancel) when a new PASV, QUIT or a closed connection arrives. The worker
    sat in a blocking accept() with cancellation enabled: when the cancel came just as accept() returned, the
    connection was accepted and the descriptor lost, a socket left in CLOSE-WAIT for ever (30 of them in a long run, one
    every few minutes under load). The accept is now done without cancellation after a poll() that holds nothing.
    The test provokes the race many times, from many clients, and counts the descriptors of the server."""

    CLIENTS = 30
    ROUNDS = 1200

    @staticmethod
    def descriptors(pid):
        return len(os.listdir("/proc/%d/fd" % pid))

    def run_clients(self, one_round, rounds):
        server = UFTPTestServer(port=PORT, idle_timeout=300, max_connections=60, max_per_ip=60,
                                extra_config={"MAXIMUM_LOG_FILES": 0, "MAX_CONNECTION_TRY_PER_IP": 0,
                                              "RANDOM_PORT_START": 20000, "RANDOM_PORT_END": 60000})
        server.start()
        self.addCleanup(server.stop)
        with open(os.path.join(server.home, "big.bin"), "wb") as f:
            f.write(b"b" * (8 << 20))
        time.sleep(1)
        base = self.descriptors(server.process.pid)
        problems = []
        lock = threading.Lock()

        def client(number):
            try:
                c = FtpControl(PORT, server.user, server.password, timeout=30)
                for _ in range(rounds):
                    one_round(c)
                c.close()
            except Exception as error:
                with lock:
                    problems.append(repr(error)[:80])

        threads = [threading.Thread(target=client, args=(n,)) for n in range(self.CLIENTS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=300)
        self.assertEqual(problems, [])
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and self.descriptors(server.process.pid) > base + 3:
            time.sleep(0.5)
        left = self.descriptors(server.process.pid)
        self.assertLessEqual(left, base + 3, "%d descriptors left open (%d at the start)" % (left, base))

    @staticmethod
    def until_227(c):
        """Read replies until the 227 of the PASV (the ones of the stopped commands come before it)."""
        for _ in range(6):
            if c.read_reply()[0] == 227:
                return
        raise AssertionError("no 227")

    def test_a_worker_stopped_while_accepting_does_not_keep_the_connection(self):
        def one_round(c):
            data = c.pasv()                 # the worker accepts this connection...
            c.send("PASV")                  # ...while this command stops it and starts another
            data.close()
            self.until_227(c)
        self.run_clients(one_round, self.ROUNDS)

    def test_a_worker_stopped_while_connecting_in_active_mode_does_not_keep_the_socket(self):
        def one_round(c):
            listener, port = listening_socket()
            c.send("PORT 127,0,0,1,%d,%d" % (port // 256, port % 256))
            c.send("PASV")                  # stops the worker that is connecting to the listener
            self.until_227(c)
            listener.close()
        self.run_clients(one_round, self.ROUNDS // 2)

    def test_a_download_stopped_half_way_does_not_keep_the_file_or_the_socket(self):
        def one_round(c):
            data = c.pasv()
            c.send("RETR big.bin")
            data.recv(65536)                # the transfer is going on...
            c.send("PASV")                  # ...and this stops it
            data.close()
            self.until_227(c)
        self.run_clients(one_round, self.ROUNDS // 4)


class ThreadLimitTests(unittest.TestCase):
    """When the system can not create another thread (the limit of processes of the user, or no memory), the
    server used to stop: exit(0) in startDataChannel, so one client that sent PASV dropped every session
    (with RESPAWN_PROCESS the supervisor started it again, with nobody connected). Now only that PASV is
    refused (425) and the others go on. The limit is set with ulimit -u in a wrapper around the binary."""

    @staticmethod
    def tasks_of_the_user():
        uid = os.getuid()
        total = 0
        for name in os.listdir("/proc"):
            if name.isdigit():
                try:
                    if os.stat("/proc/%s" % name).st_uid == uid:
                        total += len(os.listdir("/proc/%s/task" % name))
                except OSError:
                    pass
        return total

    def test_the_server_does_not_stop_when_it_can_not_create_a_thread(self):
        real = os.path.abspath(os.environ.get("UFTP_BIN", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "build", "uFTP")))
        folder = tempfile.mkdtemp(prefix="uftp-nproc-")
        self.addCleanup(shutil.rmtree, folder, True)
        wrapper = os.path.join(folder, "uftp-limited.sh")
        limit = self.tasks_of_the_user() + 120
        with open(wrapper, "w") as f:
            f.write("#!/bin/bash\nulimit -u %d || exit 99\nexec %s \"$@\"\n" % (limit, real))
        os.chmod(wrapper, 0o755)

        server = UFTPTestServer(port=PORT, idle_timeout=120, max_connections=400, max_per_ip=400, binary=wrapper,
                                extra_config={"MAXIMUM_LOG_FILES": 1, "MAX_CONNECTION_TRY_PER_IP": 0})
        server.start()
        self.addCleanup(server.stop)

        controls, results = [], []
        lock = threading.Lock()

        def client(number):
            try:
                c = FtpControl(PORT, server.user, server.password, timeout=30)
                code = c.cmd("PASV")[0]
                with lock:
                    controls.append(c)
                    results.append(code)
            except Exception as error:
                with lock:
                    results.append(repr(error)[:60])

        threads = [threading.Thread(target=client, args=(n,)) for n in range(300)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        self.assertIsNone(server.process.poll(), "the server stopped (exit status %s); replies: %s" % (
            server.process.poll(), sorted(set(map(str, results)))))
        self.assertGreater(results.count(227), 0)
        self.assertGreater(results.count(425), 0, "the limit was not reached: %s" % sorted(set(map(str, results))))
        self.assertEqual([r for r in results if r not in (227, 425)], [], "unexpected replies")
        for c in controls:                               # everybody goes away: the server is as at the start
            c.close()
        time.sleep(2)
        c = FtpControl(PORT, server.user, server.password, timeout=30)
        self.addCleanup(c.close)
        self.assertEqual(c.cmd("PASV")[0], 227)


class DescriptorLimitTests(unittest.TestCase):
    """select() can not watch a descriptor of 1024 or more: FD_SET wrote outside the sets and the
    server fell (SIGSEGV) at about the 1020th connection, with MAXIMUM_ALLOWED_FTP_CONNECTION above
    that (found by test/load_test.py). The connections that do not fit are refused and the server
    goes on."""

    def setUp(self):
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if hard != resource.RLIM_INFINITY and hard < 4096:
            self.skipTest("the limit of descriptors is below 4096")
        if soft < 4096:
            resource.setrlimit(resource.RLIMIT_NOFILE, (4096, hard))
            self.addCleanup(resource.setrlimit, resource.RLIMIT_NOFILE, (soft, hard))

    def connect(self, index):
        sock = socket.socket()
        sock.bind(("127.0.0.%d" % (2 + index // 500), 0))
        sock.settimeout(10)
        sock.connect(("127.0.0.1", PORT))
        self.addCleanup(sock.close)
        return sock

    def test_more_connections_than_select_can_watch_do_not_stop_the_server(self):
        server = UFTPTestServer(port=PORT, idle_timeout=600, max_connections=1300, max_per_ip=1300,
                                extra_config={"MAXIMUM_LOG_FILES": 1, "MAX_CONNECTION_TRY_PER_IP": 0,
                                              "MAX_CONNECTION_RATE_PER_IP": 0, "LOGIN_TIMEOUT": 0})
        server.start()
        self.addCleanup(server.stop)

        socks = []
        for index in range(1150):
            try:
                socks.append(self.connect(index))
            except OSError:
                pass
            self.assertIsNone(server.process.poll(), "the server died with %d connections" % len(socks))

        self.assertIsNone(server.process.poll(), "the server died")
        # the ones that fit are served, with the others the server must go on
        for sock in socks[:50]:
            sock.close()
        time.sleep(1)
        self.assertIsNone(server.process.poll(), "the server died after the connections (%s)" % server.read_log()[-300:])
        c = FtpControl(PORT, server.user, server.password, timeout=15)
        self.addCleanup(c.close)
        self.assertEqual(c.cmd("NOOP")[0], 200)
        self.assertNotIn("SIGSEGV", server.read_log())


class SizeRaceTests(unittest.TestCase):
    """SIZE of a file that is created and removed all the time (by another session of the user,
    or by anything else that works in the home). The file was checked and then opened, and a file
    that was gone in between made the server use a null pointer: SIGSEGV, every session lost."""

    SECONDS = 8

    def test_size_of_a_file_that_comes_and_goes_does_not_crash_the_server(self):
        server = UFTPTestServer(port=PORT, idle_timeout=60, extra_config={"MAXIMUM_LOG_FILES": 1})
        server.start()
        self.addCleanup(server.stop)
        path = os.path.join(server.home, "race.txt")
        stop = threading.Event()

        def flip():
            while not stop.is_set():
                try:
                    os.close(os.open(path, os.O_WRONLY | os.O_CREAT, 0o666))
                    os.unlink(path)
                except OSError:
                    pass

        flipper = threading.Thread(target=flip)
        flipper.start()
        self.addCleanup(flipper.join)
        self.addCleanup(stop.set)
        c = FtpControl(PORT, server.user, server.password)
        self.addCleanup(c.close)
        c.sock.settimeout(5)
        deadline = time.monotonic() + self.SECONDS
        try:
            while time.monotonic() < deadline and server.is_running():
                c.sock.sendall(b"SIZE race.txt\r\n" * 500)
                time.sleep(0.01)
                try:
                    c.sock.recv(1 << 20)
                except OSError:
                    pass
        except OSError:
            pass
        stop.set()
        self.assertTrue(server.is_running(), "the server crashed: " + server.log_folder_text()[-400:])


class LogTests(unittest.TestCase):
    """The log file can be filled by anybody (one line per refused connection, before
    any login), and a log file that can not be opened crashed the server."""

    def start(self, **extra):
        # one connection per address: every further connection is refused and logged
        server = UFTPTestServer(port=PORT, idle_timeout=60, max_per_ip=1,
                                extra_config=dict({"MAXIMUM_LOG_FILES": 1}, **extra))
        try:
            server.start()
        except FileNotFoundError as e:
            raise unittest.SkipTest(str(e))
        self.addCleanup(server.stop)
        return server

    def open_the_only_connection(self):
        """The one connection allowed per address. The server frees the slot of a closed
        connection (e.g. the probe made at startup) at its next loop, so retry briefly."""
        deadline = time.monotonic() + 3
        while True:
            sock = socket.create_connection((HOST, PORT), timeout=5)
            if recv_line(sock).startswith("220"):
                return sock
            sock.close()
            if time.monotonic() > deadline:
                self.fail("the server keeps refusing the first connection")
            time.sleep(0.2)

    def refuse_connections(self, count):
        holder = self.open_the_only_connection()
        try:
            for _ in range(count):
                sock = socket.create_connection((HOST, PORT), timeout=5)
                try:
                    self.assertTrue(recv_line(sock).startswith("530"))    # too many connections
                finally:
                    sock.close()
        finally:
            holder.close()

    def log_lines(self, server, text):
        time.sleep(1.5)                                # the log is written by its own thread
        lines = []
        folder = os.path.join(server.workdir, "log")
        for name in os.listdir(folder):
            if os.path.islink(os.path.join(folder, name)):      # uftpLog.current: the file of today again
                continue
            with open(os.path.join(folder, name), errors="replace") as f:
                lines += [line for line in f if text in line]
        return lines

    def test_repeated_message_is_written_once_and_counted(self):
        """200 identical lines: the first is written, the other 199 are counted. The
        count is written when the interval (10 s) is over, without waiting for the line
        to come back (it used to wait for it, and could be lost)."""
        server = self.start()
        self.refuse_connections(200)
        self.assertEqual(len(self.log_lines(server, "too many connection")), 1)

        deadline = time.monotonic() + 30             # interval 10 s, checked when the server wakes up
        while time.monotonic() < deadline:
            lines = self.log_lines(server, "too many connection")      # waits 1.5 s
            if len(lines) == 2:
                break
        self.assertEqual(len(lines), 2, lines)
        self.assertIn("(199 more times in the last 10 s, grouped)", lines[1])

    def test_log_folder_that_can_not_be_written(self):
        server = self.start(LOG_FOLDER="{workdir}/missing/")
        self.refuse_connections(3)
        self.assertTrue(server.is_running(), "the server crashed")
        sock = self.open_the_only_connection()
        try:
            self.assertTrue(send_cmd(sock, f"USER {server.user}").startswith("331"))
            self.assertTrue(send_cmd(sock, f"PASS {server.password}").startswith("230"))
        finally:
            sock.close()


class DiagnosticLogTests(unittest.TestCase):
    """Why the server stopped or restarted must be in the log: crashes, the supervisor,
    signals, a busy port, a broken TLS setup. None of these used to leave a line."""

    def make_server(self, **extra):
        server = UFTPTestServer(port=PORT, idle_timeout=60,
                                extra_config=dict({"MAXIMUM_LOG_FILES": 1}, **extra))
        self.addCleanup(server.stop)
        return server

    def start(self, **extra):
        server = self.make_server(**extra)
        try:
            server.start()
        except FileNotFoundError as e:
            raise unittest.SkipTest(str(e))
        return server

    def wait_for_log(self, server, text, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            log = server.log_folder_text()
            if text in log:
                return log
            time.sleep(0.2)
        self.fail(f"{text!r} not in the log:\n{server.log_folder_text()}")

    def reset_connection(self, server, tls):
        """Log in, then drop the control connection with a TCP reset: no QUIT, no close_notify."""
        c = FtpControl(PORT, server.user, server.password, login=False)
        if tls:
            try:
                c.start_tls()
            except AssertionError as e:
                if "502" in str(e):
                    raise unittest.SkipTest("uFTP was built without OpenSSL support")
                raise
        c.login()
        c.cmd("NOOP")
        c.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        os.close(c.sock.detach())

    def check_reset_is_debug(self, tls):
        server = self.start()
        self.reset_connection(server, tls)
        # the last line of the closing: the reason of the error is written just before it
        log = self.wait_for_log(server, "connection closed: control connection read error")
        line = next(l for l in log.splitlines() if "control connection read error:" in l)
        self.assertIn("[DEBUG]", line)
        self.assertNotIn("[ERROR]", log)
        # the session still ends with the same reason in the access record
        self.assertIn("connection closed: control connection read error", log)

    def test_client_reset_is_not_a_server_error(self):
        """A client that vanishes (reset, no close_notify) is the client's doing: the line
        is [DEBUG], not [ERROR], so an ERROR in the log always means a server problem."""
        self.check_reset_is_debug(tls=False)

    def test_client_reset_over_tls_is_not_a_server_error(self):
        self.check_reset_is_debug(tls=True)

    def test_cancelled_worker_line_names_the_client(self):
        """A second data command while the worker of the first one is still alive: the
        line says which client it is (it used to be a bare "[DEBUG] Cancelling thread")."""
        server = self.start()
        c = FtpControl(PORT, server.user, server.password)
        self.assertEqual(c.cmd("PASV")[0], 227)
        self.assertEqual(c.cmd("PASV")[0], 227)
        log = self.wait_for_log(server, "Cancelling the data worker")
        self.assertRegex(log, rf"\[DEBUG\] \[\d+ \S+ {server.user}\] Cancelling the data worker: it is still busy")
        self.assertNotIn("Cancelling thread because it is busy", log)

    def test_cwd_log_tells_a_missing_directory_from_a_file(self):
        """The reply is the same for both ("No such file or directory"); the log says
        which one it is, and which client asked."""
        server = self.start()
        with open(os.path.join(server.home, "plain.txt"), "w") as f:
            f.write("x")
        c = FtpControl(PORT, server.user, server.password)
        for target in ("missing", "plain.txt"):
            code, text = c.cmd(f"CWD {target}")
            self.assertEqual(code, 550)
            self.assertIn("No such file or directory", text)
        log = self.wait_for_log(server, "CWD target is not a directory")
        self.assertRegex(log, rf"\[DEBUG\] \[\d+ \S+ {server.user}\] CWD directory does not exist: \S*/missing")
        self.assertRegex(log, rf"\[DEBUG\] \[\d+ \S+ {server.user}\] CWD target is not a directory: \S*/plain\.txt")
        self.assertNotIn("CWD not a directory", log)

    def test_startup_line(self):
        server = self.start()
        log = self.wait_for_log(server, "listening on port")
        self.assertRegex(log, rf"\[pid {server.process.pid}\] \[INFO\] uFTP .* listening on port {PORT}: TLS ")

    def test_crash_is_logged_with_the_stack(self):
        server = self.start()
        pid = server.process.pid
        os.kill(pid, signal.SIGSEGV)
        # the process still ends with the signal: exit status and core dump unchanged
        self.assertEqual(server.process.wait(5), -signal.SIGSEGV)
        log = self.wait_for_log(server, "[FATAL] uFTP crashed with SIGSEGV (11)")
        self.assertIn(f"[pid {pid}] [FATAL]", log)
        # the stack follows; a line of the writer thread may land in between (no lock
        # can be taken in a signal handler)
        stack = [line for line in log.split("SIGSEGV (11)\n", 1)[1].splitlines() if "[0x" in line]
        self.assertGreater(len(stack), 2, log)

    def test_sigterm_is_logged(self):
        server = self.start()
        os.kill(server.process.pid, signal.SIGTERM)
        self.assertEqual(server.process.wait(5), -signal.SIGTERM)
        self.wait_for_log(server, "[INFO] uFTP stopped by SIGTERM (15)")

    def test_supervisor_logs_how_the_server_ended(self):
        server = self.start(RESPAWN_PROCESS="true")
        self.wait_for_log(server, "listening on port")
        child = [pid for pid in process_group_members(server.pgid) if pid != server.pgid][0]
        os.kill(child, signal.SIGKILL)
        log = self.wait_for_log(server, f"server process {child} killed by signal 9")
        self.assertIn(f"[pid {server.pgid}] [INFO] Supervisor started", log)
        self.assertIn("restarting in 1 second", log)
        # the new server process says it is listening, with its own pid
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            log = server.log_folder_text()
            started = re.findall(r"\[pid (\d+)\] \[INFO\] uFTP .* listening on port", log)
            if len(started) == 2:
                break
            time.sleep(0.2)
        self.assertEqual(len(started), 2, log)
        self.assertNotEqual(started[0], started[1])

    def occupy_the_port(self):
        """Another program listening on the port (SO_REUSEADDR: the connections in
        TIME_WAIT left by the previous tests must not get in the way)."""
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(blocker.close)
        blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        blocker.bind(("0.0.0.0", PORT))
        blocker.listen(1)

    def test_busy_port_is_logged_and_the_server_exits(self):
        self.occupy_the_port()
        server = self.make_server()
        self.assertEqual(server.run_until_exit(check_port=False), 1)
        self.assertIn(f"[FATAL] Can not listen on port {PORT}: Address already in use", server.log_folder_text())

    def test_fatal_error_goes_to_stderr_when_the_log_is_disabled(self):
        self.occupy_the_port()
        server = self.make_server(MAXIMUM_LOG_FILES=0)
        self.assertEqual(server.run_until_exit(check_port=False), 1)
        self.assertIn(f"[FATAL] Can not listen on port {PORT}", server.read_log())

    def test_missing_certificate_is_logged(self):
        server = self.make_server(CERTIFICATE_PATH="{workdir}/missing.pem")
        try:
            status = server.run_until_exit(timeout=2)
        except subprocess.TimeoutExpired:
            raise unittest.SkipTest("uFTP was built without OpenSSL support")
        self.assertNotEqual(status, 0)
        self.assertIn("[FATAL] TLS setup failed: certificate file not found (CERTIFICATE_PATH): "
                      f"{server.workdir}/missing.pem", server.log_folder_text())

    def test_owner_that_does_not_exist_means_root_and_is_reported(self):
        """USER_NAME_OWNER/GROUP_NAME_OWNER that do not exist: by design the user operates
        as root, but the id used to be read from a struct never filled (root or a random
        id, silently). Now it is always root and it is said at startup."""
        server = self.start(USER_NAME_OWNER_0="uftp-no-such-user", GROUP_NAME_OWNER_0="uftp-no-such-group")
        log = self.wait_for_log(server, "uftp-no-such-group")
        self.assertIn(f'[ERROR] Owner user "uftp-no-such-user" of FTP user "{server.user}" does not exist: '
                      "the user operates as root (uid 0)", log)
        self.assertIn(f'[ERROR] Owner group "uftp-no-such-group" of FTP user "{server.user}" does not exist: '
                      "the user operates as group root (gid 0)", log)
        c = FtpControl(PORT, server.user, server.password)
        self.addCleanup(c.close)
        self.assertEqual(c.upload("STOR owned.txt", c.pasv(), b"data"), 226)     # root: no permission refused
        self.assertEqual(c.download("RETR owned.txt", c.pasv()), (226, b"data"))

    def test_log_file_is_not_writable_by_everybody(self):
        """The log was created 0666 in daemon mode (umask 0): anybody on the machine could
        change the access records. A file of the day left by an older version is fixed."""
        folder = tempfile.mkdtemp(prefix="uftp-log-")
        self.addCleanup(shutil.rmtree, folder, True)
        existing = os.path.join(folder, "uftpLog_" + time.strftime("%Y-%m-%d"))
        with open(existing, "w") as f:
            f.write("older line\n")
        os.chmod(existing, 0o666)
        server = self.start(LOG_FOLDER=folder + "/")
        deadline = time.monotonic() + 5
        while "listening on port" not in open(existing).read() and time.monotonic() < deadline:
            time.sleep(0.2)
        self.assertEqual(stat.S_IMODE(os.stat(existing).st_mode), 0o640)
        self.assertTrue(server.is_running())

    def test_refused_size_logs_the_path_received(self):
        """SIZE of a path that can not be resolved logged "(null)" instead of the path."""
        server = self.start()
        c = FtpControl(PORT, server.user, server.password)
        self.addCleanup(c.close)
        self.assertEqual(c.cmd("SIZE missing-dir/file.txt")[0], 550)
        log = self.wait_for_log(server, "SIZE error file wrong path")
        self.assertIn("SIZE error file wrong path: missing-dir/file.txt", log)
        self.assertNotIn("(null)", log)

    def test_log_folder_without_the_trailing_slash(self):
        server = self.start(LOG_FOLDER="{workdir}/log")
        self.wait_for_log(server, "listening on port")      # the file is inside the folder


class AccessLogTests(unittest.TestCase):
    """The access records: who connected, who logged in, what was transferred or
    changed, and why each connection was closed. None of this used to be logged."""

    def start(self, **extra):
        idle = extra.pop("idle_timeout", 60)
        server = UFTPTestServer(port=PORT, idle_timeout=idle,
                                extra_config=dict({"MAXIMUM_LOG_FILES": 1}, **extra))
        try:
            server.start()
        except FileNotFoundError as e:
            raise unittest.SkipTest(str(e))
        self.addCleanup(server.stop)
        return server

    def connect(self, server, login=True):
        c = FtpControl(PORT, server.user, server.password, login=login)
        self.addCleanup(c.close)
        return c

    def client_address(self, server):
        """The address of the test client as the server logs it: 127.0.0.1, or
        ::ffff:127.0.0.1 when the server is built with IPv6 support."""
        opened = self.log_lines(server, "connection opened")      # the probe made at startup
        self.assertTrue(opened, server.log_folder_text())
        return re.search(r"\[\d+ (\S+) -\] connection opened", opened[0]).group(1)

    def log_lines(self, server, text, count=1, timeout=5):
        """The log lines containing text, once there are at least count of them."""
        deadline = time.monotonic() + timeout
        while True:
            lines = [line for line in server.log_folder_text().splitlines() if text in line]
            if len(lines) >= count or time.monotonic() > deadline:
                return lines
            time.sleep(0.2)

    def test_a_session_is_recorded(self):
        server = self.start()
        c = self.connect(server, login=False)
        c.cmd(f"USER {server.user}")
        self.assertEqual(c.cmd("PASS wrong")[0], 530)
        c.login()
        self.assertEqual(c.upload("STOR a.txt", c.pasv(), b"hello"), 226)
        self.assertEqual(c.download("RETR a.txt", c.pasv()), (226, b"hello"))
        for command, code in (("MKD d", 257), ("MKD d", 550), ("RNFR a.txt", 350), ("RNTO d/b.txt", 250),
                              ("SITE CHMOD 600 d/b.txt", 200), ("DELE d/b.txt", 250), ("RMD d", 250),
                              ("QUIT", 221)):
            self.assertEqual(c.cmd(command)[0], code, command)
        c.close()

        home = server.home.rstrip("/")
        address = self.client_address(server)
        anonymous = f"{address} -]"
        user = f"{address} {server.user}]"
        expected = [
            f"{anonymous} connection opened",
            f"{anonymous} login failed for user {server.user}",
            f"{user} login ok, home {home}/, in clear text",
            f"{user} STOR {home}/a.txt: 5 bytes received",
            f"{user} RETR {home}/a.txt: 5 bytes sent",
            f"{user} MKD {home}/d",
            f"{user} MKD {home}/d failed: File exists",
            f"{user} RNFR/RNTO {home}/a.txt -> {home}/d/b.txt",
            f"{user} SITE CHMOD 600 d/b.txt",
            f"{user} DELE {home}/d/b.txt",
            f"{user} RMD {home}/d",
            f"{user} connection closed: QUIT",
        ]
        self.log_lines(server, "connection closed: QUIT")
        log = server.log_folder_text()
        position = log.index("[INFO]")
        for text in expected:                       # all there, in this order
            found = log.find(text, position)
            self.assertNotEqual(found, -1, f"{text!r} missing or out of order in:\n{log}")
            position = found + len(text)

    def test_client_abort_during_data_handshake_keeps_the_session(self):
        """A client that closes the data connection before the TLS handshake
        (for example after a refused transfer) must not lose the control
        connection: only the data worker is closed."""
        server = self.start()
        probe = self.connect(server, login=False)
        code, _ = probe.cmd("AUTH TLS")
        probe.close()
        if code == 502:
            self.skipTest("uFTP was built without OpenSSL support")

        c = self.connect(server, login=False)
        c.start_tls()
        c.login()
        self.assertEqual(c.cmd("PBSZ 0")[0], 200)
        self.assertEqual(c.cmd("PROT P")[0], 200)

        data = c.pasv()
        data.close()                        # no ClientHello: EOF on the data socket
        self.assertTrue(self.log_lines(server, "aborted by the client"),
                        server.log_folder_text())
        self.assertEqual(c.cmd("NOOP")[0], 200, "the control connection was closed")

        # the same control session must still be able to transfer
        data = c.pasv()
        self.assertEqual(c.cmd("STOR after-abort.txt")[0], 150)
        data = tls_client_context().wrap_socket(data, server_hostname=HOST)
        data.sendall(b"still here")
        data.unwrap().close()
        self.assertEqual(c.read_reply()[0], 226)

    def test_refused_path_logs_the_reason(self):
        """A path that can not be resolved must not be reported as an attempt
        to leave the home: the log says why (missing parent, ...)."""
        server = self.start()
        c = self.connect(server)
        data = c.pasv()
        self.addCleanup(data.close)

        self.assertEqual(c.cmd("STOR missing-dir/file.txt")[0], 450)
        lines = self.log_lines(server, "Path can not be resolved")
        self.assertTrue(lines, server.log_folder_text())
        self.assertIn("missing-dir", lines[0])
        self.assertIn("No such file or directory", lines[0])
        self.assertNotIn("outside the home", lines[0])

        # a real path outside the home is still a security event
        self.assertEqual(c.cmd("STOR ../outside.txt")[0], 550)
        self.assertTrue(self.log_lines(server, "Path outside the home refused"),
                        server.log_folder_text())

    def test_upload_that_can_not_be_written_is_reported(self):
        """Disk full, quota, file size limit: the upload used to end with 226."""
        if shutil.which("prlimit") is None:
            raise unittest.SkipTest("prlimit not available")
        server = self.start()
        c = self.connect(server)
        # 1 MB file size limit for the server (the log file stays far below it)
        subprocess.run(["prlimit", f"--pid={server.process.pid}", "--fsize=1000000"], check=True)
        self.assertEqual(c.upload("STOR big.bin", c.pasv(), b"x" * 2000000), 451)
        line = self.log_lines(server, "STOR")
        self.assertTrue(line and "big.bin failed after" in line[0] and "File too large" in line[0], line)
        self.assertEqual(c.cmd("NOOP")[0], 200)

    def test_interrupted_upload_is_reported(self):
        """A data connection reset in the middle of an upload used to end with 226."""
        server = self.start()
        c = self.connect(server)
        data = c.pasv()
        self.assertEqual(c.cmd("STOR cut.bin")[0], 150)
        data.sendall(b"y" * 100)
        time.sleep(0.2)
        data.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))   # reset
        data.close()
        self.assertEqual(c.read_reply()[0], 426)
        line = self.log_lines(server, "STOR")
        self.assertTrue(line and "cut.bin failed after 100 bytes: data connection error: Connection reset by peer" in line[0], line)

    def tls_session(self, server):
        c = self.connect(server, login=False)
        if c.cmd("AUTH TLS")[0] != 234:
            raise unittest.SkipTest("uFTP was built without OpenSSL support")
        c.sock = tls_client_context().wrap_socket(c.sock, server_hostname=HOST)
        c.file = c.sock.makefile("rb")
        c.login()
        self.assertEqual(c.cmd("PBSZ 0")[0], 200)
        self.assertEqual(c.cmd("PROT P")[0], 200)
        return c

    def tls_upload(self, c, name, size):
        data = c.pasv()
        self.assertEqual(c.cmd(f"STOR {name}")[0], 150)
        data = tls_client_context().wrap_socket(data, server_hostname=HOST)
        data.sendall(b"z" * size)
        return data

    def test_tls_upload_closed_without_the_closure_alert_is_complete(self):
        """Many clients close the TLS data connection without close_notify: still 226."""
        server = self.start()
        c = self.tls_session(server)
        data = self.tls_upload(c, "plain_close.bin", 300000)
        raw = socket.socket(fileno=data.detach())
        raw.settimeout(5)
        raw.shutdown(socket.SHUT_WR)                 # end of the data, no TLS closure
        while raw.recv(4096):
            pass
        raw.close()
        self.assertEqual(c.read_reply()[0], 226)
        self.assertEqual(os.path.getsize(os.path.join(server.home, "plain_close.bin")), 300000)
        self.assertTrue(self.log_lines(server, "plain_close.bin: 300000 bytes received"))

    def test_tls_upload_cut_by_a_reset_is_reported(self):
        """Over TLS a reset shows up as a read of 0 bytes: it used to end with 226."""
        server = self.start()
        c = self.tls_session(server)
        data = self.tls_upload(c, "reset.bin", 300000)
        # a reset on purpose (linger 0): it used to depend on unread TLS records of the server
        # (the session tickets of the data connection), which the server does not send any more
        raw = socket.socket(fileno=data.detach())
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        raw.close()
        self.assertEqual(c.read_reply()[0], 426)
        line = self.log_lines(server, "reset.bin failed after")
        self.assertTrue(line and "data connection error" in line[0], server.log_folder_text())

    def test_the_log_of_today_has_a_fixed_name(self):
        """fail2ban reads the files that exist when it starts; a program that writes a new file every day
        needs a fixed name that follows the day, or the bans stop after midnight. uftpLog.current is a link
        to the file of today, moved when a new day starts."""
        server = self.start()
        self.connect(server)
        folder = os.path.join(server.workdir, "log")
        link = os.path.join(folder, "uftpLog.current")
        self.assertTrue(os.path.islink(link), os.listdir(folder))
        today = time.strftime("%Y-%m-%d")
        self.assertEqual(os.readlink(link), "uftpLog_" + today)
        with open(link) as through_the_link, open(os.path.join(folder, "uftpLog_" + today)) as the_file:
            self.assertEqual(through_the_link.read(), the_file.read())
        # the wildcard of the old jail (uftpLog_*) does not see the link: no line is counted twice
        self.assertNotIn("uftpLog.current", [n for n in os.listdir(folder) if n.startswith("uftpLog_")])

    def test_tls_and_login_over_tls_are_recorded(self):
        server = self.start()
        self.tls_session(server)
        self.assertRegex("\n".join(self.log_lines(server, "TLS established")), r"-\] TLS established \(TLSv1\.\d\)")
        self.assertTrue(self.log_lines(server, f"{server.user}] login ok, home {server.home}/, over TLS"))

    def test_blocked_user_is_recorded(self):
        server = self.start(BLOCK_USER_0="tester2")
        c = self.connect(server, login=False)
        self.assertEqual(c.cmd("USER tester2")[0], 331)          # the client is not told
        self.assertEqual(c.cmd("PASS tester2Password")[0], 530)
        self.assertTrue(self.log_lines(server, f"{self.client_address(server)} -] login refused: user tester2 is blocked"))

    def test_failed_active_connection_says_where_and_why(self):
        server = self.start()
        c = self.connect(server)
        listener, port = listening_socket()
        listener.close()                             # nobody listens there any more
        c.send("PORT " + port_argument(HOST, port))
        line = self.log_lines(server, "active data connection to")
        self.assertTrue(line and f"to 127.0.0.1 port {port} failed: Connection refused" in line[0], server.log_folder_text())
        self.assertIn("[DEBUG]", line[0])             # the client's doing, not a server error
        # the client is told (425) and the session goes on: it used to be closed, with no reply
        self.assertEqual(c.read_reply()[0], 425)
        self.assertEqual(c.cmd("NOOP")[0], 200)
        c.close()
        self.assertFalse(self.log_lines(server, "connection closed: active data connection failed"))

    def test_refusal_with_450_is_an_access_record(self):
        """The retries after a 450 can be counted in the log: each refusal is a line, with
        its time (the lines of logged in users are never grouped)."""
        server = self.start()
        c = self.connect(server)
        data = c.pasv()
        self.addCleanup(data.close)
        for attempt in range(3):
            self.assertEqual(c.cmd("STOR parallel/dir/file.txt")[0], 450)
        lines = self.log_lines(server, "STOR parallel/dir/file.txt refused (450)", count=3)
        self.assertEqual(len(lines), 3, server.log_folder_text())
        self.assertEqual(c.cmd("MKD parallel")[0], 257)
        self.assertEqual(c.cmd("MKD parallel/dir")[0], 257)
        self.assertEqual(c.upload("STOR parallel/dir/file.txt", c.pasv(), b"ok"), 226)

    def test_every_close_says_why(self):
        server = self.start(idle_timeout=2, LOGIN_TIMEOUT=30)
        quitting = self.connect(server)
        quitting.cmd("QUIT")
        dropping = self.connect(server)
        dropping.close()
        idle = self.connect(server)
        self.assertIsNotNone(read_until_closed(idle.sock, time.monotonic() + 15))
        for reason in ("QUIT", "closed by the client", "idle timeout (IDLE_MAX_TIMEOUT)"):
            self.assertTrue(self.log_lines(server, f"connection closed: {reason}"), reason)

    def test_failed_tls_handshake_says_why(self):
        server = self.start()
        sock = open_control()
        if not send_cmd(sock, "AUTH TLS").startswith("234"):
            sock.close()
            raise unittest.SkipTest("uFTP was built without OpenSSL support")
        sock.sendall(b"this is not a TLS ClientHello" * 4)
        time.sleep(0.5)
        sock.close()
        failed = self.log_lines(server, "TLS handshake failed:")
        self.assertTrue(failed, server.log_folder_text())
        self.assertRegex(failed[0], r"\[ERROR\] \[\d+ \S*127\.0\.0\.1 -\] TLS handshake failed: \S")
        self.assertTrue(self.log_lines(server, "connection closed: TLS handshake failed"))

    def test_refused_connections_are_not_logged_one_by_one(self):
        server = self.start(MAX_CONNECTION_NUMBER_PER_IP=1)
        # the slot of the probe made at startup is freed at the next loop of the server
        deadline = time.monotonic() + 3
        while True:
            holder = self.connect(server, login=False)
            if holder.welcome[0] == 220 or time.monotonic() > deadline:
                break
            holder.close()
            time.sleep(0.2)
        holder.login()
        for _ in range(20):
            sock = socket.create_connection((HOST, PORT), timeout=5)
            recv_line(sock)
            sock.close()
        self.assertEqual(len(self.log_lines(server, "too many connection")), 1)
        time.sleep(1)
        opened = [line for line in server.log_folder_text().splitlines() if "connection opened" in line]
        self.assertLessEqual(len(opened), 2, opened)      # the startup probe and the holder
        holder.cmd("NOOP")

    def test_identical_access_records_are_all_written(self):
        """Identical lines are grouped (repeated N more times), but not the records of
        logged in users: four identical failures are four events."""
        server = self.start()
        c = self.connect(server)
        self.assertEqual(c.cmd("MKD same")[0], 257)
        for _ in range(4):
            self.assertEqual(c.cmd("MKD same")[0], 550)
        failures = self.log_lines(server, "same failed: File exists", count=4)
        self.assertEqual(len(failures), 4, server.log_folder_text())
        self.assertFalse(any("repeated" in line for line in failures))

    def test_count_of_grouped_lines_is_written_after_the_burst(self):
        """The copies of a grouped line were reported only if the same line came back
        later: at the end of a burst the count was lost."""
        server = self.start()
        for _ in range(6):                           # same anonymous line six times in a row
            sock = socket.create_connection((HOST, PORT), timeout=5)
            recv_line(sock)
            sock.close()
            time.sleep(0.1)

        def opened_events():
            total = 0
            for line in server.log_folder_text().splitlines():
                if "connection opened" not in line:
                    continue
                summary = re.search(r"\((\d+) more times in the last \d+ s, grouped\)", line)
                repeated = re.search(r"\(repeated (\d+) more times\)", line)
                if summary:                          # only the copies left out
                    total += int(summary.group(1))
                else:                                # one event, plus the copies left out before it
                    total += 1 + (int(repeated.group(1)) if repeated else 0)
            return total

        deadline = time.monotonic() + 30             # interval 10 s, checked when the server wakes up
        while opened_events() < 7 and time.monotonic() < deadline:
            time.sleep(0.5)
        self.assertEqual(opened_events(), 7, server.log_folder_text())   # the startup probe and ours

    def test_access_records_are_not_dropped(self):
        """Lines are limited to 100 a second, but not the records of logged in users."""
        server = self.start()
        c = self.connect(server)
        c.sock.sendall(b"".join(b"MKD dir%03d\r\n" % i for i in range(300)))
        for _ in range(300):
            self.assertEqual(c.read_reply()[0], 257)
        self.assertEqual(len(self.log_lines(server, "] MKD ", count=300)), 300)


class PipelinedCommandsTests(unittest.TestCase):
    """More commands than the control channel reads at once (4096 bytes) arriving
    together must all be answered. Over TLS the whole record (up to 16 KB) is
    decrypted at the first read: the bytes left inside OpenSSL do not wake select() up,
    and those commands used to wait for the client to send something else."""

    COMMANDS = 2000      # "NOOP\r\n" x 2000 = 12000 bytes: one TLS record, three reads

    @classmethod
    def setUpClass(cls):
        cls.server = UFTPTestServer(port=PORT, idle_timeout=60, extra_config={"MAXIMUM_LOG_FILES": 1})
        try:
            cls.server.start()
        except FileNotFoundError as e:
            raise unittest.SkipTest(str(e))

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def answered(self, tls):
        c = FtpControl(PORT, self.server.user, self.server.password, login=False)
        if tls:
            try:
                c.start_tls()
            except AssertionError as e:
                if "502" in str(e):
                    raise unittest.SkipTest("uFTP was built without OpenSSL support")
                raise
        c.login()
        c.sock.settimeout(5)
        c.sock.sendall(b"NOOP\r\n" * self.COMMANDS)
        count = 0
        try:
            while count < self.COMMANDS:
                self.assertEqual(c.read_reply()[0], 200)
                count += 1
        except (socket.timeout, TimeoutError):
            pass
        # the session is still in step: the next command gets its own reply
        if count == self.COMMANDS:
            self.assertEqual(c.cmd("PWD")[0], 257)
        c.close()
        return count

    def test_commands_beyond_one_read_over_tls_are_all_answered(self):
        self.assertEqual(self.answered(tls=True), self.COMMANDS)

    def test_commands_beyond_one_read_in_clear_text_are_all_answered(self):
        self.assertEqual(self.answered(tls=False), self.COMMANDS)


class TlsWaitTests(unittest.TestCase):
    """TLS operations that wait for the client must not keep the other clients waiting:
    the control thread serves everybody, and it also waits for a data worker that is
    closing. And a client that is slow, or that does not answer the TLS closure, must
    still get its file and the right replies."""

    BIG = 30_000_000

    @classmethod
    def setUpClass(cls):
        cls.server = UFTPTestServer(port=PORT, idle_timeout=60, extra_config={"MAXIMUM_LOG_FILES": 1})
        try:
            cls.server.start()
        except FileNotFoundError as e:
            raise unittest.SkipTest(str(e))
        probe = FtpControl(PORT, cls.server.user, cls.server.password, login=False)
        tls = probe.cmd("AUTH TLS")[0] == 234
        probe.close()
        if not tls:
            cls.server.stop()
            raise unittest.SkipTest("uFTP was built without OpenSSL support")
        with open(os.path.join(cls.server.home, "big.bin"), "wb") as f:
            f.write(os.urandom(cls.BIG))
        with open(os.path.join(cls.server.home, "small.txt"), "wb") as f:
            f.write(b"0123456789")

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def control(self, tls=True, login=True, protect=True):
        c = FtpControl(PORT, self.server.user, self.server.password, login=False)
        self.addCleanup(c.close)
        if tls:
            c.start_tls()
        if login:
            c.login()
        if tls and login and protect:
            self.assertEqual(c.cmd("PBSZ 0")[0], 200)
            self.assertEqual(c.cmd("PROT P")[0], 200)
        return c

    def tls_data(self, raw, **options):
        data = tls_client_context().wrap_socket(raw, server_hostname=HOST, **options)
        self.addCleanup(data.close)
        return data

    def noop_latencies(self, seconds):
        """Milliseconds taken by the NOOPs of an ordinary client for some seconds."""
        c = self.control(tls=False)
        latencies = []
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            start = time.monotonic()
            self.assertEqual(c.cmd("NOOP")[0], 200)
            latencies.append((time.monotonic() - start) * 1000)
            time.sleep(0.02)
        return latencies

    def test_tls_connections_left_open_after_quit_do_not_delay_the_others(self):
        """Closing a TLS control connection waited 250 ms for the closure alert of the
        client, in the thread that serves everybody: no login needed."""
        stop = threading.Event()

        def quit_and_stay():
            while not stop.is_set():
                try:
                    c = FtpControl(PORT, self.server.user, self.server.password, login=False)
                    c.start_tls()
                    c.cmd("QUIT")
                    time.sleep(0.6)                  # connection kept open, no closure alert
                    c.close()
                except (OSError, EOFError, AssertionError):
                    time.sleep(0.05)

        threads = [threading.Thread(target=quit_and_stay, daemon=True) for _ in range(8)]
        for thread in threads:
            thread.start()
        try:
            time.sleep(0.5)
            latencies = self.noop_latencies(4)
        finally:
            stop.set()
            for thread in threads:
                thread.join(5)
        self.assertLess(statistics.median(latencies), 50, f"NOOP latencies (ms): {sorted(latencies)[-10:]}")

    def test_stopping_a_tls_download_does_not_block_the_server(self):
        """A new PASV or an ABOR during a TLS download: the control thread waits for the
        worker, which waited up to a second for the closure alert of the client."""
        for command in ("PASV", "ABOR"):
            c = self.control()
            raw = c.pasv()
            self.assertEqual(c.cmd("RETR big.bin")[0], 150)
            data = self.tls_data(raw)
            data.recv(1000)                          # then nothing is read or answered
            latencies = []
            watcher = threading.Thread(target=lambda: latencies.extend(self.noop_latencies(2)))
            watcher.start()
            time.sleep(0.3)
            c.send(command)
            watcher.join()
            self.assertLess(max(latencies), 300, f"{command}: NOOP latencies (ms): {sorted(latencies)[-5:]}")
            c.close()

    def test_new_pasv_right_after_a_tls_download(self):
        """A client that does not answer the TLS closure and asks for a new data
        connection at once (as clients without close_notify do): the worker was
        cancelled in the middle of its cleanup, and the replies came out wrong."""
        c = self.control()
        for attempt in range(3):
            raw = c.pasv()
            self.assertEqual(c.cmd("RETR small.txt")[0], 150)
            data = self.tls_data(raw)
            self.assertEqual(data.recv(100), b"0123456789")     # no closure alert sent back
            time.sleep(0.2)
            c.send("PASV")
            replies = [c.read_reply()[0], c.read_reply()[0]]
            self.assertEqual(replies, [226, 227], f"attempt {attempt}")
            self.assertEqual(c.cmd("NOOP")[0], 200)
            data.close()

    def log_in(self, connection):
        """USER and PASS on a raw connection (clear text or TLS), reading the two replies."""
        connection.settimeout(10)
        for line, expected in (("USER %s\r\n" % self.server.user, b"331"), ("PASS %s\r\n" % self.server.password, b"230")):
            connection.sendall(line.encode())
            reply = b""
            while not reply.endswith(b"\r\n"):
                reply += connection.recv(4096)
            self.assertTrue(reply.startswith(expected), reply)

    def test_slow_reader_of_the_control_connection_is_not_disconnected(self):
        """A reply that could not be written in 250 ms closed the client: live clients
        were disconnected in production. The client here stops reading for a second
        while thousands of replies are due."""
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        raw.connect((HOST, PORT))
        self.addCleanup(raw.close)
        welcome = raw.makefile("rb")
        welcome.readline()
        raw.sendall(b"AUTH TLS\r\n")
        self.assertTrue(welcome.readline().startswith(b"234"))
        tls = self.tls_data(raw)
        self.log_in(tls)                             # a client that has logged in: one that has not gets a tenth of a second

        count = 30000
        commands = b"HELP\r\n" * count

        def send_all():
            # records below 4 KB: larger ones hit another defect (problemi_aperti.md)
            for i in range(0, len(commands), 3600):
                tls.sendall(commands[i:i + 3600])

        sender = threading.Thread(target=send_all)
        sender.start()
        time.sleep(1.0)                              # not reading meanwhile
        tls.settimeout(10)
        replies, tail = 0, b""
        while replies < count:
            chunk = tls.recv(65536)
            if not chunk:
                break
            data = tail + chunk
            replies += data.count(b"214 Help OK.")
            tail = data[-11:]
        sender.join(10)
        self.assertEqual(replies, count, "the server closed the control connection")

    def test_slow_reader_of_a_clear_text_control_connection_is_not_disconnected(self):
        """The same in clear text: there a full send buffer closed the client at once
        (no wait at all), and a partial write lost the rest of a reply."""
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        raw.connect((HOST, PORT))
        self.addCleanup(raw.close)
        raw.recv(1000)                               # welcome
        self.log_in(raw)                             # a client that has logged in: one that has not gets a tenth of a second
        count = 30000
        sender = threading.Thread(target=lambda: raw.sendall(b"HELP\r\n" * count))
        sender.start()
        time.sleep(1.0)                              # not reading meanwhile
        raw.settimeout(10)
        replies, tail = 0, b""
        while replies < count:
            chunk = raw.recv(65536)
            if not chunk:
                break
            data = tail + chunk
            replies += data.count(b"214 Help OK.")
            tail = data[-11:]
        sender.join(10)
        self.assertEqual(replies, count, "the server closed the control connection")

    def test_226_is_not_delayed_by_the_tls_closure(self):
        """A client that keeps the data connection open until the 226: the server waited
        up to a second for its TLS closure before sending the 226, at every file."""
        c = self.control()
        for attempt in range(3):
            raw = c.pasv()
            self.assertEqual(c.cmd("RETR small.txt")[0], 150)
            data = self.tls_data(raw)
            received = b""
            while True:
                chunk = data.recv(4096)
                if not chunk:
                    break
                received += chunk
            self.assertEqual(received, b"0123456789")
            start = time.monotonic()
            self.assertEqual(c.read_reply()[0], 226)          # data connection still open
            self.assertLess(time.monotonic() - start, 0.3, f"attempt {attempt}")
            data.close()

    def test_data_handshake_timeout_closes_only_the_data_connection(self):
        """A data connection on which the client never starts TLS: after 5 seconds the
        whole session was closed. Now, after 15 seconds, only the data connection is
        closed: the accepted command gets 426 and the session goes on."""
        c = self.control()
        raw = c.pasv()
        self.addCleanup(raw.close)
        self.assertEqual(c.cmd("RETR small.txt")[0], 150)
        start = time.monotonic()
        c.sock.settimeout(25)
        code, text = c.read_reply()
        self.assertEqual(code, 426, text)
        self.assertGreater(time.monotonic() - start, 10)
        self.assertEqual(c.cmd("NOOP")[0], 200)

        data = c.pasv()                                    # the same session can transfer again
        self.assertEqual(c.cmd("RETR small.txt")[0], 150)
        data = self.tls_data(data)
        self.assertEqual(data.recv(100), b"0123456789")
        data.close()
        self.assertEqual(c.read_reply()[0], 226)

    def test_slow_start_of_the_data_handshake(self):
        """A client (or a link) that starts TLS on the data connection 7 seconds after
        connecting: the session was closed after 5 seconds."""
        c = self.control()
        raw = c.pasv()
        self.assertEqual(c.cmd("RETR small.txt")[0], 150)
        time.sleep(7)
        data = self.tls_data(raw)
        self.assertEqual(data.recv(100), b"0123456789")
        data.close()
        self.assertEqual(c.read_reply()[0], 226)

    def test_tls_download_ends_with_a_tls_closure(self):
        """Control: strict clients (FileZilla) need the close_notify of the server."""
        c = self.control()
        raw = c.pasv()
        self.assertEqual(c.cmd("RETR big.bin")[0], 150)
        data = self.tls_data(raw, suppress_ragged_eofs=False)    # a missing closure raises SSLEOFError
        received = 0
        while True:
            chunk = data.recv(65536)
            if not chunk:
                break
            received += len(chunk)
        self.assertEqual(received, self.BIG)
        self.assertEqual(c.read_reply()[0], 226)

    def test_tls_download_survives_a_pause_of_the_client(self):
        """A client that reads nothing for a few seconds (slow disk, slow link): each
        block had 5 seconds, then the download failed with a misleading 550."""
        c = self.control()
        raw = c.pasv()
        self.assertEqual(c.cmd("RETR big.bin")[0], 150)
        data = self.tls_data(raw)
        data.settimeout(20)
        received = len(data.recv(65536))
        time.sleep(7)
        while True:
            chunk = data.recv(65536)
            if not chunk:
                break
            received += len(chunk)
        self.assertEqual(received, self.BIG)
        c.sock.settimeout(10)
        self.assertEqual(c.read_reply()[0], 226)

    def test_download_broken_by_the_client_answers_426(self):
        """A data connection reset during a download was answered
        "550 unable to open the file for reading"."""
        c = self.control(tls=False)
        data = c.pasv()
        self.assertEqual(c.cmd("RETR big.bin")[0], 150)
        data.recv(1000)
        data.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))   # reset
        data.close()
        code, text = c.read_reply()
        self.assertEqual(code, 426, text)
        deadline = time.monotonic() + 5
        while "big.bin failed: data connection error" not in self.server.log_folder_text() and time.monotonic() < deadline:
            time.sleep(0.2)
        self.assertIn("big.bin failed: data connection error", self.server.log_folder_text())
        self.assertEqual(c.cmd("NOOP")[0], 200)

    def test_data_connection_abandoned_after_150_gets_a_final_reply(self):
        """The transfer command is accepted (150), then the client closes the data
        connection without the TLS handshake: it used to wait for a reply for ever."""
        c = self.control()
        data = c.pasv()
        self.assertEqual(c.cmd("STOR abandoned.txt")[0], 150)
        data.close()
        c.sock.settimeout(8)
        code, text = c.read_reply()
        self.assertEqual(code, 426, text)
        self.assertEqual(c.cmd("NOOP")[0], 200)


class UFTPResilienceTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = UFTPTestServer(port=PORT, idle_timeout=IDLE_TIMEOUT)
        try:
            cls.server.start()
        except FileNotFoundError as e:
            raise unittest.SkipTest(str(e))

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def assertServerAlive(self):
        self.assertTrue(self.server.is_running(), "uFTP server process died")
        sock = open_control()
        try:
            self.assertTrue(send_cmd(sock, f"USER {self.server.user}").startswith("331"))
            self.assertTrue(send_cmd(sock, f"PASS {self.server.password}").startswith("230"))
            self.assertTrue(send_cmd(sock, "NOOP").startswith("200"))
        finally:
            sock.close()

    def test_auth_tls_then_close_does_not_spin_cpu(self):
        """AUTH TLS followed by an immediate close must not keep the server busy-looping
        on the half-negotiated TLS client (it used to burn a core for 30 seconds)."""
        sock = open_control()
        reply = send_cmd(sock, "AUTH TLS")
        if not reply.startswith("234"):
            sock.close()
            self.skipTest(f"server built without TLS support (AUTH TLS -> {reply.strip()})")
        sock.close()  # peer goes away before sending a ClientHello

        time.sleep(0.5)  # let the server notice the EOF
        cpu_before = process_group_cpu_seconds(self.server.pgid)
        time.sleep(3)
        cpu_used = process_group_cpu_seconds(self.server.pgid) - cpu_before

        self.assertLess(cpu_used, 0.5,
                        f"server used {cpu_used:.2f}s of CPU in 3s while idle "
                        f"after an aborted TLS handshake (busy loop)")
        self.assertServerAlive()

    def test_garbage_after_tls_handshake_does_not_spin_cpu(self):
        """Bytes that are not TLS records, sent after a completed handshake, make
        SSL_read fail for good: the client must be dropped. It used to stay
        connected with the server busy-looping until the idle timeout."""
        sock = open_control()
        reply = send_cmd(sock, "AUTH TLS")
        if not reply.startswith("234"):
            sock.close()
            self.skipTest(f"server built without TLS support (AUTH TLS -> {reply.strip()})")

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        tls_sock = context.wrap_socket(sock)
        raw = socket.socket(fileno=os.dup(tls_sock.fileno()))   # same connection, no TLS layer
        try:
            raw.sendall(b"THIS IS NOT A TLS RECORD\r\n" * 3)

            time.sleep(0.5)
            cpu_before = process_group_cpu_seconds(self.server.pgid)
            closed = wait_closed_by_server(raw, time.monotonic() + 2)
            time.sleep(1)
            cpu_used = process_group_cpu_seconds(self.server.pgid) - cpu_before
        finally:
            raw.close()
            tls_sock.detach()

        self.assertTrue(closed, "client sending garbage inside a TLS session was not disconnected")
        self.assertLess(cpu_used, 0.5,
                        f"server used {cpu_used:.2f}s of CPU after a TLS protocol error (busy loop)")
        self.assertServerAlive()

    def test_connection_reset_is_handled(self):
        """A control connection closed with a TCP reset is cleaned up, with or without
        a pending AUTH TLS, and the server keeps working."""
        for with_auth in (False, True):
            sock = open_control()
            if with_auth:
                send_cmd(sock, "AUTH TLS")
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            sock.close()

        time.sleep(0.5)
        cpu_before = process_group_cpu_seconds(self.server.pgid)
        time.sleep(2)
        cpu_used = process_group_cpu_seconds(self.server.pgid) - cpu_before
        self.assertLess(cpu_used, 0.5, f"server used {cpu_used:.2f}s of CPU in 2s after connection resets")
        self.assertServerAlive()

    def test_failed_active_connection_does_not_close_descriptor_0(self):
        """The cleanup of a worker whose PORT connection failed closed
        descriptor 0; the next client then got descriptor 0 and could end up sharing
        it with the session of another user."""
        def descriptor_0():
            try:
                return os.readlink(f"/proc/{self.server.pgid}/fd/0")
            except OSError:
                return None

        self.assertEqual(descriptor_0(), "/dev/null")

        sock = open_control()
        try:
            self.assertTrue(send_cmd(sock, f"USER {self.server.user}").startswith("331"))
            self.assertTrue(send_cmd(sock, f"PASS {self.server.password}").startswith("230"))
            closed_port_listener = socket.socket()
            closed_port_listener.bind((HOST, 0))
            port = closed_port_listener.getsockname()[1]
            closed_port_listener.close()                     # nothing listens there now
            sock.sendall(b"PORT 127,0,0,1,%d,%d\r\n" % (port // 256, port % 256))
            wait_closed_by_server(sock, time.monotonic() + 2)
        finally:
            sock.close()

        time.sleep(0.5)
        self.assertEqual(descriptor_0(), "/dev/null", "descriptor 0 was closed by the worker cleanup")
        self.assertServerAlive()
        self.assertEqual(descriptor_0(), "/dev/null", "a new client was given descriptor 0")

    def test_cancelled_listing_does_not_leak_memory(self):
        """A LIST cancelled while the worker was sending (here with ABOR, the
        client never reads the data) left the whole directory listing allocated: about
        3.5 MB more at every cancellation for a 20000 entry directory."""
        big = os.path.join(self.server.home, "big_listing")
        os.mkdir(big)
        self.addCleanup(shutil.rmtree, big, True)
        for i in range(20000):
            os.close(os.open(os.path.join(big, "entry_%06d_%s" % (i, "n" * 60)), os.O_CREAT | os.O_WRONLY, 0o644))

        def resident_kb():
            with open(f"/proc/{self.server.pgid}/status") as f:
                return int([line for line in f if line.startswith("VmRSS")][0].split()[1])

        samples = []
        for cycle in range(8):
            sock = open_control()
            data = None
            try:
                self.assertTrue(send_cmd(sock, f"USER {self.server.user}").startswith("331"))
                self.assertTrue(send_cmd(sock, f"PASS {self.server.password}").startswith("230"))
                reply = send_cmd(sock, "PASV")
                numbers = [int(n) for n in re.search(r"\(([\d,]+)\)", reply).group(1).split(",")]
                data = socket.create_connection((HOST, numbers[4] * 256 + numbers[5]), timeout=5)
                sock.sendall(b"LIST big_listing\r\n")
                time.sleep(0.8)                      # listing built, worker blocked sending
                sock.sendall(b"ABOR\r\n")
                time.sleep(0.3)
            finally:
                if data is not None:
                    data.close()
                sock.close()
            time.sleep(0.2)
            samples.append(resident_kb())

        growth = samples[-1] - samples[1]        # the first cycles may grow the heap once
        self.assertLess(growth, 4096, f"resident memory (KB) after each cancelled LIST: {samples}")
        self.assertServerAlive()

    def test_idle_client_times_out(self):
        """Baseline: with no other traffic an idle client is disconnected, and is told
        why (RFC 959: 421 when the server closes the control connection)."""
        idle = open_control()
        try:
            # select() wakes up at least every 10s, so allow for that
            received = read_until_closed(idle, time.monotonic() + IDLE_TIMEOUT + 12)
            self.assertIsNotNone(received, "idle client was not disconnected")
            self.assertTrue(received.startswith(b"421 "), received)
        finally:
            idle.close()

    def test_idle_client_times_out_while_other_client_is_active(self):
        """A client that keeps its own connection busy must not prevent other idle
        clients from being disconnected after IDLE_MAX_TIMEOUT."""
        idle = open_control()
        active = open_control()
        try:
            deadline = time.monotonic() + IDLE_TIMEOUT + 6
            idle_closed = False
            while time.monotonic() < deadline and not idle_closed:
                # keep the server's select() constantly woken up; no login needed,
                # any reply (530 included) is fine
                reply = send_cmd(active, "NOOP")
                self.assertRegex(reply, r"^\d{3} ", "active client got no reply")
                idle_closed = wait_closed_by_server(idle, time.monotonic() + 0.5)

            self.assertTrue(idle_closed,
                            "idle client was never disconnected while another "
                            "client kept the server busy")
        finally:
            idle.close()
            active.close()
        self.assertServerAlive()


class TransferLatencyTests(unittest.TestCase):
    """A transfer must not wait for the delayed ACK of the client. The server writes two small replies on the
    control connection (150, then 226): without TCP_NODELAY the second one waited for the ACK of the first,
    which Linux delays by about 40 ms, so every transfer took at least 41 ms, even of a few bytes."""

    def test_a_small_transfer_does_not_wait_for_the_delayed_ack(self):
        server = UFTPTestServer(port=PORT, idle_timeout=60, extra_config={"MAXIMUM_LOG_FILES": 0})
        server.start()
        self.addCleanup(server.stop)
        with open(os.path.join(server.home, "small.txt"), "wb") as f:
            f.write(b"x" * 4096)
        c = FtpControl(PORT, server.user, server.password, timeout=10)
        stor, retr = [], []
        for n in range(12):
            data = c.pasv()
            c.cmd("STOR up%d" % n)
            data.sendall(b"y" * 4096)
            data.close()
            t = time.perf_counter()
            self.assertEqual(c.read_reply()[0], 226)
            stor.append(time.perf_counter() - t)
            data = c.pasv()
            c.cmd("RETR small.txt")
            while data.recv(65536):
                pass
            data.close()
            t = time.perf_counter()
            self.assertEqual(c.read_reply()[0], 226)
            retr.append(time.perf_counter() - t)
        c.close()
        # the first one of each can be quick by luck (the system answers at once at the start of a connection)
        self.assertLess(statistics.median(stor), 0.02, "the 226 of an upload took %.1f ms (median)" % (statistics.median(stor) * 1000))
        self.assertLess(statistics.median(retr), 0.02, "the 226 of a download took %.1f ms (median)" % (statistics.median(retr) * 1000))

    def test_an_upload_is_not_much_slower_than_a_download(self):
        """Every block of an upload waited 100 microseconds: 8 MB/s whatever the network (a download of the
        same file ran at 150 MB/s). Compared with the download on the same server, so that a slow machine
        or a sanitizer build does not matter."""
        server = UFTPTestServer(port=PORT, idle_timeout=60, extra_config={"MAXIMUM_LOG_FILES": 0})
        server.start()
        self.addCleanup(server.stop)
        size = 32 << 20
        block = b"z" * (1 << 20)
        c = FtpControl(PORT, server.user, server.password, timeout=30)
        c.cmd("TYPE I")
        data = c.pasv()
        c.cmd("STOR big.bin")
        t = time.perf_counter()
        for _ in range(size // len(block)):
            data.sendall(block)
        data.close()
        self.assertEqual(c.read_reply()[0], 226)
        upload = time.perf_counter() - t
        data = c.pasv()
        c.cmd("RETR big.bin")
        t = time.perf_counter()
        received = 0
        while True:
            part = data.recv(1 << 20)
            if not part:
                break
            received += len(part)
        data.close()
        self.assertEqual(c.read_reply()[0], 226)
        download = time.perf_counter() - t
        c.close()
        self.assertEqual(received, size)
        self.assertLess(upload, download * 4 + 0.5, "upload %.2f s, download %.2f s of %d MB" % (upload, download, size >> 20))

    def test_a_download_is_not_limited_by_small_blocks(self):
        """RETR read and wrote 1 KB at a time: about 150 MB/s on a machine where the other servers do GB/s (one
        system call per KB). Measured against a fixed minimum, that is a fifth of what it does now."""
        server = UFTPTestServer(port=PORT, idle_timeout=60, extra_config={"MAXIMUM_LOG_FILES": 0})
        server.start()
        self.addCleanup(server.stop)
        size = 128 << 20
        with open(os.path.join(server.home, "big.bin"), "wb") as f:
            f.write(b"q" * size)
        c = FtpControl(PORT, server.user, server.password, timeout=30)
        c.cmd("TYPE I")
        data = c.pasv()
        c.cmd("RETR big.bin")
        t = time.perf_counter()
        received = 0
        while True:
            part = data.recv(1 << 20)
            if not part:
                break
            received += len(part)
        data.close()
        self.assertEqual(c.read_reply()[0], 226)
        seconds = time.perf_counter() - t
        c.close()
        self.assertEqual(received, size)
        self.assertGreater(size / seconds / 1e6, 400, "download of %d MB at %.0f MB/s" % (size >> 20, size / seconds / 1e6))

    def test_a_listing_does_not_look_up_the_owner_of_every_file_again(self):
        """LIST asked the system for the owner and the group of every file (it reads /etc/passwd and /etc/group
        each time): about 100 microseconds a file, half a second for 5000 files. 3000 files must be listed in
        well under that (the check is generous so that a slow machine or a sanitizer build do not matter)."""
        server = UFTPTestServer(port=PORT, idle_timeout=60, extra_config={"MAXIMUM_LOG_FILES": 0})
        server.start()
        self.addCleanup(server.stop)
        listing = os.path.join(server.home, "many")
        os.mkdir(listing)
        for n in range(3000):
            with open(os.path.join(listing, "file%04d.txt" % n), "wb"):
                pass
        c = FtpControl(PORT, server.user, server.password, timeout=30)
        times = []
        for _ in range(5):
            data = c.pasv()
            c.cmd("LIST many")
            t = time.perf_counter()
            size = 0
            while True:
                part = data.recv(1 << 20)
                if not part:
                    break
                size += len(part)
            data.close()
            self.assertEqual(c.read_reply()[0], 226)
            times.append(time.perf_counter() - t)
        c.close()
        self.assertGreater(size, 3000 * 40)
        self.assertLess(min(times), 0.15 * sanitizer_factor(), "LIST of 3000 files took %.0f ms" % (min(times) * 1000))

    def test_a_tls_transfer_does_not_wait_in_steps_of_10_ms(self):
        """The TLS handshake of the data connection waited 10 ms between two attempts, so every transfer in FTPS
        lost 10 to 20 ms. A small listing takes a few milliseconds."""
        server = UFTPTestServer(port=PORT, idle_timeout=60, extra_config={"MAXIMUM_LOG_FILES": 0})
        server.start()
        self.addCleanup(server.stop)
        probe = FtpControl(PORT, login=False, timeout=10)
        code = probe.cmd("AUTH TLS")[0]
        probe.close()
        if code == 502:
            self.skipTest("uFTP was built without OpenSSL support")
        c = FtpControl(PORT, login=False, timeout=20)
        c.start_tls()
        c.login(server.user, server.password)
        self.assertEqual(c.cmd("PBSZ 0")[0], 200)
        self.assertEqual(c.cmd("PROT P")[0], 200)
        context = tls_client_context()
        times = []
        for _ in range(15):
            raw = c.pasv()
            c.cmd("LIST")
            t = time.perf_counter()
            data = context.wrap_socket(raw, server_hostname=HOST)
            while data.recv(65536):
                pass
            data.close()
            self.assertEqual(c.read_reply()[0], 226)
            times.append(time.perf_counter() - t)
        c.close()
        self.assertLess(statistics.median(times), 0.008, "a TLS listing took %.1f ms (median)" % (statistics.median(times) * 1000))


    def test_a_plain_download_is_sent_with_sendfile(self):
        """RETR read every block into the program and wrote it back (fread + write): 0.40 s of CPU per GB,
        sendfile() copies inside the kernel (0.09 s). The server runs under strace, which writes down the
        sendfile() calls (a wrapper script is the "binary" of the test server)."""
        strace = shutil.which("strace")
        if strace is None:
            self.skipTest("strace is not installed")
        workdir = tempfile.mkdtemp(prefix="uftp-sendfile-")
        self.addCleanup(shutil.rmtree, workdir, True)
        trace = os.path.join(workdir, "trace.txt")
        wrapper = os.path.join(workdir, "uftp-under-strace.sh")
        with open(wrapper, "w") as f:
            f.write('#!/bin/sh\nexec %s -f -e trace=sendfile,sendfile64 -o %s %s "$@"\n' % (strace, trace, DEFAULT_BIN))
        os.chmod(wrapper, 0o755)
        server = UFTPTestServer(port=PORT, idle_timeout=60, binary=wrapper, extra_config={"MAXIMUM_LOG_FILES": 0})
        try:
            server.start()
        except Exception as error:         # ptrace not allowed here (containers, hardened kernels)
            self.skipTest("the server can not be started under strace: %s" % error)
        self.addCleanup(server.stop)
        payload = bytes(range(256)) * (16 << 10)               # 4 MB
        with open(os.path.join(server.home, "sf.bin"), "wb") as f:
            f.write(payload)
        c = FtpControl(PORT, server.user, server.password, timeout=30)
        c.cmd("TYPE I")
        code, received = c.download("RETR sf.bin", c.pasv())
        self.assertEqual((code, received), (226, payload))
        c.close()
        time.sleep(0.5)
        with open(trace) as f:
            sent = [int(m.group(1)) for m in re.finditer(r"sendfile6?4?\(.*\) = (\d+)", f.read())]
        self.assertGreaterEqual(sum(sent), len(payload), "sendfile() sent %d of %d bytes" % (sum(sent), len(payload)))

    def test_download_with_rest_is_exact_for_every_offset(self):
        server = UFTPTestServer(port=PORT, idle_timeout=60, extra_config={"MAXIMUM_LOG_FILES": 0})
        server.start()
        self.addCleanup(server.stop)
        payload = bytes((i * 7 + i // 251) % 256 for i in range(3 * 65536 + 1234))
        with open(os.path.join(server.home, "rest.bin"), "wb") as f:
            f.write(payload)
        c = FtpControl(PORT, server.user, server.password, timeout=20)
        c.cmd("TYPE I")
        for offset in (0, 1, 4095, 65535, 65536, 65537, 2 * 65536 + 7, len(payload) - 1, len(payload)):
            self.assertEqual(c.cmd("REST %d" % offset)[0], 350)
            code, received = c.download("RETR rest.bin", c.pasv())
            self.assertEqual(code, 226, "offset %d" % offset)
            self.assertEqual(received, payload[offset:], "offset %d" % offset)
        c.close()

    def test_a_download_stopped_with_abor_leaves_the_server_working(self):
        server = UFTPTestServer(port=PORT, idle_timeout=60, extra_config={"MAXIMUM_LOG_FILES": 0})
        server.start()
        self.addCleanup(server.stop)
        with open(os.path.join(server.home, "huge.bin"), "wb") as f:
            f.write(b"h" * (64 << 20))
        c = FtpControl(PORT, server.user, server.password, timeout=20)
        c.cmd("TYPE I")
        data = c.pasv()
        self.assertEqual(c.cmd("RETR huge.bin")[0], 150)
        data.recv(1 << 16)                  # the client does not read on: the server blocks in the send
        time.sleep(0.5)
        c.send("ABOR")
        codes = [c.read_reply()[0], c.read_reply()[0]]
        data.close()
        self.assertEqual(codes, [426, 226])
        self.assertEqual(c.cmd("NOOP")[0], 200)
        code, received = c.download("RETR huge.bin", c.pasv())
        self.assertEqual((code, len(received)), (226, 64 << 20))
        c.close()
        self.assertEqual(server.process.poll(), None)

    def test_a_file_that_gets_shorter_during_the_download_ends_the_transfer(self):
        server = UFTPTestServer(port=PORT, idle_timeout=60, extra_config={"MAXIMUM_LOG_FILES": 0})
        server.start()
        self.addCleanup(server.stop)
        path = os.path.join(server.home, "shrink.bin")
        with open(path, "wb") as f:
            f.write(b"s" * (32 << 20))
        c = FtpControl(PORT, server.user, server.password, timeout=20)
        c.cmd("TYPE I")
        data = c.pasv()
        self.assertEqual(c.cmd("RETR shrink.bin")[0], 150)
        data.recv(1 << 16)
        os.truncate(path, 1 << 20)
        total = 1 << 16
        while True:
            part = data.recv(1 << 20)
            if not part:
                break
            total += len(part)
        data.close()
        self.assertEqual(c.read_reply()[0], 226)
        self.assertLessEqual(total, 32 << 20)
        self.assertEqual(c.cmd("NOOP")[0], 200)
        c.close()


    def test_download_goes_on_with_read_and_write_when_sendfile_fails(self):
        """sendfile() answering EINVAL (a file system that does not support it) must not fail the download:
        the old loop takes over from the same point. The failure is injected with strace."""
        strace = shutil.which("strace")
        if strace is None:
            self.skipTest("strace is not installed")
        workdir = tempfile.mkdtemp(prefix="uftp-inject-")
        self.addCleanup(shutil.rmtree, workdir, True)
        wrapper = os.path.join(workdir, "uftp-under-strace.sh")
        with open(wrapper, "w") as f:
            f.write('#!/bin/sh\nexec %s -f -e trace=sendfile,sendfile64 -e inject=sendfile,sendfile64:error=EINVAL -o %s %s "$@"\n'
                    % (strace, os.path.join(workdir, "trace.txt"), DEFAULT_BIN))
        os.chmod(wrapper, 0o755)
        server = UFTPTestServer(port=PORT, idle_timeout=60, binary=wrapper, extra_config={"MAXIMUM_LOG_FILES": 0})
        try:
            server.start()
        except Exception as error:
            self.skipTest("the server can not be started under strace: %s" % error)
        self.addCleanup(server.stop)
        payload = os.urandom(3 << 20) + b"\xff" * 100
        with open(os.path.join(server.home, "inject.bin"), "wb") as f:
            f.write(payload)
        c = FtpControl(PORT, server.user, server.password, timeout=30)
        c.cmd("TYPE I")
        for offset in (0, 12345, len(payload) - 7):
            c.cmd("REST %d" % offset)
            code, received = c.download("RETR inject.bin", c.pasv())
            self.assertEqual(code, 226)
            self.assertEqual(received, payload[offset:], "offset %d" % offset)
        self.assertEqual(c.cmd("NOOP")[0], 200)
        c.close()


class ControlStallTests(unittest.TestCase):
    """The control thread is one for all the clients: a client that does not read its replies must not stop the others."""

    def test_a_client_that_pipelines_commands_and_reads_nothing_does_not_stop_the_server(self):
        """A reply that could not be written waited for the timeout, and every command that followed in the same buffer
        waited again: a single connection that sent HELP some thousand times and never read stopped the whole server for
        about a minute (the probe was answered after 63 seconds, or reset)."""
        server = UFTPTestServer(port=PORT, idle_timeout=120, max_per_ip=50, extra_config={"MAXIMUM_LOG_FILES": 0})
        server.start()
        self.addCleanup(server.stop)
        probe = FtpControl(PORT, server.user, server.password, timeout=30)
        attackers = [socket.create_connection((HOST, PORT), timeout=5) for _ in range(3)]
        for a in attackers:
            self.addCleanup(a.close)

        def flood(a):
            blob = b"HELP\r\n" * 2000
            try:
                for _ in range(100):
                    a.sendall(blob)
            except OSError:
                pass

        threads = [threading.Thread(target=flood, args=(a,), daemon=True) for a in attackers]
        for t in threads:
            t.start()
        worst = 0.0
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            started = time.perf_counter()
            self.assertEqual(probe.cmd("NOOP")[0], 200)
            worst = max(worst, time.perf_counter() - started)
            time.sleep(0.05)
        self.assertLess(worst, 1.5, "a NOOP of another client waited %.1f s while three connections flooded the server" % worst)
        probe.close()

    def test_a_logged_in_client_that_reads_slowly_is_still_served(self):
        """The short wait is only for the clients that have not logged in."""
        server = UFTPTestServer(port=PORT, idle_timeout=60, extra_config={"MAXIMUM_LOG_FILES": 0})
        server.start()
        self.addCleanup(server.stop)
        c = FtpControl(PORT, server.user, server.password, timeout=10)
        for _ in range(200):
            c.send("HELP")
        time.sleep(0.5)
        for _ in range(200):
            self.assertEqual(c.read_reply()[0], 214)
        self.assertEqual(c.cmd("NOOP")[0], 200)
        c.close()


    def test_the_server_closes_the_connection_after_quit_at_once(self):
        """The client to close was closed at the next turn of the control loop, which started after the wait for events: with
        nothing else happening, 10 seconds after the 221 of QUIT (and the slot stayed taken that long)."""
        server = UFTPTestServer(port=PORT, idle_timeout=60, extra_config={"MAXIMUM_LOG_FILES": 0})
        server.start()
        self.addCleanup(server.stop)
        c = FtpControl(PORT, server.user, server.password, timeout=30)
        started = time.perf_counter()
        c.send("QUIT")
        self.assertEqual(c.read_reply()[0], 221)
        c.sock.settimeout(20)
        while c.sock.recv(1024):
            pass
        elapsed = time.perf_counter() - started
        self.assertLess(elapsed, 2.0, "the server closed the connection %.1f s after QUIT" % elapsed)
        c.close()

    def test_a_refused_login_closes_the_connection_at_once(self):
        server = UFTPTestServer(port=PORT, idle_timeout=60, extra_config={"MAXIMUM_LOG_FILES": 0, "MAX_CONNECTION_TRY_PER_IP": 2})
        server.start()
        self.addCleanup(server.stop)
        for _ in range(2):                                          # two failed logins use up the tries of this address
            c = FtpControl(PORT, login=False, timeout=30)
            c.cmd("USER nobody")
            self.assertEqual(c.cmd("PASS wrong")[0], 530)
            c.close()
        c = FtpControl(PORT, login=False, timeout=30)
        c.cmd("USER nobody")
        started = time.perf_counter()
        code, text = c.cmd("PASS wrong")
        self.assertEqual(code, 530)
        self.assertIn("Too many login failure", text)
        c.sock.settimeout(20)
        try:
            while c.sock.recv(1024):
                pass
        except OSError:
            pass
        elapsed = time.perf_counter() - started
        c.close()
        self.assertLess(elapsed, 2.0, "the server closed the connection %.1f s after refusing the login" % elapsed)

class ConfigurationLimitsTests(unittest.TestCase):
    def test_a_very_long_value_or_name_in_the_configuration_file(self):
        """A parameter of 1024 characters or more filled the array of the parser to its last byte, without the terminator:
        strcpy() read past it (AddressSanitizer: stack-buffer-overflow in readConfigurationFile)."""
        server = UFTPTestServer(port=PORT, idle_timeout=30, extra_config={"A_PARAMETER_WITH_A_LONG_VALUE": "v" * 1500,
                                                                         "N" * 1500: "a name that is too long",
                                                                         "MAXIMUM_LOG_FILES": 0})
        server.start()
        self.addCleanup(server.stop)
        c = FtpControl(PORT, server.user, server.password, timeout=10)
        self.assertEqual(c.cmd("NOOP")[0], 200)
        c.close()


    def test_values_that_can_not_work_stop_the_server_with_a_message(self):
        """MAXIMUM_ALLOWED_FTP_CONNECTION that can not be allocated (or does not fit an int) and a passive port range that is
        inverted or outside 1..65535 (it answered 227 with port 0, or with a port outside the range) are refused at the start."""
        for key, value in (("MAXIMUM_ALLOWED_FTP_CONNECTION", "-1"), ("MAXIMUM_ALLOWED_FTP_CONNECTION", "0"),
                           ("MAXIMUM_ALLOWED_FTP_CONNECTION", "99999999999"), ("RANDOM_PORT_START", "50000"),
                           ("RANDOM_PORT_END", "99999"), ("RANDOM_PORT_START", "-3")):
            server = UFTPTestServer(port=PORT, idle_timeout=30, extra_config={key: value, "MAXIMUM_LOG_FILES": 0})
            with self.assertRaises(RuntimeError, msg="%s = %s" % (key, value)):
                server.start(startup_timeout=4)
            self.assertIsNotNone(server.process.poll() if server.process else 1)

    def test_a_valid_passive_port_range_gives_a_port_in_the_range(self):
        server = UFTPTestServer(port=PORT, idle_timeout=30, extra_config={"RANDOM_PORT_START": 41000, "RANDOM_PORT_END": 41050, "MAXIMUM_LOG_FILES": 0})
        server.start()
        self.addCleanup(server.stop)
        c = FtpControl(PORT, server.user, server.password, timeout=10)
        for _ in range(5):
            code, text = c.cmd("PASV")
            self.assertEqual(code, 227)
            numbers = [int(n) for n in re.search(r"\(([\d,]+)\)", text).group(1).split(",")]
            self.assertTrue(41000 <= numbers[4] * 256 + numbers[5] <= 41050, text)
        c.close()


class SignalTests(unittest.TestCase):
    def test_sigint_stops_the_server_with_status_0_and_logs_it(self):
        """The handler of SIGINT only logs and leaves with _exit(0): it used to call the allocator and exit(), which are not
        safe inside a signal handler (a deadlock if the signal came while the allocator was in use, not provocable on demand)."""
        server = UFTPTestServer(port=PORT, idle_timeout=30, extra_config={"MAXIMUM_LOG_FILES": 5})
        server.start()
        self.addCleanup(server.stop)
        c = FtpControl(PORT, server.user, server.password, timeout=10)
        self.assertEqual(c.cmd("NOOP")[0], 200)
        server.process.send_signal(signal.SIGINT)
        try:
            self.assertIn(server.process.wait(timeout=10), (0, 66) if built_with_tsan() else (0,))
        finally:
            c.close()
        self.assertIn("stopped by SIGINT", server.log_folder_text())


class LogInjectionTests(unittest.TestCase):
    def test_control_characters_sent_by_a_client_are_not_written_to_the_log(self):
        """A user name or a path with ESC sequences, backspaces or the bell went to the log as they were: whoever read it with
        cat or tail could have the screen cleared, the title of the terminal changed or the text overwritten."""
        server = UFTPTestServer(port=PORT, idle_timeout=60, extra_config={"MAXIMUM_LOG_FILES": 5})
        server.start()
        self.addCleanup(server.stop)
        c = FtpControl(PORT, login=False, timeout=10)
        c.send(b"USER evil\x1b[2J\x1b[31mRED\x07\x08\x08\x7f")
        c.read_reply()
        c.send(b"PASS wrong")
        c.read_reply()
        c.close()
        c = FtpControl(PORT, server.user, server.password, timeout=10)
        c.send(b"CWD \x1b]0;pwned\x07dir")
        c.read_reply()
        c.send(b"STOR \x1b[1mbold\x00x")
        c.read_reply()
        c.close()
        deadline = time.monotonic() + 5
        log = ""
        while time.monotonic() < deadline and "login failed for user evil" not in log:
            time.sleep(0.3)
            log = server.log_folder_text()
        self.assertIn("login failed for user evil", log)
        for character in "\x1b\x07\x08\x7f\x00":
            self.assertNotIn(character, log, repr(character))


    def test_control_characters_are_not_in_the_summary_of_repeated_lines_either(self):
        """The same line repeated (a login failing again and again) is written once and summarised after 10 seconds from the
        text as it was received: the control characters came back in the summary."""
        server = UFTPTestServer(port=PORT, idle_timeout=60, extra_config={"MAXIMUM_LOG_FILES": 5, "MAX_CONNECTION_TRY_PER_IP": 0})
        server.start()
        self.addCleanup(server.stop)
        for _ in range(6):
            c = FtpControl(PORT, login=False, timeout=10)
            c.send(b"USER evil\x1b[2J\x07\x08name")
            c.read_reply()
            c.send(b"PASS wrong")
            c.read_reply()
            c.close()
        deadline = time.monotonic() + 25
        log = ""
        while time.monotonic() < deadline and "more times in the last" not in log:
            time.sleep(1)
            log = server.log_folder_text()
        self.assertIn("more times in the last", log)
        self.assertIn("login failed for user evil", log)
        for character in "\x1b\x07\x08\x7f":
            self.assertNotIn(character, log, repr(character))


class BigDirectoryTests(unittest.TestCase):
    def test_listing_a_directory_of_a_hundred_thousand_files_takes_seconds_not_minutes(self):
        """The allocator found the block to free or to resize by walking the list of every block of the worker: a listing was
        quadratic in the number of files (30,000 files 2.7 s, 100,000 about 30 s, a million: hours). It is now one lookup."""
        server = UFTPTestServer(port=PORT, idle_timeout=120, extra_config={"MAXIMUM_LOG_FILES": 0})
        server.start()
        self.addCleanup(server.stop)
        big = os.path.join(server.home, "big")
        os.mkdir(big)
        for n in range(100000):
            open(os.path.join(big, "file-%06d.dat" % n), "w").close()
        c = FtpControl(PORT, server.user, server.password, timeout=120 * sanitizer_factor())
        for command, minimum in (("LIST big", 100000), ("MLSD big", 100000)):
            started = time.perf_counter()
            data_socket = c.pasv()
            data_socket.settimeout(60 * sanitizer_factor())
            code, data = c.download(command, data_socket)
            elapsed = time.perf_counter() - started
            self.assertEqual(code, 226, command)
            self.assertGreaterEqual(data.count(b"\n"), minimum, command)
            self.assertLess(elapsed, 12.0 * sanitizer_factor(), "%s of 100,000 files took %.1f s" % (command, elapsed))
        c.close()


if __name__ == "__main__":
    unittest.main()
