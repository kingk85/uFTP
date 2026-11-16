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
from uftp_test_server import UFTPTestServer, HOST  # noqa: E402
from ftp_test_client import FtpControl, listening_socket, port_argument, tls_client_context  # noqa: E402

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
        log = self.wait_for_log(server, "control connection read error")
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
        os.close(data.detach())                      # unread TLS records pending: the kernel sends a reset
        self.assertEqual(c.read_reply()[0], 426)
        line = self.log_lines(server, "reset.bin failed after")
        self.assertTrue(line and "data connection error" in line[0], server.log_folder_text())

    def test_tls_and_login_over_tls_are_recorded(self):
        server = self.start()
        self.tls_session(server)
        self.assertRegex("\n".join(self.log_lines(server, "TLS established")), r"-\] TLS established \(TLSv1\.\d\)")
        self.assertTrue(self.log_lines(server, f"{server.user}] login ok, home {server.home}/, over TLS"))

    def test_blocked_user_is_recorded(self):
        server = self.start(BLOCK_USER_0="tester2")
        c = self.connect(server, login=False)
        self.assertEqual(c.cmd("USER tester2")[0], 530)
        self.assertTrue(self.log_lines(server, f"{self.client_address(server)} -] login refused: user tester2 is blocked"))

    def test_failed_active_connection_says_where_and_why(self):
        server = self.start()
        c = self.connect(server)
        listener, port = listening_socket()
        listener.close()                             # nobody listens there any more
        c.send("PORT " + port_argument(HOST, port))
        line = self.log_lines(server, "active data connection to")
        self.assertTrue(line and f"to 127.0.0.1 port {port} failed: Connection refused" in line[0], server.log_folder_text())
        c.close()
        self.assertTrue(self.log_lines(server, "connection closed: active data connection failed"))

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


if __name__ == "__main__":
    unittest.main()
