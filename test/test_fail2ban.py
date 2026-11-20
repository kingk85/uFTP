"""The fail2ban filter of contrib/fail2ban/uftp.conf against the lines that uFTP really writes.

A server is started, wrong logins and a flood of connections are made from loopback addresses, and the
log it writes is given to fail2ban-regex: the addresses of the attackers must be found, the one of a user
that made a single mistake must be found once (fail2ban bans after maxretry), and the lines that can hit a
legitimate user (too many sessions of one account) must not count. If the format of the log changes, this
fails, and the filter must be updated with it.

Needs fail2ban-regex (apt install fail2ban); the test is skipped without it. A copy that is not installed
can be used with FAIL2BAN_REGEX=/path/to/fail2ban-regex (and PYTHONPATH for its modules).
"""

import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import unittest

from uftp_test_server import UFTPTestServer

PORT = int(os.environ.get("UFTP_FAIL2BAN_PORT", "2380"))
FILTER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "contrib", "fail2ban", "uftp.conf")
REGEX = os.environ.get("FAIL2BAN_REGEX") or shutil.which("fail2ban-regex")


def connect_from(source, port):
    sock = socket.socket()
    sock.bind((source, 0))
    sock.settimeout(3)
    sock.connect(("127.0.0.1", port))
    return sock


def wrong_login(source, user):
    sock = connect_from(source, PORT)
    try:
        sock.recv(200)
        sock.sendall(("USER %s\r\n" % user).encode())
        sock.recv(200)
        sock.sendall(b"PASS wrong\r\n")
        sock.recv(200)
    finally:
        sock.close()


@unittest.skipUnless(REGEX, "fail2ban-regex is not installed")
class Fail2banFilterTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = UFTPTestServer(port=PORT, idle_timeout=60, max_connections=40, max_per_ip=40,
                                    extra_config={"MAXIMUM_LOG_FILES": 1, "MAX_CONNECTION_TRY_PER_IP": 500,
                                                  "MAX_CONNECTION_RATE_PER_IP": 6, "MAX_CONNECTION_PER_ACCOUNT": 1})
        cls.server.start()
        cls.addClassCleanup(cls.server.stop)

        user, password = cls.server.user, cls.server.password
        held = socket.create_connection(("127.0.0.1", PORT), timeout=3)     # one session of the account...
        held.recv(200)
        held.sendall(("USER %s\r\n" % user).encode())
        held.recv(200)
        held.sendall(("PASS %s\r\n" % password).encode())
        held.recv(200)
        second = socket.create_connection(("127.0.0.1", PORT), timeout=3)   # ...and a second one: refused
        second.recv(200)
        second.sendall(("USER %s\r\n" % user).encode())
        second.recv(200)
        second.sendall(("PASS %s\r\n" % password).encode())
        second.recv(200)
        second.close()
        held.close()

        for name in ("admin", "root", "ftp"):                               # an attacker that changes user
            wrong_login("127.0.0.2", name)
        wrong_login("127.0.0.3", "nobody")                                  # one mistake
        for _ in range(9):                                                  # a flood
            try:
                connect_from("127.0.0.4", PORT).close()
            except OSError:
                pass
        deadline = time.monotonic() + 5
        log = ""
        while time.monotonic() < deadline and "in the last minute" not in log:
            time.sleep(0.2)
            log = cls.server.log_folder_text()

        cls.folder = tempfile.mkdtemp(prefix="uftp-f2b-")
        cls.addClassCleanup(shutil.rmtree, cls.folder, True)
        cls.logfile = os.path.join(cls.folder, "uftpLog_test")
        with open(cls.logfile, "w") as f:
            f.write(log)
        result = subprocess.run([REGEX, "-v", cls.logfile, FILTER], capture_output=True, text=True, timeout=60)
        cls.output = result.stdout + result.stderr
        cls.found = re.findall(r"^\|\s+(\S+)\s+[A-Z][a-z]{2} [A-Z][a-z]{2} ", cls.output, re.M)

    def test_the_filter_is_valid(self):
        self.assertRegex(self.output, r"Failregex: \d+ total", self.output[-600:])

    def test_the_attacker_that_changes_the_user_is_found_at_every_attempt(self):
        self.assertEqual(self.found.count("127.0.0.2"), 3, self.output[-1500:])

    def test_a_single_mistake_is_found_once(self):
        self.assertEqual(self.found.count("127.0.0.3"), 1, self.output[-1500:])

    def test_the_flood_is_found_with_its_address(self):
        self.assertGreaterEqual(self.found.count("127.0.0.4"), 1, self.output[-1500:])

    def test_a_user_with_too_many_sessions_is_not_counted(self):
        with open(self.logfile) as f:
            self.assertIn("too many connections", f.read())                 # the line is in the log...
        self.assertEqual(self.found.count("127.0.0.1"), 0, self.output[-1500:])   # ...and does not count

    def test_every_address_found_is_one_that_the_test_used(self):
        self.assertEqual(set(self.found), {"127.0.0.2", "127.0.0.3", "127.0.0.4"})


if __name__ == "__main__":
    unittest.main()
