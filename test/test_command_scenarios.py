"""
Scenarios of the FTP commands that the other suites do not exercise (found with gcov):

  * permission denied: the user configured with an owner (USER_NAME_OWNER) other than the
    owner of the files, which uFTP checks itself; no need to be root;
  * system calls that fail for the real user of the server (a directory the server
    process can not write): remove, rmdir, mkdir, rename, fopen;
  * FORCE_TLS = true, an empty password and the lock-out after failed logins, CDUP;
  * IPv6 (::1): PASV, EPSV, EPRT, login and transfers.

Normally run through test/run_tests.sh. Standalone:
  python3 test/test_command_scenarios.py -v

Environment overrides:
  UFTP_BIN            path to the uFTP binary (default: ../build/uFTP)
  UFTP_SCENARIO_PORT  base control port (default: 2135; the classes use the next ports)
"""

import grp
import os
import pwd
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from uftp_test_server import UFTPTestServer, HOST  # noqa: E402
from ftp_test_client import FtpControl, empty_directory, listening_socket  # noqa: E402

PORT = int(os.environ.get("UFTP_SCENARIO_PORT", "2135"))
IS_ROOT = os.geteuid() == 0


def other_owner():
    """(user, group) names of an account that is not the one running the tests."""
    for user in ("nobody", "daemon"):
        try:
            entry = pwd.getpwnam(user)
        except KeyError:
            continue
        if entry.pw_uid == os.geteuid():
            continue
        try:
            group = grp.getgrgid(entry.pw_gid).gr_name
        except KeyError:
            continue
        return user, group
    return None


class ScenarioCase(unittest.TestCase):
    """A server of its own for the class; the home is emptied before each test."""

    server_port = PORT
    extra_config = {}

    @classmethod
    def setUpClass(cls):
        cls.server = UFTPTestServer(port=cls.server_port, idle_timeout=60, extra_config=cls.extra_config)
        try:
            cls.server.start()
        except FileNotFoundError as e:
            raise unittest.SkipTest(str(e))

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def setUp(self):
        self.restore_modes(self.server.home)
        empty_directory(self.server.home)

    @staticmethod
    def restore_modes(directory):
        """Directories made read-only by a test must be removable."""
        for root, dirs, _ in os.walk(directory):
            for name in dirs:
                path = os.path.join(root, name)
                if not os.path.islink(path):
                    os.chmod(path, 0o755)

    def connect(self, login=True, **options):
        c = FtpControl(self.server_port, self.server.user, self.server.password, login=login, **options)
        self.addCleanup(c.close)
        return c

    def make_file(self, name, mode, content=b"content"):
        path = os.path.join(self.server.home, name)
        with open(path, "wb") as f:
            f.write(content)
        os.chmod(path, mode)
        return path

    def make_dir(self, name, mode):
        path = os.path.join(self.server.home, name)
        os.makedirs(path, exist_ok=True)
        os.chmod(path, mode)
        return path

    def assertReply(self, c, command, code, text=None):
        reply_code, reply_text = c.cmd(command)
        self.assertEqual(reply_code, code, f"{command!r} -> {reply_text!r}")
        if text is not None:
            self.assertIn(text, reply_text, f"{command!r} -> {reply_text!r}")
        return reply_text

    def refused_transfer(self, c, command, code, text=None):
        """A transfer command that must be refused (a data connection is opened first)."""
        data = c.pasv()
        self.addCleanup(data.close)
        return self.assertReply(c, command, code, text)


# ---------------------------------------------------------------------------------------
# Permission denied: the permission check of uFTP, for a configured owner that is not the
# owner of the files.
# ---------------------------------------------------------------------------------------
@unittest.skipIf(other_owner() is None, "no other account (nobody) to configure as owner")
class PermissionDeniedTests(ScenarioCase):
    """USER_NAME_OWNER_0 = nobody: the files made by the test user belong to somebody else,
    so the "other" permission bits decide. The same commands on files and directories that
    others can use (0666, 0777) are the controls: the check does not refuse everything."""

    server_port = PORT
    owner = other_owner()
    extra_config = {"USER_NAME_OWNER_0": owner[0] if owner else "nobody",
                    "GROUP_NAME_OWNER_0": owner[1] if owner else "nogroup"}

    def test_retr_of_a_file_the_user_can_not_read(self):
        self.make_file("private.txt", 0o600, b"secret")
        c = self.connect()
        self.refused_transfer(c, "RETR private.txt", 550, "no reading permission")

    def test_retr_of_a_file_others_can_read(self):
        self.make_file("public.txt", 0o644, b"open")
        c = self.connect()
        self.assertEqual(c.download("RETR public.txt", c.pasv()), (226, b"open"))

    def test_stor_over_a_file_the_user_can_not_write(self):
        self.make_file("readonly.txt", 0o644, b"original")
        c = self.connect()
        self.refused_transfer(c, "STOR readonly.txt", 550, "no permission to overwrite")
        with open(os.path.join(self.server.home, "readonly.txt"), "rb") as f:
            self.assertEqual(f.read(), b"original")

    def test_stor_in_a_directory_the_user_can_not_write(self):
        self.make_dir("closed", 0o755)
        c = self.connect()
        self.refused_transfer(c, "STOR closed/new.txt", 550, "No permissions to write")
        self.assertFalse(os.path.exists(os.path.join(self.server.home, "closed", "new.txt")))

    def test_stor_in_the_home_itself_is_refused(self):
        """The home belongs to the test user and others can not write in it."""
        c = self.connect()
        self.refused_transfer(c, "STOR new.txt", 550)

    def test_appe_over_a_file_the_user_can_not_write(self):
        self.make_file("readonly.txt", 0o644, b"original")
        c = self.connect()
        self.refused_transfer(c, "APPE readonly.txt", 550, "no permission to append")

    def test_appe_in_a_directory_the_user_can_not_write(self):
        self.make_dir("closed", 0o755)
        c = self.connect()
        self.refused_transfer(c, "APPE closed/new.txt", 550, "No permissions to write")

    def test_writes_work_where_others_can_write(self):
        """Control: a directory 0777 and a file 0666 can be used."""
        self.make_dir("shared", 0o777)
        self.make_file("shared/open.txt", 0o666, b"before")
        c = self.connect()
        self.assertEqual(c.upload("STOR shared/open.txt", c.pasv(), b"overwritten"), 226)
        self.assertEqual(c.upload("APPE shared/open.txt", c.pasv(), b"+more"), 226)
        self.assertEqual(c.upload("STOR shared/new.txt", c.pasv(), b"new"), 226)
        self.assertEqual(c.download("RETR shared/open.txt", c.pasv()), (226, b"overwritten+more"))

    def test_dele_of_a_file_the_user_can_not_write(self):
        self.make_file("readonly.txt", 0o644)
        c = self.connect()
        self.assertReply(c, "DELE readonly.txt", 550, "no permissions")
        self.assertTrue(os.path.exists(os.path.join(self.server.home, "readonly.txt")))

    def test_dele_of_a_file_others_can_write(self):
        self.make_dir("shared", 0o777)
        self.make_file("shared/open.txt", 0o666)
        c = self.connect()
        self.assertReply(c, "DELE shared/open.txt", 250)
        self.assertFalse(os.path.exists(os.path.join(self.server.home, "shared", "open.txt")))

    def test_rmd_of_a_directory_the_user_can_not_write(self):
        self.make_dir("closed", 0o755)
        c = self.connect()
        self.assertReply(c, "RMD closed", 550, "No permissions")
        self.assertTrue(os.path.isdir(os.path.join(self.server.home, "closed")))

    def test_rmd_of_a_directory_others_can_write(self):
        self.make_dir("shared", 0o777)
        c = self.connect()
        self.assertReply(c, "RMD shared", 250)

    def test_mkd_in_a_directory_the_user_can_not_write(self):
        self.make_dir("closed", 0o755)
        c = self.connect()
        self.assertReply(c, "MKD closed/sub", 550, "no permition to create")
        self.assertFalse(os.path.exists(os.path.join(self.server.home, "closed", "sub")))

    def test_mkd_in_a_directory_others_can_write(self):
        self.make_dir("shared", 0o777)
        c = self.connect()
        self.assertReply(c, "MKD shared/sub", 257)
        self.assertTrue(os.path.isdir(os.path.join(self.server.home, "shared", "sub")))

    def test_cwd_into_a_directory_the_user_can_not_enter(self):
        """The refusal leaves the working directory as it was."""
        self.make_dir("open", 0o755)
        self.make_dir("private", 0o700)
        c = self.connect()
        self.assertReply(c, "CWD open", 250)
        self.assertReply(c, "CWD /private", 550, "no permissions")
        code, text = c.cmd("PWD")
        self.assertEqual(code, 257)
        self.assertIn('"/open"', text)

    def test_list_nlst_and_stat_of_a_directory_the_user_can_not_read(self):
        self.make_dir("private", 0o700)
        c = self.connect()
        self.refused_transfer(c, "LIST private", 550, "no permissions")
        self.refused_transfer(c, "NLST private", 550, "no permissions")
        self.assertReply(c, "STAT private", 550, "no permissions")

    def test_rnfr_of_a_file_the_user_can_not_write(self):
        self.make_file("readonly.txt", 0o644)
        c = self.connect()
        self.assertReply(c, "RNFR readonly.txt", 550, "no file permissions")
        self.assertReply(c, "RNTO other.txt", 503)             # nothing is waiting for a RNTO

    def test_rnto_into_a_directory_the_user_can_not_write(self):
        """The source can be renamed, the directory of the destination can not be written."""
        self.make_dir("shared", 0o777)
        self.make_file("shared/mine.txt", 0o666)
        self.make_dir("closed", 0o755)
        c = self.connect()
        self.assertReply(c, "RNFR shared/mine.txt", 350)
        self.assertReply(c, "RNTO closed/moved.txt", 550, "No permissions")
        self.assertTrue(os.path.exists(os.path.join(self.server.home, "shared", "mine.txt")))

    def test_rnto_over_a_file_the_user_can_not_write(self):
        self.make_dir("shared", 0o777)
        self.make_file("shared/mine.txt", 0o666)
        self.make_file("shared/other.txt", 0o644)
        c = self.connect()
        self.assertReply(c, "RNFR shared/mine.txt", 350)
        self.assertReply(c, "RNTO shared/other.txt", 550, "no permissions")
        self.assertTrue(os.path.exists(os.path.join(self.server.home, "shared", "mine.txt")))

    def test_rename_where_the_user_can_write(self):
        self.make_dir("shared", 0o777)
        self.make_file("shared/mine.txt", 0o666)
        c = self.connect()
        self.assertReply(c, "RNFR shared/mine.txt", 350)
        self.assertReply(c, "RNTO shared/renamed.txt", 250)
        self.assertTrue(os.path.exists(os.path.join(self.server.home, "shared", "renamed.txt")))

    def test_rename_of_a_dangling_link(self):
        """A link that points nowhere is renamed as a link (its own branch)."""
        self.make_dir("shared", 0o777)
        os.symlink("nowhere", os.path.join(self.server.home, "shared", "dangling"))
        c = self.connect()
        self.assertReply(c, "RNFR shared/dangling", 350)
        self.assertReply(c, "RNTO shared/moved", 250)
        self.assertTrue(os.path.islink(os.path.join(self.server.home, "shared", "moved")))

    def test_rename_of_a_dangling_link_into_a_directory_the_user_can_not_write(self):
        self.make_dir("shared", 0o777)
        os.symlink("nowhere", os.path.join(self.server.home, "shared", "dangling"))
        self.make_dir("closed", 0o755)
        c = self.connect()
        self.assertReply(c, "RNFR shared/dangling", 350)
        self.assertReply(c, "RNTO closed/moved", 550, "No permissions")

    def test_the_other_user_without_an_owner_is_not_checked(self):
        """Control: the account of the same server that has no owner operates as root and
        passes every check (by design)."""
        self.make_file("private.txt", 0o600, b"secret")
        c = FtpControl(self.server_port, "tester2", "tester2Password")
        self.addCleanup(c.close)
        self.assertEqual(c.download("RETR private.txt", c.pasv()), (226, b"secret"))


# ---------------------------------------------------------------------------------------
# System calls that fail for the real user of the server: the permission check of uFTP is
# passed (no owner = root) and the operating system refuses.
# ---------------------------------------------------------------------------------------
@unittest.skipIf(IS_ROOT, "root can write in a read-only directory")
class SystemCallFailureTests(ScenarioCase):
    """A directory 0555 owned by the user of the server: uFTP lets the operation through and
    the system call fails. The answer must be a refusal, and the server must go on."""

    server_port = PORT + 1

    def readonly_dir(self):
        self.make_dir("locked", 0o755)
        self.make_file("locked/file.txt", 0o644, b"x")
        self.make_dir("locked/sub", 0o755)
        os.chmod(os.path.join(self.server.home, "locked"), 0o555)

    def test_dele_that_the_system_refuses(self):
        self.readonly_dir()
        c = self.connect()
        self.assertReply(c, "DELE locked/file.txt", 550, "some errors occurred")
        self.assertReply(c, "NOOP", 200)
        self.assertTrue(os.path.exists(os.path.join(self.server.home, "locked", "file.txt")))

    def test_rmd_that_the_system_refuses(self):
        self.readonly_dir()
        c = self.connect()
        self.assertReply(c, "RMD locked/sub", 550, "Permission denied")
        self.assertTrue(os.path.isdir(os.path.join(self.server.home, "locked", "sub")))

    def test_mkd_that_the_system_refuses(self):
        self.readonly_dir()
        c = self.connect()
        self.assertReply(c, "MKD locked/new", 550)
        self.assertFalse(os.path.exists(os.path.join(self.server.home, "locked", "new")))

    def test_rnto_that_the_system_refuses(self):
        self.readonly_dir()
        self.make_file("mine.txt", 0o644)
        c = self.connect()
        self.assertReply(c, "RNFR mine.txt", 350)
        self.assertReply(c, "RNTO locked/moved.txt", 553)
        self.assertTrue(os.path.exists(os.path.join(self.server.home, "mine.txt")))

    def test_rnto_of_a_link_that_the_system_refuses(self):
        self.readonly_dir()
        os.symlink("nowhere", os.path.join(self.server.home, "dangling"))
        c = self.connect()
        self.assertReply(c, "RNFR dangling", 350)
        self.assertReply(c, "RNTO locked/moved", 553)

    def test_stor_and_appe_that_the_system_refuses(self):
        """The file can not be created: the worker answers 553 and the session goes on."""
        self.readonly_dir()
        c = self.connect()
        for command in ("STOR", "APPE"):
            data = c.pasv()
            self.assertReply(c, f"{command} locked/new.txt", 150)
            code, text = c.read_reply()
            data.close()
            self.assertEqual(code, 553, text)
            self.assertReply(c, "NOOP", 200)

    def test_dele_of_a_link_that_the_system_refuses(self):
        """A link is removed as a link, in its own branch of DELE."""
        self.readonly_dir()
        os.chmod(os.path.join(self.server.home, "locked"), 0o755)
        os.symlink("nowhere", os.path.join(self.server.home, "locked", "link"))
        os.chmod(os.path.join(self.server.home, "locked"), 0o555)
        c = self.connect()
        self.assertReply(c, "DELE locked/link", 550, "some errors occurred")
        self.assertTrue(os.path.islink(os.path.join(self.server.home, "locked", "link")))

    def test_site_chmod_of_a_file_in_a_directory_the_server_can_not_search(self):
        """The file can not be reached: the answer is the one of a missing file. (chmod
        refused by the system for a file of another owner needs root to be set up.)"""
        self.make_dir("hidden", 0o755)
        self.make_file("hidden/file.txt", 0o644)
        os.chmod(os.path.join(self.server.home, "hidden"), 0o000)
        c = self.connect()
        try:
            self.assertReply(c, "SITE CHMOD 600 hidden/file.txt", 550)
        finally:
            os.chmod(os.path.join(self.server.home, "hidden"), 0o755)
        self.assertEqual(os.stat(os.path.join(self.server.home, "hidden", "file.txt")).st_mode & 0o777, 0o644)

    def test_site_chmod_with_too_many_digits(self):
        self.make_file("file.txt", 0o644)
        c = self.connect()
        self.assertReply(c, "SITE CHMOD 77777 file.txt", 501)
        self.assertEqual(os.stat(os.path.join(self.server.home, "file.txt")).st_mode & 0o777, 0o644)


# ---------------------------------------------------------------------------------------
# FORCE_TLS, empty password, lock-out
# ---------------------------------------------------------------------------------------
class ForceTlsTests(ScenarioCase):
    """FORCE_TLS = true: no login in clear text."""

    server_port = PORT + 2
    extra_config = {"FORCE_TLS": "true"}

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        probe = FtpControl(cls.server_port, login=False)
        try:
            tls = probe.cmd("AUTH TLS")[0] == 234
        finally:
            probe.close()
        if not tls:
            cls.server.stop()
            raise unittest.SkipTest("uFTP was built without OpenSSL support")

    def test_user_before_tls_is_refused(self):
        c = self.connect(login=False)
        self.assertReply(c, f"USER {self.server.user}", 534, "Policy Requires SSL")
        self.assertReply(c, f"PASS {self.server.password}", 503)      # no login was started

    def test_commands_that_start_tls_are_allowed(self):
        c = self.connect(login=False)
        self.assertEqual(c.cmd("FEAT")[0], 211)
        self.assertEqual(c.cmd("NOOP")[0], 200)

    def test_login_after_auth_tls(self):
        c = self.connect(login=False)
        c.start_tls()
        c.login()
        self.assertReply(c, "PWD", 257)

    def test_clear_text_login_is_refused_again_after_ccc(self):
        """The control connection back in clear text: a new login is a clear text login."""
        c = self.connect(login=False)
        c.start_tls()
        c.login()
        self.assertReply(c, "CCC", 200)
        c.sock = c.sock.unwrap()
        c.file = c.sock.makefile("rb")
        self.assertReply(c, f"USER {self.server.user}", 534, "Policy Requires SSL")


class LockoutTests(ScenarioCase):
    """MAX_CONNECTION_TRY_PER_IP = 2: two failed logins lock the address out. The server
    remembers the failures for five minutes, so every test starts a server of its own."""

    server_port = PORT + 3
    extra_config = {"MAX_CONNECTION_TRY_PER_IP": 2}

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        type(self).server = UFTPTestServer(port=self.server_port, idle_timeout=60, extra_config=self.extra_config)
        try:
            self.server.start()
        except FileNotFoundError as e:
            raise unittest.SkipTest(str(e))
        self.addCleanup(self.server.stop)

    def test_empty_password_is_refused(self):
        c = self.connect(login=False)
        self.assertReply(c, f"USER {self.server.user}", 331)
        self.assertReply(c, "PASS", 530)
        self.assertReply(c, "PWD", 530)

    def test_empty_passwords_count_as_failed_logins(self):
        """Two empty passwords, then the right one: refused, and the connection is closed."""
        c = self.connect(login=False)
        for _ in range(2):
            self.assertReply(c, f"USER {self.server.user}", 331)
            self.assertReply(c, "PASS", 530)
        self.assertReply(c, f"USER {self.server.user}", 331)
        code, text = c.cmd(f"PASS {self.server.password}")
        self.assertEqual(code, 530, text)
        self.assertIn("Too many login failure", text)


# ---------------------------------------------------------------------------------------
# CDUP and the working directory
# ---------------------------------------------------------------------------------------
class ChangeDirectoryTests(ScenarioCase):
    server_port = PORT + 4

    def test_cdup_from_the_root_stays_in_the_root(self):
        c = self.connect()
        self.assertReply(c, "CDUP", 550, "Already at root")
        self.assertReply(c, "XCUP", 550, "Already at root")
        code, text = c.cmd("PWD")
        self.assertEqual(code, 257)
        self.assertIn('"/"', text)
        self.assertTrue(os.path.isdir(self.server.home))

    def test_cdup_goes_up_one_level_at_a_time(self):
        os.makedirs(os.path.join(self.server.home, "a", "b"))
        c = self.connect()
        self.assertReply(c, "CWD a/b", 250)
        self.assertReply(c, "CDUP", 250, "/a")
        self.assertReply(c, "XCUP", 250)
        code, text = c.cmd("PWD")
        self.assertIn('"/"', text)
        self.assertReply(c, "CDUP", 550)

    def test_cdup_can_not_leave_the_home_after_many_attempts(self):
        c = self.connect()
        for _ in range(5):
            c.cmd("CDUP")
        self.assertReply(c, "CWD ..", 550)
        code, text = c.cmd("PWD")
        self.assertIn('"/"', text)


class HomeWithoutTrailingSlashTests(ScenarioCase):
    """HOME configured without the final '/': the paths in the replies (MKD answers with
    the absolute path) must not show the home or a double slash."""

    server_port = PORT + 6
    extra_config = {"HOME_0": "{home}"}

    def test_mkd_replies_with_the_path_of_the_user(self):
        c = self.connect()
        code, text = c.cmd("MKD /made")
        self.assertEqual(code, 257, text)
        self.assertIn('"/made"', text)
        code, text = c.cmd("MKD /made/inner")
        self.assertEqual(code, 257, text)
        self.assertIn('"/made/inner"', text)
        self.assertTrue(os.path.isdir(os.path.join(self.server.home, "made", "inner")))


# ---------------------------------------------------------------------------------------
# IPv6
# ---------------------------------------------------------------------------------------
def ipv6_available():
    try:
        probe = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        probe.bind(("::1", 0))
        probe.close()
        return True
    except OSError:
        return False


@unittest.skipUnless(ipv6_available(), "IPv6 loopback (::1) is not available")
class Ipv6Tests(ScenarioCase):
    """Control connection over ::1. A build without IPv6 support does not listen there: the
    whole class is then skipped."""

    server_port = PORT + 5

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        try:
            socket.create_connection(("::1", cls.server_port), timeout=2).close()
        except OSError:
            cls.server.stop()
            raise unittest.SkipTest("uFTP was built without IPv6 support")

    def connect6(self, login=True):
        return self.connect(login=login, host="::1")

    def test_login_and_basic_commands(self):
        c = self.connect6()
        self.assertReply(c, "PWD", 257)
        self.assertReply(c, "NOOP", 200)
        self.assertReply(c, "SYST", 215)

    def test_pasv_is_refused_over_ipv6(self):
        c = self.connect6()
        self.assertReply(c, "PASV", 500, "use EPSV")

    def test_epsv_transfers(self):
        c = self.connect6()
        payload = b"over ipv6 " * 500
        self.assertEqual(c.upload("STOR v6.bin", c.epsv(), payload), 226)
        self.assertEqual(c.download("RETR v6.bin", c.epsv()), (226, payload))
        code, listing = c.download("NLST", c.epsv())
        self.assertEqual((code, listing), (226, b"v6.bin\r\n"))

    def test_passive_data_connection_from_another_address_is_refused(self):
        """The data connection must come from the address of the control connection (::1)
        also over IPv6: a connection from 127.0.0.1 is not accepted."""
        self.make_file("secret.txt", 0o644, b"for the client")
        c = self.connect6()
        code, text = c.cmd("EPSV")
        self.assertEqual(code, 229, text)
        port = int(text.split("|||")[1].split("|")[0])
        intruder = socket.create_connection((HOST, port), timeout=3)       # IPv4: another address
        self.addCleanup(intruder.close)
        client_data = socket.create_connection(("::1", port), timeout=3)
        self.addCleanup(client_data.close)
        self.assertReply(c, "RETR secret.txt", 150)
        received = b""
        while True:
            chunk = client_data.recv(4096)
            if not chunk:
                break
            received += chunk
        self.assertEqual(received, b"for the client")
        self.assertEqual(c.read_reply()[0], 226)
        intruder.settimeout(1)
        try:
            self.assertEqual(intruder.recv(100), b"")                       # closed, no data
        except (ConnectionResetError, socket.timeout):
            pass

    def test_eprt_active_mode(self):
        """EPRT |2|::1|port|: the server opens the connection to an IPv6 address."""
        self.make_file("active.txt", 0o644, b"active over ipv6")
        c = self.connect6()
        listener, port = listening_socket("::1")
        self.addCleanup(listener.close)
        self.assertReply(c, f"EPRT |2|::1|{port}|", 200)
        self.assertReply(c, "RETR active.txt", 150)
        data, _ = listener.accept()
        self.addCleanup(data.close)
        received = b""
        while True:
            chunk = data.recv(4096)
            if not chunk:
                break
            received += chunk
        self.assertEqual(received, b"active over ipv6")
        self.assertEqual(c.read_reply()[0], 226)

    def test_eprt_to_another_ipv6_address_is_refused(self):
        c = self.connect6()
        self.assertReply(c, "EPRT |2|2001:db8::1|50000|", 504)

    def test_eprt_ipv4_over_an_ipv6_connection_is_refused(self):
        """The data address must be the one of the client: 127.0.0.1 is not ::1."""
        c = self.connect6()
        self.assertReply(c, "EPRT |1|127.0.0.1|50000|", 504)

    def test_the_same_account_over_ipv4_and_ipv6(self):
        a = self.connect()
        b = self.connect6()
        self.assertReply(a, "PWD", 257)
        self.assertReply(b, "PWD", 257)


if __name__ == "__main__":
    unittest.main()
