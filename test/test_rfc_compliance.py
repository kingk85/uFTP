"""
RFC compliance tests for uFTP (reply codes, argument validation, FTP bounce
protection, pathname quoting ...).

They cover the protocol fixes of uFTP 4.2.0, plus the basic behaviour of the commands that had no test
yet. Everything is done over raw sockets so that the exact reply sent by the server is checked.

The suite starts its own throw-away uFTP instance (see uftp_test_server.py), in
a time zone far from UTC so that the MDTM test can tell UTC from local time.

Normally run through test/run_tests.sh. Standalone:
  python3 test/test_rfc_compliance.py -v

RFCs: 959, 1123 (4.1), 2228, 2389, 2428, 2577, 3659, 4217.

Environment overrides:
  UFTP_BIN        path to the uFTP binary (default: ../build/uFTP)
  UFTP_RFC_PORT   control port to use      (default: 2123; the tests that need a
                  different server configuration use the next port)
"""

import calendar
import ftplib
import grp
import io
import os
import pwd
import re
import shutil
import socket
import ssl
import stat
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from uftp_test_server import UFTPTestServer, HOST  # noqa: E402
from ftp_test_client import (FtpControl, empty_directory, listening_socket,  # noqa: E402
                             port_argument, tls_client_context)

PORT = int(os.environ.get("UFTP_RFC_PORT", "2123"))
SERVER_TIME_ZONE = "Asia/Tokyo"      # UTC+9, no daylight saving time
FOREIGN_ADDRESS = "127.0.0.2"        # a loopback address that is not the client's

server = None


def setUpModule():
    global server
    previous_tz = os.environ.get("TZ")
    os.environ["TZ"] = SERVER_TIME_ZONE      # inherited by the server process only
    try:
        server = UFTPTestServer(port=PORT, idle_timeout=60)
        server.start()
    finally:
        if previous_tz is None:
            del os.environ["TZ"]
        else:
            os.environ["TZ"] = previous_tz


def tearDownModule():
    if server is not None:
        server.stop()


class Control(FtpControl):
    """Control connection to the server of this suite (or to the one on `port`)."""

    def __init__(self, login=True, timeout=5, port=None):
        super().__init__(port or PORT, server.user, server.password, login=login, timeout=timeout)


class RFCTestCase(unittest.TestCase):
    """Every test starts from an empty home and gets fresh control connections."""

    def setUp(self):
        empty_directory(server.home)
        self._connections = []

    def tearDown(self):
        for connection in self._connections:
            connection.close()

    def connect(self, login=True):
        connection = Control(login=login)
        self._connections.append(connection)
        return connection

    def make_file(self, name, content=b"0123456789"):
        with open(os.path.join(server.home, name), "wb") as f:
            f.write(content)

    def assertReply(self, connection, command, expected_code):
        code, text = connection.cmd(command)
        self.assertEqual(code, expected_code, f"{command!r} -> {text!r}")
        return text


class BeforeLoginTests(RFCTestCase):

    def test_welcome_is_220(self):
        self.assertEqual(self.connect(login=False).welcome[0], 220)

    def test_feat_syst_help_noop_allowed_before_login(self):
        """Clients use FEAT before logging in to discover AUTH TLS (RFC 2389, RFC 4217)."""
        c = self.connect(login=False)
        self.assertReply(c, "FEAT", 211)
        self.assertReply(c, "SYST", 215)
        self.assertReply(c, "HELP", 214)
        self.assertReply(c, "NOOP", 200)

    def test_other_commands_need_login(self):
        c = self.connect(login=False)
        for command in ("PWD", "CWD /", "LIST", "PASV", "EPSV", "PORT 127,0,0,1,200,10", "MKD x",
                        "DELE x", "SIZE x", "MDTM x", "STAT", "TYPE I", "RNFR x", "SITE HELP", "REST 0"):
            self.assertReply(c, command, 530)

    def test_wrong_password_is_530(self):
        """RFC 959: 530 Not logged in (430 is not an FTP reply code)."""
        c = self.connect(login=False)
        self.assertReply(c, f"USER {server.user}", 331)
        self.assertReply(c, "PASS definitely-wrong", 530)
        self.assertReply(c, "PWD", 530)

    def test_unknown_user_is_530(self):
        c = self.connect(login=False)
        self.assertReply(c, "USER nobody-here", 331)
        self.assertReply(c, "PASS whatever", 530)

    def test_user_without_name_is_501(self):
        self.assertReply(self.connect(login=False), "USER", 501)

    def test_pass_before_user_is_503(self):
        self.assertReply(self.connect(login=False), "PASS whatever", 503)

    def test_user_command_logs_out_current_user(self):
        c = self.connect()
        self.assertReply(c, "PWD", 257)
        self.assertReply(c, "USER tester2", 331)
        self.assertReply(c, "PWD", 530)
        self.assertReply(c, "PASS tester2Password", 230)
        self.assertReply(c, "PWD", 257)

    def test_unknown_command_is_500(self):
        c = self.connect()
        self.assertReply(c, "FOOBAR", 500)
        self.assertReply(c, "PWDX", 500)

    def test_quit_is_221(self):
        self.assertReply(self.connect(login=False), "QUIT", 221)


class CommandSyntaxTests(RFCTestCase):

    def test_commands_are_case_insensitive(self):
        c = self.connect(login=False)
        self.assertReply(c, f"user {server.user}", 331)
        self.assertReply(c, f"pAsS {server.password}", 230)
        self.assertReply(c, "noop", 200)
        self.assertReply(c, "Pwd", 257)

    def test_pipelined_commands(self):
        c = self.connect()
        c.sock.sendall(b"NOOP\r\nPWD\r\nSYST\r\n")
        self.assertEqual([c.read_reply()[0] for _ in range(3)], [200, 257, 215])

    def test_line_terminated_by_lf_only(self):
        c = self.connect()
        c.sock.sendall(b"NOOP\n")
        self.assertEqual(c.read_reply()[0], 200)

    def test_feat_lists_extensions(self):
        text = self.assertReply(self.connect(), "FEAT", 211)
        features = [line.strip() for line in text.splitlines()[1:-1]]
        for feature in ("EPSV", "EPRT", "UTF8", "SIZE", "MDTM", "REST STREAM"):
            self.assertIn(feature, features)
        self.assertTrue(text.splitlines()[-1].startswith("211 "))

    def test_syst(self):
        self.assertIn("UNIX", self.assertReply(self.connect(), "SYST", 215))

    def test_opts(self):
        c = self.connect()
        self.assertReply(c, "OPTS UTF8 ON", 200)
        self.assertReply(c, "OPTS UTF8 OFF", 200)
        self.assertReply(c, "OPTS", 501)
        self.assertReply(c, "OPTS NOSUCHOPTION", 501)

    def test_help_lists_commands(self):
        """RFC 1123 4.1.2.13: HELP belongs to the minimum implementation."""
        text = self.assertReply(self.connect(), "HELP", 214)
        lines = text.splitlines()
        self.assertTrue(lines[0].startswith("214-"))
        self.assertTrue(lines[-1].startswith("214 "))
        listed = " ".join(lines[1:-1]).split()
        for command in ("USER", "PASS", "QUIT", "PORT", "PASV", "EPSV", "EPRT", "RETR", "STOR",
                        "APPE", "LIST", "NLST", "CWD", "CDUP", "PWD", "MKD", "RMD", "DELE",
                        "RNFR", "RNTO", "SIZE", "MDTM", "REST", "TYPE", "MODE", "STRU",
                        "STAT", "SYST", "NOOP", "HELP", "FEAT", "AUTH"):
            self.assertIn(command, listed)
        self.assertReply(self.connect(), "HELP RETR", 214)

    def test_site(self):
        c = self.connect()
        text = self.assertReply(c, "SITE HELP", 214)
        self.assertIn("CHMOD", text)
        self.assertReply(c, "site help", 214)
        self.assertReply(c, "SITE", 501)
        self.assertReply(c, "SITE NOSUCHCOMMAND", 500)
        self.assertReply(c, "SITE HELPME", 500)

    def test_type(self):
        c = self.connect()
        for command, code in (("TYPE I", 200), ("TYPE A", 200), ("TYPE A N", 200), ("TYPE L 8", 200),
                              ("type i", 200), ("type a", 200),
                              ("TYPE E", 504), ("TYPE E N", 504), ("TYPE A T", 504), ("TYPE A C", 504),
                              ("TYPE L 16", 504),
                              ("TYPE", 501), ("TYPE X", 501), ("TYPE Ixyz", 501), ("TYPE AA", 501)):
            self.assertReply(c, command, code)

    def test_mode(self):
        c = self.connect()
        for command, code in (("MODE S", 200), ("mode s", 200), ("MODE B", 504), ("MODE C", 504),
                              ("MODE", 501), ("MODE X", 501), ("MODE SS", 501)):
            self.assertReply(c, command, code)

    def test_stru(self):
        c = self.connect()
        for command, code in (("STRU F", 200), ("stru f", 200), ("STRU R", 504), ("STRU P", 504),
                              ("STRU", 501), ("STRU X", 501), ("STRU FF", 501)):
            self.assertReply(c, command, code)

    def test_mode_and_stru_replies_do_not_talk_about_type(self):
        c = self.connect()
        self.assertNotIn("TYPE", self.assertReply(c, "MODE S", 200))
        self.assertNotIn("TYPE", self.assertReply(c, "STRU F", 200))

    def test_allo_is_superfluous(self):
        c = self.connect()
        self.assertReply(c, "ALLO 1024", 202)
        self.assertReply(c, "ALLO 1024 R 80", 202)

    def test_not_implemented_commands_are_502(self):
        """RFC 959: 502 for a known command that is not implemented (500 = unknown)."""
        c = self.connect()
        for command in ("REIN", "STOU", "SMNT /somewhere"):
            self.assertReply(c, command, 502)
        self.assertReply(c, "ACCT account", 502)
        self.assertReply(c, "PWD", 257)       # REIN did not change the session

    def test_noop_and_abor_without_transfer(self):
        c = self.connect()
        self.assertReply(c, "NOOP", 200)
        self.assertReply(c, "ABOR", 226)

    def test_stat_without_argument(self):
        text = self.assertReply(self.connect(), "STAT", 211)
        self.assertIn(server.user, text)

    def test_stat_with_path_lists_files(self):
        self.make_file("stat_me.txt")
        text = self.assertReply(self.connect(), "STAT .", 213)
        self.assertIn("stat_me.txt", text)


class RestTests(RFCTestCase):

    def test_rest_needs_a_number(self):
        """RFC 3659 section 5: REST <byte offset>."""
        c = self.connect()
        for command in ("REST", "REST abc", "REST 12x", "REST -5", "REST 1 2", "REST 1.5",
                        "REST 99999999999999999999999"):
            self.assertReply(c, command, 501)

    def test_rest_valid_offset(self):
        c = self.connect()
        self.assertIn("5", self.assertReply(c, "REST 5", 350))
        self.assertReply(c, "REST 0", 350)

    def test_invalid_rest_does_not_change_the_next_transfer(self):
        self.make_file("data.bin", b"0123456789")
        c = self.connect()
        self.assertReply(c, "REST abc", 501)
        self.assertEqual(c.download("RETR data.bin", c.pasv()), (226, b"0123456789"))

    def test_rest_then_retr_resumes(self):
        self.make_file("data.bin", b"0123456789")
        c = self.connect()
        data = c.pasv()
        self.assertReply(c, "REST 4", 350)
        self.assertEqual(c.download("RETR data.bin", data), (226, b"456789"))


class FileInformationTests(RFCTestCase):

    def test_size_of_file(self):
        self.make_file("ten.bin", b"0123456789")
        self.assertEqual(self.assertReply(self.connect(), "SIZE ten.bin", 213).strip(), "213 10")

    def test_size_of_directory_is_550(self):
        """RFC 3659 section 4: SIZE applies to files that can be transferred."""
        os.mkdir(os.path.join(server.home, "a_directory"))
        c = self.connect()
        self.assertReply(c, "SIZE a_directory", 550)
        self.assertReply(c, "SIZE /", 550)
        self.assertReply(c, "SIZE .", 550)

    def test_size_errors(self):
        c = self.connect()
        self.assertReply(c, "SIZE", 501)
        self.assertReply(c, "SIZE no_such_file", 550)
        self.assertReply(c, "SIZE ../../etc/passwd", 550)

    def test_mdtm_is_utc(self):
        """RFC 3659 section 2.3: time values are always UTC. The server runs in UTC+9."""
        self.make_file("dated.txt")
        timestamp = calendar.timegm((2021, 3, 4, 5, 6, 7))       # 2021-03-04 05:06:07 UTC
        os.utime(os.path.join(server.home, "dated.txt"), (timestamp, timestamp))
        text = self.assertReply(self.connect(), "MDTM dated.txt", 213)
        self.assertEqual(text.strip(), "213 20210304050607")

    def test_mdtm_of_directory(self):
        os.mkdir(os.path.join(server.home, "dated_dir"))
        timestamp = calendar.timegm((2020, 12, 31, 23, 59, 58))
        os.utime(os.path.join(server.home, "dated_dir"), (timestamp, timestamp))
        text = self.assertReply(self.connect(), "MDTM dated_dir", 213)
        self.assertEqual(text.strip(), "213 20201231235958")

    def test_mdtm_errors(self):
        c = self.connect()
        self.assertReply(c, "MDTM", 501)
        self.assertReply(c, "MDTM no_such_file", 550)
        self.assertReply(c, "MDTM ../../etc/passwd", 550)


class DirectoryTests(RFCTestCase):

    def test_pwd_at_root(self):
        self.assertEqual(ftplib.parse257(self.assertReply(self.connect(), "PWD", 257)), "/")
        self.assertEqual(ftplib.parse257(self.assertReply(self.connect(), "XPWD", 257)), "/")

    def test_mkd_cwd_pwd_cdup_rmd(self):
        c = self.connect()
        self.assertReply(c, "MKD folder", 257)
        self.assertTrue(os.path.isdir(os.path.join(server.home, "folder")))
        self.assertReply(c, "CWD folder", 250)
        self.assertEqual(ftplib.parse257(self.assertReply(c, "PWD", 257)), "/folder")
        self.assertReply(c, "CDUP", 250)
        self.assertEqual(ftplib.parse257(self.assertReply(c, "PWD", 257)), "/")
        self.assertReply(c, "RMD folder", 250)
        self.assertFalse(os.path.exists(os.path.join(server.home, "folder")))

    def test_x_command_aliases(self):
        c = self.connect()
        self.assertReply(c, "XMKD xfolder", 257)
        self.assertReply(c, "CWD xfolder", 250)
        self.assertReply(c, "XCUP", 250)
        self.assertReply(c, "XRMD xfolder", 250)

    def test_mkd_reply_is_the_absolute_path(self):
        """RFC 959 appendix II: the 257 reply to MKD carries the absolute pathname."""
        c = self.connect()
        self.assertEqual(ftplib.parse257(self.assertReply(c, "MKD outer", 257)), "/outer")
        self.assertReply(c, "CWD outer", 250)
        self.assertEqual(ftplib.parse257(self.assertReply(c, "MKD inner", 257)), "/outer/inner")
        self.assertEqual(ftplib.parse257(self.assertReply(c, "MKD /outer/second", 257)), "/outer/second")
        self.assertEqual(ftplib.parse257(self.assertReply(c, "MKD ../sibling", 257)), "/sibling")

    def test_double_quotes_are_doubled_in_257(self):
        """RFC 959 appendix II: a double quote inside the pathname is sent twice."""
        c = self.connect()
        text = self.assertReply(c, 'MKD say"hi"', 257)
        self.assertTrue(text.startswith('257 "/say""hi""" '), text)
        self.assertEqual(ftplib.parse257(text), '/say"hi"')
        self.assertReply(c, 'CWD say"hi"', 250)
        text = self.assertReply(c, "PWD", 257)
        self.assertTrue(text.startswith('257 "/say""hi""" '), text)
        self.assertEqual(ftplib.parse257(text), '/say"hi"')

    def test_cwd_errors_do_not_reveal_server_paths(self):
        c = self.connect()
        for command in ("CWD no_such_directory", "CWD ..x", "CWD /a/b/c", "CWD ../.."):
            text = self.assertReply(c, command, 550)
            self.assertNotIn(server.home, text)
            self.assertNotIn(server.workdir, text)

    def test_cwd_on_a_file_is_550(self):
        self.make_file("plain.txt")
        c = self.connect()
        text = self.assertReply(c, "CWD plain.txt", 550)
        self.assertNotIn(server.home, text)
        self.assertEqual(ftplib.parse257(self.assertReply(c, "PWD", 257)), "/")

    def test_cannot_leave_the_home(self):
        c = self.connect()
        self.assertReply(c, "CWD ../..", 550)
        self.assertReply(c, "CWD /../../etc", 550)
        self.assertEqual(ftplib.parse257(self.assertReply(c, "PWD", 257)), "/")
        self.assertReply(c, "RETR ../../../../etc/passwd", 425)     # no data connection yet
        self.assertEqual(c.download("RETR ../../../../etc/passwd", c.pasv())[0], 550)

    def test_missing_pathname_is_501(self):
        """RFC 959: 501 Syntax error in parameters or arguments."""
        c = self.connect()
        for command in ("CWD", "MKD", "XMKD", "RMD", "XRMD", "DELE", "RNFR", "RNTO", "SIZE", "MDTM",
                        "STOR", "APPE"):
            self.assertReply(c, command, 501)

    def test_dele(self):
        self.make_file("to_delete.txt")
        c = self.connect()
        self.assertReply(c, "DELE to_delete.txt", 250)
        self.assertFalse(os.path.exists(os.path.join(server.home, "to_delete.txt")))
        self.assertReply(c, "DELE to_delete.txt", 550)
        self.assertReply(c, "DELE ../../etc/passwd", 550)

    def test_dele_on_links_removes_the_link_only(self):
        self.make_file("target.txt")
        os.symlink("target.txt", os.path.join(server.home, "link_to_file"))
        os.symlink("no_such_target", os.path.join(server.home, "dangling_link"))
        c = self.connect()
        self.assertReply(c, "DELE link_to_file", 250)
        self.assertReply(c, "DELE dangling_link", 250)
        self.assertEqual(sorted(os.listdir(server.home)), ["target.txt"])

    def test_dele_does_not_remove_directories(self):
        """DELE is for files (RFC 959), directories are removed with RMD."""
        os.mkdir(os.path.join(server.home, "keep_me"))
        c = self.connect()
        self.assertReply(c, "DELE keep_me", 550)
        self.assertTrue(os.path.isdir(os.path.join(server.home, "keep_me")))
        self.assertReply(c, "RMD keep_me", 250)

    def test_rmd_errors(self):
        self.make_file("plain.txt")
        os.mkdir(os.path.join(server.home, "not_empty"))
        self.make_file("not_empty/file.txt")
        c = self.connect()
        self.assertReply(c, "RMD no_such_directory", 550)
        self.assertReply(c, "RMD plain.txt", 550)
        self.assertReply(c, "RMD not_empty", 550)
        self.assertReply(c, "RMD ../../etc", 550)
        self.assertTrue(os.path.isdir(os.path.join(server.home, "not_empty")))

    def test_mkd_existing_directory_is_550(self):
        c = self.connect()
        self.assertReply(c, "MKD twice", 257)
        self.assertReply(c, "MKD twice", 550)


class RenameTests(RFCTestCase):

    def test_rename(self):
        self.make_file("before.txt", b"content")
        c = self.connect()
        self.assertReply(c, "RNFR before.txt", 350)
        self.assertReply(c, "RNTO after.txt", 250)
        self.assertFalse(os.path.exists(os.path.join(server.home, "before.txt")))
        with open(os.path.join(server.home, "after.txt"), "rb") as f:
            self.assertEqual(f.read(), b"content")

    def test_rename_directory(self):
        os.mkdir(os.path.join(server.home, "old_dir"))
        c = self.connect()
        self.assertReply(c, "RNFR old_dir", 350)
        self.assertReply(c, "RNTO new_dir", 250)
        self.assertTrue(os.path.isdir(os.path.join(server.home, "new_dir")))

    def test_rnfr_on_missing_file_is_550(self):
        """RNFR used to answer 350 for a file that does not exist."""
        c = self.connect()
        self.assertReply(c, "RNFR no_such_file", 550)
        self.assertReply(c, "RNTO anything", 503)        # the failed RNFR left nothing pending

    def test_rnfr_outside_home_is_550(self):
        self.assertReply(self.connect(), "RNFR ../../etc/passwd", 550)

    def test_rnto_without_rnfr_is_503(self):
        self.assertReply(self.connect(), "RNTO anything", 503)

    def test_rnto_is_consumed_by_one_rename(self):
        self.make_file("once.txt")
        c = self.connect()
        self.assertReply(c, "RNFR once.txt", 350)
        self.assertReply(c, "RNTO renamed.txt", 250)
        self.assertReply(c, "RNTO again.txt", 503)

    def test_rnto_when_the_source_is_gone_is_550(self):
        self.make_file("vanishing.txt")
        c = self.connect()
        self.assertReply(c, "RNFR vanishing.txt", 350)
        os.remove(os.path.join(server.home, "vanishing.txt"))
        self.assertReply(c, "RNTO new_name.txt", 550)
        self.assertFalse(os.path.exists(os.path.join(server.home, "new_name.txt")))

    def test_rnto_outside_home_is_553(self):
        """RFC 959: 553 Requested action not taken, file name not allowed."""
        self.make_file("stay.txt")
        c = self.connect()
        self.assertReply(c, "RNFR stay.txt", 350)
        self.assertReply(c, "RNTO ../../tmp/escaped.txt", 553)
        self.assertTrue(os.path.exists(os.path.join(server.home, "stay.txt")))

    def test_rnto_that_cannot_be_done_is_553(self):
        """rename() of a file over a non empty directory fails: 553, not 503."""
        self.make_file("file.txt")
        os.mkdir(os.path.join(server.home, "busy_dir"))
        self.make_file("busy_dir/inside.txt")
        c = self.connect()
        self.assertReply(c, "RNFR file.txt", 350)
        self.assertReply(c, "RNTO busy_dir", 553)
        self.assertTrue(os.path.exists(os.path.join(server.home, "file.txt")))


class PassiveTransferTests(RFCTestCase):

    def test_data_command_without_data_connection_is_425(self):
        c = self.connect()
        for command in ("LIST", "NLST", "RETR x", "STOR x", "APPE x"):
            self.assertReply(c, command, 425)

    def test_pasv_list_and_nlst(self):
        self.make_file("alpha.txt", b"12345")
        os.mkdir(os.path.join(server.home, "beta"))
        c = self.connect()
        code, listing = c.download("LIST", c.pasv())
        self.assertEqual(code, 226)
        lines = listing.decode().splitlines()
        self.assertTrue(any(l.startswith("-") and l.endswith(" alpha.txt") and " 5 " in l for l in lines), lines)
        self.assertTrue(any(l.startswith("d") and l.endswith(" beta") for l in lines), lines)
        code, names = c.download("NLST", c.pasv())
        self.assertEqual(code, 226)
        self.assertEqual(sorted(names.decode().splitlines()), ["alpha.txt", "beta"])
        self.assertTrue(lines[0].startswith("total "), lines)

    def test_listing_lines_end_with_crlf(self):
        self.make_file("crlf.txt")
        c = self.connect()
        code, names = c.download("NLST", c.pasv())
        self.assertEqual((code, names), (226, b"crlf.txt\r\n"))
        code, listing = c.download("LIST", c.pasv())
        self.assertEqual(code, 226)
        self.assertEqual(listing.count(b"\n"), listing.count(b"\r\n"), "bare LF in the listing")

    def test_list_of_missing_path_is_550(self):
        c = self.connect()
        self.assertEqual(c.download("LIST no_such_directory", c.pasv())[0], 550)
        self.assertEqual(c.download("NLST no_such_directory", c.pasv())[0], 550)

    def test_nlst_of_empty_directory_is_empty(self):
        """RFC 959: NLST sends pathnames only, no "total" line."""
        c = self.connect()
        self.assertEqual(c.download("NLST", c.pasv()), (226, b""))

    def test_fifo_is_not_a_file(self):
        """Opening a FIFO blocks until somebody writes to it: it must never be opened."""
        os.mkfifo(os.path.join(server.home, "a_fifo"))
        c = self.connect()
        self.assertReply(c, "SIZE a_fifo", 550)
        self.assertEqual(c.download("RETR a_fifo", c.pasv())[0], 550)
        self.assertReply(self.connect(), "NOOP", 200)      # the server is not stuck

    def test_list_of_a_single_file(self):
        self.make_file("single.txt", b"12345")
        self.make_file("other.txt")
        c = self.connect()
        code, listing = c.download("LIST single.txt", c.pasv())
        self.assertEqual(code, 226)
        self.assertIn(b"single.txt", listing)
        self.assertNotIn(b"other.txt", listing)

    def test_stor_overwrites_an_existing_file(self):
        self.make_file("existing.txt", b"old and longer content")
        c = self.connect()
        self.assertEqual(c.upload("STOR existing.txt", c.pasv(), b"new"), 226)
        with open(os.path.join(server.home, "existing.txt"), "rb") as f:
            self.assertEqual(f.read(), b"new")

    def test_retr_follows_a_link_to_a_file_in_the_home(self):
        self.make_file("target.txt", b"linked content")
        os.symlink("target.txt", os.path.join(server.home, "link.txt"))
        c = self.connect()
        self.assertEqual(self.assertReply(c, "SIZE link.txt", 213).strip(), "213 14")
        self.assertEqual(c.download("RETR link.txt", c.pasv()), (226, b"linked content"))

    def test_retr_of_directory_is_550(self):
        os.mkdir(os.path.join(server.home, "a_directory"))
        c = self.connect()
        self.assertEqual(c.download("RETR a_directory", c.pasv())[0], 550)

    def test_epsv_store_retrieve_append(self):
        payload = bytes(range(256)) * 300
        c = self.connect()
        self.assertEqual(c.upload("STOR blob.bin", c.epsv(), payload), 226)
        self.assertEqual(self.assertReply(c, "SIZE blob.bin", 213).strip(), "213 %d" % len(payload))
        self.assertEqual(c.download("RETR blob.bin", c.epsv()), (226, payload))
        self.assertEqual(c.upload("APPE blob.bin", c.epsv(), b"tail"), 226)
        self.assertEqual(c.download("RETR blob.bin", c.pasv()), (226, payload + b"tail"))

    def test_type_a_transfers_bytes_unchanged(self):
        """TYPE A is accepted, data always travels as an unmodified 8 bit stream."""
        payload = b"line one\nline two\r\nbinary \x00\xff\n"
        c = self.connect()
        self.assertReply(c, "TYPE A", 200)
        self.assertEqual(c.upload("STOR text.txt", c.pasv(), payload), 226)
        self.assertEqual(c.download("RETR text.txt", c.pasv()), (226, payload))

    def test_retr_missing_file_is_550(self):
        c = self.connect()
        self.assertEqual(c.download("RETR no_such_file", c.pasv())[0], 550)

    def test_stor_outside_home_is_550(self):
        c = self.connect()
        self.assertEqual(c.upload("STOR ../../tmp/uftp_escape_test.txt", c.pasv(), b"x"), 550)
        self.assertFalse(os.path.exists("/tmp/uftp_escape_test.txt"))

    def test_epsv_reply_format(self):
        """RFC 2428 section 3: 229 <text> (|||port|)."""
        text = self.assertReply(self.connect(), "EPSV", 229)
        self.assertRegex(text, r"\(\|\|\|\d{1,5}\|\)")

    def test_pasv_reply_format(self):
        text = self.assertReply(self.connect(), "PASV", 227)
        self.assertRegex(text, r"\(127,0,0,1,\d{1,3},\d{1,3}\)")


class PassiveSourceAddressTests(RFCTestCase):
    """RFC 2577: a passive data connection must come from the host of the control
    connection. The passive port is announced in clear text and comes from a small
    range: anybody reaching it first used to get the transfer."""

    def passive_port(self, c, command):
        code, text = c.cmd(command)
        self.assertIn(code, (227, 229), text)
        if code == 227:
            n = [int(x) for x in re.search(r"\(([\d,]+)\)", text).group(1).split(",")]
            return n[4] * 256 + n[5]
        return int(re.search(r"\(\|\|\|(\d+)\|\)", text).group(1))

    @staticmethod
    def connect_from(source, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((source, 0))
        s.settimeout(5)
        s.connect((HOST, port))
        return s

    def check_foreign_connection_refused(self, command):
        self.make_file("secret.txt", b"ONLY-FOR-THE-CLIENT")
        c = self.connect()
        port = self.passive_port(c, command)
        foreign = self.connect_from(FOREIGN_ADDRESS, port)      # reaches the port first
        self.addCleanup(foreign.close)
        time.sleep(0.3)
        data = self.connect_from(HOST, port)                    # the real client
        self.addCleanup(data.close)
        self.assertReply(c, "RETR secret.txt", 150)
        received = b""
        while True:
            chunk = data.recv(4096)
            if not chunk:
                break
            received += chunk
        self.assertEqual(c.read_reply()[0], 226)
        self.assertEqual(received, b"ONLY-FOR-THE-CLIENT")
        self.assertEqual(foreign.recv(100), b"", "the foreign connection got data or stayed open")

    def test_pasv_connection_from_another_address_is_refused(self):
        self.check_foreign_connection_refused("PASV")

    def test_epsv_connection_from_another_address_is_refused(self):
        self.check_foreign_connection_refused("EPSV")

    def test_list_goes_to_the_client(self):
        self.make_file("visible.txt")
        c = self.connect()
        port = self.passive_port(c, "PASV")
        foreign = self.connect_from(FOREIGN_ADDRESS, port)
        self.addCleanup(foreign.close)
        time.sleep(0.3)
        data = self.connect_from(HOST, port)
        self.addCleanup(data.close)
        self.assertReply(c, "NLST", 150)
        names = b""
        while True:
            chunk = data.recv(4096)
            if not chunk:
                break
            names += chunk
        self.assertEqual(c.read_reply()[0], 226)
        self.assertEqual(names, b"visible.txt\r\n")
        self.assertEqual(foreign.recv(100), b"")


class PasvPromiscuousTests(unittest.TestCase):
    """PASV_PROMISCUOUS = true restores the old behaviour, for networks where control
    and data connections leave from different addresses."""

    def setUp(self):
        self.server = UFTPTestServer(port=PORT + 4, idle_timeout=60,
                                     extra_config={"PASV_PROMISCUOUS": "true"})
        self.server.start()
        self.addCleanup(self.server.stop)
        with open(os.path.join(self.server.home, "file.txt"), "wb") as f:
            f.write(b"PROMISCUOUS")

    def test_data_connection_from_another_address_is_accepted(self):
        c = Control(login=False, port=PORT + 4)
        self.addCleanup(c.close)
        c.login(self.server.user, self.server.password)
        code, text = c.cmd("PASV")
        self.assertEqual(code, 227, text)
        n = [int(x) for x in re.search(r"\(([\d,]+)\)", text).group(1).split(",")]
        data = PassiveSourceAddressTests.connect_from(FOREIGN_ADDRESS, n[4] * 256 + n[5])
        self.addCleanup(data.close)
        self.assertEqual(c.cmd("RETR file.txt")[0], 150)
        received = b""
        while True:
            chunk = data.recv(4096)
            if not chunk:
                break
            received += chunk
        self.assertEqual(c.read_reply()[0], 226)
        self.assertEqual(received, b"PROMISCUOUS")


class ActiveModeTests(RFCTestCase):
    """PORT / EPRT: syntax validation and FTP bounce protection (RFC 2577 section 3)."""

    def test_port_transfer(self):
        self.make_file("active.txt", b"active mode")
        listener, port = listening_socket()
        self.addCleanup(listener.close)
        c = self.connect()
        self.assertReply(c, "PORT " + port_argument(HOST, port), 200)
        data, _ = listener.accept()
        self.assertEqual(c.download("RETR active.txt", data), (226, b"active mode"))

    def test_port_syntax_errors_are_501(self):
        """A malformed PORT used to be executed with uninitialized values, without any reply."""
        c = self.connect()
        for argument in ("", "1,2,3", "127,0,0,1,200", "127,0,0,1,200,10,5", "256,0,0,1,200,10",
                         "127,0,0,1,256,10", "127,0,0,1,200,256", "127,0,0,-1,200,10",
                         "a,b,c,d,e,f", "127.0.0.1,200,10", "127,0,0,1,200,10 extra", "127,0,0,1,200,10x"):
            self.assertReply(c, ("PORT " + argument).strip(), 501)
        self.assertReply(c, "NOOP", 200)      # the control connection is still usable

    def test_port_to_privileged_port_is_refused(self):
        """RFC 2577 section 3: no data connections to ports below 1024 (suggested reply 504)."""
        c = self.connect()
        for port in (0, 21, 22, 25, 80, 443, 1023):
            self.assertReply(c, "PORT " + port_argument(HOST, port), 504)
        self.assertReply(c, "LIST", 425)      # the refused PORT did not set up anything

    def test_port_to_another_host_is_refused(self):
        """FTP bounce: the server must not connect to an address that is not the client's."""
        listener, port = listening_socket(FOREIGN_ADDRESS)
        self.addCleanup(listener.close)
        c = self.connect()
        self.assertReply(c, "PORT " + port_argument(FOREIGN_ADDRESS, port), 504)
        listener.settimeout(1)
        with self.assertRaises(socket.timeout):
            listener.accept()
        self.assertReply(c, "LIST", 425)
        self.assertReply(c, "PORT 10,11,12,13,200,10", 504)
        self.assertReply(c, "NOOP", 200)

    def test_no_transfer_in_either_direction_after_a_refused_port(self):
        """RETR would send a file to the third host, STOR would read data from
        it (SSRF in both directions). After a refused PORT/EPRT nothing is set up."""
        self.make_file("payload.txt", b"must not leave")
        listener, port = listening_socket(FOREIGN_ADDRESS)
        self.addCleanup(listener.close)
        c = self.connect()
        for command in ("PORT " + port_argument(FOREIGN_ADDRESS, port), f"EPRT |1|{FOREIGN_ADDRESS}|{port}|"):
            self.assertReply(c, command, 504)
            self.assertReply(c, "RETR payload.txt", 425)
            self.assertReply(c, "STOR injected.txt", 425)
            self.assertReply(c, "APPE payload.txt", 425)
        listener.settimeout(1)
        with self.assertRaises(socket.timeout):
            listener.accept()
        self.assertFalse(os.path.exists(os.path.join(server.home, "injected.txt")))

    def test_eprt_transfer(self):
        self.make_file("eprt.txt", b"extended active mode")
        listener, port = listening_socket()
        self.addCleanup(listener.close)
        c = self.connect()
        self.assertReply(c, f"EPRT |1|{HOST}|{port}|", 200)
        data, _ = listener.accept()
        self.assertEqual(c.download("RETR eprt.txt", data), (226, b"extended active mode"))

    def test_eprt_accepts_any_delimiter(self):
        """RFC 2428 section 2: the delimiter is any ASCII character from 33 to 126."""
        self.make_file("delimiter.txt", b"ok")
        for delimiter in ("!", "#", "@", "~"):
            listener, port = listening_socket()
            self.addCleanup(listener.close)
            c = self.connect()
            self.assertReply(c, "EPRT " + delimiter.join(["", "1", HOST, str(port), ""]), 200)
            data, _ = listener.accept()
            self.assertEqual(c.download("RETR delimiter.txt", data), (226, b"ok"))

    def test_eprt_unsupported_protocol_is_522(self):
        """RFC 2428 section 2: 522 with the list of supported protocols, e.g. (1,2)."""
        c = self.connect()
        for protocol in ("3", "0", "9", "99"):
            text = self.assertReply(c, f"EPRT |{protocol}|{HOST}|50000|", 522)
            self.assertRegex(text, r"\(1(,2)?\)")

    def test_eprt_syntax_errors_are_501(self):
        c = self.connect()
        for argument in ("", "|1|127.0.0.1|", "|1|127.0.0.1", "|1||50000|", "||127.0.0.1|50000|",
                         "|1|999.1.1.1|50000|", "|1|not-an-address|50000|", "|1|127.0.0.1|0|",
                         "|1|127.0.0.1|70000|", "|1|127.0.0.1|abc|", "|1|127.0.0.1|50000|extra",
                         "|x|127.0.0.1|50000|", "|1|::1|50000|", "|2|127.0.0.1|50000|",
                         "1|127.0.0.1|50000"):
            self.assertReply(c, ("EPRT " + argument).strip(), 501)
        self.assertReply(c, "NOOP", 200)

    def test_eprt_overlong_address_is_501(self):
        """The address used to be copied with an unbounded sscanf("%[^|]")."""
        c = self.connect()
        self.assertReply(c, "EPRT |1|" + "1" * 3000 + "|50000|", 501)
        self.assertReply(c, "EPRT |2|" + "a:" * 1500 + "|50000|", 501)
        self.assertReply(c, "NOOP", 200)

    def test_eprt_bounce_protection(self):
        listener, port = listening_socket(FOREIGN_ADDRESS)
        self.addCleanup(listener.close)
        c = self.connect()
        self.assertReply(c, f"EPRT |1|{FOREIGN_ADDRESS}|{port}|", 504)
        listener.settimeout(1)
        with self.assertRaises(socket.timeout):
            listener.accept()
        self.assertReply(c, f"EPRT |1|{HOST}|22|", 504)
        self.assertReply(c, f"EPRT |1|{HOST}|1023|", 504)
        self.assertReply(c, "LIST", 425)

    def test_eprt_ipv6_address_that_is_not_the_client(self):
        """504 (not the client address) with ipv6 support, 522 in a build without it."""
        code, text = self.connect().cmd("EPRT |2|::1|50000|")
        self.assertIn(code, (504, 522), text)


class SiteChmodTests(RFCTestCase):

    def mode(self, name):
        return stat.S_IMODE(os.stat(os.path.join(server.home, name)).st_mode)

    def test_chmod_file(self):
        self.make_file("perm.txt")
        os.chmod(os.path.join(server.home, "perm.txt"), 0o644)
        c = self.connect()
        self.assertReply(c, "SITE CHMOD 600 perm.txt", 200)
        self.assertEqual(self.mode("perm.txt"), 0o600)
        self.assertReply(c, "site chmod 0640 /perm.txt", 200)
        self.assertEqual(self.mode("perm.txt"), 0o640)

    def test_chmod_directory(self):
        os.mkdir(os.path.join(server.home, "perm_dir"))
        self.make_file("perm_dir/inner.txt")
        c = self.connect()
        self.assertReply(c, "SITE CHMOD 750 perm_dir", 200)
        self.assertEqual(self.mode("perm_dir"), 0o750)
        self.assertReply(c, "CWD perm_dir", 250)
        self.assertReply(c, "SITE CHMOD 604 inner.txt", 200)
        self.assertEqual(self.mode("perm_dir/inner.txt"), 0o604)

    def test_chmod_cannot_reach_outside_the_home(self):
        """SITE CHMOD used to join the path to the current directory with no check."""
        outside = os.path.join(server.workdir, "outside.txt")
        with open(outside, "wb") as f:
            f.write(b"not yours")
        os.chmod(outside, 0o644)
        self.addCleanup(os.remove, outside)
        c = self.connect()
        self.assertReply(c, "SITE CHMOD 777 ../outside.txt", 550)
        self.assertReply(c, "SITE CHMOD 777 ../../../../../../" + outside.lstrip("/"), 550)
        self.assertEqual(stat.S_IMODE(os.stat(outside).st_mode), 0o644)

    def test_chmod_missing_file_is_550(self):
        self.assertReply(self.connect(), "SITE CHMOD 644 no_such_file", 550)

    def test_chmod_syntax_errors_are_501(self):
        """An invalid mode used to be read as 0 and applied (chmod 000)."""
        self.make_file("perm.txt")
        os.chmod(os.path.join(server.home, "perm.txt"), 0o644)
        c = self.connect()
        for command in ("SITE CHMOD", "SITE CHMOD 644", "SITE CHMOD perm.txt", "SITE CHMOD zzz perm.txt",
                        "SITE CHMOD 888 perm.txt", "SITE CHMOD 64x perm.txt", "SITE CHMOD 77777 perm.txt",
                        "SITE CHMOD -1 perm.txt", "SITE CHMOD u+x perm.txt"):
            self.assertReply(c, command, 501)
        self.assertEqual(self.mode("perm.txt"), 0o644)


class DataConnectionReuseTests(RFCTestCase):
    """A worker cancelled while it waits for a command must not block the server."""

    def assertServerResponds(self):
        self.assertReply(self.connect(), "NOOP", 200)

    def test_second_pasv_replaces_a_connected_data_channel(self):
        self.make_file("data.bin", b"0123456789")
        c = self.connect()
        first = c.pasv()
        self.addCleanup(first.close)
        self.assertEqual(c.download("RETR data.bin", c.pasv()), (226, b"0123456789"))
        self.assertServerResponds()

    def test_many_pasv_in_a_row(self):
        self.make_file("data.bin", b"0123456789")
        c = self.connect()
        for _ in range(5):
            pending = c.pasv()
            self.addCleanup(pending.close)
        for _ in range(3):
            pending = c.epsv()
            self.addCleanup(pending.close)
        self.assertEqual(c.download("RETR data.bin", c.pasv()), (226, b"0123456789"))
        self.assertServerResponds()

    def test_disconnect_after_two_pasv_does_not_hang_the_server(self):
        """PASV + data connection, PASV again, control connection closed: the server hung."""
        c = self.connect()
        first = c.pasv()
        second = c.pasv()
        c.close()
        first.close()
        second.close()
        self.assertServerResponds()

    def test_disconnect_with_a_connected_data_channel(self):
        c = self.connect()
        data = c.pasv()
        c.close()
        data.close()
        self.assertServerResponds()

    def test_pasv_after_a_failed_transfer_command(self):
        self.make_file("data.bin", b"0123456789")
        c = self.connect()
        self.assertEqual(c.download("RETR no_such_file", c.pasv())[0], 550)
        self.assertEqual(c.download("RETR no_such_file", c.epsv())[0], 550)
        self.assertEqual(c.download("RETR data.bin", c.pasv()), (226, b"0123456789"))

    def pipelined(self, commands, expected_codes):
        """Send all the commands in a single write. Every command must get exactly one
        reply (RFC 959): its normal reply, or 425 when the next command replaced its
        data connection before it was set up. The last command is never replaced."""
        self.make_file("data.bin", b"0123456789")
        c = self.connect()
        c.sock.sendall(b"".join(command.encode() + b"\r\n" for command in commands))
        codes = [c.read_reply()[0] for _ in commands]
        for command, code, expected in zip(commands, codes, expected_codes):
            self.assertIn(code, (expected, 425), f"{command!r} -> {code}, all replies: {codes}")
        self.assertEqual(codes[-1], expected_codes[-1], f"last command must not be superseded: {codes}")
        self.assertReply(c, "NOOP", 200)          # no reply left over: client and server in step
        self.assertEqual(c.download("RETR data.bin", c.pasv()), (226, b"0123456789"))
        self.assertServerResponds()

    def test_pipelined_pasv(self):
        """Data channel commands in the same read used to start two workers
        at once, sharing the same SSL objects (double free, server crash)."""
        for _ in range(3):
            self.pipelined(["PASV"] * 8, [227] * 8)

    def test_pipelined_epsv(self):
        for _ in range(3):
            self.pipelined(["EPSV"] * 8, [229] * 8)

    def test_pipelined_port(self):
        listener, port = listening_socket()
        listener.listen(16)
        self.addCleanup(listener.close)
        for _ in range(3):
            self.pipelined(["PORT " + port_argument(HOST, port)] * 4, [200] * 4)

    def test_pipelined_mixed_data_channel_commands(self):
        listener, port = listening_socket()
        listener.listen(16)
        self.addCleanup(listener.close)
        self.pipelined(["PASV", "EPSV", "PORT " + port_argument(HOST, port), f"EPRT |1|{HOST}|{port}|", "PASV"],
                       [227, 229, 200, 200, 227])

    def test_pipelined_pasv_then_abor(self):
        c = self.connect()
        c.sock.sendall(b"PASV\r\nABOR\r\n")
        first = c.read_reply()[0]
        self.assertIn(first, (227, 425))
        replies = [first]
        while replies[-1] != 226:          # ABOR answers 426 + 226, or 226 alone
            replies.append(c.read_reply()[0])
        self.assertReply(c, "NOOP", 200)
        self.assertServerResponds()

    def test_port_replaces_a_pending_port(self):
        """A second PORT/EPRT got no reply: the old worker reset the port of the new one."""
        self.make_file("data.bin", b"0123456789")
        c = self.connect()
        listener, port = listening_socket()
        self.addCleanup(listener.close)
        self.assertReply(c, "PORT " + port_argument(HOST, port), 200)
        unused, _ = listener.accept()
        self.addCleanup(unused.close)
        self.assertReply(c, f"EPRT |1|{HOST}|{port}|", 200)
        unused, _ = listener.accept()
        self.addCleanup(unused.close)
        self.assertReply(c, "PORT " + port_argument(HOST, port), 200)
        data, _ = listener.accept()
        self.assertEqual(c.download("RETR data.bin", data), (226, b"0123456789"))

    def test_switch_between_active_and_passive(self):
        self.make_file("data.bin", b"0123456789")
        c = self.connect()
        listener, port = listening_socket()
        self.addCleanup(listener.close)
        self.assertReply(c, "PORT " + port_argument(HOST, port), 200)
        unused, _ = listener.accept()
        self.addCleanup(unused.close)
        self.assertEqual(c.download("RETR data.bin", c.pasv()), (226, b"0123456789"))
        pending = c.pasv()
        self.addCleanup(pending.close)
        self.assertReply(c, "PORT " + port_argument(HOST, port), 200)
        data, _ = listener.accept()
        self.assertEqual(c.download("RETR data.bin", data), (226, b"0123456789"))
        self.assertServerResponds()


class HomeJailTests(RFCTestCase):
    """Nothing outside the home can be read, written, listed or
    changed, through a sibling directory with the same prefix or a symbolic link."""

    def setUp(self):
        super().setUp()
        # a sibling of the home whose name starts like the home: <workdir>/home2
        self.sibling = server.home + "2"
        shutil.rmtree(self.sibling, ignore_errors=True)
        os.mkdir(self.sibling)
        self.addCleanup(shutil.rmtree, self.sibling, True)
        self.sibling_file = os.path.join(self.sibling, "secret.txt")
        self.write(self.sibling_file, b"SIBLING-SECRET")
        # a file and a directory outside the home, reached through links in the home
        self.outside_file = os.path.join(server.workdir, "outside.txt")
        self.write(self.outside_file, b"OUTSIDE-SECRET")
        self.addCleanup(self.remove, self.outside_file)
        os.symlink(self.outside_file, os.path.join(server.home, "link_to_file"))
        os.symlink(self.sibling, os.path.join(server.home, "link_to_dir"))
        # a dangling link pointing outside: an O_CREAT open would create the target
        self.dangling_target = os.path.join(server.workdir, "created_through_link.txt")
        self.addCleanup(self.remove, self.dangling_target)
        os.symlink(self.dangling_target, os.path.join(server.home, "dangling_out"))

    @staticmethod
    def write(path, content):
        with open(path, "wb") as f:
            f.write(content)
        os.chmod(path, 0o600)

    @staticmethod
    def remove(path):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass

    def mode(self, path):
        return stat.S_IMODE(os.stat(path).st_mode)

    def test_sibling_directory_with_the_same_prefix(self):
        c = self.connect()
        for path in ("../home2/secret.txt", "/../home2/secret.txt"):
            self.assertEqual(c.download("RETR " + path, c.pasv()), (550, b""), path)
            self.assertReply(c, "SIZE " + path, 550)
            self.assertReply(c, "MDTM " + path, 550)
        self.assertEqual(c.download("LIST ../home2", c.pasv())[0], 550)
        self.assertReply(c, "CWD ../home2", 550)
        self.assertEqual(ftplib.parse257(self.assertReply(c, "PWD", 257)), "/")

    def test_sibling_directory_can_not_be_written(self):
        c = self.connect()
        self.assertEqual(c.upload("STOR ../home2/new.txt", c.pasv(), b"x"), 550)
        self.assertEqual(c.upload("APPE ../home2/secret.txt", c.pasv(), b"x"), 550)
        self.assertReply(c, "MKD ../home2/new_dir", 550)
        self.assertReply(c, "DELE ../home2/secret.txt", 550)
        self.assertReply(c, "RNFR ../home2/secret.txt", 550)
        self.assertReply(c, "SITE CHMOD 666 ../home2/secret.txt", 550)
        self.assertEqual(sorted(os.listdir(self.sibling)), ["secret.txt"])
        self.assertEqual(self.mode(self.sibling_file), 0o600)
        with open(self.sibling_file, "rb") as f:
            self.assertEqual(f.read(), b"SIBLING-SECRET")

    def test_rename_into_the_sibling_directory(self):
        self.make_file("mine.txt")
        c = self.connect()
        self.assertReply(c, "RNFR mine.txt", 350)
        self.assertReply(c, "RNTO ../home2/mine.txt", 553)
        self.assertTrue(os.path.exists(os.path.join(server.home, "mine.txt")))

    def test_link_to_a_file_outside(self):
        c = self.connect()
        self.assertEqual(c.download("RETR link_to_file", c.pasv()), (550, b""))
        self.assertReply(c, "SIZE link_to_file", 550)
        self.assertReply(c, "MDTM link_to_file", 550)
        self.assertEqual(c.upload("STOR link_to_file", c.pasv(), b"overwritten"), 550)
        self.assertEqual(c.upload("APPE link_to_file", c.pasv(), b"appended"), 550)
        self.assertReply(c, "SITE CHMOD 666 link_to_file", 550)
        self.assertEqual(self.mode(self.outside_file), 0o600)
        with open(self.outside_file, "rb") as f:
            self.assertEqual(f.read(), b"OUTSIDE-SECRET")

    def test_link_to_a_directory_outside(self):
        c = self.connect()
        self.assertReply(c, "CWD link_to_dir", 550)
        self.assertEqual(c.download("LIST link_to_dir", c.pasv())[0], 550)
        self.assertEqual(c.download("RETR link_to_dir/secret.txt", c.pasv()), (550, b""))
        self.assertEqual(c.upload("STOR link_to_dir/new.txt", c.pasv(), b"x"), 550)
        self.assertReply(c, "MKD link_to_dir/new_dir", 550)
        self.assertReply(c, "SITE CHMOD 666 link_to_dir/secret.txt", 550)
        self.assertEqual(sorted(os.listdir(self.sibling)), ["secret.txt"])
        self.assertEqual(self.mode(self.sibling_file), 0o600)

    def test_dangling_link_pointing_outside(self):
        c = self.connect()
        self.assertEqual(c.upload("STOR dangling_out", c.pasv(), b"created"), 550)
        self.assertReply(c, "MKD dangling_out", 550)
        self.assertFalse(os.path.lexists(self.dangling_target))

    def test_links_themselves_can_be_deleted_and_renamed(self):
        """DELE, RNFR and RNTO act on the link, never on the file outside."""
        c = self.connect()
        self.assertReply(c, "RNFR link_to_file", 350)
        self.assertReply(c, "RNTO renamed_link", 250)
        self.assertTrue(os.path.islink(os.path.join(server.home, "renamed_link")))
        self.assertReply(c, "DELE renamed_link", 250)
        self.assertReply(c, "DELE dangling_out", 250)
        self.assertFalse(os.path.lexists(os.path.join(server.home, "renamed_link")))
        with open(self.outside_file, "rb") as f:
            self.assertEqual(f.read(), b"OUTSIDE-SECRET")

    def test_links_inside_the_home_still_work(self):
        os.mkdir(os.path.join(server.home, "real_dir"))
        self.make_file("real_dir/inner.txt", b"inner")
        os.symlink("real_dir", os.path.join(server.home, "dir_link"))
        os.symlink("real_dir/inner.txt", os.path.join(server.home, "file_link"))
        c = self.connect()
        self.assertEqual(c.download("RETR file_link", c.pasv()), (226, b"inner"))
        self.assertReply(c, "SITE CHMOD 640 file_link", 200)
        self.assertEqual(self.mode(os.path.join(server.home, "real_dir", "inner.txt")), 0o640)
        self.assertReply(c, "CWD dir_link", 250)
        self.assertEqual(c.download("RETR inner.txt", c.pasv()), (226, b"inner"))
        self.assertReply(c, "CDUP", 250)
        self.assertEqual(c.upload("STOR dir_link/new.txt", c.pasv(), b"new"), 226)
        self.assertTrue(os.path.exists(os.path.join(server.home, "real_dir", "new.txt")))

    def test_new_files_in_new_and_nested_directories(self):
        c = self.connect()
        self.assertReply(c, "MKD a", 257)
        self.assertReply(c, "MKD a/b", 257)
        self.assertEqual(c.upload("STOR a/b/c.txt", c.pasv(), b"deep"), 226)
        self.assertEqual(c.upload("STOR /a/b/d.txt", c.pasv(), b"deep"), 226)
        # a directory that does not exist (yet): temporary error, see MissingDirectoryTests
        self.assertEqual(c.upload("STOR no_such_dir/e.txt", c.pasv(), b"x"), 450)
        self.assertEqual(sorted(os.listdir(os.path.join(server.home, "a", "b"))), ["c.txt", "d.txt"])


class MissingDirectoryTests(RFCTestCase):
    """STOR/APPE into a directory that does not exist: 450 (temporary, RFC 959) when the
    missing directory is inside the home, so that a client that uploads in parallel can
    retry once another connection has created it (the 550 of before lost the file: the
    client does not retry a permanent error). Anywhere else the answer stays 550, and it
    must not tell whether a directory outside the home exists."""

    def test_stor_into_a_missing_directory_is_450(self):
        c = self.connect()
        for command in ("STOR", "APPE"):
            data = c.pasv()
            self.addCleanup(data.close)
            code, text = c.cmd(f"{command} missing/dir/file.txt")
            self.assertEqual(code, 450, text)
            self.assertIn("try again", text)
        self.assertFalse(os.path.exists(os.path.join(server.home, "missing")))

    def test_the_same_upload_works_once_the_directory_exists(self):
        """What a client does after the 450: create the directory, upload again."""
        c = self.connect()
        self.assertEqual(c.upload("STOR late/file.txt", c.pasv(), b"x"), 450)
        self.assertReply(c, "MKD late", 257)
        self.assertEqual(c.upload("STOR late/file.txt", c.pasv(), b"retried"), 226)
        with open(os.path.join(server.home, "late", "file.txt"), "rb") as f:
            self.assertEqual(f.read(), b"retried")

    def test_missing_directory_outside_the_home_is_550_like_an_existing_one(self):
        """450 for a missing directory and 550 for an existing one would show which
        directories exist outside the home."""
        c = self.connect()
        for outside in ("../../tmp", "../../uftp-no-such-dir-xyz", "../../uftp-no-such-dir-xyz/deeper"):
            self.assertEqual(c.upload(f"STOR {outside}/uftp_escape.txt", c.pasv(), b"x"), 550, outside)
            self.assertEqual(c.upload(f"APPE {outside}/uftp_escape.txt", c.pasv(), b"x"), 550, outside)

    def test_missing_directory_behind_a_link_to_outside_is_550(self):
        """A link inside the home that points outside: what is behind it is outside."""
        outside = tempfile.mkdtemp(prefix="uftp-outside-")
        self.addCleanup(shutil.rmtree, outside, True)
        os.symlink(outside, os.path.join(server.home, "to_outside"))
        c = self.connect()
        self.assertEqual(c.upload("STOR to_outside/missing/x.txt", c.pasv(), b"x"), 550)
        self.assertEqual(c.upload("STOR to_outside/x.txt", c.pasv(), b"x"), 550)
        self.assertEqual(os.listdir(outside), [])

    def test_dangling_link_is_550_not_450(self):
        """A link that points to a missing directory is not a directory to wait for."""
        os.symlink(os.path.join(server.home, "nowhere", "x"), os.path.join(server.home, "dangling_inside"))
        c = self.connect()
        self.assertEqual(c.upload("STOR dangling_inside", c.pasv(), b"x"), 550)

    def test_550_is_kept_for_the_other_refusals(self):
        """Outside the home, no permission, a file where a directory is expected."""
        self.make_file("plain.txt")
        c = self.connect()
        self.assertEqual(c.upload("STOR ../outside.txt", c.pasv(), b"x"), 550)
        self.assertEqual(c.upload("STOR plain.txt/inside.txt", c.pasv(), b"x"), 550)


class LongReplyTests(RFCTestCase):
    """SocketPrintf/socketWorkerPrintf copied as many bytes as snprintf
    returned (the untruncated length) out of a 2048/4096 byte stack buffer. A reply
    or a listing line longer than the buffer carried stack memory to the client."""

    # a valid path, written in 3000+ bytes: the server echoes the text as received
    LONG_PREFIX = "./" * 1500

    def test_long_argument_echoed_in_an_error_reply(self):
        os.mkdir(os.path.join(server.home, "existing"))
        c = self.connect()
        argument = self.LONG_PREFIX + "existing"              # MKD fails: it already exists
        code, text = c.cmd("MKD " + argument)
        self.assertEqual(text, "550 error while creating directory " + argument + "\r\n")
        argument = self.LONG_PREFIX + "missing"               # CWD fails: no such directory
        code, text = c.cmd("CWD " + argument)
        self.assertEqual(text, "550 Can't change directory to " + argument + ": No such file or directory\r\n")
        self.assertReply(c, "NOOP", 200)

    def test_deep_directory_longer_than_the_reply_buffer(self):
        """A legitimate CWD whose reply carries a path longer than 2048 bytes."""
        names = ["d%02d" % i + "x" * 196 for i in range(12)]             # 12 * 200 bytes
        path = server.home
        for name in names:
            path = os.path.join(path, name)
            os.mkdir(path)
        expected = "/" + "/".join(names)
        self.assertGreater(len(expected), 2048)
        c = self.connect()
        code, text = c.cmd("CWD " + expected)
        self.assertEqual(text, "250 OK. Current directory is  " + expected + "\r\n")
        self.assertEqual(ftplib.parse257(self.assertReply(c, "PWD", 257)), expected)

    def test_listing_line_longer_than_the_worker_buffer(self):
        """LIST of a link with a 3900 byte target: one line of more than 4096 bytes."""
        name = "n" * 200
        target = "/" + "t" * 3899
        os.symlink(target, os.path.join(server.home, name))
        c = self.connect()
        code, listing = c.download("LIST", c.pasv())
        self.assertEqual(code, 226)
        lines = listing.split(b"\r\n")
        self.assertEqual(lines[-1], b"")                                  # ends with CRLF
        link_lines = [line for line in lines if name.encode() in line]
        self.assertEqual(len(link_lines), 1, lines)
        self.assertTrue(link_lines[0].endswith((name + " -> " + target).encode()), link_lines[0][-80:])
        self.assertEqual(len(listing), sum(len(line) + 2 for line in lines[:-1]))


class DeepPathListingTests(RFCTestCase):
    """FILE_GetDirectoryInodeList joined directory + "/" + entry into a
    PATH_MAX stack buffer with strcpy/strcat. Listing a directory whose path is a few
    bytes short of PATH_MAX (4096) overflowed it, already with "." and ".."."""

    def make_deep_directory(self, absolute_length):
        """Create a directory chain whose absolute path is exactly absolute_length bytes.
        Returns the path relative to the home."""
        home = server.home
        names = []
        length = len(home)
        while length + 1 + 200 + 1 + 1 <= absolute_length:   # keep room for a last part
            names.append("d" * 200)
            length += 201
        last = absolute_length - length - 1
        self.assertTrue(1 <= last <= 255, last)
        names.append("e" * last)
        path = home
        for name in names:
            path = os.path.join(path, name)
            os.mkdir(path)
        self.assertEqual(len(path), absolute_length)
        return "/".join(names), path

    def test_stat_a_close_to_path_max(self):
        for absolute_length in (4093, 4094):
            relative, _ = self.make_deep_directory(absolute_length)
            c = self.connect()
            code, text = c.cmd("STAT -a " + relative)
            self.assertEqual(code, 213, text[:80])
            self.assertTrue(text.splitlines()[-1].startswith("213 "), text[-80:])
            self.assertReply(c, "NOOP", 200)
            shutil.rmtree(os.path.join(server.home, relative.split("/")[0]))
        self.assertReply(self.connect(), "NOOP", 200)

    def test_list_a_close_to_path_max(self):
        for absolute_length in (4093, 4094):
            relative, _ = self.make_deep_directory(absolute_length)
            c = self.connect()
            code, listing = c.download("LIST -a " + relative, c.pasv())
            self.assertEqual(code, 226)
            self.assertReply(c, "NOOP", 200)
            shutil.rmtree(os.path.join(server.home, relative.split("/")[0]))
        self.assertReply(self.connect(), "NOOP", 200)

    def test_long_entry_name_in_a_deep_directory(self):
        """A 250 byte entry name in a directory of 3900 bytes: the joined path is more
        than 150 bytes longer than the buffer. The entry can not be opened by the
        system (ENAMETOOLONG) and is left out; the server must answer and survive."""
        relative, path = self.make_deep_directory(3900)
        directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY)        # the full path is too long
        try:
            os.close(os.open("n" * 250, os.O_CREAT | os.O_WRONLY, 0o644, dir_fd=directory))
            os.mkdir("m" * 250, dir_fd=directory)
        finally:
            os.close(directory)
        c = self.connect()
        code, text = c.cmd("STAT -a " + relative)
        self.assertEqual(code, 213, text[:80])
        self.assertNotIn("n" * 250, text)
        code, listing = c.download("LIST -a " + relative, c.pasv())
        self.assertEqual(code, 226)
        self.assertNotIn(b"n" * 250, listing)
        code, names = c.download("NLST " + relative, c.pasv())
        self.assertEqual(code, 226)
        self.assertReply(c, "NOOP", 200)
        self.assertReply(self.connect(), "NOOP", 200)

    def test_entries_that_fit_are_still_listed(self):
        relative, path = self.make_deep_directory(4060)
        with open(os.path.join(path, "file.txt"), "wb") as f:
            f.write(b"x")
        c = self.connect()
        code, text = c.cmd("STAT -a " + relative)
        self.assertEqual(code, 213)
        self.assertIn("file.txt", text)
        self.assertIn(" .\r\n", text)
        code, listing = c.download("LIST -a " + relative, c.pasv())
        self.assertEqual(code, 226)
        self.assertIn(b"file.txt", listing)


class ListOptionsTests(RFCTestCase):
    """The options of a listing command (LIST -a) must not leak into the next one.
    Freeing them left a dangling pointer that the data worker of the next listing
    read (use-after-free, found by the path overflow tests under AddressSanitizer)."""

    def setUp(self):
        super().setUp()
        self.make_file(".hidden")
        self.make_file("visible")

    def test_plain_listing_after_list_a(self):
        c = self.connect()
        code, listing = c.download("LIST -a", c.pasv())
        self.assertEqual(code, 226)
        self.assertIn(b".hidden", listing)
        for command in ("NLST", "LIST", "NLST", "LIST"):
            code, listing = c.download(command, c.pasv())
            self.assertEqual(code, 226, command)
            self.assertIn(b"visible", listing, command)
            self.assertNotIn(b".hidden", listing, f"{command} after LIST -a shows hidden files")
        self.assertReply(c, "NOOP", 200)

    def test_options_change_between_listings(self):
        c = self.connect()
        # note: only the first option letter is read, so "LIST -la" does not show hidden
        # files (pre-existing limitation, see problemi_aperti.md)
        for command, hidden_expected in (("LIST -a", True), ("NLST", False), ("LIST -A", True),
                                         ("STAT -a .", True), ("LIST", False), ("STAT .", False)):
            if command.startswith("STAT"):
                code, listing = c.cmd(command)
                listing = listing.encode()
                self.assertEqual(code, 213, command)
            else:
                code, listing = c.download(command, c.pasv())
                self.assertEqual(code, 226, command)
            self.assertEqual(b".hidden" in listing, hidden_expected, command)


class TransferInProgressTests(RFCTestCase):
    """A second LIST/NLST, or STAT <path>, freed and rewrote the path and the
    options the data worker of the first LIST reads (use-after-free when it happens
    while the worker scans the directory). The same pattern applied to RETR/STOR/APPE
    and their file names. A data connection serves one transfer: a second transfer
    command is now refused with 425 and changes nothing; STAT uses its own copies.

    The tests are deterministic: the data connection is opened only after the
    concurrent commands, so the first transfer has been handed to the worker but can
    not run yet. On the old code the concurrent command replaced the path and the
    first transfer then served the wrong directory or file."""

    def setUp(self):
        super().setUp()
        for directory, names in (("first", ["one.txt", "two.txt"]), ("second", ["visible.txt"])):
            os.mkdir(os.path.join(server.home, directory))
            for name in names:
                self.make_file(f"{directory}/{name}", name.encode())
        self.make_file(".hidden_in_home")

    def pasv_not_connected(self, c):
        code, text = c.cmd("PASV")
        self.assertEqual(code, 227, text)
        numbers = [int(n) for n in re.search(r"\(([\d,]+)\)", text).group(1).split(",")]
        return numbers[4] * 256 + numbers[5]

    @staticmethod
    def receive(port):
        with socket.create_connection((HOST, port), timeout=5) as data:
            chunks = []
            while True:
                chunk = data.recv(65536)
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)

    def test_second_listing_command_is_refused(self):
        c = self.connect()
        port = self.pasv_not_connected(c)
        self.assertReply(c, "LIST first", 150)
        self.assertReply(c, "LIST second", 425)
        self.assertReply(c, "NLST -a second", 425)
        listing = self.receive(port)
        self.assertEqual(c.read_reply()[0], 226)
        self.assertIn(b"one.txt", listing)
        self.assertIn(b"two.txt", listing)
        self.assertNotIn(b"visible.txt", listing)          # the first LIST kept its path
        self.assertReply(c, "NOOP", 200)

    def test_stat_during_a_listing_does_not_change_it(self):
        c = self.connect()
        port = self.pasv_not_connected(c)
        self.assertReply(c, "NLST first", 150)
        code, text = c.cmd("STAT -a second")               # allowed during a transfer
        self.assertEqual(code, 213)
        self.assertIn("visible.txt", text)
        self.assertIn(" .\r\n", text)
        code, text = c.cmd("STAT .")
        self.assertEqual(code, 213)
        self.assertNotIn(".hidden_in_home", text)          # its own options, not -a
        names = self.receive(port)
        self.assertEqual(c.read_reply()[0], 226)
        self.assertEqual(sorted(names.decode().split()), ["one.txt", "two.txt"])

    def test_second_retr_is_refused(self):
        c = self.connect()
        port = self.pasv_not_connected(c)
        self.assertReply(c, "RETR first/one.txt", 150)
        self.assertReply(c, "RETR second/visible.txt", 425)
        self.assertEqual(self.receive(port), b"one.txt")
        self.assertEqual(c.read_reply()[0], 226)

    def test_second_stor_is_refused(self):
        c = self.connect()
        data = c.pasv()
        self.assertReply(c, "STOR upload.bin", 150)
        data.sendall(b"first part ")
        self.assertReply(c, "STOR other.bin", 425)
        self.assertReply(c, "APPE upload.bin", 425)
        data.sendall(b"second part")
        data.close()
        self.assertEqual(c.read_reply()[0], 226)
        with open(os.path.join(server.home, "upload.bin"), "rb") as f:
            self.assertEqual(f.read(), b"first part second part")
        self.assertFalse(os.path.exists(os.path.join(server.home, "other.bin")))

    def test_list_after_a_completed_listing_needs_a_new_data_connection(self):
        c = self.connect()
        self.assertEqual(c.download("LIST first", c.pasv())[0], 226)
        self.assertReply(c, "LIST first", 425)
        self.assertEqual(c.download("LIST first", c.pasv())[0], 226)

    def test_stat_wrong_path_gets_one_reply(self):
        """STAT with a refused path answered 550 and then listed the current directory too."""
        c = self.connect()
        for path in ("no_such_dir", "../../etc", "/../.."):
            self.assertReply(c, "STAT " + path, 550)
            self.assertReply(c, "NOOP", 200)                # no extra reply in between


class ReplyInterleavingTests(RFCTestCase):
    """The data worker sends the final reply of a transfer (226) on the control
    connection by itself. It used to be able to land in the middle of a multi-line
    reply that the control thread was writing (STAT <path> during a transfer), and with
    TLS the two threads used the same SSL object at the same time."""

    def read_until(self, c, needed, timeout=15):
        """Raw control text until every string in needed has appeared."""
        c.sock.settimeout(timeout)
        text = ""
        while not all(n in text for n in needed):
            line = c.file.readline()
            if not line:
                break
            text += line.decode("utf-8", "replace")
        return text

    def test_transfer_reply_never_inside_a_multiline_reply(self):
        big = os.path.join(server.home, "big")
        os.mkdir(big)
        for i in range(3000):
            os.close(os.open(os.path.join(big, "entry_%05d" % i), os.O_CREAT | os.O_WRONLY, 0o644))
        self.make_file("small.txt")
        for attempt in range(5):
            c = self.connect()
            data = c.pasv()
            self.addCleanup(data.close)
            c.sock.sendall(b"NLST small.txt\r\nSTAT -a big\r\n")
            text = self.read_until(c, ("213 End of status", "226 "))
            self.assertIn("213-Status follow", text)
            self.assertIn("213 End of status", text)
            self.assertIn("\r\n226 ", "\r\n" + text)
            block = text[text.index("213-Status follow"):text.index("213 End of status")]
            self.assertNotIn("\n226", block, f"attempt {attempt}: 226 inside the STAT reply")
            self.assertReply(c, "NOOP", 200)            # and nothing left over

    def test_same_over_tls(self):
        """Over TLS the worker's 226 and the STAT reply are SSL_write calls on the same
        SSL object: done at the same time they corrupt the TLS stream."""
        probe = self.connect(login=False)
        if probe.cmd("AUTH TLS")[0] != 234:
            self.skipTest("server built without OpenSSL support")
        big = os.path.join(server.home, "big")
        os.mkdir(big)
        for i in range(3000):
            os.close(os.open(os.path.join(big, "entry_%05d" % i), os.O_CREAT | os.O_WRONLY, 0o644))
        self.make_file("small.txt")
        for attempt in range(5):
            c = self.connect(login=False)
            c.start_tls()
            c.login()
            data = c.pasv()                              # PROT C: clear text data channel
            self.addCleanup(data.close)
            c.sock.sendall(b"NLST small.txt\r\nSTAT -a big\r\n")
            try:
                text = self.read_until(c, ("213 End of status", "226 "))
            except ssl.SSLError as e:
                self.fail(f"attempt {attempt}: TLS stream corrupted ({e})")
            self.assertIn("213 End of status", text)
            block = text[text.index("213-Status follow"):text.index("213 End of status")]
            self.assertNotIn("\n226", block, f"attempt {attempt}: 226 inside the STAT reply")
            self.assertReply(c, "NOOP", 200)


class HomeJailLinkVariantsTests(RFCTestCase):
    """More ways to leave the home through symbolic links: chains, relative "../"
    targets, a link to "/", a link in the middle of the path, a link loop."""

    def setUp(self):
        super().setUp()
        self.outside = os.path.join(server.workdir, "outside.txt")
        HomeJailTests.write(self.outside, b"OUTSIDE")
        self.addCleanup(HomeJailTests.remove, self.outside)
        self.outdir = os.path.join(server.workdir, "outdir")
        shutil.rmtree(self.outdir, ignore_errors=True)
        os.mkdir(self.outdir)
        self.addCleanup(shutil.rmtree, self.outdir, True)
        HomeJailTests.write(os.path.join(self.outdir, "f.txt"), b"OUTDIR")
        self.created = os.path.join(server.workdir, "created_by_rel.txt")
        self.addCleanup(HomeJailTests.remove, self.created)
        home = server.home
        os.mkdir(os.path.join(home, "sub"))
        self.make_file("sub/in.txt", b"INSIDE")
        os.symlink(self.outside, os.path.join(home, "l2"))
        os.symlink("l2", os.path.join(home, "l1"))                          # chain l1 -> l2 -> outside
        os.symlink("../outside.txt", os.path.join(home, "rel"))             # relative target with ../
        os.symlink("/", os.path.join(home, "root"))                         # the root of the file system
        os.symlink(self.outdir, os.path.join(home, "sub", "deep_out"))      # link in the middle of a path
        os.symlink("loop", os.path.join(home, "loop"))                      # link to itself
        os.symlink("../created_by_rel.txt", os.path.join(home, "dangling_rel"))
        os.symlink("sub", os.path.join(home, "sublink"))                    # inside -> inside

    def test_read_through_link_variants(self):
        c = self.connect()
        for path in ("l1", "rel", "root/etc/hostname", "sub/deep_out/f.txt",
                     ".//./../outside.txt", "//..//outside.txt", "sublink/../../outside.txt"):
            self.assertEqual(c.download("RETR " + path, c.pasv()), (550, b""), path)

    def test_change_directory_through_link_variants(self):
        c = self.connect()
        self.assertReply(c, "CWD root", 550)
        self.assertReply(c, "CWD sub/deep_out", 550)
        self.assertEqual(ftplib.parse257(self.assertReply(c, "PWD", 257)), "/")

    def test_write_through_link_variants(self):
        c = self.connect()
        self.assertReply(c, "SITE CHMOD 666 l1", 550)
        self.assertEqual(stat.S_IMODE(os.stat(self.outside).st_mode), 0o600)
        self.assertReply(c, "DELE sub/deep_out/f.txt", 550)
        self.assertReply(c, "RNFR sub/deep_out/f.txt", 550)
        self.assertReply(c, "RNFR sub/in.txt", 350)
        self.assertReply(c, "RNTO sub/deep_out/moved.txt", 553)
        self.assertEqual(c.upload("STOR dangling_rel", c.pasv(), b"x"), 550)
        self.assertEqual(sorted(os.listdir(self.outdir)), ["f.txt"])
        self.assertFalse(os.path.exists(self.created))

    def test_link_loop_is_refused_and_the_server_survives(self):
        c = self.connect()
        self.assertEqual(c.download("RETR loop", c.pasv())[0], 550)
        self.assertReply(c, "NOOP", 200)
        self.assertReply(self.connect(), "NOOP", 200)

    def test_links_inside_and_absolute_paths_still_work(self):
        c = self.connect()
        self.assertEqual(c.download("RETR sublink/in.txt", c.pasv()), (226, b"INSIDE"))
        self.assertEqual(c.download("RETR /sub/in.txt", c.pasv()), (226, b"INSIDE"))
        self.assertReply(c, "CWD /sub", 250)


class HomeThroughLinkServer(UFTPTestServer):
    """HOME_0 is a symbolic link to the real home directory."""

    def _config_text(self):
        link = os.path.join(self.workdir, "homelink")
        if not os.path.islink(link):
            os.symlink(self.home, link)
        return super()._config_text().replace(f"HOME_0 = {self.home}/", f"HOME_0 = {link}/")


class HomeThroughLinkTests(unittest.TestCase):
    """The check compares resolved paths: a home configured through a link works,
    and nothing outside the real home becomes reachable."""

    def setUp(self):
        self.server = HomeThroughLinkServer(port=PORT + 3, idle_timeout=60)
        self.server.start()
        self.addCleanup(self.server.stop)
        os.mkdir(os.path.join(self.server.home, "sub"))
        with open(os.path.join(self.server.home, "sub", "in.txt"), "wb") as f:
            f.write(b"INSIDE")
        with open(os.path.join(self.server.workdir, "outside.txt"), "wb") as f:
            f.write(b"OUTSIDE")
        os.symlink(os.path.join(self.server.workdir, "outside.txt"), os.path.join(self.server.home, "out"))

    def test_home_through_a_link(self):
        c = Control(login=False, port=PORT + 3)
        self.addCleanup(c.close)
        c.login(self.server.user, self.server.password)
        self.assertEqual(c.cmd("CWD /sub")[0], 250)
        self.assertEqual(ftplib.parse257(c.cmd("PWD")[1]), "/sub")
        self.assertEqual(c.download("RETR in.txt", c.pasv()), (226, b"INSIDE"))
        self.assertEqual(c.cmd("CWD /")[0], 250)
        self.assertEqual(c.download("RETR out", c.pasv()), (550, b""))
        self.assertEqual(c.download("RETR ../outside.txt", c.pasv()), (550, b""))
        self.assertEqual(c.upload("STOR new.txt", c.pasv(), b"new"), 226)
        self.assertTrue(os.path.exists(os.path.join(self.server.home, "new.txt")))


class NoTrailingSlashHomeTests(unittest.TestCase):
    """With HOME_0 = /x/home, "/2" used to become /x/home2 and every
    absolute path like "/dir" was broken (/x/homedir)."""

    def setUp(self):
        self.server = UFTPTestServer(port=PORT + 2, idle_timeout=60,
                                     extra_config={"HOME_0": "{home}"})    # no trailing '/'
        self.server.start()
        self.addCleanup(self.server.stop)
        self.assertNotIn(f"HOME_0 = {self.server.home}/", self.server._config_text())
        os.mkdir(self.server.home + "2")
        with open(os.path.join(self.server.home + "2", "secret.txt"), "wb") as f:
            f.write(b"SIBLING-SECRET")
        os.mkdir(os.path.join(self.server.home, "dir"))

    def connect(self):
        connection = Control(login=False, port=PORT + 2)
        self.addCleanup(connection.close)
        connection.login(self.server.user, self.server.password)
        return connection

    def test_absolute_paths_stay_inside_the_home(self):
        c = self.connect()
        code, text = c.cmd("CWD /dir")
        self.assertEqual(code, 250, text)
        self.assertEqual(ftplib.parse257(c.cmd("PWD")[1]), "/dir")
        self.assertEqual(c.cmd("CWD /")[0], 250)
        self.assertEqual(ftplib.parse257(c.cmd("PWD")[1]), "/")

    def test_sibling_directory_is_not_reachable(self):
        c = self.connect()
        for command in ("CWD /2", "CWD ../home2", "SIZE /2/secret.txt", "SIZE ../home2/secret.txt",
                        "SITE CHMOD 666 /2/secret.txt"):
            code, text = c.cmd(command)
            self.assertEqual(code, 550, f"{command!r} -> {text!r}")
        self.assertEqual(ftplib.parse257(c.cmd("PWD")[1]), "/")


class ServerConfigurationTests(unittest.TestCase):
    """Behaviour that depends on uftpd.cfg: each test starts its own server."""

    def setUp(self):
        # blocked user, two login attempts per address, file owner set for the first user
        self.server = UFTPTestServer(port=PORT + 1, idle_timeout=60, extra_config={
            "MAX_CONNECTION_TRY_PER_IP": 2,
            "BLOCK_USER_0": "tester2",
            "USER_NAME_OWNER_0": pwd.getpwuid(os.getuid()).pw_name,
            "GROUP_NAME_OWNER_0": grp.getgrgid(os.getgid()).gr_name,
        })
        self.server.start()
        self.addCleanup(self.server.stop)

    def connect(self):
        connection = Control(login=False, port=PORT + 1)
        self.addCleanup(connection.close)
        return connection

    def test_blocked_user_is_530(self):
        c = self.connect()
        code, text = c.cmd("USER tester2")
        self.assertEqual(code, 530, text)
        code, text = c.cmd("PASS tester2Password")
        self.assertNotEqual(code, 230, text)
        code, text = c.cmd("PWD")
        self.assertEqual(code, 530, text)

    def test_blocked_user_makes_the_server_forget_the_previous_user(self):
        """USER a, USER <blocked>, PASS <password of a> used to log user a in."""
        c = self.connect()
        self.assertEqual(c.cmd(f"USER {self.server.user}")[0], 331)
        self.assertEqual(c.cmd("USER tester2")[0], 530)
        code, text = c.cmd(f"PASS {self.server.password}")
        self.assertEqual(code, 503, text)
        self.assertEqual(c.cmd("PWD")[0], 530)

    def test_login_failures_are_always_530(self):
        """Wrong password and "too many failures" both answer 530 (it was 430)."""
        for attempt in range(4):
            c = self.connect()
            self.assertEqual(c.cmd(f"USER {self.server.user}")[0], 331)
            code, text = c.cmd("PASS wrong-password")
            self.assertEqual(code, 530, f"attempt {attempt}: {text!r}")

    def lockout_attempt(self, attempts, pause):
        """Wrong passwords from new connections; returns the index of the first reply
        that announces the lockout, or None."""
        for attempt in range(attempts):
            c = self.connect()
            self.assertEqual(c.cmd(f"USER {self.server.user}")[0], 331)
            code, text = c.cmd("PASS wrong-password")
            self.assertEqual(code, 530, text)
            if "Too many" in text:
                return attempt
            time.sleep(pause)
        return None

    def test_lockout_after_too_many_failures(self):
        """MAX_CONNECTION_TRY_PER_IP = 2: the third wrong password is refused with the lockout."""
        self.assertEqual(self.lockout_attempt(5, 0), 2)

    def test_lockout_also_when_attempts_are_spaced_out(self):
        """On the default (ipv6) build the client address "::ffff:127.0.0.1" is
        16 characters, the counter field was 16 bytes: with attempts in different seconds
        the counter never grew and the lockout never happened."""
        self.assertEqual(self.lockout_attempt(5, 1.2), 2)

    def test_lockout_blocks_the_right_password_too(self):
        self.assertEqual(self.lockout_attempt(5, 1.2), 2)
        c = self.connect()
        self.assertEqual(c.cmd(f"USER {self.server.user}")[0], 331)
        code, text = c.cmd(f"PASS {self.server.password}")
        self.assertEqual(code, 530, text)
        self.assertIn("Too many", text)

    def test_site_chmod_with_a_configured_owner(self):
        """With USER_NAME_OWNER_n the file is also chown-ed: the reply is still 200."""
        path = os.path.join(self.server.home, "owned.txt")
        with open(path, "wb") as f:
            f.write(b"x")
        os.chmod(path, 0o644)
        c = self.connect()
        c.login(self.server.user, self.server.password)
        code, text = c.cmd("SITE CHMOD 600 owned.txt")
        self.assertEqual(code, 200, text)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(os.stat(path).st_uid, os.getuid())
        code, text = c.cmd("MKD owned_dir")
        self.assertEqual(code, 257, text)
        self.assertEqual(os.stat(os.path.join(self.server.home, "owned_dir")).st_uid, os.getuid())


@unittest.skipUnless(shutil.which("openssl"), "the openssl CLI is needed to create the test certificate")
class TlsTests(RFCTestCase):
    """AUTH / PBSZ / PROT (RFC 2228, RFC 4217)."""

    @classmethod
    def setUpClass(cls):
        # A server built without OpenSSL answers 502 to AUTH: nothing to test here
        probe = Control(login=False)
        try:
            code, _ = probe.cmd("AUTH TLS")
        finally:
            probe.close()
        if code == 502:
            raise unittest.SkipTest("uFTP was built without OpenSSL support")

    def test_feat_before_login_advertises_auth_tls(self):
        text = self.assertReply(self.connect(login=False), "FEAT", 211)
        self.assertIn(" AUTH TLS\r\n", text)

    def test_auth_without_mechanism_is_501(self):
        self.assertReply(self.connect(login=False), "AUTH", 501)

    def test_auth_unknown_mechanism_is_504(self):
        """RFC 2228: 504 when the security mechanism is not understood."""
        c = self.connect(login=False)
        for mechanism in ("SSL", "KERBEROS_V4", "GSSAPI", "TLS-P", "TLSX", "TLS extra", "T"):
            self.assertReply(c, "AUTH " + mechanism, 504)
        self.assertReply(c, "NOOP", 200)      # still in clear text and working

    def test_auth_tls_is_case_insensitive(self):
        c = self.connect(login=False)
        self.assertReply(c, "auth tls", 234)

    def test_auth_tls_c_is_accepted(self):
        """RFC 4217 section 17: TLS-C is a synonym of TLS."""
        self.assertReply(self.connect(login=False), "AUTH TLS-C", 234)

    def test_login_over_tls(self):
        c = self.connect(login=False)
        c.start_tls()
        c.login()
        self.assertReply(c, "PWD", 257)

    # ---- an accepted AUTH resets the session (RFC 4217 section 4.2) ----

    def test_pass_after_auth_needs_a_new_user(self):
        """The user name given before AUTH must not survive it: PASS alone is 503."""
        c = self.connect()                      # logged in in clear text
        c.start_tls()
        self.assertReply(c, f"PASS {server.password}", 503)
        self.assertReply(c, "PWD", 530)
        c.login()
        self.assertReply(c, "PWD", 257)

    def test_passive_data_connection_from_before_auth_is_dropped(self):
        """A data connection set up in clear text must not carry data once TLS is on."""
        self.make_file("secret.txt", b"POST-TLS-SECRET")
        c = self.connect()
        data = c.pasv()                         # endpoint chosen before AUTH
        self.addCleanup(data.close)
        c.start_tls()
        c.login()
        self.assertReply(c, "RETR secret.txt", 425)
        data.settimeout(3)
        self.assertEqual(data.recv(100), b"", "the pre-AUTH data connection was not closed")

    def test_active_data_connection_from_before_auth_is_dropped(self):
        self.make_file("secret.txt", b"POST-TLS-SECRET")
        listener, port = listening_socket()
        self.addCleanup(listener.close)
        c = self.connect()
        self.assertReply(c, "PORT " + port_argument(HOST, port), 200)
        data, _ = listener.accept()
        self.addCleanup(data.close)
        c.start_tls()
        c.login()
        self.assertReply(c, "RETR secret.txt", 425)
        data.settimeout(3)
        self.assertEqual(data.recv(100), b"", "the pre-AUTH data connection was not closed")

    def test_pending_rnfr_and_rest_do_not_survive_auth(self):
        self.make_file("data.bin", b"0123456789")
        c = self.connect()
        self.assertReply(c, "RNFR data.bin", 350)
        self.assertReply(c, "REST 5", 350)
        c.start_tls()
        c.login()
        self.assertReply(c, "RNTO renamed.bin", 503)
        self.assertTrue(os.path.exists(os.path.join(server.home, "data.bin")))
        self.assertEqual(c.download("RETR data.bin", c.pasv()), (226, b"0123456789"))

    def test_current_directory_does_not_survive_auth(self):
        os.mkdir(os.path.join(server.home, "sub"))
        c = self.connect()
        self.assertReply(c, "CWD sub", 250)
        c.start_tls()
        c.login()
        self.assertEqual(ftplib.parse257(self.assertReply(c, "PWD", 257)), "/")

    def test_pipelined_pasv_and_auth(self):
        """Every command still gets its reply, in order: PASV (227 or 425), then 234."""
        c = self.connect()
        c.sock.sendall(b"PASV\r\nAUTH TLS\r\n")
        self.assertIn(c.read_reply()[0], (227, 425))
        self.assertEqual(c.read_reply()[0], 234)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        c.sock = context.wrap_socket(c.sock, server_hostname=HOST)
        c.file = c.sock.makefile("rb")
        c.login()
        self.assertReply(c, "PWD", 257)

    def test_refused_auth_keeps_the_session(self):
        """Only an accepted AUTH resets the session: 501/504 change nothing."""
        c = self.connect()
        self.assertReply(c, "AUTH", 501)
        self.assertReply(c, "AUTH SSL", 504)
        self.assertReply(c, "PWD", 257)

    # ---- after CCC, no PBSZ/PROT (RFC 4217 section 5) ----

    def protected_then_cleared(self):
        """TLS login, PBSZ 0, PROT P, then CCC: returns the clear text connection."""
        c = self.connect(login=False)
        c.start_tls()
        c.login()
        self.assertReply(c, "PBSZ 0", 200)
        self.assertReply(c, "PROT P", 200)
        self.assertReply(c, "CCC", 200)
        c.sock = c.sock.unwrap()                 # both TLS close_notify exchanged
        c.file = c.sock.makefile("rb")
        # Before 4.2.0 the close_notify of the client reached the server as
        # clear text and spoiled the next command(s) with 500. The server now reads it
        # (test_first_command_after_ccc_is_not_spoiled); this resynchronisation on a
        # recognisable reply (SYST, 215) is kept so that these tests only check PBSZ/PROT.
        self.assertTrue(self.resynchronise(c), "control connection never back in step after CCC")
        return c

    @staticmethod
    def resynchronise(c):
        c.sock.settimeout(1)
        try:
            for _ in range(5):
                c.send("SYST")
                try:
                    while True:
                        code, _ = c.read_reply()
                        if code == 215:
                            return True                # every reply before it was a 500
                except socket.timeout:
                    c.file = c.sock.makefile("rb")     # SYST itself was spoiled: send it again
            return False
        finally:
            c.sock.settimeout(5)

    def test_first_command_after_ccc_is_not_spoiled(self):
        """RFC 4217 12.3: the TLS shutdown after CCC is bidirectional. The server did not
        read the closure alert of the client, whose bytes then spoiled the next command
        (500), sometimes more than one."""
        for attempt in range(10):
            c = self.connect(login=False)
            c.start_tls()
            c.login()
            self.assertReply(c, "PBSZ 0", 200)
            self.assertReply(c, "PROT P", 200)
            self.assertReply(c, "CCC", 200)
            c.sock = c.sock.unwrap()                 # sends our close_notify, reads the server's
            c.file = c.sock.makefile("rb")
            code, text = c.cmd("NOOP")
            self.assertEqual(code, 200, f"attempt {attempt}: first command after CCC -> {text!r}")
            self.assertReply(c, "PWD", 257)
            c.close()

    def test_closure_alert_in_two_tcp_segments_after_ccc(self):
        """The closure alert of the client may arrive in pieces: the server looked at the
        first byte of the second piece, took it for clear text and the next command got
        500. TLS is driven by hand here to choose where the record is cut."""
        for cut in (1, 3, 5, 12):
            sock = socket.create_connection((HOST, PORT), timeout=5)
            self.addCleanup(sock.close)
            sock.recv(4096)                                  # welcome
            sock.sendall(b"AUTH TLS\r\n")
            self.assertTrue(sock.recv(4096).startswith(b"234"))

            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            tls = tls_client_context().wrap_bio(incoming, outgoing, server_hostname=HOST)

            def drive(operation, *arguments):
                while True:
                    try:
                        result = operation(*arguments)
                    except ssl.SSLWantReadError:
                        sock.sendall(outgoing.read())
                        incoming.write(sock.recv(65536))
                        continue
                    sock.sendall(outgoing.read())
                    return result

            def tls_command(command):
                drive(tls.write, command.encode() + b"\r\n")
                reply = b""
                while not reply.endswith(b"\r\n"):
                    reply += drive(tls.read, 4096)
                return reply

            drive(tls.do_handshake)
            tls_command(f"USER {server.user}")
            self.assertTrue(tls_command(f"PASS {server.password}").startswith(b"230"))
            self.assertTrue(tls_command("CCC").startswith(b"200"))

            try:
                tls.unwrap()                                 # writes our close_notify
            except ssl.SSLWantReadError:
                pass
            alert = outgoing.read()
            self.assertGreater(len(alert), cut)
            sock.sendall(alert[:cut])
            time.sleep(0.3)
            sock.sendall(alert[cut:])
            time.sleep(0.3)

            sock.sendall(b"NOOP\r\n")
            received = b""
            while not received.endswith(b"\r\n"):          # close_notify of the server, then the reply
                received += sock.recv(4096)
            self.assertTrue(received.endswith(b"200 Zzz...\r\n"), f"cut at {cut}: {received[-60:]!r}")

    def test_client_that_does_not_close_tls_after_ccc(self):
        """Clients that go on in clear text right after CCC, without a TLS closure, work."""
        c = self.connect(login=False)
        c.start_tls()
        c.login()
        self.assertReply(c, "CCC", 200)
        raw = socket.socket(fileno=os.dup(c.sock.fileno()))
        self.addCleanup(raw.close)
        c.close()                                    # no close_notify from us
        raw.settimeout(0.5)
        try:                                         # drop the server's close_notify record
            while raw.recv(4096):
                pass
        except socket.timeout:
            pass
        raw.settimeout(5)
        raw.sendall(b"NOOP\r\n")
        self.assertTrue(raw.recv(100).startswith(b"200"))
        raw.sendall(b"PWD\r\n")
        self.assertTrue(raw.recv(100).startswith(b"257"))

    def test_auth_again_after_ccc(self):
        """A new AUTH TLS after CCC: the server answered 234 and then failed the handshake,
        because the TLS object of the connection had already been shut down."""
        c = self.connect(login=False)
        c.start_tls()
        c.login()
        self.assertReply(c, "CCC", 200)
        c.sock = c.sock.unwrap()
        c.file = c.sock.makefile("rb")
        self.assertReply(c, "NOOP", 200)

        c.start_tls()                                    # 234 and a complete handshake
        self.assertReply(c, "PWD", 530)                  # AUTH logs the user out
        c.login()
        self.assertReply(c, "PBSZ 0", 200)               # CCC no longer in force
        self.assertReply(c, "PROT P", 200)
        self.make_file("after_ccc.txt", b"protected again")
        data = c.pasv()
        self.assertReply(c, "RETR after_ccc.txt", 150)
        data = tls_client_context().wrap_socket(data, server_hostname=HOST)
        received = b""
        while True:
            chunk = data.recv(65536)
            if not chunk:
                break
            received += chunk
        data.close()
        self.assertEqual(c.read_reply()[0], 226)
        self.assertEqual(received, b"protected again")

    def test_prot_and_pbsz_refused_after_ccc(self):
        c = self.protected_then_cleared()
        for command in ("PROT C", "PROT P", "PROT S", "PBSZ 0"):
            self.assertReply(c, command, 503)
        self.assertReply(c, "PWD", 257)          # still logged in, still working

    def test_data_stays_protected_after_ccc(self):
        """The PROT P chosen before CCC stays in force: data still travels over TLS."""
        self.make_file("secret.txt", b"STILL-PROTECTED")
        c = self.protected_then_cleared()
        self.assertReply(c, "PROT C", 503)
        data = c.pasv()
        self.assertReply(c, "RETR secret.txt", 150)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        data = context.wrap_socket(data)         # fails if the server sends clear text
        received = b""
        while True:
            chunk = data.recv(65536)
            if not chunk:
                break
            received += chunk
        data.close()
        self.assertEqual(c.read_reply()[0], 226)
        self.assertEqual(received, b"STILL-PROTECTED")

    def test_pbsz_and_prot_need_tls(self):
        c = self.connect()
        self.assertReply(c, "PBSZ 0", 503)
        self.assertReply(c, "PROT P", 503)

    def test_prot_levels(self):
        """RFC 4217 section 9: C and P are supported, S and E are refused with 536."""
        c = self.connect(login=False)
        c.start_tls()
        self.assertReply(c, "PROT P", 503)         # PBSZ must come first
        self.assertReply(c, "PBSZ 1024", 501)
        self.assertReply(c, "PBSZ 0", 200)
        for command, code in (("PROT S", 536), ("PROT E", 536), ("prot s", 536), ("prot e", 536),
                              ("PROT X", 504), ("PROT PP", 504), ("PROT Private", 504),
                              ("PROT", 501),
                              ("PROT P", 200), ("PROT C", 200), ("prot p", 200), ("prot c", 200)):
            self.assertReply(c, command, code)


    def protected_session(self):
        c = self.connect(login=False)
        c.start_tls()
        c.login()
        self.assertReply(c, "PBSZ 0", 200)
        self.assertReply(c, "PROT P", 200)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return c, context

    def test_protected_data_connection(self):
        """PROT P: the passive data connection is TLS too (RFC 4217 section 9)."""
        payload = b"secret payload " * 1000
        c, context = self.protected_session()

        data = c.pasv()
        self.assertReply(c, "STOR secret.bin", 150)
        data = context.wrap_socket(data)
        data.sendall(payload)
        data.unwrap().close()
        self.assertEqual(c.read_reply()[0], 226)
        with open(os.path.join(server.home, "secret.bin"), "rb") as f:
            self.assertEqual(f.read(), payload)

        data = c.epsv()
        self.assertReply(c, "RETR secret.bin", 150)
        data = context.wrap_socket(data)
        received = b""
        while len(received) < len(payload):
            chunk = data.recv(65536)
            if not chunk:
                break
            received += chunk
        data.close()
        self.assertEqual(c.read_reply()[0], 226)
        self.assertEqual(received, payload)

    def test_protected_data_connection_with_session_reuse(self):
        """ftplib offers the TLS session of the control connection on the data connection."""
        payload = b"secret payload " * 1000
        ftps = ftplib.FTP_TLS()
        ftps.connect(HOST, PORT, timeout=10)
        self.addCleanup(ftps.close)
        ftps.auth()
        ftps.login(server.user, server.password)
        ftps.prot_p()
        ftps.storbinary("STOR secret.bin", io.BytesIO(payload))
        received = io.BytesIO()
        ftps.retrbinary("RETR secret.bin", received.write)
        self.assertEqual(received.getvalue(), payload)
        self.assertEqual(ftps.nlst(), ["secret.bin"])

    def test_prot_c_after_prot_p_sends_clear_data(self):
        self.make_file("clear.txt", b"clear text")
        c, _ = self.protected_session()
        self.assertReply(c, "PROT C", 200)
        self.assertEqual(c.download("RETR clear.txt", c.pasv()), (226, b"clear text"))


if __name__ == "__main__":
    unittest.main()
