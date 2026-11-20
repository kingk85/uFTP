"""PAM authentication (ENABLE_PAM_AUTH), in a Docker container with a real system user.

The build with PAM is not the default one: the test runs only if UFTP_PAM_BIN is the path of a uFTP built with
PAM_SUPPORT_ENABLED (make ENABLE_PAM_SUPPORT="-D PAM_SUPPORT_ENABLED" PAM_AUTH_LIB="-lpam") and Docker with the image
uftp-bench-uftp (test/benchmark/Dockerfile, empty PKG) is available. Otherwise it is skipped.

A user of uid 2001 and group 100 (a group number that is not the user number) checks what was wrong:
  * the uid and the gid were swapped: the user could not write in its own home (STOR and MKD answered 550) and the
    files were created with the owner and the group swapped;
  * an expired account could log in (pam_acct_mgmt was not called).
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from uftp_test_server import UFTPTestServer  # noqa: E402
from ftp_test_client import FtpControl  # noqa: E402

PAM_BIN = os.environ.get("UFTP_PAM_BIN")
IMAGE = "uftp-bench-uftp"
NAME = "uftp-pam-test"
NETWORK = "uftp-pam-net"
ADDRESS = "172.31.7.2"


def docker(*arguments):
    return subprocess.run(("docker",) + arguments, capture_output=True, text=True)


@unittest.skipUnless(PAM_BIN and os.path.isfile(PAM_BIN), "UFTP_PAM_BIN (a build with PAM) is not set")
@unittest.skipUnless(shutil.which("docker"), "docker is not installed")
class PamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if docker("image", "inspect", IMAGE).returncode != 0:
            raise unittest.SkipTest("the Docker image %s is not built" % IMAGE)
        server = UFTPTestServer(port=2121, idle_timeout=120, binary=PAM_BIN, extra_config={"ENABLE_PAM_AUTH": "true"})
        server.workdir = tempfile.mkdtemp(prefix="uftp-pam-")
        os.chmod(server.workdir, 0o755)
        os.mkdir(server.home)
        os.mkdir(server.workdir + "/log")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", server.workdir + "/key.pem",
                        "-out", server.workdir + "/cert.pem", "-days", "1", "-subj", "/CN=localhost"],
                       check=True, capture_output=True)
        with open(server.workdir + "/uftpd.cfg", "w") as f:
            f.write(server._config_text())
        cls.server = server
        docker("rm", "-f", NAME)
        docker("network", "rm", NETWORK)
        docker("network", "create", "--subnet", "172.31.7.0/24", NETWORK)
        setup = ("useradd -m -u 2001 -g 100 testuser && echo testuser:Secret123 | chpasswd && "
                 "printf 'auth required pam_unix.so\\naccount required pam_unix.so\\n' > /etc/pam.d/sudo && exec /uFTP")
        result = docker("run", "-d", "--name", NAME, "--network", NETWORK, "--ip", ADDRESS,
                        "-v", server.workdir + ":" + server.workdir, "-v", PAM_BIN + ":/uFTP:ro", "-w", server.workdir,
                        IMAGE, "sh", "-c", setup)
        if result.returncode != 0:
            raise unittest.SkipTest("the container did not start: %s" % result.stderr[:200])
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                FtpControl(2121, login=False, timeout=2, host=ADDRESS).close()
                return
            except OSError:
                time.sleep(0.5)
        raise unittest.SkipTest("the server in the container did not answer")

    @classmethod
    def tearDownClass(cls):
        docker("rm", "-f", NAME)
        docker("network", "rm", NETWORK)
        shutil.rmtree(cls.server.workdir, True)

    def login(self, user, password):
        c = FtpControl(2121, login=False, timeout=15, host=ADDRESS)
        self.addCleanup(c.close)
        c.cmd("USER " + user)
        return c, c.cmd("PASS " + password)[0]

    def test_a_wrong_password_is_refused(self):
        self.assertEqual(self.login("testuser", "wrong")[1], 530)

    def test_the_user_can_write_in_its_home_and_owns_what_it_creates(self):
        c, code = self.login("testuser", "Secret123")
        self.assertEqual(code, 230)
        c.cmd("TYPE I")
        self.assertEqual(c.upload("STOR up.txt", c.pasv(), b"hello"), 226)
        self.assertEqual(c.cmd("MKD made")[0], 257)
        time.sleep(0.5)
        owners = docker("exec", NAME, "stat", "-c", "%u:%g", "/home/testuser/up.txt", "/home/testuser/made").stdout.split()
        self.assertEqual(owners, ["2001:100", "2001:100"])

    def test_an_expired_account_can_not_log_in(self):
        docker("exec", NAME, "useradd", "-m", "-u", "2002", "-g", "100", "expireduser")
        docker("exec", NAME, "sh", "-c", "echo expireduser:Secret456 | chpasswd && chage -E 1 expireduser")
        self.assertEqual(self.login("expireduser", "Secret456")[1], 530)


if __name__ == "__main__":
    unittest.main()
