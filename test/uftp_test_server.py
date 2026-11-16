"""
Throw-away uFTP server for the test suite.

Creates a temporary directory containing:
  - uftpd.cfg   test configuration (users, passwords, port, timeouts...)
  - cert.pem / key.pem   self-signed certificate (if `openssl` is available)
  - home/       FTP root of the test users
and runs build/uFTP from there (uFTP reads ./uftpd.cfg from its cwd).

The server runs in the foreground (DAEMON_MODE=false) without the respawn
supervisor (RESPAWN_PROCESS=false) and in its own process group, so stopping
it never leaves a process listening on the port.

Usage from Python:
    with UFTPTestServer(port=2121, idle_timeout=60) as srv:
        ...  # srv.port, srv.users, srv.home, srv.pgid

Usage from the shell (used by run_tests.sh for debugging):
    python3 test/uftp_test_server.py [--port 2121] [--idle 60]
    -> runs until Ctrl+C, printing the configuration in use
"""

import argparse
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BIN = os.environ.get("UFTP_BIN", os.path.join(HERE, "..", "build", "uFTP"))
HOST = "127.0.0.1"

# Test accounts: (user, password). USER_0 is the one the tests log in with.
DEFAULT_USERS = [
    ("username", "password"),
    ("tester2", "tester2Password"),
]


def port_in_use(port, host=HOST):
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def _read_banner(port, timeout):
    with socket.create_connection((HOST, port), timeout=timeout) as s:
        return s.recv(1024).startswith(b"220")


class UFTPTestServer:

    def __init__(self, port=2121, idle_timeout=60, users=None, binary=DEFAULT_BIN,
                 max_connections=50, max_per_ip=50, extra_config=None):
        self.port = port
        self.idle_timeout = idle_timeout
        self.users = users or DEFAULT_USERS
        self.binary = os.path.abspath(binary)
        self.max_connections = max_connections
        self.max_per_ip = max_per_ip
        self.extra_config = extra_config or {}
        self.workdir = None
        self.process = None
        self.pgid = None
        self.tls_available = False

    # ---- configuration -------------------------------------------------
    @property
    def home(self):
        return os.path.join(self.workdir, "home")

    @property
    def user(self):
        return self.users[0][0]

    @property
    def password(self):
        return self.users[0][1]

    def _config_text(self):
        settings = {
            "MAXIMUM_ALLOWED_FTP_CONNECTION": self.max_connections,
            "FTP_PORT": self.port,
            "SINGLE_INSTANCE": "false",
            "DAEMON_MODE": "false",
            "RESPAWN_PROCESS": "false",
            "IDLE_MAX_TIMEOUT": self.idle_timeout,
            "MAX_CONNECTION_NUMBER_PER_IP": self.max_per_ip,
            "MAX_CONNECTION_TRY_PER_IP": self.max_per_ip,
            "LOG_FOLDER": f"{self.workdir}/log/",
            "MAXIMUM_LOG_FILES": 0,
            "CERTIFICATE_PATH": f"{self.workdir}/cert.pem",
            "PRIVATE_CERTIFICATE_PATH": f"{self.workdir}/key.pem",
            "ENABLE_PAM_AUTH": "false",
            "FORCE_TLS": "false",
            "RANDOM_PORT_START": 40000,
            "RANDOM_PORT_END": 40500,
        }
        for i, (user, password) in enumerate(self.users):
            settings[f"USER_{i}"] = user
            settings[f"PASSWORD_{i}"] = password
            settings[f"HOME_{i}"] = f"{self.home}/"

        # extra_config: adds a parameter, replaces a default, or removes it (None).
        # "{home}" and "{workdir}" are replaced with the directories of this server.
        for key, value in self.extra_config.items():
            if value is None:
                settings.pop(key, None)
            else:
                settings[key] = str(value).format(home=self.home, workdir=self.workdir)

        return "".join(f"{key} = {value}\n" for key, value in settings.items())

    # ---- lifecycle -----------------------------------------------------
    def start(self, startup_timeout=5):
        self._spawn()

        deadline = time.monotonic() + startup_timeout
        while True:
            try:
                if _read_banner(self.port, timeout=1):
                    return self
            except OSError:
                pass
            if self.process.poll() is not None or time.monotonic() > deadline:
                log = self.read_log()
                self.stop()
                raise RuntimeError(f"uFTP test server did not start. Log:\n{log}")
            time.sleep(0.1)

    def _spawn(self, check_port=True):
        """Prepare the working directory and launch the server (it may still fail)."""
        if not os.path.isfile(self.binary):
            raise FileNotFoundError(f"uFTP binary not found at {self.binary}, build it first")
        if check_port and port_in_use(self.port):
            # uFTP sets SO_REUSEPORT: a second server on the same port would get
            # a share of the connections and make test results meaningless.
            raise RuntimeError(f"port {self.port} is already in use (leftover uFTP?)")

        self.workdir = tempfile.mkdtemp(prefix="uftp-test-")
        os.mkdir(self.home)
        os.mkdir(os.path.join(self.workdir, "log"))

        self.tls_available = shutil.which("openssl") is not None
        if self.tls_available:
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", os.path.join(self.workdir, "key.pem"),
                 "-out", os.path.join(self.workdir, "cert.pem"),
                 "-days", "1", "-subj", "/CN=localhost"],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        with open(os.path.join(self.workdir, "uftpd.cfg"), "w") as f:
            f.write(self._config_text())

        self._log = open(os.path.join(self.workdir, "server.log"), "wb")
        # stdin from /dev/null: the server never reads it, and a known descriptor 0
        # lets the tests check that it is never closed by mistake
        self.process = subprocess.Popen([self.binary], cwd=self.workdir,
                                        stdin=subprocess.DEVNULL,
                                        stdout=self._log, stderr=subprocess.STDOUT,
                                        start_new_session=True)
        self.pgid = self.process.pid

    def run_until_exit(self, timeout=5, check_port=True):
        """For a configuration that must make the server stop: launch it and wait.
        Returns the exit status (negative = killed by that signal). The working
        directory, with the log, is kept until stop(). check_port=False: the port is
        expected to be busy."""
        self._spawn(check_port)
        try:
            return self.process.wait(timeout)
        finally:
            self.process = None if self.process.poll() is not None else self.process

    def log_folder_text(self):
        """Everything in the log files of the server (LOG_FOLDER = <workdir>/log/)."""
        text = ""
        folder = os.path.join(self.workdir, "log")
        for name in sorted(os.listdir(folder)):
            with open(os.path.join(folder, name), errors="replace") as f:
                text += f.read()
        return text

    def read_log(self):
        try:
            with open(os.path.join(self.workdir, "server.log"), "rb") as f:
                return f.read().decode(errors="replace")
        except (OSError, TypeError):
            return ""

    def is_running(self):
        return self.process is not None and self.process.poll() is None

    def stop(self):
        if self.process is not None:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(self.pgid, sig)
                except ProcessLookupError:
                    break
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    continue
                if not port_in_use(self.port):
                    break
            self.process = None
        if getattr(self, "_log", None):
            self._log.close()
            self._log = None
        if self.workdir:
            shutil.rmtree(self.workdir, ignore_errors=True)
            self.workdir = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()


def main():
    parser = argparse.ArgumentParser(description="Run a throw-away uFTP test server")
    parser.add_argument("--port", type=int, default=2121)
    parser.add_argument("--idle", type=int, default=60, help="IDLE_MAX_TIMEOUT seconds")
    args = parser.parse_args()

    with UFTPTestServer(port=args.port, idle_timeout=args.idle) as srv:
        print(f"uFTP test server running on {HOST}:{srv.port} (pid {srv.pgid})")
        print(f"workdir: {srv.workdir}")
        for user, password in srv.users:
            print(f"  user: {user}  password: {password}")
        print("Ctrl+C to stop")
        try:
            while srv.is_running():
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        else:
            print("server exited:\n" + srv.read_log())


if __name__ == "__main__":
    main()
