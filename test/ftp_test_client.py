"""
Raw FTP client shared by the test suites.

Everything goes over plain sockets, so that the tests check the exact replies of the
server. Each suite binds FtpControl to its own test server with a small subclass.
"""

import os
import re
import shutil
import socket
import ssl

from uftp_test_server import HOST


class FtpControl:
    """FTP control connection: cmd() returns (reply code, full reply text)."""

    def __init__(self, port, user=None, password=None, login=True, timeout=5, host=HOST):
        """host: HOST (127.0.0.1), or "::1" to connect over IPv6."""
        self.user = user
        self.password = password
        self.host = host
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.file = self.sock.makefile("rb")
        self.welcome = self.read_reply()
        if login:
            self.login()

    def login(self, user=None, password=None):
        code, text = self.cmd(f"USER {user or self.user}")
        assert code == 331, text
        code, text = self.cmd(f"PASS {password or self.password}")
        assert code == 230, text

    def send(self, line):
        """Send one command line; CRLF is added unless the bytes already end with it."""
        if isinstance(line, str):
            line = line.encode("utf-8")
        if not line.endswith(b"\r\n"):
            line += b"\r\n"
        self.sock.sendall(line)

    def read_reply(self):
        """One complete reply; multi-line replies end with '<code><space>'."""
        lines = []
        while True:
            line = self.file.readline()
            if not line:
                raise EOFError("control connection closed by the server; got so far: %r" % lines)
            line = line.decode("utf-8", errors="replace")
            lines.append(line)
            if re.match(r"\d{3} ", line) and line[:3] == lines[0][:3]:
                break
        return int(lines[0][:3]), "".join(lines)

    def cmd(self, line):
        self.send(line)
        return self.read_reply()

    def start_tls(self):
        code, text = self.cmd("AUTH TLS")
        assert code == 234, text
        self.sock = tls_client_context().wrap_socket(self.sock, server_hostname=HOST)
        self.file = self.sock.makefile("rb")

    # ---- data connections ------------------------------------------------
    def pasv(self):
        code, text = self.cmd("PASV")
        assert code == 227, text
        numbers = [int(n) for n in re.search(r"\(([\d,]+)\)", text).group(1).split(",")]
        assert len(numbers) == 6, text
        address = ".".join(str(n) for n in numbers[:4])
        return socket.create_connection((address, numbers[4] * 256 + numbers[5]), timeout=5)

    def epsv(self):
        code, text = self.cmd("EPSV")
        assert code == 229, text
        port = int(re.search(r"\(\|\|\|(\d+)\|\)", text).group(1))
        return socket.create_connection((self.host, port), timeout=5)

    def download(self, command, data_sock):
        """Run a command that sends data to the client: (final code, bytes)."""
        code, text = self.cmd(command)
        if code != 150:
            data_sock.close()
            return code, b""
        chunks = []
        while True:
            chunk = data_sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        data_sock.close()
        code, text = self.read_reply()
        return code, b"".join(chunks)

    def upload(self, command, data_sock, payload):
        code, text = self.cmd(command)
        if code != 150:
            data_sock.close()
            return code
        data_sock.sendall(payload)
        data_sock.close()
        return self.read_reply()[0]

    def close(self):
        try:
            self.file.close()
            self.sock.close()
        except OSError:
            pass


def tls_client_context():
    """TLS context for the self-signed certificate of the test server."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def listening_socket(address=HOST):
    """A listening socket for active mode (PORT/EPRT): (socket, port). An address with a
    colon ("::1") gives an IPv6 socket."""
    listener = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM)
    listener.bind((address, 0))
    listener.listen(1)
    listener.settimeout(3)
    return listener, listener.getsockname()[1]


def port_argument(address, port):
    """The h1,h2,h3,h4,p1,p2 argument of PORT."""
    return "%s,%d,%d" % (address.replace(".", ","), port // 256, port % 256)


def empty_directory(directory):
    """Remove everything inside a directory (links are removed, not followed)."""
    for name in os.listdir(directory):
        path = os.path.join(directory, name)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)
