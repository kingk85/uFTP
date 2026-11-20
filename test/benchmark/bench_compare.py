#!/usr/bin/env python3
"""Benchmark: uFTP against vsftpd, ProFTPD and Pure-FTPd, same client, same machine, same data.

Every server runs alone in a Docker container (host network, root, data on a tmpfs, so the disk does
not count), with the version of Ubuntu 24.04. uFTP runs in the same kind of container with the
binary mounted from the host. The client is this script: one raw-socket FTP client, many processes.
What is measured about the server comes from the cgroup of its container (CPU time, memory,
processes), so it includes every process the server starts, not only the first one.

  python3 test/benchmark/bench_compare.py --out DIR \\
        --uftp-stock path/to/uFTP-built-with-the-stock-Makefile --uftp-o2 path/to/uFTP-built-with--O2

Groups (--groups, default all):
  perf   large files, many small files, login rate, command latency (alone and under load), mixed work
  idle   connections kept open and logged in (100 ... 10000), memory per connection, a busy
         group of clients working while the others stay connected
  tls    the same with explicit FTPS (AUTH TLS, PROT P)

The results are written as JSON in DIR, and `--report DIR` prints them as markdown tables.
Docker images: see Dockerfile (docker build --build-arg PKG=vsftpd -t uftp-bench-vsftpd . ...).
The authentication is made free of cost on every server (PAM that accepts everyone, or a plain text
user file) so that the measure is the server and not the password hashing.
"""

import argparse
import json
import multiprocessing as mp
import os
import random
import re
import socket
import ssl
import statistics
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = 2121
USER, PASSWORD = "ubuntu", "bench"
PASV_MIN, PASV_MAX = 20000, 30000        # under the range of the ephemeral ports of the client
MEMORY_LIMIT = "10g"                      # of the container: a server that needs more is stopped, not the machine
CHUNK = 1 << 20

_TLS_CONTEXT = None


def tls_context():
    global _TLS_CONTEXT
    if _TLS_CONTEXT is None:
        _TLS_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        _TLS_CONTEXT.check_hostname = False
        _TLS_CONTEXT.verify_mode = ssl.CERT_NONE
    return _TLS_CONTEXT


def percentile(values, p):
    if not values:
        return None
    values = sorted(values)
    return values[min(len(values) - 1, int(len(values) * p / 100.0))]


def summary_ms(values):
    """p50/p95/p99/max of a list of seconds, in milliseconds."""
    if not values:
        return {"n": 0}
    return {"n": len(values), "p50": round(percentile(values, 50) * 1000, 3),
            "p95": round(percentile(values, 95) * 1000, 3), "p99": round(percentile(values, 99) * 1000, 3),
            "max": round(max(values) * 1000, 3)}


# --------------------------------------------------------------------------------------------- client
class FtpError(Exception):
    pass


class Ftp:
    """Minimal FTP client on raw sockets (plain or explicit TLS)."""

    def __init__(self, port=PORT, source=None, tls=False, timeout=60):
        self.tls = tls
        self.protected = False
        self.timeout = timeout
        self.source = source
        sock = socket.socket()
        if source:
            sock.bind((source, 0))
        sock.settimeout(timeout)
        sock.connect(("127.0.0.1", port))
        self.sock = sock
        self.buf = b""
        banner = self.reply()
        if not banner.startswith("220"):
            raise FtpError("banner: " + banner)

    def reply(self):
        lines = []
        while True:
            while b"\n" not in self.buf:
                data = self.sock.recv(65536)
                if not data:
                    raise FtpError("connection closed")
                self.buf += data
            line, self.buf = self.buf.split(b"\n", 1)
            line = line.decode("latin-1").rstrip("\r")
            lines.append(line)
            if re.match(r"^\d{3} ", line) or (len(lines) == 1 and re.match(r"^\d{3}$", line)):
                if len(lines) == 1 or re.match(r"^%s " % lines[0][:3], line):
                    return "\n".join(lines)

    def cmd(self, line, expect=None):
        self.sock.sendall(line.encode() + b"\r\n")
        text = self.reply()
        if expect is not None and not text.startswith(expect):
            raise FtpError("%s -> %s" % (line, text))
        return text

    def login(self):
        if self.tls:
            self.cmd("AUTH TLS", "234")
            self.sock = tls_context().wrap_socket(self.sock, server_hostname=None)
        self.cmd("USER " + USER, "331")
        self.cmd("PASS " + PASSWORD, "230")
        if self.tls:
            self.cmd("PBSZ 0", "200")
            self.cmd("PROT P", "200")
            self.protected = True
        self.cmd("TYPE I", "200")

    def tls_info(self):
        return self.sock.version(), self.sock.cipher()[0] if self.tls else None

    def quit(self):
        try:
            self.sock.sendall(b"QUIT\r\n")
            self.sock.settimeout(2)
            self.sock.recv(1024)
        except Exception:
            pass
        self.close()

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass

    def _data(self, command):
        text = self.cmd("PASV", "227")
        m = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", text)
        port = int(m.group(5)) * 256 + int(m.group(6))
        data = socket.create_connection(("127.0.0.1", port), timeout=self.timeout,
                                        source_address=(self.source, 0) if self.source else None)
        self.sock.sendall(command.encode() + b"\r\n")
        text = self.reply()
        if not text.startswith(("150", "125")):
            data.close()
            raise FtpError("%s -> %s" % (command, text))
        if self.protected:
            data = tls_context().wrap_socket(data, server_hostname=None, session=self.sock.session)
        return data

    def retr(self, name):
        data = self._data("RETR " + name)
        total = 0
        buf = bytearray(CHUNK)
        while True:
            n = data.recv_into(buf)
            if n == 0:
                break
            total += n
        data.close()
        text = self.reply()
        if not text.startswith("226"):
            raise FtpError("RETR end: " + text)
        return total

    def stor(self, name, size, block=None):
        block = block or memoryview(os.urandom(CHUNK))
        data = self._data("STOR " + name)
        left = size
        while left > 0:
            part = block[:min(left, len(block))]
            data.sendall(part)
            left -= len(part)
        if self.protected:
            try:
                data = data.unwrap()
            except Exception:
                pass
        data.close()
        text = self.reply()
        if not text.startswith("226"):
            raise FtpError("STOR end: " + text)
        return size

    def list(self, path=""):
        data = self._data("LIST " + path if path else "LIST")
        chunks = []
        while True:
            part = data.recv(65536)
            if not part:
                break
            chunks.append(part)
        data.close()
        text = self.reply()
        if not text.startswith("226"):
            raise FtpError("LIST end: " + text)
        return b"".join(chunks)


# ------------------------------------------------------------------------------------- the servers
def write(path, text):
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, 0o755)


PRELUDE = """#!/bin/sh
usermod -d /data %s 2>/dev/null
chown %s:%s /data
chmod 755 /data
printf 'auth required pam_permit.so\\naccount required pam_permit.so\\nsession required pam_permit.so\\npassword required pam_permit.so\\n' > /etc/pam.d/bench-permit
""" % (USER, USER, USER)


class Server:
    """A server in a container."""

    name = ""
    image = ""

    def __init__(self, tmp, binary=None):
        self.tmp = tmp
        self.binary = binary
        self.conf = os.path.join(tmp, "conf-" + self.name)
        os.makedirs(self.conf, exist_ok=True)
        self.cid = None
        self.container = "ub-" + self.name

    def files(self, slots):
        """Writes the configuration into self.conf; returns the extra docker arguments."""
        raise NotImplementedError

    def start(self, slots=500):
        subprocess.run(["docker", "rm", "-f", self.container], capture_output=True)
        extra = self.files(slots)
        cert = os.path.join(self.tmp, "cert.pem")
        if not os.path.exists(cert):
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30", "-subj",
                            "/CN=bench", "-keyout", os.path.join(self.tmp, "key.pem"), "-out", cert],
                           check=True, capture_output=True)
            with open(os.path.join(self.tmp, "both.pem"), "w") as out:
                out.write(open(os.path.join(self.tmp, "key.pem")).read() + open(cert).read())
            for f in ("cert.pem", "key.pem", "both.pem"):
                os.chmod(os.path.join(self.tmp, f), 0o644)
        cmd = ["docker", "run", "-d", "--name", self.container, "--network", "host",
               "--init", "--ulimit", "nofile=1048576:1048576", "--memory", MEMORY_LIMIT, "--memory-swap", MEMORY_LIMIT,
               "--tmpfs", "/data:rw,size=14g,mode=755", "-v", self.conf + ":/conf:ro",
               "-v", self.tmp + ":/certs:ro"] + extra + [self.image, "/bin/sh", "/conf/start.sh"]
        out = subprocess.run(cmd, capture_output=True, text=True)
        if out.returncode != 0:
            raise RuntimeError(out.stderr)
        self.cid = out.stdout.strip()
        self.cg = "/sys/fs/cgroup/system.slice/docker-%s.scope" % self.cid
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", PORT), timeout=1) as s:
                    if s.recv(100).startswith(b"220"):
                        time.sleep(0.5)
                        return
            except OSError:
                pass
            time.sleep(0.2)
        logs = subprocess.run(["docker", "logs", self.container], capture_output=True, text=True)
        raise RuntimeError("%s does not answer: %s" % (self.name, (logs.stdout + logs.stderr)[-500:]))

    def stop(self):
        subprocess.run(["docker", "rm", "-f", self.container], capture_output=True)

    def alive(self):
        return os.path.exists(self.cg) and subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", self.container], capture_output=True, text=True
        ).stdout.strip() == "true"

    # ---- cgroup readings ------------------------------------------------------------------------
    def cpu(self):
        values = {}
        with open(self.cg + "/cpu.stat") as f:
            for line in f:
                k, v = line.split()
                values[k] = int(v)
        return values["usage_usec"] / 1e6, values["user_usec"] / 1e6, values["system_usec"] / 1e6

    def memory(self):
        """Memory of the server in MB: everything the cgroup uses except the files in the tmpfs."""
        stat = {}
        with open(self.cg + "/memory.stat") as f:
            for line in f:
                k, v = line.split()
                stat[k] = int(v)
        with open(self.cg + "/memory.current") as f:
            current = int(f.read())
        return (current - stat.get("file", 0) - stat.get("shmem", 0)) / 1048576.0

    def pids(self):
        with open(self.cg + "/pids.current") as f:
            return int(f.read())

    def oom_killed(self):
        try:
            with open(self.cg + "/memory.events") as f:
                for line in f:
                    if line.startswith("oom_kill ") and int(line.split()[1]) > 0:
                        return True
        except OSError:
            pass
        return False


class UFTP(Server):
    image = "uftp-bench-uftp"

    def __init__(self, tmp, binary, name):
        self.name = name
        super().__init__(tmp, binary)

    def files(self, slots):
        cfg = {
            "MAXIMUM_ALLOWED_FTP_CONNECTION": slots, "FTP_PORT": PORT, "SINGLE_INSTANCE": "false",
            "DAEMON_MODE": "false", "RESPAWN_PROCESS": "false", "IDLE_MAX_TIMEOUT": 3600, "LOGIN_TIMEOUT": 0,
            "MAX_CONNECTION_NUMBER_PER_IP": 0, "MAX_CONNECTION_TRY_PER_IP": 0, "MAX_CONNECTION_RATE_PER_IP": 0,
            "LOG_FOLDER": "/tmp/", "MAXIMUM_LOG_FILES": 0, "CERTIFICATE_PATH": "/certs/cert.pem",
            "PRIVATE_CERTIFICATE_PATH": "/certs/key.pem", "ENABLE_PAM_AUTH": "false", "FORCE_TLS": "false",
            "RANDOM_PORT_START": PASV_MIN, "RANDOM_PORT_END": PASV_MAX, "USER_0": USER, "PASSWORD_0": PASSWORD,
            "HOME_0": "/data/",
        }
        with open(os.path.join(self.conf, "uftpd.cfg"), "w") as f:
            f.write("".join("%s = %s\n" % kv for kv in cfg.items()))
        write(os.path.join(self.conf, "start.sh"), PRELUDE + "cd /conf && exec /opt/uFTP\n")
        return ["-v", "%s:/opt/uFTP:ro" % os.path.abspath(self.binary)]


class Vsftpd(Server):
    name = "vsftpd"
    image = "uftp-bench-vsftpd"

    def files(self, slots):
        cfg = """listen=YES
listen_ipv6=NO
listen_port=%d
background=NO
local_enable=YES
write_enable=YES
local_umask=022
chroot_local_user=YES
allow_writeable_chroot=YES
local_root=/data
pam_service_name=bench-permit
max_clients=0
max_per_ip=0
pasv_enable=YES
pasv_min_port=%d
pasv_max_port=%d
xferlog_enable=NO
dirmessage_enable=NO
idle_session_timeout=3600
data_connection_timeout=3600
seccomp_sandbox=NO
isolate=NO
isolate_network=NO
secure_chroot_dir=/var/run/vsftpd/empty
ssl_enable=YES
force_local_data_ssl=NO
force_local_logins_ssl=NO
require_ssl_reuse=NO
rsa_cert_file=/certs/cert.pem
rsa_private_key_file=/certs/key.pem
""" % (PORT, PASV_MIN, PASV_MAX)
        with open(os.path.join(self.conf, "vsftpd.conf"), "w") as f:
            f.write(cfg)
        write(os.path.join(self.conf, "start.sh"),
              PRELUDE + "mkdir -p /var/run/vsftpd/empty\ncp /conf/vsftpd.conf /etc/vsftpd-bench.conf\nexec vsftpd /etc/vsftpd-bench.conf\n")
        return []


class Proftpd(Server):
    name = "proftpd"
    image = "uftp-bench-proftpd"

    def files(self, slots):
        cfg = """ServerName "bench"
ServerType standalone
DefaultServer on
Port %d
UseIPv6 off
User root
Group root
MaxInstances none
MaxClients none
MaxClientsPerHost none
MaxClientsPerUser none
UseReverseDNS off
DelayEngine off
TimeoutLogin 3600
TimeoutIdle 3600
TimeoutNoTransfer 3600
TimeoutStalled 3600
RequireValidShell off
UseFtpUsers off
AuthOrder mod_auth_pam.c* mod_auth_unix.c
AuthPAM on
AuthPAMConfig bench-permit
DefaultRoot /data
PassivePorts %d %d
TransferLog none
WtmpLog off
SystemLog /dev/null
ScoreboardFile /run/proftpd.scoreboard
PidFile /run/proftpd.pid
AllowOverwrite on
AllowForeignAddress on
<Global>
  <Limit ALL>
    AllowAll
  </Limit>
</Global>
LoadModule mod_tls.c
<IfModule mod_tls.c>
  TLSEngine on
  TLSLog /dev/null
  TLSRequired off
  TLSRSACertificateFile /certs/cert.pem
  TLSRSACertificateKeyFile /certs/key.pem
  TLSOptions NoSessionReuseRequired
  TLSVerifyClient off
  TLSProtocol TLSv1.2 TLSv1.3
</IfModule>
""" % (PORT, PASV_MIN, PASV_MAX)
        with open(os.path.join(self.conf, "proftpd.conf"), "w") as f:
            f.write(cfg)
        write(os.path.join(self.conf, "start.sh"), PRELUDE +
              "exec proftpd -n -c /conf/proftpd.conf\n")
        return []


class Pureftpd(Server):
    name = "pureftpd"
    image = "uftp-bench-pureftpd"

    def files(self, slots):
        write(os.path.join(self.conf, "start.sh"), PRELUDE +
              "mkdir -p /etc/ssl/private && cp /certs/both.pem /etc/ssl/private/pure-ftpd.pem && chmod 600 "
              "/etc/ssl/private/pure-ftpd.pem\n"
              "cp /etc/pam.d/bench-permit /etc/pam.d/pure-ftpd\n"
              "exec pure-ftpd -l pam -S 0.0.0.0,%d -c 30000 -C 30000 -p %d:%d -H -A -R -u 100 -I 60 -Y 1 "
              "-E 2>&1\n" % (PORT, PASV_MIN, PASV_MAX))
        return ["--privileged"]          # without it: "Unable to switch capabilities" (it drops the capabilities itself)


def make_servers(tmp, args):
    servers = {}
    if args.uftp_stock:
        servers["uftp-stock"] = UFTP(tmp, args.uftp_stock, "uftp-stock")
    if args.uftp_o2:
        servers["uftp-o2"] = UFTP(tmp, args.uftp_o2, "uftp-o2")
    servers["vsftpd"] = Vsftpd(tmp)
    servers["proftpd"] = Proftpd(tmp)
    servers["pureftpd"] = Pureftpd(tmp)
    wanted = [s for s in args.servers.split(",") if s]
    return {k: v for k, v in servers.items() if not wanted or k in wanted}


# ------------------------------------------------------------------------------------- scenarios
CTX = mp.get_context("fork")


def run_workers(target, count, args_for, server, extra_wait=0):
    """Starts `count` processes that log in and wait at a barrier; the CPU of the server is read when
    they are released and when they finish. Returns (results, wall seconds, cpu tuple)."""
    barrier = CTX.Barrier(count + 1)
    queue = CTX.Queue()
    procs = []
    for i in range(count):
        p = CTX.Process(target=target, args=(i, barrier, queue) + tuple(args_for(i)))
        p.start()
        procs.append(p)
    barrier.wait(timeout=300)
    cpu0 = server.cpu()
    t0 = time.time()
    results = []
    for _ in procs:
        results.append(queue.get(timeout=900))
    wall = time.time() - t0
    cpu1 = server.cpu()
    for p in procs:
        p.join(30)
    return results, wall, tuple(b - a for a, b in zip(cpu0, cpu1))


def source_for(i):
    return "127.0.0.%d" % (2 + i % 50)


def w_transfer(i, barrier, queue, kind, name, size, tls):
    try:
        c = Ftp(source=source_for(i), tls=tls)
        c.login()
        barrier.wait()
        t0 = time.time()
        n = c.stor(name, size) if kind == "stor" else c.retr(name)
        t1 = time.time()
        c.quit()
        queue.put(("ok", t0, t1, n))
    except Exception as e:
        try:
            barrier.wait(0.1)
        except Exception:
            pass
        queue.put(("error", repr(e)))


def throughput(server, kind, count, size, tls, names):
    results, wall, cpu = run_workers(w_transfer, count, lambda i: (kind, names[i], size, tls), server)
    ok = [r for r in results if r[0] == "ok"]
    errors = [r[1] for r in results if r[0] == "error"]
    if not ok:
        return {"errors": errors[:3]}
    span = max(r[2] for r in ok) - min(r[1] for r in ok)
    total = sum(r[3] for r in ok)
    return {"clients": count, "bytes": total, "seconds": round(span, 3), "MB_s": round(total / span / 1e6, 1),
            "cpu_s": round(cpu[0], 3), "cpu_user_s": round(cpu[1], 3), "cpu_sys_s": round(cpu[2], 3),
            "cpu_s_per_GB": round(cpu[0] / (total / 1e9), 3), "errors": len(errors), "error_sample": errors[:2]}


def w_small(i, barrier, queue, count, size, tls):
    try:
        c = Ftp(source=source_for(i), tls=tls)
        c.login()
        block = memoryview(os.urandom(size))
        barrier.wait()
        t0 = time.time()
        errors = 0
        for k in range(count):
            try:
                c.stor("s%d_%d" % (i, k), size, block)
            except Exception:
                errors += 1
        t1 = time.time()
        barrier.wait()
        t2 = time.time()
        for k in range(count):
            try:
                c.retr("s%d_%d" % (i, k))
            except Exception:
                errors += 1
        t3 = time.time()
        c.quit()
        queue.put(("ok", t0, t1, t2, t3, errors))
    except Exception as e:
        queue.put(("error", repr(e)))


def small_files(server, clients, count, size, tls):
    """STOR then RETR of many small files; the barrier between the two phases is inside the worker."""
    barrier = CTX.Barrier(clients + 1)
    queue = CTX.Queue()
    procs = [CTX.Process(target=w_small, args=(i, barrier, queue, count, size, tls)) for i in range(clients)]
    for p in procs:
        p.start()
    barrier.wait(timeout=300)
    cpu0 = server.cpu()
    barrier.wait(timeout=600)               # the workers finished the STORs
    cpu1 = server.cpu()
    results = [queue.get(timeout=900) for _ in procs]
    cpu2 = server.cpu()
    for p in procs:
        p.join(30)
    ok = [r for r in results if r[0] == "ok"]
    if not ok:
        return {"errors": [r[1] for r in results][:3]}
    files = clients * count
    stor_span = max(r[2] for r in ok) - min(r[1] for r in ok)
    retr_span = max(r[4] for r in ok) - min(r[3] for r in ok)
    return {"clients": clients, "files_each": count, "size": size,
            "stor_files_s": round(files / stor_span, 1), "retr_files_s": round(files / retr_span, 1),
            "stor_cpu_ms_per_file": round((cpu1[0] - cpu0[0]) / files * 1000, 3),
            "retr_cpu_ms_per_file": round((cpu2[0] - cpu1[0]) / files * 1000, 3),
            "errors": sum(r[5] for r in ok)}


def w_login(i, barrier, queue, seconds, tls):
    lat, errors, n = [], 0, 0
    barrier.wait()
    end = time.time() + seconds
    while time.time() < end:
        t = time.perf_counter()
        try:
            c = Ftp(source=source_for(i), tls=tls)
            c.login()
            lat.append(time.perf_counter() - t)
            c.quit()
        except Exception:
            errors += 1
    queue.put((lat, errors))


def login_rate(server, clients, seconds, tls):
    results, wall, cpu = run_workers(w_login, clients, lambda i: (seconds, tls), server)
    lat = [x for r in results for x in r[0]]
    errors = sum(r[1] for r in results)
    out = {"clients": clients, "logins_s": round(len(lat) / wall, 1), "errors": errors,
           "cpu_ms_per_login": round(cpu[0] / max(1, len(lat)) * 1000, 3)}
    out.update({"lat_" + k: v for k, v in summary_ms(lat).items()})
    return out


def noop_latency(port, count, tls):
    c = Ftp(source="127.0.0.60", tls=tls)
    c.login()
    out = {}
    for name, command in (("NOOP", "NOOP"), ("PWD", "PWD")):
        lat = []
        for _ in range(count):
            t = time.perf_counter()
            c.cmd(command)
            lat.append(time.perf_counter() - t)
        out[name] = summary_ms(lat)
    lat = []
    c.cmd("MKD listdir")
    for k in range(50):
        c.stor("listdir/f%d" % k, 100)
    for _ in range(max(20, count // 40)):
        t = time.perf_counter()
        c.list("listdir")
        lat.append(time.perf_counter() - t)
    out["LIST_small_dir"] = summary_ms(lat)
    c.quit()
    return out


def w_background_retr(i, barrier, queue, name, stop, tls):
    try:
        c = Ftp(source=source_for(i), tls=tls)
        c.login()
        barrier.wait()
        while not stop.is_set():
            c.retr(name)
        c.quit()
        queue.put("ok")
    except Exception as e:
        queue.put(repr(e))


def latency_under_load(server, background, name, tls):
    stop = CTX.Event()
    barrier = CTX.Barrier(background + 1)
    queue = CTX.Queue()
    procs = [CTX.Process(target=w_background_retr, args=(i, barrier, queue, name, stop, tls))
             for i in range(background)]
    for p in procs:
        p.start()
    barrier.wait(timeout=120)
    time.sleep(0.5)
    try:
        out = noop_latency(PORT, 1500, tls)
    finally:
        stop.set()
        for p in procs:
            p.join(60)
    out["background_downloads"] = background
    return out


MIX_DIR_FILES = 50


def w_mixed(i, barrier, queue, seconds, tls):
    lat, errors, ops = {}, 0, 0
    try:
        c = Ftp(source=source_for(i), tls=tls)
        c.login()
        block = memoryview(os.urandom(65536))
        c.cmd("MKD mix%d" % i)
        c.cmd("CWD mix%d" % i, "250")
        for k in range(MIX_DIR_FILES):
            c.stor("f%d" % k, 100, block)
        c.stor("data", 65536, block)
        barrier.wait()
    except Exception as e:
        queue.put(({}, 1, 0, repr(e)))
        return
    end = time.time() + seconds
    k = 0
    while time.time() < end:
        for name, fn in (
                ("NOOP", lambda: c.cmd("NOOP", "200")),
                ("PWD", lambda: c.cmd("PWD", "257")),
                ("SIZE", lambda: c.cmd("SIZE data", "213")),
                ("LIST", lambda: c.list()),
                ("RETR64K", lambda: c.retr("data")),
                ("STOR64K", lambda: c.stor("up%d" % (k % 20), 65536, block)),
                ("DELE", lambda: c.cmd("DELE up%d" % (k % 20))),
        ):
            t = time.perf_counter()
            try:
                fn()
            except Exception:
                errors += 1
            lat.setdefault(name, []).append(time.perf_counter() - t)
            ops += 1
        k += 1
    queue.put((lat, errors, ops, None))
    c.quit()


def mixed(server, clients, seconds, tls):
    barrier = CTX.Barrier(clients + 1)
    queue = CTX.Queue()
    procs = [CTX.Process(target=w_mixed, args=(i, barrier, queue, seconds, tls)) for i in range(clients)]
    for p in procs:
        p.start()
    barrier.wait(timeout=300)
    cpu0 = server.cpu()
    t0 = time.time()
    results = [queue.get(timeout=seconds + 300) for _ in procs]
    wall = time.time() - t0
    cpu1 = server.cpu()
    for p in procs:
        p.join(30)
    failed = [r[3] for r in results if r[3]]
    ops = sum(r[2] for r in results)
    errors = sum(r[1] for r in results)
    alllat = {}
    for r in results:
        for k, v in r[0].items():
            alllat.setdefault(k, []).extend(v)
    flat = [x for v in alllat.values() for x in v]
    out = {"clients": clients, "seconds": round(wall, 1), "ops": ops, "ops_s": round(ops / wall, 1),
           "errors": errors, "workers_failed": len(failed), "cpu_s": round(cpu1[0] - cpu0[0], 2),
           "cpu_ms_per_op": round((cpu1[0] - cpu0[0]) / max(1, ops) * 1000, 3)}
    out.update({"lat_" + k: v for k, v in summary_ms(flat).items()})
    out["lat_by_op_p95_ms"] = {k: round(percentile(v, 95) * 1000, 2) for k, v in alllat.items()}
    return out


def open_idle(count, offset, tls, threads=32):
    """Opens `count` logged in connections; returns (connections, failures, seconds)."""
    conns, failures = [], [0]
    lock = threading.Lock()
    index = [offset]

    def run():
        while True:
            with lock:
                if index[0] >= offset + count:
                    return
                i = index[0]
                index[0] += 1
            try:
                c = Ftp(source="127.0.0.%d" % (100 + i // 5000), tls=tls, timeout=60)
                c.login()
                with lock:
                    conns.append(c)
            except Exception:
                with lock:
                    failures[0] += 1

    t0 = time.time()
    ts = [threading.Thread(target=run) for _ in range(threads)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return conns, failures[0], time.time() - t0


def host_memory_available_mb():
    with open("/proc/meminfo") as f:
        for line in f:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) / 1024.0


def idle_group(server, steps, tls, workers, work_seconds):
    base_mem = server.memory()
    base_pids = server.pids()
    out = {"baseline_MB": round(base_mem, 1), "baseline_pids": base_pids, "steps": {}}
    conns = []
    last_ok = 0
    for step in steps:
        if host_memory_available_mb() < 4000:
            out["steps"][str(step)] = {"skipped": "host memory low"}
            break
        more = step - len(conns)
        new, failures, secs = open_idle(more, len(conns), tls)
        conns.extend(new)
        entry = {"opened": len(conns), "failures": failures, "open_seconds": round(secs, 1)}
        if failures > 0.01 * step or not server.alive() or server.oom_killed():
            entry["result"] = "FAIL"
            entry["alive"] = server.alive()
            entry["oom_killed"] = server.oom_killed()
            out["steps"][str(step)] = entry
            break
        time.sleep(3)
        mem = server.memory()
        entry["memory_MB"] = round(mem, 1)
        entry["KB_per_connection"] = round((mem - base_mem) * 1024 / max(1, len(conns)), 1)
        entry["processes"] = server.pids()
        c0 = server.cpu()
        time.sleep(5)
        c1 = server.cpu()
        entry["idle_cpu_percent"] = round((c1[0] - c0[0]) / 5 * 100, 2)
        # latency on some of the open connections
        lat = []
        for c in random.sample(conns, min(30, len(conns))):
            for _ in range(10):
                t = time.perf_counter()
                try:
                    c.cmd("NOOP", "200")
                    lat.append(time.perf_counter() - t)
                except Exception:
                    entry["noop_failures"] = entry.get("noop_failures", 0) + 1
        entry.update({"noop_" + k: v for k, v in summary_ms(lat).items()})
        if workers:
            try:
                entry["working"] = mixed(server, workers, work_seconds, tls)
            except Exception as e:
                entry["working"] = {"error": repr(e)}
        entry["result"] = "OK"
        out["steps"][str(step)] = entry
        last_ok = step
        print("   %6d connections: %s" % (step, {k: entry.get(k) for k in
              ("failures", "KB_per_connection", "idle_cpu_percent", "noop_p95")}), flush=True)
    out["max_ok_step"] = last_ok
    # close them all and see how the server recovers
    t0 = time.time()
    for c in conns:
        c.close()
    deadline = time.time() + 60
    while time.time() < deadline and server.alive() and server.pids() > base_pids + 3:
        time.sleep(0.5)
    out["after_close"] = {"seconds_to_release": round(time.time() - t0, 1),
                          "memory_MB": round(server.memory(), 1) if server.alive() else None,
                          "processes": server.pids() if server.alive() else None}
    return out


# ------------------------------------------------------------------------------------- the groups
def group_perf(server, quick, tls=False):
    res = {}
    size = (64 if quick else 1024) * (1 << 20) // (4 if tls else 1)
    par = 4 if tls else 8
    par_size = size // 2 if not tls else size
    names = ["big%d" % i for i in range(par)]

    def step(name, fn):
        print("  %-28s" % name, end="", flush=True)
        t = time.time()
        try:
            res[name] = fn()
            print(" %.0fs" % (time.time() - t), flush=True)
        except Exception as e:
            res[name] = {"error": repr(e)}
            print(" ERROR %r" % e, flush=True)

    step("stor_1_client", lambda: throughput(server, "stor", 1, size, tls, ["big0"]))
    step("retr_1_client", lambda: throughput(server, "retr", 1, size, tls, ["big0"]))
    step("stor_%d_clients" % par, lambda: throughput(server, "stor", par, par_size, tls, ["p%d" % i for i in range(par)]))
    step("retr_%d_clients" % par, lambda: throughput(server, "retr", par, size, tls, ["big0"] * par))
    if not tls:
        n_small = 100 if quick else 1000
        step("small_files_1_client", lambda: small_files(server, 1, n_small, 4096, tls))
        step("small_files_16_clients", lambda: small_files(server, 16, n_small // 2, 4096, tls))
    step("login_rate", lambda: login_rate(server, 32 if not tls else 16, 4 if quick else 10, tls))
    step("latency_alone", lambda: noop_latency(PORT, 500 if quick else 3000, tls))
    step("latency_under_load", lambda: latency_under_load(server, 8 if not tls else 4, "big0", tls))
    step("mixed_16_clients", lambda: mixed(server, 16, 4 if quick else 15, tls))
    step("mixed_64_clients", lambda: mixed(server, 64 if not tls else 32, 4 if quick else 15, tls))
    return res


def negotiated_tls():
    c = Ftp(source="127.0.0.61", tls=True)
    c.login()
    info = c.tls_info()
    c.quit()
    return {"version": info[0], "cipher": info[1]}


def merge_median(runs):
    """One result from several runs: the median of every number, the first run for everything else."""
    first = runs[0]
    if isinstance(first, dict):
        return {k: merge_median([r[k] for r in runs if isinstance(r, dict) and k in r]) for k in first}
    if isinstance(first, bool) or not isinstance(first, (int, float)):
        return first
    values = [r for r in runs if isinstance(r, (int, float)) and not isinstance(r, bool)]
    return round(statistics.median(values), 3)


def run_server(server, groups, out_dir, quick, repeat=1):
    path = os.path.join(out_dir, server.name + ".json")
    results = json.load(open(path)) if os.path.exists(path) else {}

    def save():
        with open(path, "w") as f:
            json.dump(results, f, indent=1)

    steps_plain = [100, 500, 1000] if quick else [100, 1000, 5000, 10000]
    steps_tls = [100, 500] if quick else [100, 1000, 5000]
    work = 4 if quick else 8
    if "perf" in groups:
        print("== %s: perf" % server.name, flush=True)
        runs = []
        for n in range(repeat):
            server.start(slots=500)
            try:
                run = group_perf(server, quick)
                run["baseline_MB_idle"] = round(server.memory(), 1)
                runs.append(run)
            finally:
                server.stop()
        results["perf"] = merge_median(runs) if len(runs) > 1 else runs[0]
        results["perf_runs"] = runs
        save()
    if "idle" in groups:
        print("== %s: idle connections" % server.name, flush=True)
        server.start(slots=12000)
        try:
            results["idle"] = idle_group(server, steps_plain, False, 16, work)
        finally:
            server.stop()
        save()
    if "tls" in groups:
        print("== %s: tls" % server.name, flush=True)
        tls_runs = []
        tls_res = {}
        for n in range(repeat):
            server.start(slots=6000)
            try:
                tls_res["negotiated"] = negotiated_tls()
                tls_runs.append(group_perf(server, quick, tls=True))
            finally:
                server.stop()
        tls_res["perf"] = merge_median(tls_runs) if len(tls_runs) > 1 else tls_runs[0]
        tls_res["perf_runs"] = tls_runs
        results["tls"] = tls_res
        save()
        server.start(slots=6000)                 # a new container: the files of the transfers do not count
        try:
            results["tls"]["idle"] = idle_group(server, steps_tls, True, 8, work)
        finally:
            server.stop()
        save()


# --------------------------------------------------------------------------------------- report
def report(directory):
    data = {}
    for f in sorted(os.listdir(directory)):
        if f.endswith(".json"):
            data[f[:-5]] = json.load(open(os.path.join(directory, f)))
    names = [n for n in ("uftp-stock", "uftp-o2", "vsftpd", "proftpd", "pureftpd") if n in data]

    def table(title, rows, header_note=""):
        print("\n### %s\n%s" % (title, header_note))
        print("| Metrica | " + " | ".join(names) + " |")
        print("|---|" + "---|" * len(names))
        for label, getter in rows:
            vals = []
            for n in names:
                try:
                    v = getter(data[n])
                except Exception:
                    v = None
                vals.append("-" if v is None else str(v))
            print("| %s | %s |" % (label, " | ".join(vals)))

    def g(*path):
        def f(d):
            for p in path:
                d = d[p]
            return d
        return f

    for group, label, prefix in (("perf", "Plain", ("perf",)), ("tls", "FTPS", ("tls", "perf"))):
        if not any(group in data[n] for n in names):
            continue
        rows = []
        for key in [k for k in (data[names[0]].get(group, {}) if group == "perf" else data[names[0]].get("tls", {}).get("perf", {})).keys()]:
            pass
        table("%s: large files (MB/s, and CPU seconds of the server per GB)" % label, [
            ("STOR 1 client, MB/s", g(*prefix, "stor_1_client", "MB_s")),
            ("RETR 1 client, MB/s", g(*prefix, "retr_1_client", "MB_s")),
            ("STOR parallel, MB/s", lambda d, p=prefix: next(v["MB_s"] for k, v in _get(d, p).items() if k.startswith("stor_") and k != "stor_1_client")),
            ("RETR parallel, MB/s", lambda d, p=prefix: next(v["MB_s"] for k, v in _get(d, p).items() if k.startswith("retr_") and k != "retr_1_client")),
            ("RETR 1 client, CPU s/GB", g(*prefix, "retr_1_client", "cpu_s_per_GB")),
            ("STOR 1 client, CPU s/GB", g(*prefix, "stor_1_client", "cpu_s_per_GB")),
        ])
        table("%s: logins and command latency" % label, [
            ("logins/s", g(*prefix, "login_rate", "logins_s")),
            ("login p95 ms", g(*prefix, "login_rate", "lat_p95")),
            ("NOOP p50 ms (alone)", g(*prefix, "latency_alone", "NOOP", "p50")),
            ("NOOP p99 ms (alone)", g(*prefix, "latency_alone", "NOOP", "p99")),
            ("NOOP p99 ms (under load)", g(*prefix, "latency_under_load", "NOOP", "p99")),
            ("LIST small dir p50 ms", g(*prefix, "latency_alone", "LIST_small_dir", "p50")),
        ])
        table("%s: mixed work (NOOP/PWD/SIZE/LIST/RETR/STOR/DELE)" % label, [
            ("16 clients, ops/s", g(*prefix, "mixed_16_clients", "ops_s")),
            ("16 clients, p95 ms", g(*prefix, "mixed_16_clients", "lat_p95")),
            ("16 clients, errors", g(*prefix, "mixed_16_clients", "errors")),
            ("many clients, ops/s", lambda d, p=prefix: _get(d, p)[[k for k in _get(d, p) if k.startswith("mixed_") and "16" not in k][0]]["ops_s"]),
            ("many clients, p95 ms", lambda d, p=prefix: _get(d, p)[[k for k in _get(d, p) if k.startswith("mixed_") and "16" not in k][0]]["lat_p95"]),
            ("many clients, errors", lambda d, p=prefix: _get(d, p)[[k for k in _get(d, p) if k.startswith("mixed_") and "16" not in k][0]]["errors"]),
        ])
    if any("perf" in data[n] and "small_files_1_client" in data[n]["perf"] for n in names):
        table("Small files (4 KB)", [
            ("STOR 1 client, files/s", g("perf", "small_files_1_client", "stor_files_s")),
            ("RETR 1 client, files/s", g("perf", "small_files_1_client", "retr_files_s")),
            ("STOR 16 clients, files/s", g("perf", "small_files_16_clients", "stor_files_s")),
            ("RETR 16 clients, files/s", g("perf", "small_files_16_clients", "retr_files_s")),
            ("RETR 16 clients, CPU ms/file", g("perf", "small_files_16_clients", "retr_cpu_ms_per_file")),
        ])
    for label, key in (("Plain", ("idle",)), ("FTPS", ("tls", "idle"))):
        steps = set()
        for n in names:
            try:
                steps.update(int(s) for s in _get(data[n], key)["steps"])
            except Exception:
                pass
        if not steps:
            continue
        rows = [("baseline MB (0 connections)", g(*key, "baseline_MB"))]
        for s in sorted(steps):
            s = str(s)
            rows += [
                ("%s conn: result" % s, lambda d, s=s: _get(d, key)["steps"][s].get("result", _get(d, key)["steps"][s].get("skipped"))),
                ("%s conn: KB/conn" % s, lambda d, s=s: _get(d, key)["steps"][s]["KB_per_connection"]),
                ("%s conn: processes" % s, lambda d, s=s: _get(d, key)["steps"][s]["processes"]),
                ("%s conn: idle CPU %%" % s, lambda d, s=s: _get(d, key)["steps"][s]["idle_cpu_percent"]),
                ("%s conn: NOOP p95 ms" % s, lambda d, s=s: _get(d, key)["steps"][s]["noop_p95"]),
                ("%s conn: workers ops/s" % s, lambda d, s=s: _get(d, key)["steps"][s]["working"]["ops_s"]),
                ("%s conn: workers p95 ms" % s, lambda d, s=s: _get(d, key)["steps"][s]["working"]["lat_p95"]),
            ]
        table("%s: connections kept open" % label, rows)
    if any("tls" in data[n] for n in names):
        print("\nTLS negotiated:", {n: data[n]["tls"]["negotiated"] for n in names if "tls" in data[n]})


def _get(d, path):
    for p in path:
        d = d[p]
    return d


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default=None)
    parser.add_argument("--report", default=None)
    parser.add_argument("--uftp-stock")
    parser.add_argument("--uftp-o2")
    parser.add_argument("--servers", default="")
    parser.add_argument("--groups", default="perf,idle,tls")
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--repeat", type=int, default=3, help="runs of the perf and tls groups; the median is reported")
    args = parser.parse_args()
    if args.report:
        report(args.report)
        return
    out = args.out or tempfile.mkdtemp(prefix="bench-")
    os.makedirs(out, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="bench-conf-")
    os.chmod(tmp, 0o755)
    groups = args.groups.split(",")
    for name, server in make_servers(tmp, args).items():
        try:
            run_server(server, groups, out, args.quick, args.repeat)
        except Exception as e:
            print("!! %s: %r" % (name, e), flush=True)
            server.stop()
    print("results in", out)


if __name__ == "__main__":
    main()
