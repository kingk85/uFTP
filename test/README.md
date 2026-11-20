# uFTP tests

One command builds uFTP with OpenSSL and runs every test:

```
test/run_tests.sh
```

It needs `python3` (standard library only), `openssl`, `make` and a C compiler. Nothing
has to be configured and nothing is installed: every suite starts its own throw-away server on
`127.0.0.1`, with a generated configuration, test users, self-signed certificate and FTP root in a
temporary directory that is removed at the end. Run it as a normal user, not as root. It takes about four minutes;
the exit code is 0 only if every test passed.

## Options

```
test/run_tests.sh --no-build           use the build/uFTP already built
test/run_tests.sh -v                   one line per test
test/run_tests.sh -k idle              only the tests whose name contains "idle"
test/run_tests.sh --only integration   only integration.py (a few seconds)
test/run_tests.sh --only suites        only the test_*.py suites
UFTP_BIN=/path/to/uFTP test/run_tests.sh --no-build    test another binary
```

## What is in here

| File | Tests | What it covers |
|---|---|---|
| `integration.py` | 28 | Functional and RFC checks against one shared server |
| `test_rfc_compliance.py` | 180 | Reply codes, argument checks, path handling, FTP bounce, TLS rules |
| `test_server_resilience.py` | 62 | Timeouts, slow or vanishing clients, TLS shutdown, crashes, the log |
| `test_command_scenarios.py` | 50 | Permission denied, failing system calls, `FORCE_TLS`, lockout, IPv6 |
| `test_documentation.py` | 7 | `SECURITY.md` is in the root, tells how to report in private, has no placeholder or email by mistake (no server started) |
| `test_fail2ban.py` | 6 | the filter of `contrib/fail2ban/uftp.conf` against the log that a server really writes (skipped if `fail2ban-regex` is not installed) |
| `uftp_test_server.py`, `ftp_test_client.py` | | The throw-away server and the raw FTP client used by the suites |

A new `test_*.py` file in this folder is picked up automatically.

## Notes

- **Ports:** 2121-2133 and 2135-2144 on `127.0.0.1` must be free. Each suite has a variable to
  move it (`UFTP_INTEGRATION_PORT`, `UFTP_RESILIENCE_PORT`, `UFTP_RFC_PORT`,
  `UFTP_SCENARIO_PORT`).
- **Skipped tests:** the IPv6 tests are skipped when `::1` is not available or the server is built
  without IPv6; the TLS tests when the server is built without OpenSSL.
- **A server by hand**, for debugging: `python3 test/uftp_test_server.py --port 2121` (users
  `username` / `password` and `tester2` / `tester2Password`).

## Sanitizer build

`OPTIMIZATION=` in the `Makefile` is not used to compile the objects, so `-fsanitize=address` must go in `CFLAGSTEMP`:

```
make 'CFLAGSTEMP=-c -Wall -I. -O1 -g -fno-omit-frame-pointer -fsanitize=address' \
     'ENABLE_OPENSSL_SUPPORT=-D OPENSSL_ENABLED' 'LIBS=-lpthread -lssl -lcrypto -fsanitize=address'
ASAN_OPTIONS=detect_leaks=0:verify_asan_link_order=0:quarantine_size_mb=0 UFTP_BIN=build/uFTP python3 test/run_tests.py
```

Check that it is instrumented: `nm build/modules/connection.o | grep -c __asan` must be above zero.
The control channel waits with `epoll` on Linux; add `-D UFTP_USE_POLL` to `CFLAGSTEMP` to build the `poll()` version.

## Load tools (not part of the suite)

`load_test.py` (open connections in steps, with clients working), `load_scenarios.py` (`transfers`, `abuse`, `soak`), and
`fuzz_commands.py` (random and concurrent commands). See the docstring of each for the options.

## Confronto con altri server

`test/benchmark/bench_compare.py` misura uFTP, vsftpd, ProFTPD e Pure-FTPd, ognuno in un container Docker. Risultati, metodo e limiti: [../riepilogo_modifiche/4.3.0/confronto_prestazioni.md](../riepilogo_modifiche/4.3.0/confronto_prestazioni.md).

`test_pam_container.py` prova l'accesso PAM (`ENABLE_PAM_AUTH`) in un container Docker con un utente di sistema; si esegue solo con `UFTP_PAM_BIN=<uFTP compilato con PAM>` e l'immagine `uftp-bench-uftp`, altrimenti è saltato.
