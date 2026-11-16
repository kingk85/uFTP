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
| `uftp_test_server.py`, `ftp_test_client.py` | | The throw-away server and the raw FTP client used by the suites |

A new `test_*.py` file in this folder is picked up automatically.

## Notes

- **Ports:** 2121-2123 and 2135-2141 on `127.0.0.1` must be free. Each suite has a variable to
  move it (`UFTP_INTEGRATION_PORT`, `UFTP_RESILIENCE_PORT`, `UFTP_RFC_PORT`,
  `UFTP_SCENARIO_PORT`).
- **Skipped tests:** the IPv6 tests are skipped when `::1` is not available or the server is built
  without IPv6; the TLS tests when the server is built without OpenSSL.
- **A server by hand**, for debugging: `python3 test/uftp_test_server.py --port 2121` (users
  `username` / `password` and `tester2` / `tester2Password`).
