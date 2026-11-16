#!/usr/bin/env python3
"""
Runs the uFTP test suites against throw-away servers.

  1. integration.py   RFC / functional tests, run against a shared test server
                      with a normal idle timeout (users from uftp_test_server.py)
  2. test_*.py        every other suite in this folder, discovered automatically;
                      each one starts its own server (e.g. test_server_resilience.py)

Usually invoked through test/run_tests.sh, which builds uFTP first.

  python3 test/run_tests.py [-v] [-k PATTERN] [--only integration|suites]

Exit code is 0 only if every executed test passed.
"""

import argparse
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from uftp_test_server import UFTPTestServer  # noqa: E402

INTEGRATION_PORT = int(os.environ.get("UFTP_INTEGRATION_PORT", "2121"))


def run_suite(title, suite, verbosity):
    print(f"\n========== {title} ==========", flush=True)
    result = unittest.TextTestRunner(verbosity=verbosity).run(suite)
    return result.wasSuccessful()


def load(module_name, patterns):
    loader = unittest.TestLoader()
    if patterns:
        loader.testNamePatterns = [p if "*" in p else f"*{p}*" for p in patterns]
    return loader.loadTestsFromName(module_name)


def run_integration(args):
    server = UFTPTestServer(port=INTEGRATION_PORT, idle_timeout=60)
    server.start()
    # integration.py reads these at import time
    os.environ.update(FTP_HOST="127.0.0.1", FTP_PORT=str(server.port),
                      FTP_USER=server.user, FTP_PASS=server.password)
    cwd = os.getcwd()
    # integration.py creates scratch files in the current directory
    with tempfile.TemporaryDirectory(prefix="uftp-client-") as tmp:
        os.chdir(tmp)
        try:
            ok = run_suite(f"integration (uFTP on port {server.port})",
                           load("integration", args.k), args.verbosity)
        finally:
            os.chdir(cwd)
            if not ok:
                print("---- server log ----\n" + server.read_log())
            server.stop()
    return ok


def run_suites(args):
    """Discover every test_*.py in this folder (each manages its own server)."""
    loader = unittest.TestLoader()
    if args.k:
        loader.testNamePatterns = [p if "*" in p else f"*{p}*" for p in args.k]
    suite = loader.discover(HERE, pattern="test_*.py", top_level_dir=HERE)
    names = sorted(os.path.splitext(f)[0] for f in os.listdir(HERE)
                   if f.startswith("test_") and f.endswith(".py"))
    return run_suite("suites: " + ", ".join(names), suite, args.verbosity)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-v", dest="verbosity", action="store_const", const=2, default=1)
    parser.add_argument("-k", action="append",
                        help="only run tests whose name matches (may be repeated)")
    parser.add_argument("--only", choices=["integration", "suites"])
    args = parser.parse_args()

    results = {}
    if args.only in (None, "integration"):
        results["integration"] = run_integration(args)
    if args.only in (None, "suites"):
        results["suites"] = run_suites(args)

    print("\n========== summary ==========")
    for name, ok in results.items():
        print(f"  {name:12s} {'OK' if ok else 'FAILED'}")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
