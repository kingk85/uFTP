#!/usr/bin/env bash
#
# Build uFTP (with OpenSSL) and run the whole test suite against throw-away
# servers. Nothing to configure: users, passwords, ports, certificate and FTP
# root are generated in a temporary directory by uftp_test_server.py.
#
#   test/run_tests.sh                 build + run everything
#   test/run_tests.sh --no-build      skip the build
#   test/run_tests.sh -v              verbose
#   test/run_tests.sh -k idle         only tests whose name matches "idle"
#   test/run_tests.sh --only integration   (or --only suites: every test_*.py)
#
# Test accounts (see DEFAULT_USERS in uftp_test_server.py):
#   username / password
#   tester2  / tester2Password
#
# Ports (all on 127.0.0.1, each can be changed with its variable): integration 2121
# (UFTP_INTEGRATION_PORT), resilience 2122 (UFTP_RESILIENCE_PORT), RFC compliance 2123
# (UFTP_RFC_PORT, 2123-2133), command scenarios 2135-2144
# (UFTP_SCENARIO_PORT). To start a test server by hand for debugging:
#   python3 test/uftp_test_server.py --port 2121

set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$TEST_DIR")"

BUILD=1
ARGS=()
for arg in "$@"; do
    case "$arg" in
        --no-build) BUILD=0 ;;
        *) ARGS+=("$arg") ;;
    esac
done

for tool in python3 openssl make cc; do
    command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done

if [[ $BUILD -eq 1 ]]; then
    echo "==> building uFTP with OpenSSL support"
    mkdir -p "$ROOT_DIR/build/modules"
    make -C "$ROOT_DIR" \
        ENABLE_OPENSSL_SUPPORT="-D OPENSSL_ENABLED" \
        LIBS="-lpthread -lssl -lcrypto" >/dev/null
fi

export UFTP_BIN="${UFTP_BIN:-$ROOT_DIR/build/uFTP}"
echo "==> using $UFTP_BIN"

exec python3 "$TEST_DIR/run_tests.py" "${ARGS[@]+"${ARGS[@]}"}"
