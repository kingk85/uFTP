#!/bin/bash
# Checks that uFTP sends the whole certificate chain of CERTIFICATE_PATH (fullchain.pem), not only the first certificate.
# It does not touch the configuration of a running server: it makes a test chain in a temporary folder and starts its own
# uFTP on a high port.
#
# Usage: ./check_certificate_chain.sh [path of the uFTP binary]   (default /sbin/uFTP)
#   PORT=2121 ./check_certificate_chain.sh /path/to/uFTP
# The binary must be built with OpenSSL. Needs: openssl, bash.
BIN=${1:-/sbin/uFTP}
PORT=${PORT:-2121}

[ -x "$BIN" ] || { echo "ERROR: $BIN is not executable (pass the path of the uFTP binary)"; exit 2; }
command -v openssl >/dev/null || { echo "ERROR: openssl is needed"; exit 2; }
if (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null; then echo "ERROR: port $PORT is in use, run with PORT=<another port>"; exit 2; fi

DIR=$(mktemp -d /tmp/uftp-chain.XXXXXX)
SERVER_PID=
cleanup() { [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null; wait 2>/dev/null; rm -rf "$DIR"; }
trap cleanup EXIT
cd "$DIR" || exit 2

# a chain: root -> intermediate -> server certificate
printf "basicConstraints=critical,CA:TRUE\nkeyUsage=keyCertSign,cRLSign\n" > ca.ext
{ openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 2 -subj "/CN=Test Root" &&
  openssl req -newkey rsa:2048 -nodes -keyout ica.key -out ica.csr -subj "/CN=Test Intermediate" &&
  openssl x509 -req -in ica.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out ica.pem -days 2 -extfile ca.ext &&
  openssl req -newkey rsa:2048 -nodes -keyout key.pem -out leaf.csr -subj "/CN=localhost" &&
  openssl x509 -req -in leaf.csr -CA ica.pem -CAkey ica.key -CAcreateserial -out leaf.pem -days 2 &&
  cat leaf.pem ica.pem > fullchain.pem; } >/dev/null 2>&1 || { echo "ERROR: could not make the test certificates"; exit 2; }

# a configuration of its own: ./uftpd.cfg is read first, /etc/uftpd.cfg is not used
cat > uftpd.cfg <<EOF
FTP_PORT = $PORT
SINGLE_INSTANCE = false
DAEMON_MODE = false
RESPAWN_PROCESS = false
LOG_FOLDER = $DIR/
MAXIMUM_LOG_FILES = 1
MAXIMUM_ALLOWED_FTP_CONNECTION = 5
CERTIFICATE_PATH=$DIR/fullchain.pem
PRIVATE_CERTIFICATE_PATH=$DIR/key.pem
RANDOM_PORT_START = 41000
RANDOM_PORT_END = 41100
USER_0 = test
PASSWORD_0 = test
HOME_0 = $DIR
EOF

"$BIN" > server.out 2>&1 &
SERVER_PID=$!
for i in $(seq 1 50); do (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break; sleep 0.2; done
(exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null || { echo "ERROR: the server did not start (is it built with OpenSSL?)"; cat server.out; exit 2; }

OUT=$(openssl s_client -starttls ftp -connect 127.0.0.1:$PORT -CAfile ca.pem -showcerts </dev/null 2>&1)
CERTS=$(echo "$OUT" | grep -c "BEGIN CERTIFICATE")
VERIFY=$(echo "$OUT" | grep -m1 "Verify return code")

echo "binary:                $BIN"
echo "certificates sent:     $CERTS (expected 2)"
echo "verification:         $VERIFY (expected: 0 (ok))"
if [ "$CERTS" -ge 2 ] && echo "$VERIFY" | grep -q "code: 0 (ok)"; then
    echo "RESULT: PASS - the whole chain is sent"
    exit 0
fi
echo "RESULT: FAIL - only the first certificate is sent (old version?)"
exit 1
