#!/bin/bash
# Checks uFTP with a real certificate (for example Let's Encrypt): it must send the whole chain and a client must trust it.
# It starts its own uFTP on a high port; the running server and its configuration are not touched. The private key is
# read from where it is: nothing is copied. The key is usually readable only by root, so run it with sudo.
#
# Usage: sudo ./check_real_certificate.sh <uFTP binary> <fullchain.pem> <private key> <host name>
# Example: sudo ./check_real_certificate.sh /sbin/uFTP /etc/letsencrypt/live/uftpserver.com/fullchain.pem \
#                 /etc/letsencrypt/live/uftpserver.com/privkey.pem www.uftpserver.com
# PORT=2121 changes the port; CAFILE=ca.pem checks against that file instead of the CA certificates of the system.
BIN=$1; CHAIN=$2; KEY=$3; HOST=$4
PORT=${PORT:-2121}
[ -n "$HOST" ] || { sed -n 2,10p "$0"; exit 2; }
[ -x "$BIN" ]   || { echo "ERROR: $BIN is not executable"; exit 2; }
[ -r "$CHAIN" ] || { echo "ERROR: cannot read $CHAIN (run with sudo?)"; exit 2; }
[ -r "$KEY" ]   || { echo "ERROR: cannot read $KEY (run with sudo?)"; exit 2; }
command -v openssl >/dev/null || { echo "ERROR: openssl is needed"; exit 2; }
if (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null; then echo "ERROR: port $PORT is in use, run with PORT=<another port>"; exit 2; fi

DIR=$(mktemp -d /tmp/uftp-cert.XXXXXX)
SERVER_PID=
cleanup() { [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null; wait 2>/dev/null; rm -rf "$DIR"; }
trap cleanup EXIT
cd "$DIR" || exit 2

cat > uftpd.cfg <<EOF
FTP_PORT = $PORT
SINGLE_INSTANCE = false
DAEMON_MODE = false
RESPAWN_PROCESS = false
LOG_FOLDER = $DIR/
MAXIMUM_LOG_FILES = 1
MAXIMUM_ALLOWED_FTP_CONNECTION = 5
CERTIFICATE_PATH=$CHAIN
PRIVATE_CERTIFICATE_PATH=$KEY
RANDOM_PORT_START = 41000
RANDOM_PORT_END = 41100
USER_0 = test
PASSWORD_0 = test
HOME_0 = $DIR
EOF

"$BIN" > server.out 2>&1 &
SERVER_PID=$!
for i in $(seq 1 50); do (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break; sleep 0.2; done
(exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null || { echo "ERROR: the server did not start (built with OpenSSL? key matches the certificate?)"; cat server.out; exit 2; }

CA=(); [ -n "$CAFILE" ] && CA=(-CAfile "$CAFILE")
OUT=$(openssl s_client -starttls ftp -connect 127.0.0.1:$PORT -servername "$HOST" -verify_hostname "$HOST" "${CA[@]}" -showcerts </dev/null 2>&1)
CERTS=$(echo "$OUT" | grep -c "BEGIN CERTIFICATE")
VERIFY=$(echo "$OUT" | grep -m1 "Verify return code")
SUBJECT=$(echo "$OUT" | grep -m1 " 0 s:" | sed 's/^ *0 s://')
PROTO=$(echo "$OUT" | grep -m1 "^New, " | sed 's/^New, //')

echo "binary:             $BIN"
echo "certificate:        ${SUBJECT:-?}"
echo "host name checked:  $HOST"
echo "protocol:           ${PROTO:-?}"
echo "certificates sent:  $CERTS (a real certificate: 2 or more)"
echo "verification:       $VERIFY (expected: 0 (ok))"
if [ "$CERTS" -ge 2 ] && echo "$VERIFY" | grep -q "code: 0 (ok)"; then
    echo "RESULT: PASS - the whole chain is sent and the certificate is trusted"; exit 0
fi
echo "RESULT: FAIL - see the lines above"; exit 1
