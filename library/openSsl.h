/*
 * The MIT License
 *
 * Copyright 2018 Ugo Cirmignani.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#ifdef OPENSSL_ENABLED
#ifndef OPENSSL_H
#define OPENSSL_H

#include <openssl/ssl.h>
#include <openssl/err.h>

#define TLS_NEGOTIATING_TIMEOUT	30

/* Timeouts (milliseconds) of the TLS operations that wait for the peer.

   - Closing a data connection: time to send our close_notify (a full send buffer must
     drain first). The close_notify of the client is not waited for: it is not
     required (RFC 8446 6.1), and waiting delayed the 226 of every transfer by up to a
     second for the clients that keep the data connection open until the 226.
     The wait ends at once when the control thread asks the worker to stop.
   - Replies on the control connection: CONTROL_WRITE_TIMEOUT_MS in connection.h (it
     applies to clear text too).
   - Handshake of a data connection: done by the data worker, so it delays nobody
     else. Some clients start TLS only after the 150 reply; when it expires only the
     data connection is closed, not the session.
   - The control connection is closed without waiting for the client.
   - Data blocks have no constant here: the limit is the idle timeout of the server
     (see dataWriteTimeoutMs() in connection.c). */
#define TLS_SHUTDOWN_TIMEOUT_MS          1000
#define TLS_DATA_HANDSHAKE_TIMEOUT_MS   15000
#define TLS_STOP_CHECK_INTERVAL_MS         10

#ifdef __cplusplus
extern "C" {
#endif

void initOpenssl();
void cleanupOpenssl();
int thread_cleanup(void);
int thread_setup(void);
void handle_error(const char *file, int lineno, const char *msg);
SSL_CTX *createServerContext();
void configureContext(SSL_CTX *ctx, const char *certificatePath, const char* privateCertificatePath);
void ShowCerts(SSL* ssl);

/* Bounded bidirectional TLS close and bounded SSL_write on a socket that may
   be non-blocking. See the comments in openSsl.c. */
int tlsShutdownBounded(SSL *ssl, int fd, int sendTimeoutMs, int peerTimeoutMs, const volatile int *stopRequested);
int tlsWriteBounded(SSL *ssl, int fd, const void *buffer, int length, int timeoutMs);
#ifdef __cplusplus
}
#endif

#endif /* OPENSSL_H */
#endif
