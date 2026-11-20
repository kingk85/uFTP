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
SSL_CTX *createServerContext();
void configureContext(SSL_CTX *ctx, const char *certificatePath, const char* privateCertificatePath);

/* Bounded bidirectional TLS close and bounded SSL_write on a socket that may
   be non-blocking. See the comments in openSsl.c. */
int tlsShutdownBounded(SSL *ssl, int fd, int sendTimeoutMs, int peerTimeoutMs, const volatile int *stopRequested);
int tlsWriteBounded(SSL *ssl, int fd, const void *buffer, int length, int timeoutMs);
#ifdef __cplusplus
}
#endif

#endif /* OPENSSL_H */
#endif

/* Password hashes: PBKDF2-HMAC-SHA256, "$pbkdf2-sha256$<iterations>$<salt>$<hash>" with the
   salt (16 bytes) and the hash (32 bytes) in base64 without padding and with '.' instead of
   '+' (the format of passlib). Always declared: a build without OpenSSL can not make or check
   them and the functions say so. */
#ifndef PASSWORD_HASH_H
#define PASSWORD_HASH_H

#include <stddef.h>

#define PASSWORD_HASH_PREFIX "$pbkdf2-sha256$"
#define PASSWORD_HASH_DEFAULT_ITERATIONS 100000
#define PASSWORD_HASH_MAX_ITERATIONS 10000000
#define PASSWORD_HASH_BUFFER_SIZE 128

/* 1 if the stored password is a hash (it starts with the prefix), 0 if it is plain text */
int passwordIsHashed(const char *stored);
/* 1 if the stored hash is well formed and this build can check it */
int passwordHashIsValid(const char *stored);
/* 1 if the password sent by the client is the stored one (plain text or hash) */
int passwordMatches(const char *stored, const char *given);
/* The iterations of a well formed hash, 0 if it is not one or this build can not check it */
int passwordHashIterations(const char *stored);
/* Does the work of checking a password against a hash with that many iterations (the highest of the
   hashes of the configuration) and throws the result away: the time of a wrong password is then the
   same whatever the name (see ftpCommandElaborate.c). 0 or less: the default iterations. */
void passwordDummyVerify(const char *given, int iterations);
/* The hash of a password with a new random salt, in out (PASSWORD_HASH_BUFFER_SIZE bytes).
   1 on success, 0 on error or without OpenSSL. */
int passwordHashCreate(const char *password, int iterations, char *out, size_t outSize);

#endif /* PASSWORD_HASH_H */
