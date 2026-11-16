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
/*
 * The MIT License
 * Copyright 2018 Ugo Cirmignani.
 * [license text unchanged...]
 */

#ifdef OPENSSL_ENABLED
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/conf.h>

#include "openSsl.h"
#include "fileManagement.h"
#include "../debugHelper.h"
#include "log.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define NEED_OPENSSL_THREADING 1
#else
#define NEED_OPENSSL_THREADING 0
#endif

#if NEED_OPENSSL_THREADING
#define MUTEX_TYPE       pthread_mutex_t
#define MUTEX_SETUP(x)   pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
#define MUTEX_LOCK(x)    pthread_mutex_lock(&(x))
#define MUTEX_UNLOCK(x)  pthread_mutex_unlock(&(x))
#define THREAD_ID        pthread_self()
static MUTEX_TYPE *mutex_buf = NULL;
#endif

void initOpenssl()
{
#if NEED_OPENSSL_THREADING
    thread_setup();
#endif
    // No longer needed in OpenSSL >= 1.1.0
    // OpenSSL_add_all_algorithms();
    // SSL_load_error_strings();
    // ERR_load_BIO_strings();
    // ERR_load_crypto_strings();
    // SSL_library_init();
}

void cleanupOpenssl()
{
#if NEED_OPENSSL_THREADING
    thread_cleanup();
#endif
    // Deprecated in OpenSSL >= 1.1.0
    // EVP_cleanup();
}

/* Fatal TLS setup error: the reason (with the OpenSSL error queue) goes to the log,
   which is written at once because the server stops right after. */
static void tlsSetupFailed(const char *what, const char *path)
{
    char reason[256] = "";
    unsigned long errorCode = ERR_get_error();

    if (errorCode != 0)
        ERR_error_string_n(errorCode, reason, sizeof(reason));

    LOGF_NOW("%sTLS setup failed: %s %s %s", LOG_FATAL_PREFIX, what, path != NULL ? path : "", reason);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

SSL_CTX *createServerContext()
{
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        tlsSetupFailed("unable to create the server context", NULL);
    }
    return ctx;
}


void configureContext(SSL_CTX *ctx, const char *certPath, const char *keyPath)
{
    if (!FILE_IsFile(certPath, 1)) {
        tlsSetupFailed("certificate file not found (CERTIFICATE_PATH):", certPath);
    }

    if (!FILE_IsFile(keyPath, 1)) {
        tlsSetupFailed("private key file not found (PRIVATE_CERTIFICATE_PATH):", keyPath);
    }

    // Removed SSL_CTX_set_ecdh_auto (no-op since OpenSSL 1.1.0)
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5");

    if (SSL_CTX_use_certificate_file(ctx, certPath, SSL_FILETYPE_PEM) <= 0) {
        tlsSetupFailed("invalid certificate:", certPath);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, keyPath, SSL_FILETYPE_PEM) <= 0) {
        tlsSetupFailed("invalid private key:", keyPath);
    }

    // Enable session cache on server side
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
}

void ShowCerts(SSL *ssl)
{
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        char *line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        my_printf("Subject: %s\n", line);
        free(line);

        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        my_printf("Issuer: %s\n", line);
        free(line);

        X509_free(cert);
    } else {
        my_printf("No certificates.\n");
    }
}

static long long int monotonicMilliseconds(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long long int)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

/* Waits until the socket is ready for the requested event, the timeout expires or
   *stopRequested becomes non zero (checked every few milliseconds; NULL = not used).
   Returns 1 when ready, 0 otherwise. */
static int waitSocketEvent(int fd, short events, long long int timeoutMilliseconds, const volatile int *stopRequested)
{
    struct pollfd descriptor;
    long long int deadline = monotonicMilliseconds() + timeoutMilliseconds;

    descriptor.fd = fd;
    descriptor.events = events;

    for (;;)
    {
        long long int remaining = deadline - monotonicMilliseconds();
        int result;

        if (remaining <= 0)
            return 0;

        if (stopRequested != NULL)
        {
            if (*stopRequested != 0)
                return 0;
            if (remaining > TLS_STOP_CHECK_INTERVAL_MS)
                remaining = TLS_STOP_CHECK_INTERVAL_MS;
        }

        descriptor.revents = 0;
        result = poll(&descriptor, 1, (int)remaining);

        if (result > 0)
            return 1;
        if (result < 0 && errno != EINTR)
            return 0;
    }
}

/* The TLS close is bidirectional (RFC 8446 6.1, RFC 5246 7.2.1): each side sends its
   close_notify and reads the one of the peer. If the TCP connection is closed before
   our close_notify is complete, strict clients abort the transfer with a TLS decode
   error (FileZilla logs "GnuTLS -9 ... The server did not properly shut down TLS
   connection").

   sendTimeoutMs: how long to wait for the socket to take our close_notify.
   peerTimeoutMs: how long to wait for the close_notify of the peer. Many clients never
                  send it, and waiting is not required (RFC 8446 6.1): 0 = do not wait.
   stopRequested: when it becomes non zero the waits end at once (NULL = not used).

   Whoever waits here keeps other work waiting: the control thread serves every client,
   and it also waits for a data worker that is closing. So the control connection is
   closed with both timeouts at 0, and the data worker passes a stop flag.

   The socket is made non-blocking for the call and its flags are restored.

   Returns 1 when both close_notify messages have been exchanged, 0 when ours has been
   sent but the one of the peer has not been read, -1 on error or if ours was not sent. */
int tlsShutdownBounded(SSL *ssl, int fd, int sendTimeoutMs, int peerTimeoutMs, const volatile int *stopRequested)
{
    long long int deadline;
    int flags;
    int result = -1;
    int sslError = SSL_ERROR_NONE;

    if (ssl == NULL || fd < 0)
        return -1;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return -1;

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
        return -1;

    /* Send our close_notify; WANT_WRITE means it has not been sent completely
       yet, so wait for the socket and retry. */
    deadline = monotonicMilliseconds() + (sendTimeoutMs > 0 ? sendTimeoutMs : 0);

    for (;;)
    {
        result = SSL_shutdown(ssl);
        if (result >= 0)
            break;

        sslError = SSL_get_error(ssl, result);
        if (sslError != SSL_ERROR_WANT_READ && sslError != SSL_ERROR_WANT_WRITE)
            break;

        if (!waitSocketEvent(fd, sslError == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT,
                             deadline - monotonicMilliseconds(), stopRequested))
            break;
    }

    /* result 0: our close_notify is out, wait for the one of the peer */
    deadline = monotonicMilliseconds() + (peerTimeoutMs > 0 ? peerTimeoutMs : 0);

    while (result == 0)
    {
        if (!waitSocketEvent(fd, POLLIN, deadline - monotonicMilliseconds(), stopRequested))
            break;

        result = SSL_shutdown(ssl);
        if (result >= 0)
            break;

        sslError = SSL_get_error(ssl, result);
        if (sslError != SSL_ERROR_WANT_READ && sslError != SSL_ERROR_WANT_WRITE)
            break;

        result = 0;         /* the record of the peer is not complete yet: keep waiting */
    }

    (void)fcntl(fd, F_SETFL, flags);

    if (result < 0)
    {
        ERR_clear_error();
        return -1;
    }

    return result;
}

/* SSL_write() on a socket that may be non-blocking, with a bounded wait on
   WANT_READ/WANT_WRITE. It is used for the data channel and for the replies on
   the control connection (non-blocking): a single SSL_write() used to be
   enough and a WANT_WRITE was treated as a fatal error, closing the client.

   Returns the bytes written (always the whole buffer) or -1 with errno set:
   ETIMEDOUT if the peer did not take the data in time, the system error for a
   broken connection, EPROTO for a TLS error. */
int tlsWriteBounded(SSL *ssl, int fd, const void *buffer, int length, int timeoutMs)
{
    long long int deadline;
    int flags;
    int written = 0;
    int failure = 0;

    if (ssl == NULL || fd < 0 || length < 0)
    {
        errno = EINVAL;
        return -1;
    }

    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return -1;

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
        return -1;

    deadline = monotonicMilliseconds() + (timeoutMs > 0 ? timeoutMs : 0);

    while (written < length)
    {
        errno = 0;
        int result = SSL_write(ssl, (const char *)buffer + written, length - written);

        if (result > 0)
        {
            written += result;
            continue;
        }

        int systemError = errno;
        int sslError = SSL_get_error(ssl, result);
        if (sslError == SSL_ERROR_WANT_READ || sslError == SSL_ERROR_WANT_WRITE)
        {
            if (!waitSocketEvent(fd, sslError == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT,
                                 deadline - monotonicMilliseconds(), NULL))
            {
                failure = ETIMEDOUT;
                break;
            }
            continue;
        }

        failure = (sslError == SSL_ERROR_SYSCALL && systemError != 0) ? systemError : EPROTO;
        break;
    }

    (void)fcntl(fd, F_SETFL, flags);

    /* The callers (control replies, file blocks) need the whole buffer. With
       the default OpenSSL semantics SSL_write() either writes everything or
       fails; the check also covers partial writes, if they are ever enabled. */
    if (written != length)
    {
        ERR_clear_error();
        errno = failure != 0 ? failure : EPROTO;
        return -1;
    }

    return written;
}

void handle_error(const char *file, int lineno, const char *msg)
{
    fprintf(stderr, "** %s:%d %s\n", file, lineno, msg);
    ERR_print_errors_fp(stderr);
}

#if NEED_OPENSSL_THREADING
static void locking_function(int mode, int n, const char *file, int line)
{
    if (mode & CRYPTO_LOCK)
        MUTEX_LOCK(mutex_buf[n]);
    else
        MUTEX_UNLOCK(mutex_buf[n]);
}

static unsigned long id_function(void)
{
    return (unsigned long)THREAD_ID;
}

int thread_setup(void)
{
    int i;
    mutex_buf = malloc(CRYPTO_num_locks() * sizeof(MUTEX_TYPE));
    if (!mutex_buf) return 0;

    for (i = 0; i < CRYPTO_num_locks(); i++)
        MUTEX_SETUP(mutex_buf[i]);

    CRYPTO_set_id_callback(id_function);
    CRYPTO_set_locking_callback(locking_function);
    return 1;
}

int thread_cleanup(void)
{
    int i;
    if (!mutex_buf) return 0;

    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);

    for (i = 0; i < CRYPTO_num_locks(); i++)
        MUTEX_CLEANUP(mutex_buf[i]);

    free(mutex_buf);
    mutex_buf = NULL;
    return 1;
}
#endif
#endif
