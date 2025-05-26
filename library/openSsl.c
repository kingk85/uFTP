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

SSL_CTX *createServerContext()
{
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create server SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

SSL_CTX *createClientContext()
{
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create client SSL context");
        addLog("Unable to create client SSL context", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configureContext(SSL_CTX *ctx, const char *certPath, const char *keyPath)
{
    if (!FILE_IsFile(certPath, 1)) {
        my_printf("\nCertificate file not found: %s", certPath);
        exit(EXIT_FAILURE);
    }

    if (!FILE_IsFile(keyPath, 1)) {
        my_printf("\nPrivate key file not found: %s", keyPath);
        exit(EXIT_FAILURE);
    }

    // Removed SSL_CTX_set_ecdh_auto (no-op since OpenSSL 1.1.0)
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5");

    if (SSL_CTX_use_certificate_file(ctx, certPath, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, keyPath, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
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
