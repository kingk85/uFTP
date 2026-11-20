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


#ifndef CONNECTION_H
#define CONNECTION_H

#include "../ftpData.h"
#include "log.h"
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

int createSocket(ftpDataType * ftpData);
int createPassiveSocket(int port);
int ipAddressToBinary(const char *theAddress, struct in6_addr *binary);
int isSameIpAddress(const char *firstAddress, const char *secondAddress);
int isPeerFromAddress(const struct sockaddr *peer, const char *theAddress);
int dataWriteTimeoutMs(ftpDataType *ftpData);

/* Time allowed to write a reply on the control connection, TLS and clear text. The
   control thread serves every client, so the wait must stay short; it is long enough
   for a slow link. A reply that can not be written in this time means that the client
   is not reading: it is closed. 250 ms (release candidate) closed live clients in
   production, and in clear text there was no wait at all. */
#define CONTROL_WRITE_TIMEOUT_MS    2000
/* the same for a client that has not logged in */
#define CONTROL_WRITE_TIMEOUT_UNAUTHENTICATED_MS 100

/* Log lines about one client: "[<slot> <address> <user>] message". isAccessRecord = 1
   for the actions of a logged in user (see logMessageRecord() in log.c). */
void logClientf(ftpDataType *ftpData, int clientId, int isAccessRecord, const char *file, int line,
                const char *function, const char *prefix, const char *fmt, ...);
#define LOG_CLIENT(data, id, prefix, fmt, ...) \
    logClientf(data, id, 0, __FILE__, __LINE__, __func__, prefix, fmt, ##__VA_ARGS__)
/* an action of the client: access record if the client is logged in */
#define LOG_ACCESS(data, id, fmt, ...) \
    logClientf(data, id, (data)->clients[id].login.userLoggedIn == 1, __FILE__, __LINE__, __func__, LOG_ACCESS_PREFIX, fmt, ##__VA_ARGS__)

/* Close the client at the next loop, saying why in the log (the first reason given wins) */
void markClientForClosing(ftpDataType *ftpData, int clientId, const char *reason);
void setCloseReason(ftpDataType *ftpData, int clientId, const char *reason);
#ifdef OPENSSL_ENABLED
/* Log why the TLS handshake of the control connection failed (OpenSSL error queue or
   system error) */
void logTlsHandshakeFailure(ftpDataType *ftpData, int clientId, int sslError);
#endif
void setTcpNoDelay(int fd);
int createActiveSocket(int port, char *ipAddress, volatile int *descriptorSlot);

#ifdef IPV6_ENABLED
int createActiveSocketV6(int port, char *ipAddress, volatile int *descriptorSlot);
#endif

#ifdef OPENSSL_ENABLED
int acceptSSLConnection(int theSocketId, ftpDataType * ftpData);
#endif

void fdInit(ftpDataType * ftpData);
void fdAdd(ftpDataType * ftpData, int index);

void checkClientConnectionTimeout(ftpDataType * ftpData);
void flushLoginWrongTriesData(ftpDataType * ftpData);
void closeSocket(ftpDataType * ftpData, int processingSocket);
void closeClient(ftpDataType * ftpData, int processingSocket);
int waitForClientEvents(ftpDataType * ftpData);
int isClientConnected(ftpDataType * ftpData, int cliendId);
int getAvailableClientSocketIndex(ftpDataType * ftpData);
int evaluateClientSocketConnection(ftpDataType * ftpData);
int socketPrintf(ftpDataType * ftpData, int clientId, const char *__restrict __fmt, ...);
int socketWorkerPrintf(ftpDataType * ftpData, int clientId, const char *__restrict __fmt, ...);

#ifdef __cplusplus
}
#endif

#endif /* CONNECTION_H */

