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

#ifdef __cplusplus
extern "C" {
#endif

int getMaximumSocketFd(int mainSocket, ftpDataType * data);
int createSocket(ftpDataType * ftpData);
int createPassiveSocket(int port);
int createActiveSocket(int port, char *ipAddress);
void fdInit(ftpDataType * ftpData);
void fdAdd(ftpDataType * ftpData, int index);
void fdRemove(ftpDataType * ftpData, int index);

void checkClientConnectionTimeout(ftpDataType * ftpData);
void flushLoginWrongTriesData(ftpDataType * ftpData);
void closeSocket(ftpDataType * ftpData, int processingSocket);
void closeClient(ftpDataType * ftpData, int processingSocket);
int selectWait(ftpDataType * ftpData);
int isClientConnected(ftpDataType * ftpData, int cliendId);
int getAvailableClientSocketIndex(ftpDataType * ftpData);
int evaluateClientSocketConnection(ftpDataType * ftpData);
int socketPrintf(ftpDataType * ftpData, int clientId, const char *__restrict __fmt, ...);
int socketWorkerPrintf(ftpDataType * ftpData, int clientId, const char *__restrict __fmt, ...);


#ifdef __cplusplus
}
#endif

#endif /* CONNECTION_H */

