
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>     
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>
#include <errno.h>

/* FTP LIBS */
#include "library/fileManagement.h"
#include "library/configRead.h"
#include "library/signals.h"
#include "library/openSsl.h"
#include "library/connection.h"
#include "library/dynamicMemory.h"
#include "library/errorHandling.h"
#include "library/daemon.h"
#include "library/log.h"

#include "ftpServer.h"
#include "ftpData.h"
#include "ftpCommandsElaborate.h"
#include "debugHelper.h"
#include "dataChannel.h"

static int acceptConnection(cleanUpWorkerArgs *args);
static int processStorAppe(cleanUpWorkerArgs *args);
static int processListNlst(cleanUpWorkerArgs *args);
static int processRetr(cleanUpWorkerArgs *args);

void workerCleanup(cleanUpWorkerArgs *args)
{
    ftpDataType *ftpData = args->ftpData;
	int theSocketId = args->socketId;
	int returnCode = 0;

	//my_printf("\nWorker %d cleanup", theSocketId);

    /* The cleanup must run to its end. It is also called when the worker ends on its
       own, and there the thread can still be cancelled: a new PASV arriving while it
       was waiting below cut the cleanup in the middle (no reply sent, worker data not
       reset, the next commands answered out of step). */
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

	#ifdef OPENSSL_ENABLED
    /* Close the TLS data channel properly before closing the socket.
       SSL_shutdown() is bidirectional: it used to be called once, on a
       non-blocking socket, ignoring WANT_READ/WANT_WRITE, and
       shutdown(SHUT_RDWR) was called before the second SSL_shutdown(). The
       client could so receive a truncated record and abort the transfer
       ("GnuTLS -9 ... The server did not properly shut down TLS connection",
       e.g. FileZilla). */
    if (ftpData->clients[theSocketId].dataChannelIsTls == 1)
    {
        SSL *dataSsl = NULL;

        if (ftpData->clients[theSocketId].workerData.passiveModeOn == 1)
            dataSsl = ftpData->clients[theSocketId].workerData.serverSsl;
        else if (ftpData->clients[theSocketId].workerData.activeModeOn == 1)
            dataSsl = ftpData->clients[theSocketId].workerData.clientSsl;

        /* Our close_notify is sent, waiting if the send buffer is full: strict clients
           (FileZilla) need it complete before the connection is closed. The close_notify
           of the client is not waited for: the 226 below would wait with it.
           The control thread may be waiting for this worker (pthread_join), and it
           serves every client: when it has asked the worker to stop there is no wait at
           all, and a wait in progress ends as soon as it asks. */
        if (dataSsl != NULL && ftpData->clients[theSocketId].workerData.stopRequested != 0)
            tlsShutdownBounded(dataSsl, ftpData->clients[theSocketId].workerData.socketConnection, 0, 0, NULL);
        else if (dataSsl != NULL)
            tlsShutdownBounded(dataSsl, ftpData->clients[theSocketId].workerData.socketConnection,
                               TLS_SHUTDOWN_TIMEOUT_MS, 0,
                               &ftpData->clients[theSocketId].workerData.stopRequested);
    }
	#endif

    /* Close only what this worker really opened (-1 = not open). In active mode there
       is no listening socket: closing its reset value used to close descriptor 0, which
       can be the control connection of another client. */
    if (ftpData->clients[theSocketId].workerData.socketConnection >= 0)
    {
        /* Read what the client has already sent (typically its close_notify): closing
           a socket with unread data makes the system send a reset instead of a normal
           close, and a reset can make the client drop data it has not read yet. */
        char unread[4096];
        while (recv(ftpData->clients[theSocketId].workerData.socketConnection, unread, sizeof(unread), MSG_DONTWAIT) > 0)
            ;

        shutdown(ftpData->clients[theSocketId].workerData.socketConnection, SHUT_RDWR);
        returnCode = close(ftpData->clients[theSocketId].workerData.socketConnection);
    }

    if (ftpData->clients[theSocketId].workerData.passiveListeningSocket >= 0)
    {
        shutdown(ftpData->clients[theSocketId].workerData.passiveListeningSocket, SHUT_RDWR);
        returnCode = close(ftpData->clients[theSocketId].workerData.passiveListeningSocket);
    }

    if (ftpData->clients[theSocketId].workerData.commandProcessed)
    {
        returnCode = socketPrintf(ftpData, theSocketId, "s", ftpData->clients[theSocketId].workerData.theCommandResponse);
        if (returnCode <= 0)
        {
            ftpData->clients[theSocketId].closeTheClient = 1;
            my_printf("\n Closing the client 10");
        }
    }
    
    resetWorkerData(ftpData, theSocketId, 0);

    DYNMEM_free(args, &ftpData->clients[theSocketId].workerData.memoryTable);

    /* Free whatever the worker left in its memory table. A LIST/NLST cancelled
       while sending (ABOR, a new PASV/PORT, the client closing) left the whole directory
       listing allocated here, a few MB for a big directory, at every cancellation.
       Nothing in this table outlives the worker: its arguments are freed above, the
       LIST options by resetWorkerData(), STAT uses the client table, and a new
       PASV/EPSV/PORT/EPRT joins this thread before allocating again. */
    if (ftpData->clients[theSocketId].workerData.memoryTable != NULL)
    {
        DYNMEM_dump(ftpData->clients[theSocketId].workerData.memoryTable);
        DYNMEM_freeAll(&ftpData->clients[theSocketId].workerData.memoryTable);
    }

}

static int processStorAppe(cleanUpWorkerArgs *args)
{
    ftpDataType *ftpData = args->ftpData;
    int theSocketId = args->socketId;
    int returnCode = 0;
    off_t restartPos = ftpData->clients[theSocketId].workerData.retrRestartAtByte;
    FILE *file = NULL;

    const char *filePath = ftpData->clients[theSocketId].fileToStor.text;
    const char *command = ftpData->clients[theSocketId].workerData.theCommandReceived;

    int isAppe = compareStringCaseInsensitive((char *)command, "APPE", strlen("APPE")) == 1;

    #ifdef LARGE_FILE_SUPPORT_ENABLED
        if (isAppe) {
            file = fopen64(filePath, "ab");
        } else if (restartPos > 0) {
            file = fopen64(filePath, "r+b");
        } else {
            file = fopen64(filePath, "wb");
        }
    #else
        if (isAppe) {
            file = fopen(filePath, "ab");
        } else if (restartPos > 0) {
            file = fopen(filePath, "r+b");
        } else {
            file = fopen(filePath, "wb");
        }
    #endif

    ftpData->clients[theSocketId].workerData.theStorFile = file;

    if (file == NULL) {
        LOG_ACCESS(ftpData, theSocketId, "%s %s failed: %s", isAppe ? "APPE" : "STOR", filePath, strerror(errno));
        returnCode = socketPrintf(ftpData, theSocketId, "s", "553 Unable to write the file\r\n");
        if (returnCode <= 0) {
            ftpData->clients[theSocketId].closeTheClient = 1;
            my_printf("\n Closing the client 6");
            return -1;
        }
        return -1;
    }

    if (!isAppe && restartPos > 0) {
        fseeko(file, restartPos, SEEK_SET);
        ftpData->clients[theSocketId].workerData.retrRestartAtByte = 0;
    }

    /* An upload used to end with "226 file stor ok" even when the data connection broke
       (read error) or the file could not be written (disk full, quota, file size limit):
       the client and the log were told that an incomplete file had been stored. */
    long long int bytesStored = 0;
    const char *failure = NULL;
    char failureText[160] = "";

    while (1) {
        int bytesRead = 0;
        errno = 0;

        if (ftpData->clients[theSocketId].dataChannelIsTls != 1) {
            bytesRead = read(ftpData->clients[theSocketId].workerData.socketConnection,
                             ftpData->clients[theSocketId].workerData.buffer, CLIENT_BUFFER_STRING_SIZE);
        }
    #ifdef OPENSSL_ENABLED
        else {
            if (ftpData->clients[theSocketId].workerData.passiveModeOn == 1) {
                bytesRead = SSL_read(ftpData->clients[theSocketId].workerData.serverSsl,
                                     ftpData->clients[theSocketId].workerData.buffer, CLIENT_BUFFER_STRING_SIZE);
            } else if (ftpData->clients[theSocketId].workerData.activeModeOn == 1) {
                bytesRead = SSL_read(ftpData->clients[theSocketId].workerData.clientSsl,
                                     ftpData->clients[theSocketId].workerData.buffer, CLIENT_BUFFER_STRING_SIZE);
            }
        }
    #endif

    #ifdef OPENSSL_ENABLED
        /* With TLS a broken connection can also show up as 0. A connection closed
           without the TLS closure alert is the end of the file, as many clients do
           just that; a reset or another system error is a failure. */
        if (bytesRead <= 0 && ftpData->clients[theSocketId].dataChannelIsTls == 1) {
            int readError = errno;
            SSL *dataSsl = ftpData->clients[theSocketId].workerData.passiveModeOn == 1 ?
                           ftpData->clients[theSocketId].workerData.serverSsl : ftpData->clients[theSocketId].workerData.clientSsl;
            int sslError = SSL_get_error(dataSsl, bytesRead);
            ERR_clear_error();

            /* OpenSSL reports both cases as "unexpected EOF": only the system error
               (EPIPE, ECONNRESET...) tells the reset from the plain close */
            if (sslError != SSL_ERROR_ZERO_RETURN && readError != 0) {
                errno = readError;
                bytesRead = -1;
            } else {
                bytesRead = 0;
            }
        }
    #endif

        if (bytesRead == 0) {
            break;
        } else if (bytesRead > 0) {
            if (fwrite(ftpData->clients[theSocketId].workerData.buffer, bytesRead, 1, file) != 1) {
                snprintf(failureText, sizeof(failureText), "write error: %s", strerror(errno));
                failure = "451 Requested action aborted: local error in processing\r\n";
                break;
            }
            bytesStored += bytesRead;
            usleep(100);
            ftpData->clients[theSocketId].lastActivityTimeStamp = (int)time(NULL);
        } else {
            snprintf(failureText, sizeof(failureText), "data connection error: %s", strerror(errno));
            failure = "426 Connection closed; transfer aborted\r\n";
            break;
        }
    }

    /* buffered data is written by fclose: a full disk can show up only here */
    if (fclose(file) != 0 && failure == NULL) {
        snprintf(failureText, sizeof(failureText), "write error: %s", strerror(errno));
        failure = "451 Requested action aborted: local error in processing\r\n";
    }
    ftpData->clients[theSocketId].workerData.theStorFile = NULL;

    if (failure != NULL) {
        LOG_ACCESS(ftpData, theSocketId, "%s %s failed after %lld bytes: %s", isAppe ? "APPE" : "STOR", filePath, bytesStored, failureText);
        ftpData->clients[theSocketId].workerData.commandProcessed = 1;
        snprintf(ftpData->clients[theSocketId].workerData.theCommandResponse, STRING_SZ_SMALL, "%s", failure);
        return -1;
    }

    LOG_ACCESS(ftpData, theSocketId, "%s %s: %lld bytes received", isAppe ? "APPE" : "STOR", filePath, bytesStored);

    if (ftpData->clients[theSocketId].login.ownerShip.ownerShipSet == 1) {
        FILE_doChownFromUidGid(filePath, ftpData->clients[theSocketId].login.ownerShip.uid,
                               ftpData->clients[theSocketId].login.ownerShip.gid);
    }

    ftpData->clients[theSocketId].workerData.commandProcessed = 1;
    snprintf(ftpData->clients[theSocketId].workerData.theCommandResponse, STRING_SZ_SMALL, "226 file stor ok\r\n");

    return 1;
}

/* The reply of PASV/EPSV/PORT/EPRT (227, 229, 200) is sent by the worker between these
   two calls. It must not be cut by pthread_cancel (write() is a cancellation point),
   and replaceDataWorker() must know whether it has been sent. */
static int dataReplyBegin(void)
{
    int previousCancelState;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previousCancelState);
    return previousCancelState;
}

static void dataReplyEnd(ftpDataType *ftpData, int theSocketId, int replyReturnCode, int previousCancelState)
{
    if (replyReturnCode > 0)
        ftpData->clients[theSocketId].dataReplyPending = 0;

    pthread_setcancelstate(previousCancelState, NULL);
}

static int acceptConnection(cleanUpWorkerArgs *args)
{
    ftpDataType *ftpData = args->ftpData;
    int theSocketId = args->socketId;
    int returnCode;

    //Passive data connection mode
    if (ftpData->clients[theSocketId].workerData.passiveModeOn == 1)
    {
        int tries = 30;

        while (tries > 0)
        {
            setRandomicPort(ftpData, theSocketId);
            ftpData->clients[theSocketId].workerData.passiveListeningSocket = createPassiveSocket(ftpData->clients[theSocketId].workerData.connectionPort);

            if (ftpData->clients[theSocketId].workerData.passiveListeningSocket != -1)
            {
                break;
            }
            tries--;
        }

        if (ftpData->clients[theSocketId].workerData.passiveListeningSocket == -1)
        {
            LOG_CLIENT(ftpData, theSocketId, LOG_ERROR_PREFIX, "no free passive port between RANDOM_PORT_START and RANDOM_PORT_END");
            markClientForClosing(ftpData, theSocketId, "no passive port available");
            my_printf("\n Closing the client 1");
            return -1;
        }

        if (ftpData->clients[theSocketId].workerData.socketIsConnected == 0)
        {
            int previousCancelState = dataReplyBegin();

            if (ftpData->clients[theSocketId].workerData.passiveModeOn == 1 && ftpData->clients[theSocketId].workerData.extendedPassiveModeOn == 0)
            {
                if(strnlen(ftpData->ftpParameters.natIpAddress, STRING_SZ_SMALL) > 0) 
                {
                    my_printf("\n Using nat ip: %s", ftpData->ftpParameters.natIpAddress);
                    returnCode = socketPrintf(ftpData, theSocketId, "sssdsds", "227 Entering Passive Mode (", ftpData->ftpParameters.natIpAddress, ",", (ftpData->clients[theSocketId].workerData.connectionPort / 256), ",", (ftpData->clients[theSocketId].workerData.connectionPort % 256), ")\r\n");
                }
                else
                {
                    my_printf("\n Using server ip: %s", ftpData->ftpParameters.natIpAddress);
                    returnCode = socketPrintf(ftpData, theSocketId, "sdsdsdsdsdsds", "227 Entering Passive Mode (", ftpData->clients[theSocketId].serverIpV4AddressInteger[0], ",", ftpData->clients[theSocketId].serverIpV4AddressInteger[1], ",", ftpData->clients[theSocketId].serverIpV4AddressInteger[2], ",", ftpData->clients[theSocketId].serverIpV4AddressInteger[3], ",", (ftpData->clients[theSocketId].workerData.connectionPort / 256), ",", (ftpData->clients[theSocketId].workerData.connectionPort % 256), ")\r\n");
                }
            }
            else if (ftpData->clients[theSocketId].workerData.passiveModeOn == 1 && ftpData->clients[theSocketId].workerData.extendedPassiveModeOn == 1)
            {
                returnCode = socketPrintf(ftpData, theSocketId, "sds", "229 Entering Extended Passive Mode (|||", ftpData->clients[theSocketId].workerData.connectionPort, "|)\r\n");
            }
            else
            {
                returnCode = -1;
                my_printfError("\nUnknown passive state, should be PASV or EPSV");
                perror("Unknown passive state, should be PASV or EPSV");
            }

            dataReplyEnd(ftpData, theSocketId, returnCode, previousCancelState);

            ftpData->clients[theSocketId].workerData.socketIsReadyForConnection = 1;

            if (returnCode <= 0)
            {
                ftpData->clients[theSocketId].closeTheClient = 1;
                my_printf("\n Closing the client 2");
                return -1;
            }

            /* Wait for the data connection. RFC 2577: it must come from the host of the
               control connection, otherwise anybody who reaches the passive port first
               (the port is announced in clear text and comes from a small range) gets
               the transfer. Connections from other addresses are closed and the server
               keeps waiting for the client. PASV_PROMISCUOUS = true disables the check. */
            while (1)
            {
                struct sockaddr_storage peerAddress;
                socklen_t peerAddressLength = sizeof(peerAddress);
                int dataSocket = accept(ftpData->clients[theSocketId].workerData.passiveListeningSocket, (struct sockaddr *)&peerAddress, &peerAddressLength);

                if (dataSocket == -1)
                {
                    ftpData->clients[theSocketId].workerData.socketConnection = -1;
                    break;
                }

                if (ftpData->ftpParameters.pasvPromiscuous == 1 ||
                    isPeerFromAddress((struct sockaddr *)&peerAddress, ftpData->clients[theSocketId].clientIpAddress) == 1)
                {
                    ftpData->clients[theSocketId].workerData.socketConnection = dataSocket;
                    break;
                }

                LOGF("%sPassive data connection from another address refused (client %s)", LOG_SECURITY_PREFIX, ftpData->clients[theSocketId].clientIpAddress);
                close(dataSocket);
            }

            if (ftpData->clients[theSocketId].workerData.socketConnection != -1)
            {
                ftpData->clients[theSocketId].workerData.socketIsConnected = 1;
                #ifdef OPENSSL_ENABLED
                if (ftpData->clients[theSocketId].dataChannelIsTls == 1)
                {
                    if (acceptSSLConnection(theSocketId, ftpData) < 0)
                    {
                        my_printf("\nSSL_Accept failed");
                        return -1;
                    }
                }
                #endif
            }
            else
            {
                LOG_CLIENT(ftpData, theSocketId, LOG_ERROR_PREFIX, "passive data connection: accept failed: %s", strerror(errno));
                markClientForClosing(ftpData, theSocketId, "passive data connection failed");
                my_printf("\n Closing the client 3");
                return -1;
            }
        }
        else
            my_printf("\n Socket already connected");
    }
  else if (ftpData->clients[theSocketId].workerData.activeModeOn == 1)
  {
    my_printf("\n -----------------  CREATING ACTIVE SOCKET --------------!");
    if (ftpData->clients[theSocketId].workerData.addressType == 1)
        ftpData->clients[theSocketId].workerData.socketConnection = createActiveSocket(ftpData->clients[theSocketId].workerData.connectionPort, ftpData->clients[theSocketId].workerData.activeIpAddress);
    #ifdef IPV6_ENABLED
    else if (ftpData->clients[theSocketId].workerData.addressType == 2)
        ftpData->clients[theSocketId].workerData.socketConnection = createActiveSocketV6(ftpData->clients[theSocketId].workerData.connectionPort, ftpData->clients[theSocketId].workerData.activeIpAddress);    
    #endif
    int activeConnectError = errno;     /* the TLS setup below may change errno */

	#ifdef OPENSSL_ENABLED
	if (ftpData->clients[theSocketId].dataChannelIsTls == 1)
	{
		returnCode = SSL_set_fd(ftpData->clients[theSocketId].workerData.clientSsl, ftpData->clients[theSocketId].workerData.socketConnection);

		if (returnCode == 0)
		{
			my_printf("\nSSL ERRORS ON WORKER SSL_set_fd");
			markClientForClosing(ftpData, theSocketId, "TLS setup of the active data connection failed (SSL_set_fd)");
		}

		//SSL_set_connect_state(ftpData->clients[theSocketId].workerData.clientSsl);
		returnCode = SSL_connect(ftpData->clients[theSocketId].workerData.clientSsl);
		if (returnCode <= 0)
		{
			my_printf("\nSSL ERRORS ON WORKER %d error code: %d", returnCode, SSL_get_error(ftpData->clients[theSocketId].workerData.clientSsl, returnCode));
			ERR_print_errors_fp(stderr);
		}
		else
		{
			//my_printf("\nSSL ACCEPTED ON WORKER");
		}
	}
	#endif

    if (ftpData->clients[theSocketId].workerData.socketConnection < 0)
    {
        LOG_CLIENT(ftpData, theSocketId, LOG_ERROR_PREFIX, "active data connection to %s port %d failed: %s",
                   ftpData->clients[theSocketId].workerData.activeIpAddress, ftpData->clients[theSocketId].workerData.connectionPort, strerror(activeConnectError));
        markClientForClosing(ftpData, theSocketId, "active data connection failed");
        my_printf("\n Closing the client 4");
        return -1;
    }

    int previousCancelState = dataReplyBegin();
    returnCode = socketPrintf(ftpData, theSocketId, "s", "200 connection accepted\r\n");
    dataReplyEnd(ftpData, theSocketId, returnCode, previousCancelState);
    ftpData->clients[theSocketId].workerData.socketIsReadyForConnection = 1;

    if (returnCode <= 0)
    {
        ftpData->clients[theSocketId].closeTheClient = 1;
        my_printf("\n Closing the client 5");
        return -1;
    }

    ftpData->clients[theSocketId].workerData.socketIsConnected = 1;
  }

  return 1;
}

static int processRetr(cleanUpWorkerArgs *args)
{
    ftpDataType *ftpData = args->ftpData;
	int theSocketId = args->socketId;
    long long int writenSize = 0, writeReturn = 0;

    my_printf("\n ftpData->clients[theSocketId].workerData.retrRestartAtByte = %lld", ftpData->clients[theSocketId].workerData.retrRestartAtByte);

    writenSize = writeRetrFile(ftpData, theSocketId, ftpData->clients[theSocketId].workerData.retrRestartAtByte, ftpData->clients[theSocketId].workerData.theStorFile);
    ftpData->clients[theSocketId].workerData.retrRestartAtByte = 0;

    if (writenSize == RETR_TRANSFER_FAILED)
    {
        /* the file was being sent and the data connection failed: it used to be
           answered "550 unable to open the file for reading" */
        LOG_ACCESS(ftpData, theSocketId, "RETR %s failed: data connection error: %s", ftpData->clients[theSocketId].fileToRetr.text, strerror(errno));
        ftpData->clients[theSocketId].workerData.commandProcessed = 1;
        snprintf(ftpData->clients[theSocketId].workerData.theCommandResponse, STRING_SZ_SMALL, "426 Connection closed; transfer aborted\r\n");
        return -1;
    }

    if (writenSize <= -1)
    {
        LOG_ACCESS(ftpData, theSocketId, "RETR %s failed", ftpData->clients[theSocketId].fileToRetr.text);
        writeReturn = socketPrintf(ftpData, theSocketId, "s", "550 unable to open the file for reading\r\n");

        if (writeReturn <= 0)
        {
        ftpData->clients[theSocketId].closeTheClient = 1;
        my_printf("\n Closing the client 12");
        return -1;
        }

        return -1;
    }

    LOG_ACCESS(ftpData, theSocketId, "RETR %s: %lld bytes sent", ftpData->clients[theSocketId].fileToRetr.text, writenSize);
    ftpData->clients[theSocketId].workerData.commandProcessed = 1;
    snprintf(ftpData->clients[theSocketId].workerData.theCommandResponse, STRING_SZ_SMALL, "226-File successfully transferred\r\n226 done\r\n");

    return 1;
}

static int processListNlst(cleanUpWorkerArgs *args)
{
    ftpDataType *ftpData = args->ftpData;
	int theSocketId = args->socketId;
	int returnCode = 0;

    int theFiles = 0, theCommandType = 0;

    if (compareStringCaseInsensitive(ftpData->clients[theSocketId].workerData.theCommandReceived, "LIST", strlen("LIST")) == 1)
        theCommandType = COMMAND_TYPE_LIST;
    else if (compareStringCaseInsensitive(ftpData->clients[theSocketId].workerData.theCommandReceived, "NLST", strlen("NLST")) == 1)
        theCommandType = COMMAND_TYPE_NLST;

    /* listPath and the options are not touched by the control thread while this worker
       has a command (dataWorkerHasCommand() in ftpCommandElaborate.c) */
    returnCode = writeListDataInfoToSocket(ftpData, theSocketId,
                                           ftpData->clients[theSocketId].listPath.text,
                                           ftpData->clients[theSocketId].workerData.ftpCommand.commandOps.text,
                                           &theFiles, theCommandType, &ftpData->clients[theSocketId].workerData.memoryTable);
    if (returnCode <= 0)
    {
        markClientForClosing(ftpData, theSocketId, "the listing could not be sent");
        my_printf("\n Closing the client 9");
        return -1;
    }

    ftpData->clients[theSocketId].workerData.commandProcessed = 1;
    snprintf(ftpData->clients[theSocketId].workerData.theCommandResponse, STRING_SZ_SMALL, "226 %d matches total\r\n", theFiles);

    return 1;
}

void *connectionWorkerHandle(cleanUpWorkerArgs *args)
{
  ftpDataType *ftpData = args->ftpData;
  int theSocketId = args->socketId;

  // Enable cancellation for this thread
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
  pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

  pthread_cleanup_push((void (*)(void *))workerCleanup,  args);
  /* threadIsAlive and threadHasBeenCreated are set by startDataWorker() before the
     thread is created, see library/serverHelpers.c */

  my_printf("\n -----------------  WORKER CREATED --------------!");

  // deal with connections
  if (acceptConnection(args) != 1)
  {
    my_printf("\n Connection error on the worker, exit from thread.");
    goto data_channel_exit;
  }

 //Endless loop ftp process

  while (1)
  {

    if (ftpData->clients[theSocketId].workerData.socketIsConnected > 0)
    {
    	my_printf("\nWorker %d is waiting for commands!", theSocketId);
        //Conditional lock on tconditionVariablehread actions
        pthread_mutex_lock(&ftpData->clients[theSocketId].conditionMutex);

        /* pthread_cond_wait is a cancellation point and a cancelled thread owns the
           mutex again when its cleanup handlers run: without this handler the mutex
           stays locked forever and the next PASV/PORT of the client, or its
           disconnection, blocks the whole server. */
        pthread_cleanup_push((void (*)(void *))pthread_mutex_unlock, &ftpData->clients[theSocketId].conditionMutex);
        while (ftpData->clients[theSocketId].workerData.commandReceived == 0)
        {
            pthread_cond_wait(&ftpData->clients[theSocketId].conditionVariable, &ftpData->clients[theSocketId].conditionMutex);
        }
        pthread_cleanup_pop(1);

        if (ftpData->clients[theSocketId].workerData.commandReceived == 1 &&
            (compareStringCaseInsensitive(ftpData->clients[theSocketId].workerData.theCommandReceived, "STOR", strlen("STOR")) == 1 || 
            compareStringCaseInsensitive(ftpData->clients[theSocketId].workerData.theCommandReceived, "APPE", strlen("APPE")) == 1) &&
            ftpData->clients[theSocketId].fileToStor.textLen > 0)
        {
            if (processStorAppe(args) != 1)
            {
                my_printf("\nWorker %d errors on STOR APPE!", theSocketId);
            }
            break;
        }
        else if (ftpData->clients[theSocketId].workerData.commandReceived == 1 &&
               (  (compareStringCaseInsensitive(ftpData->clients[theSocketId].workerData.theCommandReceived, "LIST", strlen("LIST")) == 1)
               || (compareStringCaseInsensitive(ftpData->clients[theSocketId].workerData.theCommandReceived, "NLST", strlen("NLST")) == 1)))
        {
            if (processListNlst(args) != 1)
            {
                my_printf("\nWorker %d errors on LIST NLST!", theSocketId);
            }
            break;
        }
        else if (ftpData->clients[theSocketId].workerData.commandReceived == 1 &&
                 compareStringCaseInsensitive(ftpData->clients[theSocketId].workerData.theCommandReceived, "RETR", strlen("RETR")) == 1)
        {
            if (processRetr(args) != 1)
            {
                my_printf("\nWorker %d errors on RETR!", theSocketId);
            }
            break;
        }
      break;
    }
    else
    {
        break;
    }
  }

  data_channel_exit:
  pthread_cleanup_pop(1);
  pthread_exit((void *)1);
}