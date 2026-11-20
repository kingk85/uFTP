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
#include "controlChannel.h"

/* Private function definition */
static int processCommand(int processingElement, ftpDataType *ftpData);
static int isCommandByte(struct clientData *client, unsigned char byte);
static void memoryDebug(ftpDataType *ftpData);
static int isTransferCommand(int processingElement, ftpDataType *ftpData);

/* Telnet (RFC 854) on the control connection. RFC 959 section 4.1.3 and RFC 1123 section
   4.1.2.12: a client aborts a transfer with IAC IP IAC DM (the Telnet synch) followed by
   ABOR, and a Telnet client may negotiate options. Those bytes are not part of the command.

   Only the bytes before the first character of a line are looked at: a 0xFF inside a
   command (a file name in latin-1) is left as it is. The state is kept in the client
   because a sequence can arrive in two reads. */
enum { TELNET_DATA = 0, TELNET_IAC, TELNET_OPTION, TELNET_SUBNEGOTIATION, TELNET_SUBNEGOTIATION_IAC };

#define TELNET_IAC_BYTE 255
#define TELNET_SB 250
#define TELNET_SE 240
#define TELNET_WILL 251
#define TELNET_DONT 254

/* 1 if the byte belongs to the command, 0 if it is a Telnet byte to be skipped */
static int isCommandByte(struct clientData *client, unsigned char byte)
{
    if (client->commandIndex != 0 && client->telnetState == TELNET_DATA)
        return 1;

    switch (client->telnetState)
    {
        case TELNET_IAC:
            if (byte == TELNET_IAC_BYTE)                      /* IAC IAC: the byte 255 as data */
            {
                client->telnetState = TELNET_DATA;
                return 1;
            }
            if (byte >= TELNET_WILL && byte <= TELNET_DONT)   /* WILL WONT DO DONT <option> */
                client->telnetState = TELNET_OPTION;
            else if (byte == TELNET_SB)                       /* subnegotiation until IAC SE */
                client->telnetState = TELNET_SUBNEGOTIATION;
            else                                              /* NOP, DM, IP, AO...: one byte */
                client->telnetState = TELNET_DATA;
            return 0;

        case TELNET_OPTION:
            client->telnetState = TELNET_DATA;
            return 0;

        case TELNET_SUBNEGOTIATION:
            if (byte == TELNET_IAC_BYTE)
                client->telnetState = TELNET_SUBNEGOTIATION_IAC;
            return 0;

        case TELNET_SUBNEGOTIATION_IAC:
            client->telnetState = (byte == TELNET_SE) ? TELNET_DATA : TELNET_SUBNEGOTIATION;
            return 0;

        default:                                              /* TELNET_DATA at the start of a line */
            if (byte == TELNET_IAC_BYTE)
            {
                client->telnetState = TELNET_IAC;
                return 0;
            }
            return 1;
    }
}

void evaluateControlChannel(ftpDataType *ftpData)
{
    int returnCode = 0;

    //Update watchdog timer
   	updateWatchDogTime((int)time(NULL));

    //debug memory usage
    memoryDebug(ftpData);

    /* waits for socket activity */
    waitForClientEvents(ftpData);

    /* Timeouts must be checked regardless of socket activity: checking them only
       when select() times out lets a single busy client prevent every other idle
       client from ever being disconnected. Run the check at most once per second. */
    static time_t lastTimeoutCheck = 0;
    time_t now = time(NULL);
    if (now != lastTimeoutCheck)
    {
        lastTimeoutCheck = now;
        checkClientConnectionTimeout(ftpData);
        flushLoginWrongTriesData(ftpData);
        logFlushRepeated();
    }

    /*Main loop handle client commands */
    for (int processingSock = 0; processingSock < ftpData->ftpParameters.maxClients; processingSock++)
    {
        /* close the connection if quit flag has been set */
        if (ftpData->clients[processingSock].closeTheClient == 1)
        {
            closeClient(ftpData, processingSock);
            continue;
        }

        /* Check if there are client pending connections, accept the connection if possible otherwise reject */  
        if ((returnCode = evaluateClientSocketConnection(ftpData)) == 1)
        {
            break;
        }

        /* no data to check client is not connected, continue to check other clients */
        if (isClientConnected(ftpData, processingSock) == 0) 
        {
            /* socket is not conneted */
            continue;
        }

        if (ftpData->clients[processingSock].socketEventReady == 1)
        {

        #ifdef OPENSSL_ENABLED
            if (ftpData->clients[processingSock].tlsIsNegotiating == 1)
            {
                returnCode = SSL_accept(ftpData->clients[processingSock].ssl);

                if (returnCode <= 0)
                {
                    //my_printf("\nSSL NOT YET ACCEPTED: %d", returnCode);
                    ftpData->clients[processingSock].tlsIsEnabled = 0;
                    ftpData->clients[processingSock].tlsIsNegotiating = 1;

                    /* Only WANT_READ/WANT_WRITE mean the handshake is still in progress.
                       Any other error (EOF, SSL_ERROR_SYSCALL, protocol error) is fatal:
                       keeping the client would make the wait return immediately forever
                       on the readable-at-EOF socket and spin the CPU. */
                    int sslError = SSL_get_error(ftpData->clients[processingSock].ssl, returnCode);
                    if (sslError != SSL_ERROR_WANT_READ && sslError != SSL_ERROR_WANT_WRITE)
                    {
                        ftpData->clients[processingSock].tlsIsNegotiating = 0;
                        logTlsHandshakeFailure(ftpData, processingSock, sslError);
                        markClientForClosing(ftpData, processingSock, "TLS handshake failed");
                    }
                    else if ( ((int)time(NULL) - ftpData->clients[processingSock].tlsNegotiatingTimeStart) > TLS_NEGOTIATING_TIMEOUT )
                    {
                        markClientForClosing(ftpData, processingSock, "TLS handshake not completed in time");
                        //my_printf("\nTLS timeout closing the client time:%lld, start time: %lld..", (int)time(NULL), ftpData->clients[processingSock].tlsNegotiatingTimeStart);
                    }
                }
                else
                {
                    //my_printf("\nSSL ACCEPTED");
                    ftpData->clients[processingSock].tlsIsEnabled = 1;
                    ftpData->clients[processingSock].tlsIsNegotiating = 0;
                    LOG_ACCESS(ftpData, processingSock, "TLS established (%s)", SSL_get_version(ftpData->clients[processingSock].ssl));
                }

                continue;
            }
        #endif

        #ifdef OPENSSL_ENABLED
        /* After CCC: read the TLS closure alert of the client (RFC 4217 12.3) before
           reading clear text. A TLS record starts with a content type byte 0x14-0x17;
           anything else means the client went on in clear text without closing TLS.
           The first byte is looked at only until the record has started to be read
           (CCC_SHUTDOWN_READING): the rest of a record that arrives in more than one
           TCP segment does not start with a content type byte. */
        if (ftpData->clients[processingSock].cccShutdownPending != CCC_SHUTDOWN_DONE)
        {
            unsigned char firstByte = 0;
            ssize_t peeked = 1;

            if (ftpData->clients[processingSock].cccShutdownPending == CCC_SHUTDOWN_WAITING)
            {
                peeked = recv(ftpData->clients[processingSock].socketDescriptor, &firstByte, 1, MSG_PEEK);
            }

            if (ftpData->clients[processingSock].cccShutdownPending == CCC_SHUTDOWN_READING ||
                (peeked == 1 && firstByte >= 0x14 && firstByte <= 0x17))
            {
                pthread_mutex_lock(&ftpData->clients[processingSock].writeMutex);
                int shutdownReturn = SSL_shutdown(ftpData->clients[processingSock].ssl);
                int shutdownError = (shutdownReturn < 0) ? SSL_get_error(ftpData->clients[processingSock].ssl, shutdownReturn) : SSL_ERROR_NONE;
                pthread_mutex_unlock(&ftpData->clients[processingSock].writeMutex);

                /* finished (1), or anything but "record not complete yet" (WANT_READ /
                   WANT_WRITE: try again at the next read event): stop waiting. 0 is
                   included so that a readable socket can never make the loop spin. */
                if (shutdownReturn >= 0 ||
                    (shutdownError != SSL_ERROR_WANT_READ && shutdownError != SSL_ERROR_WANT_WRITE))
                {
                    ftpData->clients[processingSock].cccShutdownPending = CCC_SHUTDOWN_DONE;
                }
                else
                {
                    ftpData->clients[processingSock].cccShutdownPending = CCC_SHUTDOWN_READING;
                }

                continue;
            }

            if (peeked != 0)
            {
                ftpData->clients[processingSock].cccShutdownPending = CCC_SHUTDOWN_DONE;
            }
            /* peeked == 0: the client closed, the read below sees it */
        }
        #endif

            if (ftpData->clients[processingSock].tlsIsEnabled == 1)
            {
                #ifdef OPENSSL_ENABLED
                /* the worker may be writing a reply on the same SSL object */
                pthread_mutex_lock(&ftpData->clients[processingSock].writeMutex);
                ftpData->clients[processingSock].bufferIndex = SSL_read(ftpData->clients[processingSock].ssl, ftpData->clients[processingSock].buffer, CLIENT_BUFFER_STRING_SIZE);
                pthread_mutex_unlock(&ftpData->clients[processingSock].writeMutex);
                #endif
            }
            else
            {
                ftpData->clients[processingSock].bufferIndex = read(ftpData->clients[processingSock].socketDescriptor, ftpData->clients[processingSock].buffer, CLIENT_BUFFER_STRING_SIZE);
            }

        //The client is not connected anymore
        if ((ftpData->clients[processingSock].bufferIndex) == 0)
        {
            setCloseReason(ftpData, processingSock, "closed by the client");
            closeClient(ftpData, processingSock);
        }
        else if (ftpData->clients[processingSock].bufferIndex < 0)
        {
            /* A failed read is final unless it only means "try again later". Otherwise
               (TLS protocol error, connection reset...) the unread bytes stay on the
               socket, select() reports it readable forever and the loop spins the CPU
               until the idle timeout. */
            int readErrorIsFatal = 1;

            if (ftpData->clients[processingSock].tlsIsEnabled == 1)
            {
                #ifdef OPENSSL_ENABLED
                int sslReadError = SSL_get_error(ftpData->clients[processingSock].ssl, ftpData->clients[processingSock].bufferIndex);
                if (sslReadError == SSL_ERROR_WANT_READ || sslReadError == SSL_ERROR_WANT_WRITE)
                    readErrorIsFatal = 0;
                #endif
            }
            else if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            {
                readErrorIsFatal = 0;
            }

            if (readErrorIsFatal == 1)
            {
                /* A peer that resets, times out or breaks the TLS stream is the client's doing:
                   [ERROR] stays for problems of the server. */
                int clientCaused = ftpData->clients[processingSock].tlsIsEnabled == 1 ||
                                   errno == ECONNRESET || errno == ECONNABORTED || errno == ETIMEDOUT ||
                                   errno == EPIPE || errno == EHOSTUNREACH || errno == ENETUNREACH;

                LOG_CLIENT(ftpData, processingSock, clientCaused ? LOG_DEBUG_PREFIX : LOG_ERROR_PREFIX,
                           "control connection read error: %s",
                           ftpData->clients[processingSock].tlsIsEnabled == 1 ? "TLS protocol error" : strerror(errno));
                markClientForClosing(ftpData, processingSock, "control connection read error");
            }
        }


        //Some commands has been received
        if (ftpData->clients[processingSock].bufferIndex > 0)
        {
            int i = 0;
            int commandProcessStatus = 0;
            for (i = 0; i < ftpData->clients[processingSock].bufferIndex; i++)
            {
                /* A reply could not be written (the client does not read): the client is going to be closed,
                   and every command of the same buffer that followed waited again for the write, up to the
                   timeout each, with the whole server stopped (a client that sends HELP a few hundred times
                   and reads nothing stopped it for about a minute). */
                if (ftpData->clients[processingSock].closeTheClient == 1)
                {
                    break;
                }

                if (isCommandByte(&ftpData->clients[processingSock], (unsigned char)ftpData->clients[processingSock].buffer[i]) == 0)
                {
                    continue;
                }

                if (ftpData->clients[processingSock].commandIndex < CLIENT_COMMAND_STRING_SIZE)
                {
                    if (ftpData->clients[processingSock].buffer[i] != '\r' && ftpData->clients[processingSock].buffer[i] != '\n')
                    {
                        ftpData->clients[processingSock].theCommandReceived[ftpData->clients[processingSock].commandIndex++] = ftpData->clients[processingSock].buffer[i];
                    }

                    if (ftpData->clients[processingSock].buffer[i] == '\n') 
                        {
                            ftpData->clients[processingSock].socketCommandReceived = 1;
                            //my_printf("\n Processing the command: %s", ftpData->clients[processingSock].theCommandReceived);
                            commandProcessStatus = processCommand(processingSock, ftpData);
                            //Echo unrecognized commands
                            if (commandProcessStatus == FTP_COMMAND_NOT_RECONIZED) 
                            {
                                int returnCode = 0;
                                returnCode = socketPrintf(ftpData, processingSock, "s", "500 Unknown command\r\n");
                                if (returnCode < 0)
                                {
                                    ftpData->clients[processingSock].closeTheClient = 1;
                                }
                                my_printf("\n COMMAND NOT SUPPORTED ********* %s", ftpData->clients[processingSock].buffer);
                                LOGF("%sCommand not supported: %s", LOG_DEBUG_PREFIX, ftpData->clients[processingSock].buffer);
                            }
                            else if (commandProcessStatus == FTP_COMMAND_PROCESSED)
                            {
                                ftpData->clients[processingSock].lastActivityTimeStamp = (int)time(NULL);
                            }
                            else if (commandProcessStatus == FTP_COMMAND_PROCESSED_WRITE_ERROR)
                            {
                                ftpData->clients[processingSock].closeTheClient = 1;
                                my_printf("\n Write error WARNING!");
                            }
                        }
                }
                else
                {
                    //Command overflow can't be processed
                    int returnCode;
                    ftpData->clients[processingSock].commandIndex = 0;
                    memset(ftpData->clients[processingSock].theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE+1);
                    returnCode = socketPrintf(ftpData, processingSock, "s", "500 Unknown command\r\n");
                    if (returnCode <= 0) 
                    {
                        ftpData->clients[processingSock].closeTheClient = 1;
                    }
                    my_printf("\n Command too long closing the client.");
                    break;
                }
            }
            memset(ftpData->clients[processingSock].buffer, 0, CLIENT_BUFFER_STRING_SIZE+1);
        }
    }
    }
}

/* Private static functions */
static void memoryDebug(ftpDataType *ftpData)
{
	my_printf("\nUsed memory : %lld", DYNMEM_GetTotalMemory());
	for (int memCount = 0; memCount < ftpData->ftpParameters.maxClients; memCount++)
	{
		if (ftpData->clients[memCount].memoryTable != NULL)
		{
			my_printf("\nftpData->clients[%d].memoryTable = %s", memCount, ftpData->clients[memCount].memoryTable->theName);
		}
		if (ftpData->clients[memCount].workerData.memoryTable != NULL)
		{
			my_printf("\nftpData->clients[%d].workerData.memoryTable = %s", memCount, ftpData->clients[memCount].workerData.memoryTable->theName);
		}

		if (ftpData->clients[memCount].workerData.directoryInfo.memoryTable != NULL)
		{
			my_printf("\nftpData->clients[%d].workerData.directoryInfo.memoryTable = %s", memCount, ftpData->clients[memCount].workerData.directoryInfo.memoryTable->theName);
		}
	}
}

static int isTransferCommand(int processingElement, ftpDataType *ftpData)
{
    if (IS_CMD(ftpData->clients[processingElement].theCommandReceived, "RETR") ||
        IS_CMD(ftpData->clients[processingElement].theCommandReceived, "STOR") ||
        IS_CMD(ftpData->clients[processingElement].theCommandReceived, "PASV") ||
        IS_CMD(ftpData->clients[processingElement].theCommandReceived, "EPSV") ||
        IS_CMD(ftpData->clients[processingElement].theCommandReceived, "PORT") ||
        IS_CMD(ftpData->clients[processingElement].theCommandReceived, "EPRT") ||
        IS_CMD(ftpData->clients[processingElement].theCommandReceived, "TYPE") ||
        IS_CMD(ftpData->clients[processingElement].theCommandReceived, "APPE"))
    {
        return 1;
    }

    return 0;
}

static int processCommand(int processingElement, ftpDataType *ftpData)
{
    //command handler structure
     static CommandMapEntry commandMap[] = {
        {"USER", parseCommandUser},
        {"PASS", parseCommandPass},
        {"SITE", parseCommandSite},
        {"AUTH", parseCommandAuth},
        {"PROT", parseCommandProt},
        {"PBSZ", parseCommandPbsz},
        {"CCC", parseCommandCcc},
        {"PWD", parseCommandPwd},
        {"XPWD", parseCommandPwd},
        {"SYST", parseCommandSyst},
        {"FEAT", parseCommandFeat},
        {"TYPE", parseCommandType},
        {"STRU", parseCommandStru},
        {"MODE", parseCommandMode},
        {"EPSV", parseCommandEpsv},
        {"PASV", parseCommandPasv},
        {"PORT", parseCommandPort},
        {"EPRT", parseCommandEprt},
        {"LIST", parseCommandList},
        {"STAT", parseCommandStat},
        {"CDUP", parseCommandCdup},
        {"XCUP", parseCommandCdup},
        {"CWD ..", parseCommandCdup},
        {"CWD", parseCommandCwd},
        {"REST", parseCommandRest},
        {"RETR", parseCommandRetr},
        {"STOR", parseCommandStor},
        {"MKD", parseCommandMkd},
        {"XMKD", parseCommandMkd},
        {"ABOR", parseCommandAbor},
        {"DELE", parseCommandDele},
        {"OPTS", parseCommandOpts},
        {"MDTM", parseCommandMdtm},
        {"NLST", parseCommandNlst},
        {"MLSD", parseCommandMlsd},
        {"MLST", parseCommandMlst},
        {"LANG", parseCommandLang},
        {"HOST", parseCommandHost},
        {"QUIT", parseCommandQuit},
        {"RMD", parseCommandRmd},
        {"XRMD", parseCommandRmd},
        {"RNFR", parseCommandRnfr},
        {"RNTO", parseCommandRnto},
        {"SIZE", parseCommandSize},
        {"APPE", parseCommandAppe},
        {"NOOP", parseCommandNoop},
        {"ACCT", parseCommandAcct},
        {"HELP", parseCommandHelp},
        {"ALLO", parseCommandAllo},
        {"REIN", parseCommandNotImplemented},
        {"STOU", parseCommandNotImplemented},
        {"SMNT", parseCommandNotImplemented}
    };

    #define COMMAND_MAP_SIZE (sizeof(commandMap) / sizeof(CommandMapEntry))

    int toReturn = 0;
    int commandIndex = -1;

    //printTimeStamp();
    my_printf("\nCommand received from (%d): %s", processingElement, ftpData->clients[processingElement].theCommandReceived);

    for (int i = 0; i < COMMAND_MAP_SIZE; ++i)
    {
        if (IS_CMD(ftpData->clients[processingElement].theCommandReceived, (char *)commandMap[i].command))
        {
            commandIndex = i;
            break;
        }
    }

    if (commandIndex == -1)
    {
        toReturn = invalidCommandResponse(ftpData, processingElement);
        ftpData->clients[processingElement].commandIndex = 0;
        memset(ftpData->clients[processingElement].theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE+1);
        return toReturn;        
    }

    if(!isTransferCommand(processingElement, ftpData) && 
        ftpData->clients[processingElement].workerData.retrRestartAtByte != 0)
    {
        my_printf("Reset: retrRestartAtByte");
        ftpData->clients[processingElement].workerData.retrRestartAtByte = 0;
    }

    cleanDynamicStringDataType(&ftpData->clients[processingElement].ftpCommand.commandArgs, 0, &ftpData->clients[processingElement].memoryTable);
    cleanDynamicStringDataType(&ftpData->clients[processingElement].ftpCommand.commandOps, 0, &ftpData->clients[processingElement].memoryTable);

    if (ftpData->clients[processingElement].login.userLoggedIn == 0 &&
        (IS_NOT_CMD(ftpData->clients[processingElement].theCommandReceived, "USER") &&
         IS_NOT_CMD(ftpData->clients[processingElement].theCommandReceived, "PASS") &&
         IS_NOT_CMD(ftpData->clients[processingElement].theCommandReceived, "QUIT") &&
		 IS_NOT_CMD(ftpData->clients[processingElement].theCommandReceived, "PBSZ") &&
		 IS_NOT_CMD(ftpData->clients[processingElement].theCommandReceived, "PROT") &&
         /* FEAT, SYST, HELP and NOOP carry no user data: clients use them before
            logging in (e.g. FEAT to discover AUTH TLS, RFC 2389 / RFC 4217) */
         IS_NOT_CMD(ftpData->clients[processingElement].theCommandReceived, "FEAT") &&
         IS_NOT_CMD(ftpData->clients[processingElement].theCommandReceived, "HOST") &&
         IS_NOT_CMD(ftpData->clients[processingElement].theCommandReceived, "LANG") &&
         IS_NOT_CMD(ftpData->clients[processingElement].theCommandReceived, "SYST") &&
         IS_NOT_CMD(ftpData->clients[processingElement].theCommandReceived, "HELP") &&
         IS_NOT_CMD(ftpData->clients[processingElement].theCommandReceived, "NOOP") &&
         IS_NOT_CMD(ftpData->clients[processingElement].theCommandReceived, "AUTH")))
    {
        toReturn = notLoggedInMessage(ftpData, processingElement);
        ftpData->clients[processingElement].commandIndex = 0;
        memset(ftpData->clients[processingElement].theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE+1);
        return 1;
    }

    my_printf("\n%s COMMAND RECEIVED", commandMap[commandIndex].command);
    toReturn = ((int (*)(ftpDataType *, int))commandMap[commandIndex].handler)(ftpData, processingElement);

    ftpData->clients[processingElement].commandIndex = 0;
    memset(ftpData->clients[processingElement].theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE+1);
    return toReturn;
}