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
#include <errno.h>
#include <netdb.h>

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
#include "controlChannel/controlChannel.h"

ftpDataType ftpData;
pthread_t watchDogThread;

/* One line that says which server is running and how: the first thing to look at
   when something goes wrong */
static void logStartupSummary(ftpParameters_DataType *parameters)
{
    const char *tls = "no";
    const char *ipv6 = "no";
#ifdef OPENSSL_ENABLED
    tls = parameters->forceTLS == 1 ? "required" : "available";
#endif
#ifdef IPV6_ENABLED
    ipv6 = "yes";
#endif

    LOGF_NOW("%suFTP %s listening on port %d: TLS %s, IPv6 %s, daemon %s, respawn %s, "
             "%d users, max %d clients (%d per address), idle timeout %d s, login timeout %d s",
             LOG_INFO_PREFIX, UFTP_SERVER_VERSION, parameters->port, tls, ipv6,
             parameters->daemonModeOn == 1 ? "yes" : "no",
             parameters->respawnProcessOn == 1 ? "yes" : "no",
             parameters->usersVector.Size, parameters->maxClients, parameters->maximumConnectionsPerIp,
             parameters->maximumIdleInactivity, parameters->loginTimeout);
}

/* USER_NAME_OWNER_n / GROUP_NAME_OWNER_n that do not exist on the system: the user
   operates as root in their place (by design). Said once at startup, where a typo in
   uftpd.cfg is easy to spot. */
static void logMissingOwners(ftpParameters_DataType *parameters)
{
    for (int i = 0; i < parameters->usersVector.Size; i++)
    {
        usersParameters_DataType *user = (usersParameters_DataType *)parameters->usersVector.Data[i];

        if (user->ownerShip.ownerNotFound & OWNER_USER_NOT_FOUND)
            LOGF_NOW("%sOwner user \"%s\" of FTP user \"%s\" does not exist: the user operates as root (uid 0)",
                     LOG_ERROR_PREFIX, user->ownerShip.userOwnerString, user->name);

        if (user->ownerShip.ownerNotFound & OWNER_GROUP_NOT_FOUND)
            LOGF_NOW("%sOwner group \"%s\" of FTP user \"%s\" does not exist: the user operates as group root (gid 0)",
                     LOG_ERROR_PREFIX, user->ownerShip.groupOwnerString, user->name);
    }
}

void initFtpServer(void)
{
    int returnCode = 0;

    printf("\nHello uFTP server %s starting..\n", UFTP_SERVER_VERSION);

    /* Handle signals */
    signalHandlerInstall();

    /*Read the configuration file */
    configurationRead(&ftpData.ftpParameters, &ftpData.generalDynamicMemoryTable);

    /* The log is ready right after the configuration, before anything that can fail
       (daemon mode, TLS certificates, supervisor, listening port): until the writer
       thread starts, lines are written at once. */
    logConfigure(ftpData.ftpParameters.logFolder, ftpData.ftpParameters.maximumLogFileCount);

    /* apply the reden configuration */
    applyConfiguration(&ftpData.ftpParameters);

    /* initialize the ftp data structure */
    initFtpData(&ftpData);

    my_printf("\nRespawn routine okay\n");

    //Fork the process (a supervisor parent restarts the server if it dies)
    if (ftpData.ftpParameters.respawnProcessOn == 1)
    {
        respawnProcess();
    }

    //The process that serves the clients writes the log from a thread of its own
    logStartWriter();

    //Socket main creator
    ftpData.connectionData.theMainSocket = createSocket(&ftpData);

    if (ftpData.connectionData.theMainSocket < 0)
    {
        /* it used to go on with an invalid socket and stop soon after, saying nothing */
        LOGF_NOW("%sCan not listen on port %d: %s", LOG_FATAL_PREFIX, ftpData.ftpParameters.port, strerror(errno));
        exit(EXIT_FAILURE);
    }

    logStartupSummary(&ftpData.ftpParameters);
    logMissingOwners(&ftpData.ftpParameters);

    printf("\nuFTP server starting..");

    /* init fd set needed for select */
    fdInit(&ftpData);

    /* the maximum socket fd is now the main socket descriptor */
    ftpData.connectionData.maxSocketFD = ftpData.connectionData.theMainSocket+1;
    returnCode = pthread_create(&watchDogThread, NULL, watchDog, NULL);

	if(returnCode != 0)
	{
		my_printf("pthread_create WatchDog Error %d", returnCode);
        LOGF_NOW("%sCan not start the watchdog thread: %s, exiting", LOG_FATAL_PREFIX, strerror(returnCode));
        exit(0);
	}
}

void runFtpServer(void)
{
    initFtpServer();

    //Endless loop ftp process
    while (1)
    {
        evaluateControlChannel(&ftpData);
    }

    //Server Close
    shutdown(ftpData.connectionData.theMainSocket, SHUT_RDWR);
    close(ftpData.connectionData.theMainSocket);
    return;
}

void deallocateMemory(void)
{
	int i = 0;
    my_printf("\nDeallocating server memory ..");
    my_printf("\nDYNMEM_freeAll called");
    my_printf("\nMemory Table size: %ld", ftpData.generalDynamicMemoryTable->size);
    my_printf("\nMemory Table: %ld", (long int) ftpData.generalDynamicMemoryTable->address);
    my_printf("\nMemory Table: %ld",(long int) ftpData.generalDynamicMemoryTable->nextElement);
    my_printf("\nMemory Table: %ld",(long int) ftpData.generalDynamicMemoryTable->previousElement);

    for (i = 0; i < ftpData.ftpParameters.maxClients; i++)
    {
        DYNMEM_freeAll(&ftpData.clients[i].memoryTable);
        DYNMEM_freeAll(&ftpData.clients[i].workerData.memoryTable);
    }

    DYNMEM_freeAll(&ftpData.loginFailsVector.memoryTable);
    DYNMEM_freeAll(&ftpData.ftpParameters.usersVector.memoryTable);
    DYNMEM_freeAll(&ftpData.generalDynamicMemoryTable);

    my_printf("\n\nUsed memory at end: %lld", DYNMEM_GetTotalMemory());
    my_printf("\n ftpData.generalDynamicMemoryTable = %p", ftpData.generalDynamicMemoryTable);

    #ifdef OPENSSL_ENABLED
    SSL_CTX_free(ftpData.serverCtx);
    cleanupOpenssl();
    #endif
}
