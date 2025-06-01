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
#include "controlChannel/controlChannel.h"

ftpDataType ftpData;
pthread_t watchDogThread;

void initFtpServer(void)
{
    int returnCode = 0;

    printf("\nHello uFTP server %s starting..\n", UFTP_SERVER_VERSION);

    /* Handle signals */
    signalHandlerInstall();

    /*Read the configuration file */
    configurationRead(&ftpData.ftpParameters, &ftpData.generalDynamicMemoryTable);

    /* apply the reden configuration */
    applyConfiguration(&ftpData.ftpParameters);

    /* initialize the ftp data structure */
    initFtpData(&ftpData);

    my_printf("\nRespawn routine okay\n");

    //Fork the process
    respawnProcess();

    //Init log
    logInit(ftpData.ftpParameters.logFolder, ftpData.ftpParameters.maximumLogFileCount);

    //Socket main creator
    ftpData.connectionData.theMainSocket = createSocket(&ftpData);

    printf("\nuFTP server starting..");

    /* init fd set needed for select */
    fdInit(&ftpData);

    /* the maximum socket fd is now the main socket descriptor */
    ftpData.connectionData.maxSocketFD = ftpData.connectionData.theMainSocket+1;
    returnCode = pthread_create(&watchDogThread, NULL, watchDog, NULL);

	if(returnCode != 0)
	{
		my_printf("pthread_create WatchDog Error %d", returnCode);
        LOG_ERROR("Pthead create error restarting the server");
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
    my_printf("\n ftpData.generalDynamicMemoryTable = %ld", ftpData.generalDynamicMemoryTable);

    #ifdef OPENSSL_ENABLED
    SSL_CTX_free(ftpData.serverCtx);
    cleanupOpenssl();
    #endif
}
