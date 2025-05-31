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
#include "library/logFunctions.h"
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
static void memoryDebug(ftpDataType *ftpData);

void evaluateControlChannel(ftpDataType *ftpData)
{
    int returnCode = 0;

    //Update watchdog timer
   	updateWatchDogTime((int)time(NULL));

    //debug memory usage
    memoryDebug(ftpData);

    /* waits for socket activity, if no activity then checks for client socket timeouts */
    if (selectWait(ftpData) == 0)
    {
        checkClientConnectionTimeout(ftpData);
        flushLoginWrongTriesData(ftpData);
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

        if (FD_ISSET(ftpData->clients[processingSock].socketDescriptor, &ftpData->connectionData.rset) || 
            FD_ISSET(ftpData->clients[processingSock].socketDescriptor, &ftpData->connectionData.eset))
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

                    if ( ((int)time(NULL) - ftpData->clients[processingSock].tlsNegotiatingTimeStart) > TLS_NEGOTIATING_TIMEOUT )
                    {
                        ftpData->clients[processingSock].closeTheClient = 1;
                        LOGF("%sTLS timeout closing the client time:%lld, start time: %lld..", LOG_DEBUG_PREFIX, (int)time(NULL), ftpData->clients[processingSock].tlsNegotiatingTimeStart); 
                        //my_printf("\nTLS timeout closing the client time:%lld, start time: %lld..", (int)time(NULL), ftpData->clients[processingSock].tlsNegotiatingTimeStart);
                    }
                }
                else
                {
                    //my_printf("\nSSL ACCEPTED");
                    ftpData->clients[processingSock].tlsIsEnabled = 1;
                    ftpData->clients[processingSock].tlsIsNegotiating = 0;
                }

                continue;
            }
        #endif

            if (ftpData->clients[processingSock].tlsIsEnabled == 1)
            {
                #ifdef OPENSSL_ENABLED
                ftpData->clients[processingSock].bufferIndex = SSL_read(ftpData->clients[processingSock].ssl, ftpData->clients[processingSock].buffer, CLIENT_BUFFER_STRING_SIZE);
                #endif
            }
            else
            {
                ftpData->clients[processingSock].bufferIndex = read(ftpData->clients[processingSock].socketDescriptor, ftpData->clients[processingSock].buffer, CLIENT_BUFFER_STRING_SIZE);
            }

        //The client is not connected anymore
        if ((ftpData->clients[processingSock].bufferIndex) == 0)
        {
            closeClient(ftpData, processingSock);
        }


        //Some commands has been received
        if (ftpData->clients[processingSock].bufferIndex > 0)
        {
            int i = 0;
            int commandProcessStatus = 0;
            for (i = 0; i < ftpData->clients[processingSock].bufferIndex; i++)
            {
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
                                    LOG_ERROR("socketPrintf"); 
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
                                LOG_ERROR("ftp command processed error"); 
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
                        LOG_ERROR("socketPrintf"); 
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

static int processCommand(int processingElement, ftpDataType *ftpData)
{
    //command handler structure
     static CommandMapEntry commandMap[] = {
        {"USER", parseCommandUser},
        {"PASS", parseCommandPass},
        {"SITE", parseCommandSite},
        {"AUTH TLS", parseCommandAuth},
        {"PROT", parseCommandProt},
        {"PBSZ", parseCommandPbsz},
        {"CCC", parseCommandCcc},
        {"PWD", parseCommandPwd},
        {"XPWD", parseCommandPwd},
        {"SYST", parseCommandSyst},
        {"FEAT", parseCommandFeat},
        {"TYPE I", parseCommandTypeI},
        {"TYPE A", parseCommandTypeI},
        {"STRU F", parseCommandStruF},
        {"MODE S", parseCommandModeS},
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
        {"QUIT", parseCommandQuit},
        {"RMD", parseCommandRmd},
        {"XRMD", parseCommandRmd},
        {"RNFR", parseCommandRnfr},
        {"RNTO", parseCommandRnto},
        {"SIZE", parseCommandSize},
        {"APPE", parseCommandAppe},
        {"NOOP", parseCommandNoop},
        {"ACCT", parseCommandAcct}
    };

    #define COMMAND_MAP_SIZE (sizeof(commandMap) / sizeof(CommandMapEntry))

    int toReturn = 0;
    //printTimeStamp();
    my_printf("\nCommand received from (%d): %s", processingElement, ftpData->clients[processingElement].theCommandReceived);

    cleanDynamicStringDataType(&ftpData->clients[processingElement].ftpCommand.commandArgs, 0, ftpData->clients[processingElement].memoryTable);
    cleanDynamicStringDataType(&ftpData->clients[processingElement].ftpCommand.commandOps, 0, ftpData->clients[processingElement].memoryTable);

    if (ftpData->clients[processingElement].login.userLoggedIn == 0 &&
        (IS_NOT_CMD(ftpData->clients[processingElement].theCommandReceived, "USER") &&
         IS_NOT_CMD(ftpData->clients[processingElement].theCommandReceived, "PASS") &&
         IS_NOT_CMD(ftpData->clients[processingElement].theCommandReceived, "QUIT") &&
		 IS_NOT_CMD(ftpData->clients[processingElement].theCommandReceived, "PBSZ") &&
		 IS_NOT_CMD(ftpData->clients[processingElement].theCommandReceived, "PROT") &&
		 IS_NOT_CMD(ftpData->clients[processingElement].theCommandReceived, "CCC") &&
         IS_NOT_CMD(ftpData->clients[processingElement].theCommandReceived, "AUTH TLS")))
    {
        toReturn = notLoggedInMessage(ftpData, processingElement);
        ftpData->clients[processingElement].commandIndex = 0;
        memset(ftpData->clients[processingElement].theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE+1);
        return 1;
    }

    for (int i = 0; i < COMMAND_MAP_SIZE; ++i)
    {
        if (IS_CMD(ftpData->clients[processingElement].theCommandReceived, commandMap[i].command))
        {
            my_printf("\n%s COMMAND RECEIVED", commandMap[i].command);
            toReturn = commandMap[i].handler(ftpData, processingElement);
            break;
        }
    }

    ftpData->clients[processingElement].commandIndex = 0;
    memset(ftpData->clients[processingElement].theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE+1);
    return toReturn;
}