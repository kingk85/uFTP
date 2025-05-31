
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

	#ifdef OPENSSL_ENABLED
    int error;
    error = fcntl(ftpData->clients[theSocketId].workerData.socketConnection, F_SETFL, O_NONBLOCK);

	if (ftpData->clients[theSocketId].dataChannelIsTls == 1)
	{
		if(ftpData->clients[theSocketId].workerData.passiveModeOn == 1)
		{
			//my_printf("\nSSL worker Shutdown 1");
			returnCode = SSL_shutdown(ftpData->clients[theSocketId].workerData.serverSsl);
			//my_printf("\nnSSL worker Shutdown 1 return code : %d", returnCode);

			if (!returnCode)
			{
			    shutdown(ftpData->clients[theSocketId].workerData.socketConnection, SHUT_RDWR);
			    shutdown(ftpData->clients[theSocketId].workerData.passiveListeningSocket, SHUT_RDWR);

				//my_printf("\nSSL worker Shutdown 2");
				returnCode = SSL_shutdown(ftpData->clients[theSocketId].workerData.serverSsl);
				//my_printf("\nnSSL worker Shutdown 2 return code : %d", returnCode);
			}
		}

		if(ftpData->clients[theSocketId].workerData.activeModeOn == 1)
		{
			returnCode = SSL_shutdown(ftpData->clients[theSocketId].workerData.clientSsl);

			if (!returnCode)
			{
			    shutdown(ftpData->clients[theSocketId].workerData.socketConnection, SHUT_RDWR);
			    shutdown(ftpData->clients[theSocketId].workerData.passiveListeningSocket, SHUT_RDWR);
			    returnCode = SSL_shutdown(ftpData->clients[theSocketId].workerData.clientSsl);
			}
		}
	}
	#endif

    shutdown(ftpData->clients[theSocketId].workerData.socketConnection, SHUT_RDWR);

    shutdown(ftpData->clients[theSocketId].workerData.passiveListeningSocket, SHUT_RDWR);

    returnCode = close(ftpData->clients[theSocketId].workerData.socketConnection);
    returnCode = close(ftpData->clients[theSocketId].workerData.passiveListeningSocket);

    if (ftpData->clients[theSocketId].workerData.commandProcessed)
    {
        returnCode = socketPrintf(ftpData, theSocketId, "s", ftpData->clients[theSocketId].workerData.theCommandResponse);
        if (returnCode <= 0)
        {
            ftpData->clients[theSocketId].closeTheClient = 1;
            LOG_ERROR("socketPrintf"); 
            my_printf("\n Closing the client 10");
        }
    }
    
    resetWorkerData(ftpData, theSocketId, 0);

    DYNMEM_free(args, &ftpData->clients[theSocketId].workerData.memoryTable);

    if (ftpData->clients[theSocketId].workerData.memoryTable != NULL)
    	DYNMEM_dump(ftpData->clients[theSocketId].workerData.memoryTable);//my_printf("\nMemory table element label: %s", ftpData->clients[theSocketId].workerData.memoryTable->theName);

}

static int processStorAppe(cleanUpWorkerArgs *args)
{
    ftpDataType *ftpData = args->ftpData;
	int theSocketId = args->socketId;
	int returnCode = 0;

    if (compareStringCaseInsensitive(ftpData->clients[theSocketId].workerData.theCommandReceived, "APPE", strlen("APPE")) == 1)
    {
        #ifdef LARGE_FILE_SUPPORT_ENABLED
                //#warning LARGE FILE SUPPORT IS ENABLED!
                ftpData->clients[theSocketId].workerData.theStorFile = fopen64(ftpData->clients[theSocketId].fileToStor.text, "ab");
        #endif

        #ifndef LARGE_FILE_SUPPORT_ENABLED
                #warning LARGE FILE SUPPORT IS NOT ENABLED!
                ftpData->clients[theSocketId].workerData.theStorFile = fopen(ftpData->clients[theSocketId].fileToStor.text, "ab");
        #endif
    }
    else
    {
        #ifdef LARGE_FILE_SUPPORT_ENABLED
                //#warning LARGE FILE SUPPORT IS ENABLED!
                ftpData->clients[theSocketId].workerData.theStorFile = fopen64(ftpData->clients[theSocketId].fileToStor.text, "wb");
        #endif

        #ifndef LARGE_FILE_SUPPORT_ENABLED
                #warning LARGE FILE SUPPORT IS NOT ENABLED!
                ftpData->clients[theSocketId].workerData.theStorFile = fopen(ftpData->clients[theSocketId].fileToStor.text, "wb");
        #endif
    }

    if (ftpData->clients[theSocketId].workerData.theStorFile == NULL)
    {
        returnCode = socketPrintf(ftpData, theSocketId, "s", "553 Unable to write the file\r\n");

        if (returnCode <= 0)
        {
            ftpData->clients[theSocketId].closeTheClient = 1;
            LOG_ERROR("socketPrintf"); 
            my_printf("\n Closing the client 6");
            return -1;
        }

        return -1;
    }

    while(1)
    {
        if (ftpData->clients[theSocketId].dataChannelIsTls != 1)
        {
            ftpData->clients[theSocketId].workerData.bufferIndex = read(ftpData->clients[theSocketId].workerData.socketConnection, ftpData->clients[theSocketId].workerData.buffer, CLIENT_BUFFER_STRING_SIZE);
        }
        else if (ftpData->clients[theSocketId].dataChannelIsTls == 1)
        {
            #ifdef OPENSSL_ENABLED
            if (ftpData->clients[theSocketId].workerData.passiveModeOn == 1)
                ftpData->clients[theSocketId].workerData.bufferIndex = SSL_read(ftpData->clients[theSocketId].workerData.serverSsl, ftpData->clients[theSocketId].workerData.buffer, CLIENT_BUFFER_STRING_SIZE);
            else if(ftpData->clients[theSocketId].workerData.activeModeOn == 1)
                ftpData->clients[theSocketId].workerData.bufferIndex = SSL_read(ftpData->clients[theSocketId].workerData.clientSsl, ftpData->clients[theSocketId].workerData.buffer, CLIENT_BUFFER_STRING_SIZE);
            #endif
        }
        else
        {
            my_printf("\nError state");
        }

        if (ftpData->clients[theSocketId].workerData.bufferIndex == 0)
        {
            break;
        }
        else if (ftpData->clients[theSocketId].workerData.bufferIndex > 0)
        {
            fwrite(ftpData->clients[theSocketId].workerData.buffer, ftpData->clients[theSocketId].workerData.bufferIndex, 1, ftpData->clients[theSocketId].workerData.theStorFile);
            usleep(100);
            ftpData->clients[theSocketId].lastActivityTimeStamp = (int)time(NULL);
        }
        else if (ftpData->clients[theSocketId].workerData.bufferIndex < 0)
        {
            break;
        }
    }

    int theReturnCode;
    theReturnCode = fclose(ftpData->clients[theSocketId].workerData.theStorFile);
    ftpData->clients[theSocketId].workerData.theStorFile = NULL;

    if (ftpData->clients[theSocketId].login.ownerShip.ownerShipSet == 1)
    {
        FILE_doChownFromUidGid(ftpData->clients[theSocketId].fileToStor.text, ftpData->clients[theSocketId].login.ownerShip.uid, ftpData->clients[theSocketId].login.ownerShip.gid);
    }

    ftpData->clients[theSocketId].workerData.commandProcessed = 1;
    snprintf(ftpData->clients[theSocketId].workerData.theCommandResponse, STRING_SZ_SMALL, "226 file stor ok\r\n");

    return 1;
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
            ftpData->clients[theSocketId].closeTheClient = 1;
            my_printf("\n Closing the client 1");
            return -1;
        }

        if (ftpData->clients[theSocketId].workerData.socketIsConnected == 0)
        {
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

            ftpData->clients[theSocketId].workerData.socketIsReadyForConnection = 1;

            if (returnCode <= 0)
            {
                ftpData->clients[theSocketId].closeTheClient = 1;
                LOG_ERROR("socketPrintf");            
                my_printf("\n Closing the client 2");
                return -1;
            }

            //Wait for sockets
            if ((ftpData->clients[theSocketId].workerData.socketConnection = accept(ftpData->clients[theSocketId].workerData.passiveListeningSocket, 0, 0))!=-1)
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
                ftpData->clients[theSocketId].closeTheClient = 1;
                LOG_ERROR("Socket error"); 
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

	#ifdef OPENSSL_ENABLED
	if (ftpData->clients[theSocketId].dataChannelIsTls == 1)
	{
		returnCode = SSL_set_fd(ftpData->clients[theSocketId].workerData.clientSsl, ftpData->clients[theSocketId].workerData.socketConnection);

		if (returnCode == 0)
		{
			my_printf("\nSSL ERRORS ON WORKER SSL_set_fd");
			ftpData->clients[theSocketId].closeTheClient = 1;
            LOG_ERROR("SSL ERRORS ON WORKER SSL_set_fd"); 
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
        ftpData->clients[theSocketId].closeTheClient = 1;
        LOG_ERROR("Socket error"); 
        my_printf("\n Closing the client 4");
        return -1;
    }

    returnCode = socketPrintf(ftpData, theSocketId, "s", "200 connection accepted\r\n");
    ftpData->clients[theSocketId].workerData.socketIsReadyForConnection = 1;

    if (returnCode <= 0)
    {
        ftpData->clients[theSocketId].closeTheClient = 1;
        LOG_ERROR("socketPrintf"); 
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
	int returnCode = 0;
    long long int writenSize = 0, writeReturn = 0;

    writenSize = writeRetrFile(ftpData, theSocketId, ftpData->clients[theSocketId].workerData.retrRestartAtByte, ftpData->clients[theSocketId].workerData.theStorFile);
    ftpData->clients[theSocketId].workerData.retrRestartAtByte = 0;

    if (writenSize <= -1)
    {
        writeReturn = socketPrintf(ftpData, theSocketId, "s", "550 unable to open the file for reading\r\n");

        if (writeReturn <= 0)
        {
        ftpData->clients[theSocketId].closeTheClient = 1;
        LOG_ERROR("socketPrintf"); 
        my_printf("\n Closing the client 12");
        return -1;
        }

        return -1;
    }

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

    returnCode = writeListDataInfoToSocket(ftpData, theSocketId, &theFiles, theCommandType, &ftpData->clients[theSocketId].workerData.memoryTable);
    if (returnCode <= 0)
    {
        ftpData->clients[theSocketId].closeTheClient = 1;
        LOG_ERROR("writeListDataInfoToSocket"); 
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
  int returnCode = 0;

  // Enable cancellation for this thread
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
  pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

  pthread_cleanup_push(workerCleanup,  args);
  ftpData->clients[theSocketId].workerData.threadIsAlive = 1;
  ftpData->clients[theSocketId].workerData.threadHasBeenCreated = 1;
  int returnCode;

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
        while (ftpData->clients[theSocketId].workerData.commandReceived == 0)
        {
            pthread_cond_wait(&ftpData->clients[theSocketId].conditionVariable, &ftpData->clients[theSocketId].conditionMutex);
        }
        pthread_mutex_unlock(&ftpData->clients[theSocketId].conditionMutex);

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