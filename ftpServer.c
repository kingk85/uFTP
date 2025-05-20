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

ftpDataType ftpData;
pthread_t watchDogThread;

static int processCommand(int processingElement);

void workerCleanup(void *socketId)
{
	int theSocketId = *(int *)socketId;
	int returnCode = 0;

	//my_printf("\nWorker %d cleanup", theSocketId);

	#ifdef OPENSSL_ENABLED
    int error;
    error = fcntl(ftpData.clients[theSocketId].workerData.socketConnection, F_SETFL, O_NONBLOCK);

	if (ftpData.clients[theSocketId].dataChannelIsTls == 1)
	{
		if(ftpData.clients[theSocketId].workerData.passiveModeOn == 1)
		{
			//my_printf("\nSSL worker Shutdown 1");
			returnCode = SSL_shutdown(ftpData.clients[theSocketId].workerData.serverSsl);
			//my_printf("\nnSSL worker Shutdown 1 return code : %d", returnCode);

			if (!returnCode)
			{
			    shutdown(ftpData.clients[theSocketId].workerData.socketConnection, SHUT_RDWR);
			    shutdown(ftpData.clients[theSocketId].workerData.passiveListeningSocket, SHUT_RDWR);

				//my_printf("\nSSL worker Shutdown 2");
				returnCode = SSL_shutdown(ftpData.clients[theSocketId].workerData.serverSsl);
				//my_printf("\nnSSL worker Shutdown 2 return code : %d", returnCode);
			}
		}

		if(ftpData.clients[theSocketId].workerData.activeModeOn == 1)
		{
			returnCode = SSL_shutdown(ftpData.clients[theSocketId].workerData.clientSsl);

			if (!returnCode)
			{
			    shutdown(ftpData.clients[theSocketId].workerData.socketConnection, SHUT_RDWR);
			    shutdown(ftpData.clients[theSocketId].workerData.passiveListeningSocket, SHUT_RDWR);
			    returnCode = SSL_shutdown(ftpData.clients[theSocketId].workerData.clientSsl);
			}
		}
	}
	#endif

    shutdown(ftpData.clients[theSocketId].workerData.socketConnection, SHUT_RDWR);

    shutdown(ftpData.clients[theSocketId].workerData.passiveListeningSocket, SHUT_RDWR);

    returnCode = close(ftpData.clients[theSocketId].workerData.socketConnection);
    returnCode = close(ftpData.clients[theSocketId].workerData.passiveListeningSocket);

    resetWorkerData(&ftpData, theSocketId, 0);

   // my_printf("\nWorker cleaned!");
    //my_printf("\nWorker memory table :%lld", ftpData.clients[theSocketId].workerData.memoryTable);

    if (ftpData.clients[theSocketId].workerData.memoryTable != NULL)
    	;//my_printf("\nMemory table element label: %s", ftpData.clients[theSocketId].workerData.memoryTable->theName);
    else
    	;//my_printf("\nNo data to print");
}

void *connectionWorkerHandle(void * socketId)
{
  int theSocketId = *(int *)socketId;
  // Enable cancellation for this thread
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
  pthread_cleanup_push(workerCleanup,  (void *) &theSocketId);
  ftpData.clients[theSocketId].workerData.threadIsAlive = 1;
  ftpData.clients[theSocketId].workerData.threadHasBeenCreated = 1;
  int returnCode;

  my_printf("\n -----------------  WORKER CREATED --------------!");

  //Passive data connection mode
  if (ftpData.clients[theSocketId].workerData.passiveModeOn == 1)
  {
    int tries = 30;
    while (tries > 0)
    {
        setRandomicPort(&ftpData, theSocketId);
        ftpData.clients[theSocketId].workerData.passiveListeningSocket = createPassiveSocket(ftpData.clients[theSocketId].workerData.connectionPort);

        if (ftpData.clients[theSocketId].workerData.passiveListeningSocket != -1)
        {
            break;
        }

        tries--;
    }

    if (ftpData.clients[theSocketId].workerData.passiveListeningSocket == -1)
    {
        ftpData.clients[theSocketId].closeTheClient = 1;
        my_printf("\n Closing the client 1");
        goto data_channel_exit;
    }

    if (ftpData.clients[theSocketId].workerData.socketIsConnected == 0)
    {
        if (ftpData.clients[theSocketId].workerData.passiveModeOn == 1 && ftpData.clients[theSocketId].workerData.extendedPassiveModeOn == 0)
        {
            if(strnlen(ftpData.ftpParameters.natIpAddress, STRING_SZ_SMALL) > 0) 
            {
                my_printf("\n Using nat ip: %s", ftpData.ftpParameters.natIpAddress);
    	        returnCode = socketPrintf(&ftpData, theSocketId, "sssdsds", "227 Entering Passive Mode (", ftpData.ftpParameters.natIpAddress, ",", (ftpData.clients[theSocketId].workerData.connectionPort / 256), ",", (ftpData.clients[theSocketId].workerData.connectionPort % 256), ")\r\n");
            }
            else
            {
                my_printf("\n Using server ip: %s", ftpData.ftpParameters.natIpAddress);
                returnCode = socketPrintf(&ftpData, theSocketId, "sdsdsdsdsdsds", "227 Entering Passive Mode (", ftpData.clients[theSocketId].serverIpV4AddressInteger[0], ",", ftpData.clients[theSocketId].serverIpV4AddressInteger[1], ",", ftpData.clients[theSocketId].serverIpV4AddressInteger[2], ",", ftpData.clients[theSocketId].serverIpV4AddressInteger[3], ",", (ftpData.clients[theSocketId].workerData.connectionPort / 256), ",", (ftpData.clients[theSocketId].workerData.connectionPort % 256), ")\r\n");
            }
        }
        else if (ftpData.clients[theSocketId].workerData.passiveModeOn == 1 && ftpData.clients[theSocketId].workerData.extendedPassiveModeOn == 1)
        {
    	    returnCode = socketPrintf(&ftpData, theSocketId, "sds", "229 Entering Extended Passive Mode (|||", ftpData.clients[theSocketId].workerData.connectionPort, "|)\r\n");
        }
        else
        {
            returnCode = -1;
            my_printfError("\nUnknown passive state, should be PASV or EPSV");
            perror("Unknown passive state, should be PASV or EPSV");
        }

        ftpData.clients[theSocketId].workerData.socketIsReadyForConnection = 1;

        if (returnCode <= 0)
        {
            ftpData.clients[theSocketId].closeTheClient = 1;
            addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);            
            my_printf("\n Closing the client 2");
            goto data_channel_exit;
        }

        //Wait for sockets
        if ((ftpData.clients[theSocketId].workerData.socketConnection = accept(ftpData.clients[theSocketId].workerData.passiveListeningSocket, 0, 0))!=-1)
        {
            ftpData.clients[theSocketId].workerData.socketIsConnected = 1;
			#ifdef OPENSSL_ENABLED
            if (ftpData.clients[theSocketId].dataChannelIsTls == 1)
            {

            	returnCode = SSL_set_fd(ftpData.clients[theSocketId].workerData.serverSsl, ftpData.clients[theSocketId].workerData.socketConnection);

        		if (returnCode == 0)
        		{
        			my_printf("\nSSL ERRORS ON WORKER SSL_set_fd");
        			ftpData.clients[theSocketId].closeTheClient = 1;
                    addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);            
        		}

                returnCode = SSL_accept(ftpData.clients[theSocketId].workerData.serverSsl);

				if (returnCode <= 0)
				{
					my_printf("\nSSL ERRORS ON WORKER");
					ERR_print_errors_fp(stderr);
					ftpData.clients[theSocketId].closeTheClient = 1;
                    addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC); 
				}
				else
				{
					//my_printf("\nSSL ACCEPTED ON WORKER");
				}
            }
			#endif
        }
        else
        {
            ftpData.clients[theSocketId].closeTheClient = 1;
            addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC); 
            my_printf("\n Closing the client 3");
            goto data_channel_exit;
        }
    }
    else
        my_printf("\n Socket already connected");
  }
  else if (ftpData.clients[theSocketId].workerData.activeModeOn == 1)
  {
    my_printf("\n -----------------  CREATING ACTIVE SOCKET --------------!");
    if (ftpData.clients[theSocketId].workerData.addressType == 1)
        ftpData.clients[theSocketId].workerData.socketConnection = createActiveSocket(ftpData.clients[theSocketId].workerData.connectionPort, ftpData.clients[theSocketId].workerData.activeIpAddress);
#ifdef IPV6_ENABLED
    else if (ftpData.clients[theSocketId].workerData.addressType == 2)
        ftpData.clients[theSocketId].workerData.socketConnection = createActiveSocketV6(ftpData.clients[theSocketId].workerData.connectionPort, ftpData.clients[theSocketId].workerData.activeIpAddress);    
#endif

	#ifdef OPENSSL_ENABLED
	if (ftpData.clients[theSocketId].dataChannelIsTls == 1)
	{
		returnCode = SSL_set_fd(ftpData.clients[theSocketId].workerData.clientSsl, ftpData.clients[theSocketId].workerData.socketConnection);

		if (returnCode == 0)
		{
			my_printf("\nSSL ERRORS ON WORKER SSL_set_fd");
			ftpData.clients[theSocketId].closeTheClient = 1;
            addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC); 
		}
		//SSL_set_connect_state(ftpData.clients[theSocketId].workerData.clientSsl);
		returnCode = SSL_connect(ftpData.clients[theSocketId].workerData.clientSsl);
		if (returnCode <= 0)
		{
			my_printf("\nSSL ERRORS ON WORKER %d error code: %d", returnCode, SSL_get_error(ftpData.clients[theSocketId].workerData.clientSsl, returnCode));
			ERR_print_errors_fp(stderr);
		}
		else
		{
			//my_printf("\nSSL ACCEPTED ON WORKER");
		}
	}
	#endif

    if (ftpData.clients[theSocketId].workerData.socketConnection < 0)
    {
        ftpData.clients[theSocketId].closeTheClient = 1;
        addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC); 
        my_printf("\n Closing the client 4");
        goto data_channel_exit;
    }


    returnCode = socketPrintf(&ftpData, theSocketId, "s", "200 connection accepted\r\n");
    ftpData.clients[theSocketId].workerData.socketIsReadyForConnection = 1;

    if (returnCode <= 0)
    {
        ftpData.clients[theSocketId].closeTheClient = 1;
        addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC); 
        my_printf("\n Closing the client 5");
        goto data_channel_exit;
    }

    ftpData.clients[theSocketId].workerData.socketIsConnected = 1;
  }


  //my_printf("\nftpData.clients[theSocketId].workerData.socketIsConnected = %d", ftpData.clients[theSocketId].workerData.socketIsConnected);

//Endless loop ftp process
  while (1)
  {

    if (ftpData.clients[theSocketId].workerData.socketIsConnected > 0)
    {
    	my_printf("\nWorker %d is waiting for commands!", theSocketId);
        //Conditional lock on tconditionVariablehread actions
        pthread_mutex_lock(&ftpData.clients[theSocketId].conditionMutex);
        while (ftpData.clients[theSocketId].workerData.commandReceived == 0)
        {
            pthread_cond_wait(&ftpData.clients[theSocketId].conditionVariable, &ftpData.clients[theSocketId].conditionMutex);
        }
        pthread_mutex_unlock(&ftpData.clients[theSocketId].conditionMutex);


        if (ftpData.clients[theSocketId].workerData.commandReceived == 1 &&
            (compareStringCaseInsensitive(ftpData.clients[theSocketId].workerData.theCommandReceived, "STOR", strlen("STOR")) == 1 || compareStringCaseInsensitive(ftpData.clients[theSocketId].workerData.theCommandReceived, "APPE", strlen("APPE")) == 1) &&
            ftpData.clients[theSocketId].fileToStor.textLen > 0)
        {

        	if (compareStringCaseInsensitive(ftpData.clients[theSocketId].workerData.theCommandReceived, "APPE", strlen("APPE")) == 1)
        	{
				#ifdef LARGE_FILE_SUPPORT_ENABLED
						//#warning LARGE FILE SUPPORT IS ENABLED!
						ftpData.clients[theSocketId].workerData.theStorFile = fopen64(ftpData.clients[theSocketId].fileToStor.text, "ab");
				#endif

				#ifndef LARGE_FILE_SUPPORT_ENABLED
						#warning LARGE FILE SUPPORT IS NOT ENABLED!
						ftpData.clients[theSocketId].workerData.theStorFile = fopen(ftpData.clients[theSocketId].fileToStor.text, "ab");
				#endif
        	}
        	else
        	{
				#ifdef LARGE_FILE_SUPPORT_ENABLED
						//#warning LARGE FILE SUPPORT IS ENABLED!
						ftpData.clients[theSocketId].workerData.theStorFile = fopen64(ftpData.clients[theSocketId].fileToStor.text, "wb");
				#endif

				#ifndef LARGE_FILE_SUPPORT_ENABLED
						#warning LARGE FILE SUPPORT IS NOT ENABLED!
						ftpData.clients[theSocketId].workerData.theStorFile = fopen(ftpData.clients[theSocketId].fileToStor.text, "wb");
				#endif
        	}

            if (ftpData.clients[theSocketId].workerData.theStorFile == NULL)
            {
            	returnCode = socketPrintf(&ftpData, theSocketId, "s", "553 Unable to write the file\r\n");

                if (returnCode <= 0)
                {
                    ftpData.clients[theSocketId].closeTheClient = 1;
                    addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC); 
                    my_printf("\n Closing the client 6");
                    goto data_channel_exit;
                }

                break;
            }

            returnCode = socketPrintf(&ftpData, theSocketId, "s", "150 Accepted data connection\r\n");

            if (returnCode <= 0)
            {
                ftpData.clients[theSocketId].closeTheClient = 1;
                addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC); 
                my_printf("\n Closing the client 7");
                goto data_channel_exit;
            }

            while(1)
            {

            	if (ftpData.clients[theSocketId].dataChannelIsTls != 1)
            	{
            		ftpData.clients[theSocketId].workerData.bufferIndex = read(ftpData.clients[theSocketId].workerData.socketConnection, ftpData.clients[theSocketId].workerData.buffer, CLIENT_BUFFER_STRING_SIZE);
            	}
            	else if (ftpData.clients[theSocketId].dataChannelIsTls == 1)
            	{

					#ifdef OPENSSL_ENABLED
            		if (ftpData.clients[theSocketId].workerData.passiveModeOn == 1)
            			ftpData.clients[theSocketId].workerData.bufferIndex = SSL_read(ftpData.clients[theSocketId].workerData.serverSsl, ftpData.clients[theSocketId].workerData.buffer, CLIENT_BUFFER_STRING_SIZE);
            		else if(ftpData.clients[theSocketId].workerData.activeModeOn == 1)
            			ftpData.clients[theSocketId].workerData.bufferIndex = SSL_read(ftpData.clients[theSocketId].workerData.clientSsl, ftpData.clients[theSocketId].workerData.buffer, CLIENT_BUFFER_STRING_SIZE);
					#endif
            	}
            	else
            	{
            		my_printf("\nError state");
            	}

                if (ftpData.clients[theSocketId].workerData.bufferIndex == 0)
                {
                    break;
                }
                else if (ftpData.clients[theSocketId].workerData.bufferIndex > 0)
                {
                    fwrite(ftpData.clients[theSocketId].workerData.buffer, ftpData.clients[theSocketId].workerData.bufferIndex, 1, ftpData.clients[theSocketId].workerData.theStorFile);
                    usleep(100);
                }
                else if (ftpData.clients[theSocketId].workerData.bufferIndex < 0)
                {
                    break;
                }
            }

            int theReturnCode;
            theReturnCode = fclose(ftpData.clients[theSocketId].workerData.theStorFile);
            ftpData.clients[theSocketId].workerData.theStorFile = NULL;

            if (ftpData.clients[theSocketId].login.ownerShip.ownerShipSet == 1)
            {
                FILE_doChownFromUidGid(ftpData.clients[theSocketId].fileToStor.text, ftpData.clients[theSocketId].login.ownerShip.uid, ftpData.clients[theSocketId].login.ownerShip.gid);
            }

            returnCode = socketPrintf(&ftpData, theSocketId, "s", "226 file stor ok\r\n");
            if (returnCode <= 0)
            {
                ftpData.clients[theSocketId].closeTheClient = 1;
                addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC); 
                my_printf("\n Closing the client 8");
                goto data_channel_exit;
            }

            break;
        }
      else if (ftpData.clients[theSocketId].workerData.commandReceived == 1 &&
               (  (compareStringCaseInsensitive(ftpData.clients[theSocketId].workerData.theCommandReceived, "LIST", strlen("LIST")) == 1)
               || (compareStringCaseInsensitive(ftpData.clients[theSocketId].workerData.theCommandReceived, "NLST", strlen("NLST")) == 1))
              )
        {
          int theFiles = 0, theCommandType = 0;

          if (compareStringCaseInsensitive(ftpData.clients[theSocketId].workerData.theCommandReceived, "LIST", strlen("LIST")) == 1)
              theCommandType = COMMAND_TYPE_LIST;
          else if (compareStringCaseInsensitive(ftpData.clients[theSocketId].workerData.theCommandReceived, "NLST", strlen("NLST")) == 1)
              theCommandType = COMMAND_TYPE_NLST;

          returnCode = socketPrintf(&ftpData, theSocketId, "s", "150 Accepted data connection\r\n");
          if (returnCode <= 0)
          {
              ftpData.clients[theSocketId].closeTheClient = 1;
              addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC); 
              my_printf("\n Closing the client 8");
              goto data_channel_exit;
          }

          returnCode = writeListDataInfoToSocket(&ftpData, theSocketId, &theFiles, theCommandType, &ftpData.clients[theSocketId].workerData.memoryTable);
          if (returnCode <= 0)
          {
              ftpData.clients[theSocketId].closeTheClient = 1;
              addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC); 
              my_printf("\n Closing the client 9");
              goto data_channel_exit;
          }

          returnCode = socketPrintf(&ftpData, theSocketId, "sds", "226 ", theFiles, " matches total\r\n");
          if (returnCode <= 0)
          {
              ftpData.clients[theSocketId].closeTheClient = 1;
              addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC); 
              my_printf("\n Closing the client 10");
              goto data_channel_exit;
          }

          break;
      }
        else if (ftpData.clients[theSocketId].workerData.commandReceived == 1 &&
                 compareStringCaseInsensitive(ftpData.clients[theSocketId].workerData.theCommandReceived, "RETR", strlen("RETR")) == 1)
        {
            long long int writenSize = 0, writeReturn = 0;
            writeReturn = socketPrintf(&ftpData, theSocketId, "s", "150 Accepted data connection\r\n");
            if (writeReturn <= 0)
            {
                ftpData.clients[theSocketId].closeTheClient = 1;
                addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC); 
                my_printf("\n Closing the client 11");
                goto data_channel_exit;
            }

            writenSize = writeRetrFile(&ftpData, theSocketId, ftpData.clients[theSocketId].workerData.retrRestartAtByte, ftpData.clients[theSocketId].workerData.theStorFile);
            ftpData.clients[theSocketId].workerData.retrRestartAtByte = 0;

            if (writenSize <= -1)
            {
              writeReturn = socketPrintf(&ftpData, theSocketId, "s", "550 unable to open the file for reading\r\n");

              if (writeReturn <= 0)
              {
                ftpData.clients[theSocketId].closeTheClient = 1;
                addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC); 
                my_printf("\n Closing the client 12");
                goto data_channel_exit;
              }
              break;
            }

            writeReturn = socketPrintf(&ftpData, theSocketId, "s", "226-File successfully transferred\r\n226 done\r\n");

            if (writeReturn <= 0)
            {
              ftpData.clients[theSocketId].closeTheClient = 1;
              addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC); 
              my_printf("\n Closing the client 13");
              goto data_channel_exit;
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

void runFtpServer(void)
{
    printf("\nHello uFTP server %s starting..\n", UFTP_SERVER_VERSION);

    /* Needed for Select*/
    static int processingSock = 0, returnCode = 0;

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
        addLog("Pthead create error restarting the server", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
        exit(0);
	}

  //Endless loop ftp process
    while (1)
    {

    //Update watchdog timer
   	updateWatchDogTime((int)time(NULL));

	
	my_printf("\nUsed memory : %lld", DYNMEM_GetTotalMemory());
	int memCount = 0;
	for (memCount = 0; memCount < ftpData.ftpParameters.maxClients; memCount++)
	{
		if (ftpData.clients[memCount].memoryTable != NULL)
		{
			my_printf("\nftpData.clients[%d].memoryTable = %s", memCount, ftpData.clients[memCount].memoryTable->theName);
		}
		if (ftpData.clients[memCount].workerData.memoryTable != NULL)
		{
			my_printf("\nftpData.clients[%d].workerData.memoryTable = %s", memCount, ftpData.clients[memCount].workerData.memoryTable->theName);
		}

		if (ftpData.clients[memCount].workerData.directoryInfo.memoryTable != NULL)
		{
			my_printf("\nftpData.clients[%d].workerData.directoryInfo.memoryTable = %s", memCount, ftpData.clients[memCount].workerData.directoryInfo.memoryTable->theName);
		}
	}

    /* waits for socket activity, if no activity then checks for client socket timeouts */
    if (selectWait(&ftpData) == 0)
    {
        checkClientConnectionTimeout(&ftpData);
        flushLoginWrongTriesData(&ftpData);
    }

    /*Main loop handle client commands */
    for (processingSock = 0; processingSock < ftpData.ftpParameters.maxClients; processingSock++)
    {
        /* close the connection if quit flag has been set */
        if (ftpData.clients[processingSock].closeTheClient == 1)
        {
            closeClient(&ftpData, processingSock);
            continue;
        }

        /* Check if there are client pending connections, accept the connection if possible otherwise reject */  
        if ((returnCode = evaluateClientSocketConnection(&ftpData)) == 1)
        {
            break;
        }

        /* no data to check client is not connected, continue to check other clients */
        if (isClientConnected(&ftpData, processingSock) == 0) 
        {
            /* socket is not conneted */
            continue;
        }

        if (FD_ISSET(ftpData.clients[processingSock].socketDescriptor, &ftpData.connectionData.rset) || 
            FD_ISSET(ftpData.clients[processingSock].socketDescriptor, &ftpData.connectionData.eset))
        {

        #ifdef OPENSSL_ENABLED
            if (ftpData.clients[processingSock].tlsIsNegotiating == 1)
            {
                returnCode = SSL_accept(ftpData.clients[processingSock].ssl);

                if (returnCode <= 0)
                {
                    //my_printf("\nSSL NOT YET ACCEPTED: %d", returnCode);
                    ftpData.clients[processingSock].tlsIsEnabled = 0;
                    ftpData.clients[processingSock].tlsIsNegotiating = 1;

                    if ( ((int)time(NULL) - ftpData.clients[processingSock].tlsNegotiatingTimeStart) > TLS_NEGOTIATING_TIMEOUT )
                    {
                        ftpData.clients[processingSock].closeTheClient = 1;
                        addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC); 
                        //my_printf("\nTLS timeout closing the client time:%lld, start time: %lld..", (int)time(NULL), ftpData.clients[processingSock].tlsNegotiatingTimeStart);
                    }

                }
                else
                {
                    //my_printf("\nSSL ACCEPTED");
                    ftpData.clients[processingSock].tlsIsEnabled = 1;
                    ftpData.clients[processingSock].tlsIsNegotiating = 0;
                }

                continue;
            }
        #endif

            if (ftpData.clients[processingSock].tlsIsEnabled == 1)
            {
                #ifdef OPENSSL_ENABLED
                ftpData.clients[processingSock].bufferIndex = SSL_read(ftpData.clients[processingSock].ssl, ftpData.clients[processingSock].buffer, CLIENT_BUFFER_STRING_SIZE);
                #endif
            }
            else
            {
                ftpData.clients[processingSock].bufferIndex = read(ftpData.clients[processingSock].socketDescriptor, ftpData.clients[processingSock].buffer, CLIENT_BUFFER_STRING_SIZE);
            }

        //The client is not connected anymore
        if ((ftpData.clients[processingSock].bufferIndex) == 0)
        {
            //addLog("Client not connected anymore", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
            closeClient(&ftpData, processingSock);
        }

        //Debug print errors
        if (ftpData.clients[processingSock].bufferIndex < 0)
        {
            //ftpData.clients[processingSock].closeTheClient = 1;
            //addLog("Socket write error ", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
            //my_printfError("\n1 Errno = %d", errno);
            continue;
        }

        //Some commands has been received
        if (ftpData.clients[processingSock].bufferIndex > 0)
        {
            int i = 0;
            int commandProcessStatus = 0;
            for (i = 0; i < ftpData.clients[processingSock].bufferIndex; i++)
            {
                if (ftpData.clients[processingSock].commandIndex < CLIENT_COMMAND_STRING_SIZE)
                {
                    if (ftpData.clients[processingSock].buffer[i] != '\r' && ftpData.clients[processingSock].buffer[i] != '\n')
                    {
                        ftpData.clients[processingSock].theCommandReceived[ftpData.clients[processingSock].commandIndex++] = ftpData.clients[processingSock].buffer[i];
                    }

                    if (ftpData.clients[processingSock].buffer[i] == '\n') 
                        {
                            ftpData.clients[processingSock].socketCommandReceived = 1;
                            //my_printf("\n Processing the command: %s", ftpData.clients[processingSock].theCommandReceived);
                            commandProcessStatus = processCommand(processingSock);
                            //Echo unrecognized commands
                            if (commandProcessStatus == FTP_COMMAND_NOT_RECONIZED) 
                            {
                                int returnCode = 0;
                                returnCode = socketPrintf(&ftpData, processingSock, "s", "500 Unknown command\r\n");
                                if (returnCode < 0)
                                {
                                    ftpData.clients[processingSock].closeTheClient = 1;
                                    addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC); 
                                }
                                my_printf("\n COMMAND NOT SUPPORTED ********* %s", ftpData.clients[processingSock].buffer);
                            }
                            else if (commandProcessStatus == FTP_COMMAND_PROCESSED)
                            {
                                ftpData.clients[processingSock].lastActivityTimeStamp = (int)time(NULL);
                            }
                            else if (commandProcessStatus == FTP_COMMAND_PROCESSED_WRITE_ERROR)
                            {
                                ftpData.clients[processingSock].closeTheClient = 1;
                                addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC); 
                                my_printf("\n Write error WARNING!");
                            }
                        }
                }
                else
                {
                    //Command overflow can't be processed
                    int returnCode;
                    ftpData.clients[processingSock].commandIndex = 0;
                    memset(ftpData.clients[processingSock].theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE+1);
                    returnCode = socketPrintf(&ftpData, processingSock, "s", "500 Unknown command\r\n");
                    if (returnCode <= 0) 
                    {
                        ftpData.clients[processingSock].closeTheClient = 1;
                        addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC); 
                    }
                    my_printf("\n Command too long closing the client.");
                    break;
                }
            }
            usleep(100);
            memset(ftpData.clients[processingSock].buffer, 0, CLIENT_BUFFER_STRING_SIZE+1);
        }
    }
    }
  }

  //Server Close
  shutdown(ftpData.connectionData.theMainSocket, SHUT_RDWR);
  close(ftpData.connectionData.theMainSocket);
  return;
}

static int processCommand(int processingElement)
{
    int toReturn = 0;
    //printTimeStamp();
    my_printf ("\nCommand received from (%d): %s", processingElement, ftpData.clients[processingElement].theCommandReceived);

    cleanDynamicStringDataType(&ftpData.clients[processingElement].ftpCommand.commandArgs, 0, &ftpData.clients[processingElement].memoryTable);
    cleanDynamicStringDataType(&ftpData.clients[processingElement].ftpCommand.commandOps, 0, &ftpData.clients[processingElement].memoryTable);

    if (ftpData.clients[processingElement].login.userLoggedIn == 0 &&
        (compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "USER", strlen("USER")) != 1 &&
         compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "PASS", strlen("PASS")) != 1 &&
         compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "QUIT", strlen("QUIT")) != 1 &&
		 compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "PBSZ", strlen("PBSZ")) != 1 &&
		 compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "PROT", strlen("PROT")) != 1 &&
		 compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "CCC", strlen("CCC")) != 1 &&
         compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "AUTH", strlen("AUTH")) != 1))
        {
            toReturn = notLoggedInMessage(&ftpData, processingElement);
            ftpData.clients[processingElement].commandIndex = 0;
            memset(ftpData.clients[processingElement].theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE+1);
            return 1;
        }

    //Process Command
    if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "USER", strlen("USER")) == 1)
    {
        //my_printf("\nUSER COMMAND RECEIVED");
        toReturn = parseCommandUser(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "PASS", strlen("PASS")) == 1)
    {
        //my_printf("\nPASS COMMAND RECEIVED");
        toReturn = parseCommandPass(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "SITE", strlen("SITE")) == 1)
    {
        //my_printf("\nSITE COMMAND RECEIVED");
        toReturn = parseCommandSite(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "AUTH", strlen("AUTH")) == 1)
    {
        //my_printf("\nAUTH COMMAND RECEIVED");
        toReturn = parseCommandAuth(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "PROT", strlen("PROT")) == 1)
    {
        //my_printf("\nPROT COMMAND RECEIVED");
        toReturn = parseCommandProt(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "PBSZ", strlen("PBSZ")) == 1)
    {
        //my_printf("\nPBSZ COMMAND RECEIVED");
        toReturn = parseCommandPbsz(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "CCC", strlen("CCC")) == 1)
    {
        //my_printf("\nCCC COMMAND RECEIVED");
        toReturn = parseCommandCcc(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "PWD", strlen("PWD")) == 1 ||
            compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "XPWD", strlen("XPWD")) == 1)
    {
        // XPWD
        //my_printf("\nPWD COMMAND RECEIVED");
        toReturn = parseCommandPwd(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "SYST", strlen("SYST")) == 1)
    {
        //my_printf("\nSYST COMMAND RECEIVED");
        toReturn = parseCommandSyst(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "FEAT", strlen("FEAT")) == 1)
    {
        //my_printf("\nFEAT COMMAND RECEIVED");
        toReturn = parseCommandFeat(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "TYPE I", strlen("TYPE I")) == 1)
    {
        //my_printf("\nTYPE I COMMAND RECEIVED");
        toReturn = parseCommandTypeI(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "STRU F", strlen("STRU F")) == 1)
    {
        //my_printf("\nTYPE I COMMAND RECEIVED");
        toReturn = parseCommandStruF(&ftpData, processingElement);
    }    
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "MODE S", strlen("MODE S")) == 1)
    {
        //my_printf("\nMODE S COMMAND RECEIVED");
        toReturn = parseCommandModeS(&ftpData, processingElement);
    }    
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "TYPE A", strlen("TYPE A")) == 1)
    {
        //my_printf("\nTYPE A COMMAND RECEIVED");
        toReturn = parseCommandTypeI(&ftpData, processingElement);
    }    
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "EPSV", strlen("EPSV")) == 1)
    {
        my_printf("\nEPSV COMMAND RECEIVED");
        toReturn = parseCommandEpsv(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "PASV", strlen("PASV")) == 1)
    {
        my_printf("\nPASV COMMAND RECEIVED");
        toReturn = parseCommandPasv(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "PORT", strlen("PORT")) == 1)
    {
        my_printf("\nPORT COMMAND RECEIVED");
        toReturn = parseCommandPort(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "EPRT", strlen("EPRT")) == 1)
    {
        my_printf("\nEPRT COMMAND RECEIVED");
        toReturn = parseCommandEprt(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "LIST", strlen("LIST")) == 1)
    {
        //my_printf("\nLIST COMMAND RECEIVED");
        toReturn = parseCommandList(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "STAT", strlen("STAT")) == 1)
    {
        my_printf("\nSTAT COMMAND RECEIVED");
        toReturn = parseCommandStat(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "CDUP", strlen("CDUP")) == 1 ||
            compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "XCUP", strlen("XCUP")) == 1 ||
            compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "CWD ..", strlen("CWD ..")) == 1)
    {
        //my_printf("\nCDUP COMMAND RECEIVED");
        toReturn = parseCommandCdup(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "CWD", strlen("CWD")) == 1)
    {
        //my_printf("\nCWD COMMAND RECEIVED");
        toReturn = parseCommandCwd(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "REST", strlen("REST")) == 1)
    {
        //my_printf("\nREST COMMAND RECEIVED");
        toReturn = parseCommandRest(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "RETR", strlen("RETR")) == 1)
    {
        //my_printf("\nRETR COMMAND RECEIVED");
        toReturn = parseCommandRetr(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "STOR", strlen("STOR")) == 1)
    {
        //my_printf("\nSTOR COMMAND RECEIVED");
        toReturn = parseCommandStor(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "MKD", strlen("MKD")) == 1 ||
            compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "XMKD", strlen("XMKD")) == 1)
    {
        //my_printf("\nMKD command received");
        toReturn = parseCommandMkd(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "ABOR", strlen("ABOR")) == 1)
    {
        //my_printf("\nABOR command received");
        toReturn = parseCommandAbor(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "DELE", strlen("DELE")) == 1)
    {
        //my_printf("\nDELE comman200 OKd received");
        toReturn = parseCommandDele(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "OPTS", strlen("OPTS")) == 1)
    {
        //my_printf("\nOPTS command received");
        toReturn = parseCommandOpts(&ftpData, processingElement);
    }    
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "MDTM", strlen("MDTM")) == 1)
    {
        my_printf("\nMTDM command received");
    	toReturn = parseCommandMdtm(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "NLST", strlen("NLST")) == 1)
    {
       // my_printf("\nNLST command received");
        toReturn = parseCommandNlst(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "QUIT", strlen("QUIT")) == 1)
    {
        //my_printf("\nQUIT command received");
        toReturn = parseCommandQuit(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "RMD", strlen("RMD")) == 1 ||
            compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "XRMD", strlen("XRMD")) == 1)
    {
        // XRMD
       // my_printf("\nRMD command received");
        toReturn = parseCommandRmd(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "RNFR", strlen("RNFR")) == 1)
    {
       // my_printf("\nRNFR command received");
        toReturn = parseCommandRnfr(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "RNTO", strlen("RNTO")) == 1)
    {
       // my_printf("\nRNTO command received");
        toReturn = parseCommandRnto(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "SIZE", strlen("SIZE")) == 1)
    {
        //my_printf("\nSIZE command received");
        toReturn = parseCommandSize(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "APPE", strlen("APPE")) == 1)
    {
       // my_printf("\nAPPE command received");
    	toReturn = parseCommandAppe(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "NOOP", strlen("NOOP")) == 1)
    {
        //my_printf("\nNOOP command received");
        toReturn = parseCommandNoop(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "ACCT", strlen("ACCT")) == 1)
    {
        //my_printf("\nNOOP command received");
        toReturn = parseCommandAcct(&ftpData, processingElement);
    }
    else
    {
        ; //Parse unsupported command not needed
    }

    ftpData.clients[processingElement].commandIndex = 0;
    memset(ftpData.clients[processingElement].theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE+1);
    return toReturn;
}

void deallocateMemory(void)
{
	int i = 0;
//  my_printf("\n Deallocating the memory.. ");
//	my_printf("\nDYNMEM_freeAll called");
//	my_printf("\nElement size: %ld", ftpData.generalDynamicMemoryTable->size);
//	my_printf("\nElement address: %ld", (long int) ftpData.generalDynamicMemoryTable->address);
//	my_printf("\nElement nextElement: %ld",(long int) ftpData.generalDynamicMemoryTable->nextElement);
//	my_printf("\nElement previousElement: %ld",(long int) ftpData.generalDynamicMemoryTable->previousElement);

    for (i = 0; i < ftpData.ftpParameters.maxClients; i++)
    {
        DYNMEM_freeAll(&ftpData.clients[i].memoryTable);
        DYNMEM_freeAll(&ftpData.clients[i].workerData.memoryTable);
    }

    DYNMEM_freeAll(&ftpData.loginFailsVector.memoryTable);
    DYNMEM_freeAll(&ftpData.ftpParameters.usersVector.memoryTable);
    DYNMEM_freeAll(&ftpData.generalDynamicMemoryTable);

    //my_printf("\n\nUsed memory at end: %lld", DYNMEM_GetTotalMemory());

    //my_printf("\n ftpData.generalDynamicMemoryTable = %ld", ftpData.generalDynamicMemoryTable);
    #ifdef OPENSSL_ENABLED
    SSL_CTX_free(ftpData.serverCtx);
    cleanupOpenssl();
    #endif
}
