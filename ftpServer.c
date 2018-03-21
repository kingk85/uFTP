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
#include "ftpServer.h"
#include "ftpData.h"
#include "ftpCommandsElaborate.h"

#include "library/fileManagement.h"
#include "library/logFunctions.h"
#include "library/configRead.h"
#include "library/signals.h"
#include "library/connection.h"

ftpDataType ftpData;

static int processCommand(int processingElement);

void workerCleanup(void *socketId)
{
    int theSocketId = *(int *)socketId;
    printTimeStamp();
    printf("\nCleanup called for thread id: %d", theSocketId);
    printf("\nClosing pasv socket (%d) ok!", theSocketId);
    shutdown(ftpData.clients[theSocketId].workerData.socketConnection, SHUT_RDWR);
    shutdown(ftpData.clients[theSocketId].workerData.passiveListeningSocket, SHUT_RDWR);
    close(ftpData.clients[theSocketId].workerData.socketConnection);
    close(ftpData.clients[theSocketId].workerData.passiveListeningSocket);  
    resetWorkerData(&ftpData.clients[theSocketId].workerData, 0); 
}

void *connectionWorkerHandle(void * socketId)
{
  int returnCode;
  int theSocketId = *(int *)socketId;
  pthread_cleanup_push(workerCleanup,  (void *) &theSocketId);
  ftpData.clients[theSocketId].workerData.threadIsAlive = 1;
  
  if (ftpData.clients[theSocketId].workerData.passiveModeOn == 1)
  {
    printf("\nPasv (%d) thread init opening port: %d", theSocketId, ftpData.clients[theSocketId].workerData.connectionPort);
    printf("\nPasv (%d) open ok: %d", theSocketId, ftpData.clients[theSocketId].workerData.connectionPort);
    setRandomicPort(&ftpData, theSocketId);
    ftpData.clients[theSocketId].workerData.passiveListeningSocket = createPassiveSocket(ftpData.clients[theSocketId].workerData.connectionPort);
    
    	if (ftpData.clients[theSocketId].workerData.socketIsConnected == 0)
	{
            //printTimeStamp();
            printf("Waiting for pasv client connection on port: %d", ftpData.clients[theSocketId].workerData.connectionPort);

            char theResponse[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
            memset(theResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
            sprintf(theResponse, "227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)\r\n", ftpData.clients[theSocketId].serverIpAddressInteger[0], ftpData.clients[theSocketId].serverIpAddressInteger[1], ftpData.clients[theSocketId].serverIpAddressInteger[2], ftpData.clients[theSocketId].serverIpAddressInteger[3], (ftpData.clients[theSocketId].workerData.connectionPort / 256), (ftpData.clients[theSocketId].workerData.connectionPort % 256));
            returnCode = write(ftpData.clients[theSocketId].socketDescriptor, theResponse, strlen(theResponse));            

            //Wait for sockets
            if ((ftpData.clients[theSocketId].workerData.socketConnection = accept(ftpData.clients[theSocketId].workerData.passiveListeningSocket, 0, 0))!=-1)
            {
                printTimeStamp();
                printf("\nPasv (%d) connection initialized", theSocketId);
                //int error;
                ftpData.clients[theSocketId].workerData.socketIsConnected = 1;
                printf("\nPasv (%d) connection ok", theSocketId);
                //error = fcntl(ftpData.clients[theSocketId].pasvData.passiveSocketConnection, F_SETFL, O_NONBLOCK);
            }
	}
  }
  else if (ftpData.clients[theSocketId].workerData.activeModeOn == 1)
  {
    char *activeResponse = "200 connection accepted\r\n";
    printf("\nConnecting on the active client %s:%d", ftpData.clients[theSocketId].workerData.activeIpAddress, ftpData.clients[theSocketId].workerData.connectionPort);
    ftpData.clients[theSocketId].workerData.socketConnection = createActiveSocket(ftpData.clients[theSocketId].workerData.connectionPort, ftpData.clients[theSocketId].workerData.activeIpAddress);
    returnCode = write(ftpData.clients[theSocketId].socketDescriptor, activeResponse, strlen(activeResponse));
    if (ftpData.clients[theSocketId].workerData.socketConnection != -1)
    {
        ftpData.clients[theSocketId].workerData.socketIsConnected = 1;
    }
  }
  
  //Endless loop ftp process
    while (1)
    {
        usleep(1000);

	if (ftpData.clients[theSocketId].workerData.socketIsConnected > 0)
	{
        //Conditional lock on thread actions
        pthread_mutex_lock(&ftpData.clients[theSocketId].workerData.conditionMutex);
        printTimeStamp();
        printf("\nPasv (%d) waiting for commands..", theSocketId);
        while (ftpData.clients[theSocketId].workerData.commandReceived == 0) {
            printf("\nPasv (%d) waiting for conditional variable..", theSocketId);
            pthread_cond_wait(&ftpData.clients[theSocketId].workerData.conditionVariable, &ftpData.clients[theSocketId].workerData.conditionMutex);
        }
        printf("\nPasv (%d) waiting ok, unlock mutex", theSocketId);
        pthread_mutex_unlock(&ftpData.clients[theSocketId].workerData.conditionMutex);
        printf("\nPasv (%d) processing commands..", theSocketId);
        
          if (ftpData.clients[theSocketId].workerData.commandReceived == 1 &&
              ((strncmp(ftpData.clients[theSocketId].workerData.theCommandReceived, "STOR", strlen("STOR")) == 0) || 
               (strncmp(ftpData.clients[theSocketId].workerData.theCommandReceived, "stor", strlen("stor")) == 0)) &&
               ftpData.clients[theSocketId].fileToStor.textLen > 0)
          {
            //Set the busy flag
            ftpData.clients[theSocketId].workerData.threadIsBusy = 1;
            FILE *theStorFile;
            char theResponse[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
            memset(theResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
            
            theStorFile = fopen(ftpData.clients[theSocketId].fileToStor.text, "wb");
            if (theStorFile == NULL)
            {
            perror("Can't open the file");    
            strcpy(theResponse, "550 Unable to write the file\r\n");
            returnCode = write(ftpData.clients[theSocketId].socketDescriptor, theResponse, strlen(theResponse));
            break;
            }
            
            printf("\nftpData.clients[theSocketId].theFileNameToStor: %s", ftpData.clients[theSocketId].fileToStor.text);
            printf("\nftpData.clients[theSocketId].login.absolutePath.text: %s", ftpData.clients[theSocketId].login.absolutePath.text);
            
            strcpy(theResponse, "150 Accepted data connection\r\n");
            returnCode = write(ftpData.clients[theSocketId].socketDescriptor, theResponse, strlen(theResponse));

            while(1)
            {
                if ((ftpData.clients[theSocketId].workerData.bufferIndex = read(ftpData.clients[theSocketId].workerData.socketConnection, ftpData.clients[theSocketId].workerData.buffer, CLIENT_BUFFER_STRING_SIZE)) == 0)
                {
                    //Client is disconnected!
                    break;
                }             
                
                if (ftpData.clients[theSocketId].workerData.bufferIndex > 0)
                {
                  fwrite(ftpData.clients[theSocketId].workerData.buffer, ftpData.clients[theSocketId].workerData.bufferIndex, 1, theStorFile);
                  usleep(100);
                }
            }
            fclose(theStorFile);

            memset(theResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
            sprintf(theResponse, "226 file stor ok\r\n");
            returnCode = write(ftpData.clients[theSocketId].socketDescriptor, theResponse, strlen(theResponse));
            break;
          }
        else if (ftpData.clients[theSocketId].workerData.commandReceived == 1 &&
               ((strncmp(ftpData.clients[theSocketId].workerData.theCommandReceived, "LIST", strlen("LIST")) == 0) ||
                (strncmp(ftpData.clients[theSocketId].workerData.theCommandReceived, "list", strlen("list")) == 0))
                )
          {
            DYNV_VectorGenericDataType directoryInfo;
            DYNV_VectorGeneric_Init(&directoryInfo);
            int i;

            getListDataInfo(ftpData.clients[theSocketId].listPath.text, &directoryInfo);
            printf("\nPasv (%d) ftpData.clients[theSocketId].listPath.text = %s", theSocketId, ftpData.clients[theSocketId].listPath.text);
            
            char theResponse[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
            memset(theResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
            strcpy(theResponse, "150 Accepted data connection\r\n");
            returnCode = write(ftpData.clients[theSocketId].socketDescriptor, theResponse, strlen(theResponse));
            
            char theBufferWrite[4096];
            memset(theBufferWrite, 0, 4096);
            sprintf(theBufferWrite, "total %d\r\n", directoryInfo.Size);
            returnCode = write(ftpData.clients[theSocketId].workerData.socketConnection, theBufferWrite, strlen(theBufferWrite));
            //printf("%s", theBufferWrite);
            for (i = 0; i < directoryInfo.Size; i++)
            {
                memset(theBufferWrite, 0, 1024);
                sprintf(theBufferWrite, "%s %d %s %s %d %s %s\r\n", 
                 ((((ftpListDataType *) directoryInfo.Data[i])->inodePermissionString) == NULL? "Uknown" : (((ftpListDataType *) directoryInfo.Data[i])->inodePermissionString))
                ,((ftpListDataType *) directoryInfo.Data[i])->numberOfSubDirectories
                ,((((ftpListDataType *) directoryInfo.Data[i])->owner) == NULL? "Uknown" : (((ftpListDataType *) directoryInfo.Data[i])->owner))
                ,((((ftpListDataType *) directoryInfo.Data[i])->groupOwner) == NULL? "Uknown" : (((ftpListDataType *) directoryInfo.Data[i])->groupOwner))
                ,((ftpListDataType *) directoryInfo.Data[i])->fileSize
                ,((((ftpListDataType *) directoryInfo.Data[i])->lastModifiedDataString) == NULL? "Uknown" : (((ftpListDataType *) directoryInfo.Data[i])->lastModifiedDataString))
                ,((((ftpListDataType *) directoryInfo.Data[i])->finalStringPath) == NULL? "Uknown" : (((ftpListDataType *) directoryInfo.Data[i])->finalStringPath)));
                printf("\n%s", theBufferWrite);
                returnCode = write(ftpData.clients[theSocketId].workerData.socketConnection, theBufferWrite, strlen(theBufferWrite));
            }
            
            memset(theResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
            sprintf(theResponse, "226 %d matches total\r\n", directoryInfo.Size);
            returnCode = write(ftpData.clients[theSocketId].socketDescriptor, theResponse, strlen(theResponse));

            int theSize = directoryInfo.Size;
            char ** lastToDestroy = NULL;
            if (theSize > 0)
            {
                lastToDestroy = ((ftpListDataType *)directoryInfo.Data[0])->fileList;
            }

            directoryInfo.Destroy(&directoryInfo, deleteListDataInfoVector);

            if (theSize > 0)
            {
                 free(lastToDestroy);
            }
            printf("\nPasv (%d) List end", theSocketId);
            break;
          }
        else if (ftpData.clients[theSocketId].workerData.commandReceived == 1 &&
               ((strncmp(ftpData.clients[theSocketId].workerData.theCommandReceived, "NLST", strlen("NLST")) == 0) ||
                (strncmp(ftpData.clients[theSocketId].workerData.theCommandReceived, "nlst", strlen("nlst")) == 0))
                )
          {
            DYNV_VectorGenericDataType directoryInfo;
            DYNV_VectorGeneric_Init(&directoryInfo);
            int i;
            getListDataInfo(ftpData.clients[theSocketId].nlistPath.text, &directoryInfo);

            printf("\nPasv (%d) ftpData.clients[theSocketId].login.absolutePath.text = %s",theSocketId, ftpData.clients[theSocketId].login.absolutePath.text);
            
            char theResponse[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
            memset(theResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
            strcpy(theResponse, "150 Accepted data connection\r\n");
            returnCode = write(ftpData.clients[theSocketId].socketDescriptor, theResponse, strlen(theResponse));
            
            char theBufferWrite[1024];
            memset(theBufferWrite, 0, 1024);
            sprintf(theBufferWrite, "total %d\r\n", directoryInfo.Size);
            returnCode = write(ftpData.clients[theSocketId].workerData.socketConnection, theBufferWrite, strlen(theBufferWrite));
            //printf("%s", theBufferWrite);
            for (i = 0; i < directoryInfo.Size; i++)
            {
                memset(theBufferWrite, 0, 1024);
                sprintf(theBufferWrite, "%s\r\n"
                ,((ftpListDataType *) directoryInfo.Data[i])->fileNameNoPath);
                //printf("%s", theBufferWrite);
                 returnCode = write(ftpData.clients[theSocketId].workerData.socketConnection, theBufferWrite, strlen(theBufferWrite));
            }

            memset(theResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
            
            sprintf(theResponse, "226 %d matches total\r\n", directoryInfo.Size);
            returnCode = write(ftpData.clients[theSocketId].socketDescriptor, theResponse, strlen(theResponse));
            
            int theSize = directoryInfo.Size;
            char ** lastToDestroy = NULL;
            if (theSize > 0)
            {
                lastToDestroy = ((ftpListDataType *)directoryInfo.Data[0])->fileList;
            }

            directoryInfo.Destroy(&directoryInfo, deleteListDataInfoVector);

            if (theSize > 0)
            {
                 free(lastToDestroy);
            }
            printf("\nPasv (%d) List end", theSocketId);
            break;
          }
          else if (ftpData.clients[theSocketId].workerData.commandReceived == 1 &&
              ((strncmp(ftpData.clients[theSocketId].workerData.theCommandReceived, "RETR", strlen("RETR")) == 0) ||
               (strncmp(ftpData.clients[theSocketId].workerData.theCommandReceived, "retr", strlen("retr")) == 0)))
          {
              ftpData.clients[theSocketId].workerData.threadIsBusy = 1;
              int writenSize = 0;
              char theResponse[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
              printTimeStamp();
              printf("The (%d) pasvData Command: %s",theSocketId, ftpData.clients[theSocketId].workerData.theCommandReceived);
              int writeReturn = 0;
              memset(theResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
              strcpy(theResponse, "150 Accepted data connection\r\n");
              writeReturn = write(ftpData.clients[theSocketId].socketDescriptor, theResponse, strlen(theResponse));              
              printf("\nPasv (%d) writeReturn: %d",theSocketId, writeReturn);
              
              writenSize = writeRetrFile(ftpData.clients[theSocketId].fileToRetr.text, ftpData.clients[theSocketId].workerData.socketConnection, ftpData.clients[theSocketId].workerData.retrRestartAtByte);

              ftpData.clients[theSocketId].workerData.retrRestartAtByte = 0;
              printf("\nPasv (%d) writeReturn data: %d",theSocketId, writeReturn);
              
              if (writenSize == -1)
              {
                memset(theResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
                sprintf(theResponse, "550 unable to open the file for reading\r\n");
                writeReturn =  write(ftpData.clients[theSocketId].socketDescriptor, theResponse, strlen(theResponse));
                break;
              }
              
              memset(theResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
              sprintf(theResponse, "226-File successfully transferred\r\n226 done\r\n");
              writeReturn =  write(ftpData.clients[theSocketId].socketDescriptor, theResponse, strlen(theResponse));
              printf("\nPasv (%d) writeReturn response to 21: %d",theSocketId, writeReturn);
              break;
          }
        break;
      }
        break;
    }

  pthread_exit((void *)1);
  pthread_cleanup_pop(0);
  pthread_exit((void *)2);

  return NULL;
}

void runFtpServer(void)
{
    /* Needed for Select*/
    static int processingSock = 0, returnCode = 0;

    /* Handle signals */
    signalHandlerInstall();

    /*Read the configuration file */
    configurationRead(&ftpData.ftpParameters);

    /* apply the reden configuration */
    applyConfiguration(&ftpData.ftpParameters);

    /* initialize the ftp data structure */
    initFtpData(&ftpData);

    //Socket main creator
    ftpData.connectionData.theMainSocket = createSocket(&ftpData);
    printf("\nuFTP server starting..");

    /* init fd set needed for select */
    fdInit(&ftpData);

    /* the maximum socket fd is now the main socket descriptor */
    ftpData.connectionData.maxSocketFD = ftpData.connectionData.theMainSocket+1;

  //Endless loop ftp process
    while (1)
    {
        /* waits for socket activity, if no activity then checks for client socket timeouts */
        if (selectWait(&ftpData) == 0)
        {
            checkClientConnectionTimeout(&ftpData);
        }

        /*Main loop handle client commands */
        for (processingSock = 0; processingSock < ftpData.ftpParameters.maxClients; processingSock++)
        {
            /* close the connection if quit flag has been set */
            if (ftpData.clients[processingSock].closeTheClient == 1)
            {
                printf("\nClosing client connection %d", ftpData.clients[processingSock].closeTheClient);
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
            //The client is not connected anymore
            if ((ftpData.clients[processingSock].bufferIndex = read(ftpData.clients[processingSock].socketDescriptor, ftpData.clients[processingSock].buffer, CLIENT_BUFFER_STRING_SIZE)) == 0)
            {
              fdRemove(&ftpData, processingSock);
              closeSocket(&ftpData, processingSock);
              ftpData.connectionData.maxSocketFD = getMaximumSocketFd(ftpData.connectionData.theMainSocket, &ftpData);
              printf("\nA client has been disconnected!\n");
            }

            //Debug print errors
            if (ftpData.clients[processingSock].bufferIndex < 0)
            {
                ftpData.clients[processingSock].closeTheClient = 1;
                printf("\n1 Errno = %d", errno);
                perror("1 Error: ");
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
                              commandProcessStatus = processCommand(processingSock);
                              //Echo unrecognized commands
                              if (commandProcessStatus == FTP_COMMAND_NOT_RECONIZED) 
                              {
                                  char * theNotSupportedString = "500 Unknown command\r\n";
                                  write(ftpData.clients[processingSock].socketDescriptor, theNotSupportedString, strlen(theNotSupportedString));
                                  printf("\n COMMAND NOT SUPPORTED ********* %s", ftpData.clients[processingSock].buffer);
                              }
                              else if (commandProcessStatus == FTP_COMMAND_PROCESSED)
                              {
                                  ftpData.clients[processingSock].lastActivityTimeStamp = (int)time(NULL);
                              }
                              else if (commandProcessStatus == FTP_COMMAND_PROCESSED_WRITE_ERROR)
                              {
                                  ftpData.clients[processingSock].closeTheClient = 1;
                              }
                          }
                  }
                  else
                  {
                      //Command overflow can't be processed
                      int returnCode;
                      char * theNotSupportedString = "500 Unknown command\r\n";
                      ftpData.clients[processingSock].commandIndex = 0;
                      memset(ftpData.clients[processingSock].theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);
                      //Write some error message to the client
                      returnCode = write(ftpData.clients[processingSock].socketDescriptor, theNotSupportedString, strlen(theNotSupportedString));
                      if (returnCode <= 0) ftpData.clients[processingSock].closeTheClient = 1;
                      break;
                  }
              }
              usleep(100);
              memset(ftpData.clients[processingSock].buffer, 0, CLIENT_BUFFER_STRING_SIZE);
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
    printTimeStamp();
    printf ("Command received from (%d): %s", processingElement, ftpData.clients[processingElement].theCommandReceived);
   
    cleanDynamicStringDataType(&ftpData.clients[processingElement].ftpCommand.commandArgs, 0);
    cleanDynamicStringDataType(&ftpData.clients[processingElement].ftpCommand.commandOps, 0);

    if (ftpData.clients[processingElement].login.userLoggedIn == 0 &&
        (compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "USER", strlen("USER")) != 1 &&
         compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "PASS", strlen("PASS")) != 1 &&
         compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "QUIT", strlen("QUIT")) != 1 &&
         compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "AUTH", strlen("AUTH")) != 1))
        {
            toReturn = notLoggedInMessage(&ftpData.clients[processingElement]);
            ftpData.clients[processingElement].commandIndex = 0;
            memset(ftpData.clients[processingElement].theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);
            return 1;
        }

    //Process Command
    if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "USER", strlen("USER")) == 1)
    {
        printf("\nUSER COMMAND RECEIVED");
        toReturn = parseCommandUser(&ftpData.clients[processingElement]);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "PASS", strlen("PASS")) == 1)
    {
        printf("\nPASS COMMAND RECEIVED");
        toReturn = parseCommandPass(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "SITE", strlen("SITE")) == 1)
    {
        printf("\nSITE COMMAND RECEIVED");
        toReturn = parseCommandSite(&ftpData.clients[processingElement]);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "AUTH", strlen("AUTH")) == 1)
    {
        printf("\nAUTH COMMAND RECEIVED");
        toReturn = parseCommandAuth(&ftpData.clients[processingElement]);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "PWD", strlen("PWD")) == 1)
    {
        printf("\nPWD COMMAND RECEIVED");
        toReturn = parseCommandPwd(&ftpData.clients[processingElement]);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "SYST", strlen("SYST")) == 1)
    {
        printf("\nSYST COMMAND RECEIVED");
        toReturn = parseCommandSyst(&ftpData.clients[processingElement]);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "FEAT", strlen("FEAT")) == 1)
    {
        printf("\nFEAT COMMAND RECEIVED");
        toReturn = parseCommandFeat(&ftpData.clients[processingElement]);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "TYPE I", strlen("TYPE I")) == 1)
    {
        printf("\nTYPE I COMMAND RECEIVED");
        toReturn = parseCommandTypeI(&ftpData.clients[processingElement]);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "STRU F", strlen("STRU F")) == 1)
    {
        printf("\nTYPE I COMMAND RECEIVED");
        toReturn = parseCommandStruF(&ftpData.clients[processingElement]);
    }    
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "MODE S", strlen("MODE S")) == 1)
    {
        printf("\nMODE S COMMAND RECEIVED");
        toReturn = parseCommandModeS(&ftpData.clients[processingElement]);
    }    
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "TYPE A", strlen("TYPE A")) == 1)
    {
        printf("\nTYPE A COMMAND RECEIVED");
        toReturn = parseCommandTypeI(&ftpData.clients[processingElement]);
    }    
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "PASV", strlen("PASV")) == 1)
    {
        printf("\nPASV COMMAND RECEIVED");
        toReturn = parseCommandPasv(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "PORT", strlen("PORT")) == 1)
    {
        printf("\nPORT COMMAND RECEIVED");
        toReturn = parseCommandPort(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "LIST", strlen("LIST")) == 1)
    {
        printf("\nLIST COMMAND RECEIVED");
        toReturn = parseCommandList(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "CWD", strlen("CWD")) == 1)
    {
        printf("\nCWD COMMAND RECEIVED");
        toReturn = parseCommandCwd(&ftpData.clients[processingElement]);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "CDUP", strlen("CDUP")) == 1)
    {
        printf("\nCDUP COMMAND RECEIVED");
        toReturn = parseCommandCdup(&ftpData.clients[processingElement]);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "REST", strlen("REST")) == 1)
    {
        printf("\nREST COMMAND RECEIVED");
        toReturn = parseCommandRest(&ftpData.clients[processingElement]);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "RETR", strlen("RETR")) == 1)
    {
        printf("\nRETR COMMAND RECEIVED");
        toReturn = parseCommandRetr(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "STOR", strlen("STOR")) == 1)
    {
        printf("\nSTOR COMMAND RECEIVED");
        toReturn = parseCommandStor(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "MKD", strlen("MKD")) == 1)
    {
        printf("\nMKD command received");
        toReturn = parseCommandMkd(&ftpData.clients[processingElement]);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "ABOR", strlen("ABOR")) == 1)
    {
        printf("\nABOR command received");
        toReturn = parseCommandAbor(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "DELE", strlen("DELE")) == 1)
    {
        printf("\nDELE command received");
        toReturn = parseCommandDele(&ftpData.clients[processingElement]);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "OPTS", strlen("OPTS")) == 1)
    {
        printf("\nOPTS command received");
        toReturn = parseCommandOpts(&ftpData.clients[processingElement]);
    }    
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "MTDM", strlen("MTDM")) == 1)
    {
        printf("\nMTDM command received");
        //To implement
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "NLST", strlen("NLST")) == 1)
    {
        printf("\nNLST command received");
        toReturn = parseCommandNlst(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "PORT", strlen("PORT")) == 1)
    {
        printf("\nPORT command received");
        //To implement
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "QUIT", strlen("QUIT")) == 1)
    {
        printf("\nQUIT command received");
        toReturn = parseCommandQuit(&ftpData, processingElement);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "RMD", strlen("RMD")) == 1)
    {
        printf("\nRMD command received");
        toReturn = parseCommandRmd(&ftpData.clients[processingElement]);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "RNFR", strlen("RNFR")) == 1)
    {
        printf("\nRNFR command received");
        toReturn = parseCommandRnfr(&ftpData.clients[processingElement]);

    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "RNTO", strlen("RNTO")) == 1)
    {
        printf("\nRNTO command received");
        toReturn = parseCommandRnto(&ftpData.clients[processingElement]);
    }    
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "SIZE", strlen("SIZE")) == 1)
    {
        printf("\nSIZE command received");
        toReturn = parseCommandSize(&ftpData.clients[processingElement]);
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "APPE", strlen("APPE")) == 1)
    {
        printf("\nAPPE command received");
        //To implement
    }
    else if(compareStringCaseInsensitive(ftpData.clients[processingElement].theCommandReceived, "NOOP", strlen("NOOP")) == 1)
    {
        printf("\nNOOP command received");
        toReturn = parseCommandNoop(&ftpData.clients[processingElement]);
    }
    else
    {
        ; //Parse unsupported command not needed
    }

    ftpData.clients[processingElement].commandIndex = 0;
    memset(ftpData.clients[processingElement].theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);
    return toReturn;
}
