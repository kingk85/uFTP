/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>     
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>


/* FTP LIBS */
#include "ftpServer.h"
#include "ftpData.h"
#include "ftpCommandsElaborate.h"
#include "fileManagement.h"
#include "logFunctions.h"



/* Catch Signal Handler functio */
void signal_callback_handler(int signum){

        printf("Caught signal SIGPIPE %d\n",signum);
}

#define SERVER_PORT     21

static ftpDataType ftpData;

static int createSocket(int port);
static void closeSocket(int processingSocket);
static void initFtpData(void);
static int processCommand(int processingElement);
static int getMaximumSocketFd(int mainSocket, ftpDataType * data);


void pasvThreadHandlerCleanup(void *socketId)
{
    int theSocketId = *(int *)socketId;
    printTimeStamp();
    printf("\nCleanup called for thread id: %d", theSocketId);
    printf("\nClosing pasv socket (%d) ok!", theSocketId);
    shutdown(ftpData.clients[theSocketId].pasvData.passiveSocketConnection, SHUT_RDWR);
    shutdown(ftpData.clients[theSocketId].pasvData.passiveSocket, SHUT_RDWR);
    close(ftpData.clients[theSocketId].pasvData.passiveSocketConnection);
    close(ftpData.clients[theSocketId].pasvData.passiveSocket);  
    resetPasvData(&ftpData.clients[theSocketId].pasvData, 0); 
}

void *pasvThreadHandler(void * socketId)
{
  int theSocketId = *(int *)socketId;
  pthread_cleanup_push(pasvThreadHandlerCleanup,  (void *) &theSocketId);

  //Setting Alive Flag
  ftpData.clients[theSocketId].pasvData.threadIsAlive = 1;
  
  printf("\nPasv (%d) thread init opening port: %d", theSocketId, ftpData.clients[theSocketId].pasvData.passivePort);
  
  ftpData.clients[theSocketId].pasvData.passiveSocket = createPassiveSocket(ftpData.clients[theSocketId].pasvData.passivePort);
    
  //Endless loop ftp process
    while (1)
    {
        usleep(1000);

	if (ftpData.clients[theSocketId].pasvData.passiveSocketIsConnected == 0)
	{
            //printTimeStamp();
            //printf("Waiting for pasv client connection on port: %d", ftpData.clients[theSocketId].pasvData.passivePort);

            //Wait for sockets
            if ((ftpData.clients[theSocketId].pasvData.passiveSocketConnection = accept(ftpData.clients[theSocketId].pasvData.passiveSocket, 0, 0))!=-1)
            {
                printTimeStamp();
                printf("\nPasv (%d) connection initialized", theSocketId);
                int error;
                ftpData.clients[theSocketId].pasvData.passiveSocketIsConnected = 1;
                //error = fcntl(ftpData.clients[theSocketId].pasvData.passiveSocketConnection, F_SETFL, O_NONBLOCK);
            }
	}
	else
	{
        
        
        //Conditional lock on thread actions
        pthread_mutex_lock(&ftpData.clients[theSocketId].pasvData.conditionMutex);
        printTimeStamp();
        printf("\nPasv (%d) waiting for commands..", theSocketId);
        while (ftpData.clients[theSocketId].pasvData.commandReceived == 0) {
            printf("\nPasv (%d) waiting for conditional variable..", theSocketId);
            pthread_cond_wait(&ftpData.clients[theSocketId].pasvData.conditionVariable, &ftpData.clients[theSocketId].pasvData.conditionMutex);
            
        }
        printf("\nPasv (%d) waiting ok, unlock mutex", theSocketId);
        pthread_mutex_unlock(&ftpData.clients[theSocketId].pasvData.conditionMutex);
        printf("\nPasv (%d) processing commands..", theSocketId);
        
           //the connection is closed
        //  if ((ftpData.clients[theSocketId].pasvData.bufferIndex = read(ftpData.clients[theSocketId].pasvData.passiveSocketConnection, ftpData.clients[theSocketId].pasvData.buffer, CLIENT_BUFFER_STRING_SIZE)) == 0)
        //  {
        ///   break;
         // }
          
        //Some data is received
          //if (ftpData.clients[theSocketId].pasvData.bufferIndex > 0)
         // {
           // int i = 0;
          //  for (i = 0; i < ftpData.clients[theSocketId].pasvData.bufferIndex; i++)
          //  {
         //           ;
         //   }

       //     usleep(100);            
            //write(ftpData.clients[theSocketId].pasvData.passiveSocketConnection, ftpData.clients[theSocketId].pasvData.buffer, ftpData.clients[theSocketId].pasvData.bufferIndex);
        //  }

          if (ftpData.clients[theSocketId].pasvData.commandReceived == 1 &&
              ((strncmp(ftpData.clients[theSocketId].pasvData.theCommandReceived, "STOR", strlen("STOR")) == 0) || 
               (strncmp(ftpData.clients[theSocketId].pasvData.theCommandReceived, "stor", strlen("stor")) == 0)) &&
              ftpData.clients[theSocketId].pasvData.theFileNameToStorIndex > 0)
          {
            char theResponse[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
            memset(theResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);

            char theAbsoluteFileNamePath[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
            memset(theAbsoluteFileNamePath, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);

            //strcpy(theAbsoluteFileNamePath, ftpData.clients[theSocketId].login.absolutePath);
            
            if (theAbsoluteFileNamePath[strlen(theAbsoluteFileNamePath)-1] != '/')
                strcat(theAbsoluteFileNamePath, "/");
            
            strcat(theAbsoluteFileNamePath, ftpData.clients[theSocketId].pasvData.theFileNameToStor);

            strcpy(theResponse, "150 Accepted data connection\r\n");
            write(ftpData.clients[theSocketId].socketDescriptor, theResponse, strlen(theResponse));


            while(1)
            {
                if ((ftpData.clients[theSocketId].pasvData.bufferIndex = read(ftpData.clients[theSocketId].pasvData.passiveSocketConnection, ftpData.clients[theSocketId].pasvData.buffer, CLIENT_BUFFER_STRING_SIZE)) == 0)
                {
                    //Client is disconnected!
                    break;
                }             
                
                if (ftpData.clients[theSocketId].pasvData.bufferIndex > 0)
                {
                  int i = 0;
                  for (i = 0; i < ftpData.clients[theSocketId].pasvData.bufferIndex; i++)
                  {
                    ;
                  }
                  usleep(100);
                }
            }

            memset(theResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
            sprintf(theResponse, "226 file stor ok\r\n");
            write(ftpData.clients[theSocketId].socketDescriptor, theResponse, strlen(theResponse));
            break;
          }        
        else if (ftpData.clients[theSocketId].pasvData.commandReceived == 1 &&
               ((strncmp(ftpData.clients[theSocketId].pasvData.theCommandReceived, "LIST", strlen("LIST")) == 0) ||
                (strncmp(ftpData.clients[theSocketId].pasvData.theCommandReceived, "list", strlen("list")) == 0))
                )
          {
            DYNV_VectorGenericDataType directoryInfo;
            DYNV_VectorGeneric_Init(&directoryInfo);
            
            //printf("directoryInfo address: %lX", &directoryInfo);
            int i;
            getListDataInfo(ftpData.clients[theSocketId].login.absolutePath.text, &directoryInfo);

            printf("\nPasv (%d) ftpData.clients[theSocketId].login.absolutePath.text = %s",theSocketId, ftpData.clients[theSocketId].login.absolutePath.text);
            
            char theResponse[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
            memset(theResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
            strcpy(theResponse, "150 Accepted data connection\r\n");
            write(ftpData.clients[theSocketId].socketDescriptor, theResponse, strlen(theResponse));
            
            char theBufferWrite[1024];
            memset(theBufferWrite, 0, 1024);
            sprintf(theBufferWrite, "total %d\r\n", directoryInfo.Size);
            write(ftpData.clients[theSocketId].pasvData.passiveSocketConnection, theBufferWrite, strlen(theBufferWrite));
            //printf("%s", theBufferWrite);
            for (i = 0; i < directoryInfo.Size; i++)
            {
                memset(theBufferWrite, 0, 1024);
                sprintf(theBufferWrite, "%s %d %s %s %d %s %s\r\n", ((ftpListDataType *) directoryInfo.Data[i])->inodePermissionString
                ,((ftpListDataType *) directoryInfo.Data[i])->numberOfSubDirectories
                ,((ftpListDataType *) directoryInfo.Data[i])->owner
                ,((ftpListDataType *) directoryInfo.Data[i])->groupOwner
                ,((ftpListDataType *) directoryInfo.Data[i])->fileSize
                ,((ftpListDataType *) directoryInfo.Data[i])->lastModifiedDataString
                ,((ftpListDataType *) directoryInfo.Data[i])->fileNameNoPath);
                //printf("%s", theBufferWrite);
                 write(ftpData.clients[theSocketId].pasvData.passiveSocketConnection, theBufferWrite, strlen(theBufferWrite));
            }

            memset(theResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
            
            sprintf(theResponse, "226 %d matches total\r\n", directoryInfo.Size);
            write(ftpData.clients[theSocketId].socketDescriptor, theResponse, strlen(theResponse));
            
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
          else if (ftpData.clients[theSocketId].pasvData.commandReceived == 1 &&
              ((strncmp(ftpData.clients[theSocketId].pasvData.theCommandReceived, "RETR", strlen("RETR")) == 0) ||
               (strncmp(ftpData.clients[theSocketId].pasvData.theCommandReceived, "retr", strlen("retr")) == 0)))
          {
              int theFileSize = 0;
              int writenSize = 0;
              char theResponse[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
              printTimeStamp();
              printf("The (%d) pasvData Command: %s",theSocketId, ftpData.clients[theSocketId].pasvData.theCommandReceived);
              int writeReturn = 0;
              int i;
              char theFileName[CLIENT_COMMAND_STRING_SIZE];
              int theFileNameCursor = 0;
              memset(theFileName, 0, CLIENT_COMMAND_STRING_SIZE);
              char *theFullFileName;
              
              for (i = strlen("RETR") + 1; i < CLIENT_COMMAND_STRING_SIZE; i++)
              {
                  if (ftpData.clients[theSocketId].pasvData.theCommandReceived[i] == '\r' ||
                      ftpData.clients[theSocketId].pasvData.theCommandReceived[i] == '\n' ||
                      ftpData.clients[theSocketId].pasvData.theCommandReceived[i] == '\0') {
                      break;
                  }

                  if (theFileNameCursor < CLIENT_COMMAND_STRING_SIZE)
                  {
                    theFileName[theFileNameCursor++] = ftpData.clients[theSocketId].pasvData.theCommandReceived[i];
                  }
              }

              theFullFileName = (char *) malloc(ftpData.clients[theSocketId].login.absolutePath.textLen+1);
              strcpy(theFullFileName, ftpData.clients[theSocketId].login.absolutePath.text);
              FILE_AppendToString(&theFullFileName, "/");
              FILE_AppendToString(&theFullFileName, theFileName);

              if (FILE_IsFile(theFullFileName) == 0)
                  break;
              
              theFileSize = FILE_GetFileSizeFromPath(theFullFileName);
              
              memset(theResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
              strcpy(theResponse, "150 Accepted data connection\r\n");
              
              writeReturn = write(ftpData.clients[theSocketId].socketDescriptor, theResponse, strlen(theResponse));              
              printf("\nPasv (%d) writeReturn: %d",theSocketId, writeReturn);
              fflush(0);
              
              writenSize = writeRetrFile(theFullFileName, ftpData.clients[theSocketId].pasvData.passiveSocketConnection, ftpData.clients[theSocketId].pasvData.retrRestartAtByte);
              
              //writeReturn = write(ftpData.clients[theSocketId].pasvData.passiveSocketConnection, theFullFileContent+ftpData.clients[theSocketId].pasvData.retrRestartAtByte, theFileSize-ftpData.clients[theSocketId].pasvData.retrRestartAtByte);
              ftpData.clients[theSocketId].pasvData.retrRestartAtByte = 0;
              printf("\nPasv (%d) writeReturn data: %d",theSocketId, writeReturn);
              fflush(0);
            
            free(theFullFileName);
            //226-File successfully transferred
            //226 0.013 seconds (measured here), 105.22 Kbytes per second
             
            memset(theResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
            sprintf(theResponse, "226-File successfully transferred\r\n226 done\r\n");
            writeReturn =  write(ftpData.clients[theSocketId].socketDescriptor, theResponse, strlen(theResponse));
            printf("\nPasv (%d) writeReturn response to 21: %d",theSocketId, writeReturn);
            fflush(0);
            break;
          }
        
        break;
      }
    }

 
  pthread_exit((void *)1);
  pthread_cleanup_pop(0);
  pthread_exit((void *)2);
  
  return NULL;
}

void runFtpServer(void)
{

  static int processingSock = 0;
  static int maxSocketFD = 0;

  //Initialize all ftp data
  initFtpData();    
  
  //Socket main creator
  ftpData.theSocket = createSocket(SERVER_PORT);
  printTimeStamp();
  printf("uFTP server starting..");
  printf("\n Server: Clients connected: %d", ftpData.connectedClients);
  printf("\nServer: Max Client Allowed: %d", ftpData.maxClients);
  fd_set rset, wset, eset, rsetTemp, wsetTemp, esetTemp;
    //Initialize the select structure
    FD_ZERO(&rset);
    FD_ZERO(&wset);
    FD_ZERO(&eset);
    
    FD_ZERO(&rsetTemp);
    FD_ZERO(&wsetTemp);
    FD_ZERO(&esetTemp);

    FD_SET(ftpData.theSocket, &rset);    
    FD_SET(ftpData.theSocket, &wset);
    FD_SET(ftpData.theSocket, &eset);
    
    maxSocketFD = ftpData.theSocket+1;
    
  //Endless loop ftp process
    while (1)
    {
      int i, selectResult;
      struct timeval selectMaximumLockTime;   // sleep for 1 second!
      selectMaximumLockTime.tv_sec = 10;
      selectMaximumLockTime.tv_usec = 0;


      memcpy(&rsetTemp, &rset, sizeof(rsetTemp));
      memcpy(&wsetTemp, &wset, sizeof(wsetTemp));
      memcpy(&esetTemp, &eset, sizeof(esetTemp));

      //printf("\n\nSelect will wait for socket data.. ");
      if (ftpData.connectedClients < ftpData.maxClients)
      {
           printf("\nServer: Clients connected: %d", ftpData.connectedClients);
           selectResult = select(maxSocketFD, &rsetTemp, NULL, &esetTemp, &selectMaximumLockTime);
      }
      else
      {    
          printf("\nServer (maximum reached): Clients connected: %d", ftpData.connectedClients);
          selectResult = select(maxSocketFD, &rsetTemp, NULL, &esetTemp, &selectMaximumLockTime);
      }
      
    if (selectResult == 0)
    {
       printf("select() timed out!\n");
       continue;
    }

      for (processingSock = 0; processingSock < ftpData.maxClients; processingSock++)
      {
	if (ftpData.clients[processingSock].socketIsConnected == 0 &&
            FD_ISSET(ftpData.theSocket, &rsetTemp))
	{
            //Wait for sockets
            if ((ftpData.clients[processingSock].socketDescriptor = accept(ftpData.theSocket,0 ,0 ))!=-1)
            {
                int i;
                int error;
                ftpData.connectedClients++;
                ftpData.clients[processingSock].socketIsConnected = 1;
                error = fcntl(ftpData.clients[processingSock].socketDescriptor, F_SETFL, O_NONBLOCK);
                printTimeStamp();
                printf("Server: New client connected with id: %d", processingSock);
                printf("\nServer: Clients connected: %d", ftpData.connectedClients);
                write(ftpData.clients[processingSock].socketDescriptor, ftpData.welcomeMessage, strlen(ftpData.welcomeMessage));
                
                FD_SET(ftpData.clients[processingSock].socketDescriptor, &rset);    
                FD_SET(ftpData.clients[processingSock].socketDescriptor, &wset);
                FD_SET(ftpData.clients[processingSock].socketDescriptor, &eset);
                
                maxSocketFD = getMaximumSocketFd(ftpData.theSocket, &ftpData) + 1;
                
            }
	}
	else if (FD_ISSET(ftpData.clients[processingSock].socketDescriptor, &rsetTemp) || 
                 FD_ISSET(ftpData.clients[processingSock].socketDescriptor, &esetTemp))
	{
          //The client is not connected anymore
          if ((ftpData.clients[processingSock].bufferIndex = read(ftpData.clients[processingSock].socketDescriptor, ftpData.clients[processingSock].buffer, CLIENT_BUFFER_STRING_SIZE)) == 0)
          {
            FD_CLR(ftpData.clients[processingSock].socketDescriptor, &rset);    
            FD_CLR(ftpData.clients[processingSock].socketDescriptor, &wset);
            FD_CLR(ftpData.clients[processingSock].socketDescriptor, &eset);
            
            maxSocketFD = getMaximumSocketFd(ftpData.theSocket, &ftpData) + 1;
            
            closeSocket(processingSock);
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
                            if (commandProcessStatus == 0) 
                            {
                                write(ftpData.clients[processingSock].socketDescriptor, ftpData.clients[processingSock].buffer, ftpData.clients[processingSock].bufferIndex);
                            }
                        }
                }
                else
                {
                    //Command overflow can't be processed
                    ftpData.clients[processingSock].commandIndex = 0;
                    memset(ftpData.clients[processingSock].theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);
                    //Write some error message to the client
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
  closeSocket(ftpData.theSocket);
  printTimeStamp();
  printf("Server: Closed.");
  
  ftpData.clients[processingSock].socketIsConnected = 0;
  return;
}

/* STATIC FUNCTIONS */
static int createSocket(int port)
{
  int sock, errore;
  struct sockaddr_in temp;

  //Socket creation
  sock = socket(AF_INET, SOCK_STREAM, 0);
  temp.sin_family = AF_INET;
  temp.sin_addr.s_addr = INADDR_ANY;
  temp.sin_port = htons(port);

  //No blocking socket
  errore = fcntl(sock, F_SETFL, O_NONBLOCK);
  
  
    int reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
        perror("setsockopt(SO_REUSEADDR) failed");

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) 
        perror("setsockopt(SO_REUSEPORT) failed");


  //Bind socket
  errore = bind(sock,(struct sockaddr*) &temp,sizeof(temp));

  //Number of client allowed
  errore = listen(sock, ftpData.maxClients);
 
  return sock;
}

 int createPassiveSocket(int port)
{
  int sock, errore, flags;
  struct sockaddr_in temp;

  //Socket creation
  sock = socket(AF_INET, SOCK_STREAM, 0);
  temp.sin_family = AF_INET;
  temp.sin_addr.s_addr = INADDR_ANY;
  temp.sin_port = htons(port);

  

    flags = fcntl(sock, F_GETFL, 0);
    flags &= ~O_NONBLOCK;
    errore =  fcntl(sock, F_SETFL, flags);
  
  
  int reuse = 1;
   if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
        perror("setsockopt(SO_REUSEADDR) failed");

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) 
       perror("setsockopt(SO_REUSEPORT) failed");


  //Bind socket
  errore = bind(sock,(struct sockaddr*) &temp,sizeof(temp));

  //Number of client allowed
  errore = listen(sock, 1);

  return sock;
}

static void closeSocket(int processingSocket)
{
    //Close the socket
    close(ftpData.clients[processingSocket].socketDescriptor);

    resetClientData(&ftpData.clients[processingSocket], 0);
    resetPasvData(&ftpData.clients[processingSocket].pasvData, 0);
    //Update client connecteds
    ftpData.connectedClients--;
    
    if (ftpData.connectedClients < 0){
        ftpData.connectedClients = 0;
    }
    printTimeStamp();
    printf("Client id: %d disconnected", processingSocket);
    printf("\nServer: Clients connected:%d", ftpData.connectedClients);
    return;
}

static void initFtpData(void)
{
 int i;
 ftpData.connectedClients = 0;
 ftpData.maxClients = 10;
 ftpData.clients = (clientDataType *) malloc( sizeof(clientDataType) * ftpData.maxClients);
 
 ftpData.serverIp.ip[0] = 127;
 ftpData.serverIp.ip[1] = 0;
 ftpData.serverIp.ip[2] = 0;
 ftpData.serverIp.ip[3] = 1;

 memset(ftpData.welcomeMessage, 0, 1024);
 strcpy(ftpData.welcomeMessage, "220 Hello\r\n");
 
  //Client data reset to zero
  for (i = 0; i < ftpData.maxClients; i++)
  {
      resetPasvData(&ftpData.clients[i].pasvData, 1);
      resetClientData(&ftpData.clients[i], 1);
      ftpData.clients[i].clientProgressiveNumber = i;
  }
 
 return;
}

static int processCommand(int processingElement)
{
    int toReturn = 0;
    printTimeStamp();
    printf ("Command received from (%d): %s", processingElement, ftpData.clients[processingElement].theCommandReceived);
   
    //Process Command
    if(strncmp(ftpData.clients[processingElement].theCommandReceived, "USER", strlen("USER")) == 0 || 
       strncmp(ftpData.clients[processingElement].theCommandReceived, "user", strlen("user")) == 0)
    {
        printf("\nUSER COMMAND RECEIVED");
        toReturn = parseCommandUser(&ftpData.clients[processingElement]);
    }
    else if(strncmp(ftpData.clients[processingElement].theCommandReceived, "PASS", strlen("PASS")) == 0 ||
            strncmp(ftpData.clients[processingElement].theCommandReceived, "pass", strlen("pass")) == 0)
    {
        printf("\nPASS COMMAND RECEIVED");
        toReturn = parseCommandPass(&ftpData.clients[processingElement]);
    }
    else if(strncmp(ftpData.clients[processingElement].theCommandReceived, "AUTH", strlen("AUTH")) == 0 ||
            strncmp(ftpData.clients[processingElement].theCommandReceived, "auth", strlen("auth")) == 0)
    {
        printf("\nAUTH COMMAND RECEIVED");
        toReturn = parseCommandAuth(&ftpData.clients[processingElement]);
    }
    else if(strncmp(ftpData.clients[processingElement].theCommandReceived, "PWD", strlen("PWD")) == 0 ||
            strncmp(ftpData.clients[processingElement].theCommandReceived, "pwd", strlen("pwd")) == 0)
    {
        printf("\nPWD COMMAND RECEIVED");
        toReturn = parseCommandPwd(&ftpData.clients[processingElement]);
    }
    else if(strncmp(ftpData.clients[processingElement].theCommandReceived, "SYST", strlen("SYST")) == 0 ||
            strncmp(ftpData.clients[processingElement].theCommandReceived, "syst", strlen("syst")) == 0)
    {
        printf("\nSYST COMMAND RECEIVED");
        toReturn = parseCommandSyst(&ftpData.clients[processingElement]);
    }
    else if(strncmp(ftpData.clients[processingElement].theCommandReceived, "FEAT", strlen("FEAT")) == 0 ||
            strncmp(ftpData.clients[processingElement].theCommandReceived, "feat", strlen("feat")) == 0)
    {
        printf("\nFEAT COMMAND RECEIVED");
        toReturn = parseCommandFeat(&ftpData.clients[processingElement]);
    }
    else if(strncmp(ftpData.clients[processingElement].theCommandReceived, "TYPE I", strlen("TYPE I")) == 0 ||
            strncmp(ftpData.clients[processingElement].theCommandReceived, "type i", strlen("type i")) == 0)
    {
        printf("\nTYPE I COMMAND RECEIVED");
        toReturn = parseCommandTypeI(&ftpData.clients[processingElement]);
    }
    else if(strncmp(ftpData.clients[processingElement].theCommandReceived, "PASV", strlen("PASV")) == 0 ||
            strncmp(ftpData.clients[processingElement].theCommandReceived, "pasv", strlen("pasv")) == 0)
    {
        printf("\nPASV COMMAND RECEIVED");
        setRandomicPort(&ftpData, processingElement);
        toReturn = parseCommandPasv(&ftpData, processingElement);
    }
    else if(strncmp(ftpData.clients[processingElement].theCommandReceived, "LIST", strlen("LIST")) == 0 ||
            strncmp(ftpData.clients[processingElement].theCommandReceived, "list", strlen("list")) == 0)
    {
        printf("\nLIST COMMAND RECEIVED");
        toReturn = parseCommandList(&ftpData, processingElement);
    }
    else if(strncmp(ftpData.clients[processingElement].theCommandReceived, "CWD", strlen("CWD")) == 0 ||
            strncmp(ftpData.clients[processingElement].theCommandReceived, "cwd", strlen("cwd")) == 0)
    {
        printf("\nCWD COMMAND RECEIVED");
        toReturn = parseCommandCwd(&ftpData.clients[processingElement]);
    }
    else if(strncmp(ftpData.clients[processingElement].theCommandReceived, "CDUP", strlen("CDUP")) == 0 ||
            strncmp(ftpData.clients[processingElement].theCommandReceived, "cdup", strlen("cdup")) == 0)
    {
        printf("\nCDUP COMMAND RECEIVED");
        toReturn = parseCommandCdup(&ftpData.clients[processingElement]);
    }
    else if(strncmp(ftpData.clients[processingElement].theCommandReceived, "REST", strlen("REST")) == 0 ||
            strncmp(ftpData.clients[processingElement].theCommandReceived, "rest", strlen("rest")) == 0)
    {
        printf("\nREST COMMAND RECEIVED");
        toReturn = parseCommandRest(&ftpData.clients[processingElement]);
    }
    else if(strncmp(ftpData.clients[processingElement].theCommandReceived, "RETR", strlen("RETR")) == 0 ||
            strncmp(ftpData.clients[processingElement].theCommandReceived, "retr", strlen("retr")) == 0)
    {
        printf("\nRETR COMMAND RECEIVED");
        toReturn = parseCommandRetr(&ftpData, processingElement);
    }
    else if(strncmp(ftpData.clients[processingElement].theCommandReceived, "STOR", strlen("STOR")) == 0 ||
            strncmp(ftpData.clients[processingElement].theCommandReceived, "stor", strlen("stor")) == 0)
    {
        printf("\nSTOR COMMAND RECEIVED");
        toReturn = parseCommandStor(&ftpData, processingElement);
    }
    
    //REST COMMAND 
    //REST 0
    //350 Restarting at 0
    
    //RETR info.php
    //150 Accepted data connection
    //226-File successfully transferred
    //226 0.013 seconds (measured here), 105.22 Kbytes per second
    
    //227 Entering Passive Mode (192,185,16,65,182,64)
    //STOR testUgo.txt
    //150 Accepted data connection
    //226-File successfully transferred
    //226 21.350 seconds (measured here), 3.33 bytes per second
    
    ftpData.clients[processingElement].commandIndex = 0;
    memset(ftpData.clients[processingElement].theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);

    return toReturn;
}

static int getMaximumSocketFd(int mainSocket, ftpDataType * data)
{
    int toReturn = mainSocket;
    int i = 0;
    
    for (i = 0; i < data->maxClients; i++)
    {
        if (data->clients[i].socketDescriptor > toReturn) {
            toReturn = data->clients[i].socketDescriptor;
        }
    }
    
    return toReturn;
}