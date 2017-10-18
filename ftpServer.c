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

#define SERVER_PORT     21

static ftpDataType ftpData;

static int createSocket(int port);
static void closeSocket(int processingSocket);
static void initFtpData(void);
static int processCommand(int processingElement);

void *pasvThreadHandler(void * socketId)
{
  int theSocketId = *(int *)socketId;
  ftpData.clients[theSocketId].pasvData.passiveSocket = createPassiveSocket(ftpData.clients[theSocketId].pasvData.passivePort);
  char theResponse[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
    
  //Endless loop ftp process
    while (1)
    {
        usleep(1000);

	if (ftpData.clients[theSocketId].pasvData.passiveSocketIsConnected == 0)
	{
            printf("\nWaiting for pasv client connection");
            
            //Wait for sockets
            if ((ftpData.clients[theSocketId].pasvData.passiveSocketConnection = accept(ftpData.clients[theSocketId].pasvData.passiveSocket, 0, 0))!=-1)
            {
                int error;
                ftpData.clients[theSocketId].pasvData.passiveSocketIsConnected = 1;
                error = fcntl(ftpData.clients[theSocketId].pasvData.passiveSocketConnection, F_SETFL, O_NONBLOCK);
                memset(theResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
                strcpy(theResponse, "150 Accepted data connection\r\n");
                write(ftpData.clients[theSocketId].socketDescriptor, theResponse, strlen(theResponse));
            }
	}
	else
	{
          //The client is not connected anymore
          if ((ftpData.clients[theSocketId].pasvData.bufferIndex = read(ftpData.clients[theSocketId].pasvData.passiveSocketConnection, ftpData.clients[theSocketId].pasvData.buffer, CLIENT_BUFFER_STRING_SIZE)) == 0)
          {
           close(theSocketId);
           ftpData.clients[theSocketId].pasvData.passiveSocketIsConnected = 0;
          }
          
          if (ftpData.clients[theSocketId].pasvData.bufferIndex > 0)
          {
            int i = 0;
            for (i = 0; i < ftpData.clients[theSocketId].pasvData.bufferIndex; i++)
            {
                    ;
            }

            usleep(100);
                        
            write(ftpData.clients[theSocketId].pasvData.passiveSocketConnection, ftpData.clients[theSocketId].pasvData.buffer, ftpData.clients[theSocketId].pasvData.bufferIndex);
          }
          
          if (ftpData.clients[theSocketId].socketCommandReceived == 1 &&
              strncmp(ftpData.clients[theSocketId].pasvData.theCommandReceived, "LIST", strlen("LIST")) == 0)
          {
            DYNV_VectorGenericDataType directoryInfo;
            DYNV_VectorGeneric_Init(&directoryInfo);
            int i;
            getListDataInfo(ftpData.clients[theSocketId].login.absolutePath.text, &directoryInfo);
            char theBufferWrite[1024];
            memset(theBufferWrite, 0, 1024);
            
            sprintf(theBufferWrite, "total %d\r\n", directoryInfo.Size);
            write(ftpData.clients[theSocketId].pasvData.passiveSocketConnection, theBufferWrite, strlen(theBufferWrite));
            printf("%s", theBufferWrite);
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
                printf("%s", theBufferWrite);
                write(ftpData.clients[theSocketId].pasvData.passiveSocketConnection, theBufferWrite, strlen(theBufferWrite));
            }

            memset(theResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
            
            sprintf(theResponse, "226 %d matches total\r\n", directoryInfo.Size);
            write(ftpData.clients[theSocketId].socketDescriptor, theResponse, strlen(theResponse));
            
            int theSize = directoryInfo.Size;
            
            char ** lastToDestroy = NULL;
            
            if (theSize > 0)
                lastToDestroy = ((ftpListDataType *)directoryInfo.Data[0])->fileList;
            
            directoryInfo.Destroy(&directoryInfo, deleteListDataInfoVector);
            //Not freed by destroy
            if (theSize > 0)
                free(lastToDestroy);
            //return;
            ftpData.clients[theSocketId].socketCommandReceived = 0;
            
            close(ftpData.clients[theSocketId].pasvData.passiveSocketConnection);
            //close (ftpData.clients[theSocketId].pasvData.passiveSocket);
            //pthread_exit();
            ftpData.clients[theSocketId].pasvData.passiveSocketIsConnected = 0;
            break;
          } else if (ftpData.clients[theSocketId].socketCommandReceived == 1 &&
              strncmp(ftpData.clients[theSocketId].pasvData.theCommandReceived, "RETR", strlen("RETR")) == 0)
          {
              
              break;
          }
          
          
      }
  }

  printf("\nClosing pasv socket (%d) ok!", theSocketId);
  fflush(0);
  return NULL;
}

void runFtpServer(void)
{
  static int processingSock = 0;
  
  char *test;
  test = (char *) malloc(strlen("/home/ugo/scrivania/viaggio california") + 1);
;  

  //Initialize all ftp data
  initFtpData();  

  //Socket main creator
  ftpData.theSocket = createSocket(SERVER_PORT);
  printf("\nuFTP server starting..");
  printf("\n Server: Clients connected: %d", ftpData.connectedClients);
  printf("\nServer: Max Client Allowed: %d", ftpData.maxClients);


  //Endless loop ftp process
    while (1)
    {
      usleep(1000);

      for (processingSock = 0; processingSock < ftpData.maxClients; processingSock++)
      {
	if (ftpData.clients[processingSock].socketIsConnected == 0)
	{
            //Wait for sockets
            if ((ftpData.clients[processingSock].socketDescriptor = accept(ftpData.theSocket,0 ,0 ))!=-1)
            {
                int error;
                ftpData.connectedClients++;
                ftpData.clients[processingSock].socketIsConnected = 1;
                error = fcntl(ftpData.clients[processingSock].socketDescriptor, F_SETFL, O_NONBLOCK);
                printf("\nServer: New client connected with id: %d", processingSock);
                printf("\nServer: Clients connected: %d", ftpData.connectedClients);
                write(ftpData.clients[processingSock].socketDescriptor, ftpData.welcomeMessage, strlen(ftpData.welcomeMessage));
            }
	}
	else
	{
          //The client is not connected anymore
          if ((ftpData.clients[processingSock].bufferIndex = read(ftpData.clients[processingSock].socketDescriptor, ftpData.clients[processingSock].buffer, CLIENT_BUFFER_STRING_SIZE)) == 0)
          {
           closeSocket(processingSock);
          }
          
          if (ftpData.clients[processingSock].bufferIndex > 0)
          {
            int i = 0;
            int commandProcessStatus = 0;
            for (i = 0; i < ftpData.clients[processingSock].bufferIndex; i++)
            {
                ftpData.clients[processingSock].theCommandReceived[ftpData.clients[processingSock].commandIndex++] = ftpData.clients[processingSock].buffer[i];

                if (ftpData.clients[processingSock].buffer[i] == '\n') {
                    ftpData.clients[processingSock].socketCommandReceived = 1;
                    commandProcessStatus = processCommand(processingSock);
                }
            }
            usleep(100);
            
            //Echo unrecognized commands
            if (commandProcessStatus == 0){
                
                write(ftpData.clients[processingSock].socketDescriptor, ftpData.clients[processingSock].buffer, ftpData.clients[processingSock].bufferIndex);
            }
            
            memset(ftpData.clients[processingSock].buffer, 0, CLIENT_BUFFER_STRING_SIZE);
          }
      }
    }
  }
  
  //Server Close
  closeSocket(ftpData.theSocket);
  printf("Server: Closed.\n");
  
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
  int sock, errore;
  struct sockaddr_in temp;

  //Socket creation
  sock = socket(AF_INET, SOCK_STREAM, 0);
  temp.sin_family = AF_INET;
  temp.sin_addr.s_addr = INADDR_ANY;
  temp.sin_port = htons(port);

  //No blocking socket
  //errore = fcntl(sock, F_SETFL, O_NONBLOCK);
  
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

    //Reset the data
    ftpData.clients[processingSocket].socketDescriptor = 0;
    ftpData.clients[processingSocket].socketCommandReceived = 0;
    ftpData.clients[processingSocket].socketIsConnected = 0;
    ftpData.clients[processingSocket].bufferIndex = 0;
    ftpData.clients[processingSocket].commandIndex = 0;
    ftpData.clients[processingSocket].pasvData.passivePort = 0;
    ftpData.clients[processingSocket].pasvData.passiveModeOn = 0;
    ftpData.clients[processingSocket].pasvData.passiveSocketIsConnected = 0;
    
    memset(ftpData.clients[processingSocket].buffer, 0, CLIENT_BUFFER_STRING_SIZE);
    memset(ftpData.clients[processingSocket].theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);
    memset(ftpData.clients[processingSocket].pasvData.buffer, 0, CLIENT_BUFFER_STRING_SIZE);
    cleanLoginData(&ftpData.clients[processingSocket].login, 0);
    
    //Update client connecteds
    ftpData.connectedClients--;
    
    if (ftpData.connectedClients < 0){
        ftpData.connectedClients = 0;
    }
    
    printf("\nClient id: %d disconnected", processingSocket);
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
      ftpData.clients[i].socketDescriptor = 0;
      ftpData.clients[i].socketCommandReceived = 0;
      ftpData.clients[i].socketIsConnected = 0;
      ftpData.clients[i].bufferIndex = 0;
      ftpData.clients[i].commandIndex = 0;
      ftpData.clients[i].pasvData.passivePort = 0;
      ftpData.clients[i].pasvData.passiveModeOn = 0;
      ftpData.clients[i].pasvData.passiveSocketIsConnected = 0;

        if (pthread_mutex_init(&ftpData.clients[i].pasvData.lock, NULL) != 0)
        {
            printf("\nMutex init failed");
        }

      memset(ftpData.clients[i].buffer, 0, CLIENT_BUFFER_STRING_SIZE);
      memset(ftpData.clients[i].pasvData.buffer, 0, CLIENT_BUFFER_STRING_SIZE);
      memset(ftpData.clients[i].theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);
      
      cleanLoginData(&ftpData.clients[i].login, 1);
  }
 
 return;
}

static int processCommand(int processingElement)
{
    int toReturn = 0;
    printf ("\nCommand received from (%d): %s", processingElement, ftpData.clients[processingElement].theCommandReceived);
   
    //Process Command
    if(strncmp(ftpData.clients[processingElement].theCommandReceived, "USER", strlen("USER")) == 0)
    {
        printf("\nUSER COMMAND RECEIVED");
        toReturn = parseCommandUser(&ftpData.clients[processingElement]);
    }
    else if(strncmp(ftpData.clients[processingElement].theCommandReceived, "PASS", strlen("PASS")) == 0)
    {
        printf("\nPASS COMMAND RECEIVED");
        toReturn = parseCommandPass(&ftpData.clients[processingElement]);
    }
    else if(strncmp(ftpData.clients[processingElement].theCommandReceived, "AUTH", strlen("AUTH")) == 0)
    {
        printf("\nAUTH COMMAND RECEIVED");
        toReturn = parseCommandAuth(&ftpData.clients[processingElement]);
    }
    else if(strncmp(ftpData.clients[processingElement].theCommandReceived, "PWD", strlen("PWD")) == 0)
    {
        printf("\nPWD COMMAND RECEIVED");
        toReturn = parseCommandPwd(&ftpData.clients[processingElement]);
    }
    else if(strncmp(ftpData.clients[processingElement].theCommandReceived, "SYST", strlen("SYST")) == 0)
    {
        printf("\nSYST COMMAND RECEIVED");
        toReturn = parseCommandSyst(&ftpData.clients[processingElement]);
    }
    else if(strncmp(ftpData.clients[processingElement].theCommandReceived, "FEAT", strlen("FEAT")) == 0)
    {
        printf("\nSYST COMMAND RECEIVED");
        toReturn = parseCommandFeat(&ftpData.clients[processingElement]);
    }
    else if(strncmp(ftpData.clients[processingElement].theCommandReceived, "TYPE I", strlen("TYPE I")) == 0)
    {
        printf("\nTYPE I COMMAND RECEIVED");
        toReturn = parseCommandTypeI(&ftpData.clients[processingElement]);
    }
    else if(strncmp(ftpData.clients[processingElement].theCommandReceived, "PASV", strlen("PASV")) == 0)
    {
        printf("\nPASV COMMAND RECEIVED");
        setRandomicPort(&ftpData, processingElement);
        toReturn = parseCommandPasv(&ftpData, processingElement);
    }
    else if(strncmp(ftpData.clients[processingElement].theCommandReceived, "LIST", strlen("LIST")) == 0)
    {
        printf("\nLIST COMMAND RECEIVED");
        toReturn = parseCommandList(&ftpData, processingElement);
    }
    else if(strncmp(ftpData.clients[processingElement].theCommandReceived, "CWD", strlen("CWD")) == 0)
    {
        printf("\nCWD COMMAND RECEIVED");
        toReturn = parseCommandCwd(&ftpData.clients[processingElement]);
    }
    else if(strncmp(ftpData.clients[processingElement].theCommandReceived, "CDUP", strlen("CDUP")) == 0)
    {
        printf("\nCDUP COMMAND RECEIVED");
        toReturn = parseCommandCdup(&ftpData.clients[processingElement]);
    }
    else if(strncmp(ftpData.clients[processingElement].theCommandReceived, "REST", strlen("REST")) == 0)
    {
        printf("\nREST COMMAND RECEIVED");
        toReturn = parseCommandRest(&ftpData.clients[processingElement]);
    }
    //REST COMMAND 
    //REST 0
    //350 Restarting at 0
    
    //RETR info.php
    //150 Accepted data connection
    //226-File successfully transferred
    //226 0.013 seconds (measured here), 105.22 Kbytes per second
    
    ftpData.clients[processingElement].commandIndex = 0;
    memset(ftpData.clients[processingElement].theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);

    return toReturn;
}

