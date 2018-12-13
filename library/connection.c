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


#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdarg.h>


#include "../ftpData.h"
#include "connection.h"



int socketPrintf(ftpDataType * ftpData, int clientId, const char *__restrict __fmt, ...)
{
	#define COMMAND_BUFFER								9600
	#define SOCKET_PRINTF_BUFFER						2048
	int bytesWritten = 0;
	char theBuffer[SOCKET_PRINTF_BUFFER];
	char commandBuffer[COMMAND_BUFFER];
	int theStringSize = 0, theCommandSize = 0;
	memset(&theBuffer, 0, SOCKET_PRINTF_BUFFER);
	memset(&commandBuffer, 0, COMMAND_BUFFER);
	printf("\nWriting to socket id %d, TLS %d: ", clientId, ftpData->clients[clientId].tlsIsEnabled);

	pthread_mutex_lock(&ftpData->clients[clientId].writeMutex);

	va_list args;
	va_start(args, __fmt);
	while (*__fmt != '\0')
	{
		int i = 0;
		theStringSize = 0;
		switch(*__fmt)
		{
			case 'd':
			case 'D':
			{
				int theInteger = va_arg(args, int);
				memset(&theBuffer, 0, SOCKET_PRINTF_BUFFER);
				theStringSize = snprintf(theBuffer, SOCKET_PRINTF_BUFFER, "%d", theInteger);
			}
			break;

			case 'c':
			case 'C':
			{
				int theCharInteger = va_arg(args, int);
				memset(&theBuffer, 0, SOCKET_PRINTF_BUFFER);
				theStringSize = snprintf(theBuffer, SOCKET_PRINTF_BUFFER, "%c", theCharInteger);
			}
			break;

			case 'f':
			case 'F':
			{
				float theDouble = va_arg(args, double);
				memset(&theBuffer, 0, SOCKET_PRINTF_BUFFER);
				theStringSize = snprintf(theBuffer, SOCKET_PRINTF_BUFFER, "%f", theDouble);
			}
			break;

			case 's':
			case 'S':
			{
				char * theString = va_arg(args, char *);
				memset(&theBuffer, 0, SOCKET_PRINTF_BUFFER);
				theStringSize = snprintf(theBuffer, SOCKET_PRINTF_BUFFER, "%s", theString);
			}
			break;

			case 'l':
			case 'L':
			{
				long long int theLongLongInt = va_arg(args, long long int);
				memset(&theBuffer, 0, SOCKET_PRINTF_BUFFER);
				theStringSize = snprintf(theBuffer, SOCKET_PRINTF_BUFFER, "%lld",  theLongLongInt);
			}
			break;

			default:
			{
				printf("\n Switch is default (%c)", *__fmt);
			}
			break;
		}

		for (i = 0; i <theStringSize; i++)
		{
			if (theCommandSize < COMMAND_BUFFER)
			{
				commandBuffer[theCommandSize++] = theBuffer[i];
			}
		}

		++__fmt;
	}
	va_end(args);


	if (ftpData->clients[clientId].tlsIsEnabled != 1)
	{
		bytesWritten = write(ftpData->clients[clientId].socketDescriptor, commandBuffer, theCommandSize);
	}
	else if (ftpData->clients[clientId].tlsIsEnabled == 1)
	{
		#ifdef OPENSSL_ENABLED
		bytesWritten = SSL_write(ftpData->clients[clientId].ssl, commandBuffer, theCommandSize);
		#endif
	}

	printf("\n%s", commandBuffer);

	pthread_mutex_unlock(&ftpData->clients[clientId].writeMutex);

	return bytesWritten;
}

int socketWorkerPrintf(ftpDataType * ftpData, int clientId, const char *__restrict __fmt, ...)
{
	#define SOCKET_PRINTF_BUFFER						2048

	int bytesWritten = 0;
	char theBuffer[SOCKET_PRINTF_BUFFER];
	int theStringSize = 0;
	memset(&theBuffer, 0, SOCKET_PRINTF_BUFFER);
	printf("\nWriting to worker socket id %dd, TLS %d: ", clientId, ftpData->clients[clientId].dataChannelIsTls);
	va_list args;
	va_start(args, __fmt);
	while (*__fmt != '\0')
	{
		theStringSize = 0;
		switch(*__fmt)
		{
			case 'd':
			case 'D':
			{
				int theInteger = va_arg(args, int);
				memset(&theBuffer, 0, SOCKET_PRINTF_BUFFER);
				theStringSize = snprintf(theBuffer, SOCKET_PRINTF_BUFFER, "%d", theInteger);
			}
			break;

			case 'c':
			case 'C':
			{
				int theCharInteger = va_arg(args, int);
				memset(&theBuffer, 0, SOCKET_PRINTF_BUFFER);
				theStringSize = snprintf(theBuffer, SOCKET_PRINTF_BUFFER, "%c", theCharInteger);
			}
			break;

			case 'f':
			case 'F':
			{
				float theDouble = va_arg(args, double);
				memset(&theBuffer, 0, SOCKET_PRINTF_BUFFER);
				theStringSize = snprintf(theBuffer, SOCKET_PRINTF_BUFFER, "%f", theDouble);
			}
			break;

			case 's':
			case 'S':
			{
				char * theString = va_arg(args, char *);
				memset(&theBuffer, 0, SOCKET_PRINTF_BUFFER);
				theStringSize = snprintf(theBuffer, SOCKET_PRINTF_BUFFER, "%s", theString);
			}
			break;

			case 'l':
			case 'L':
			{
				long long int theLongLongInt = va_arg(args, long long int);
				memset(&theBuffer, 0, SOCKET_PRINTF_BUFFER);
				theStringSize = snprintf(theBuffer, SOCKET_PRINTF_BUFFER, "%lld",  theLongLongInt);
			}
			break;

			default:
			{
				printf("\n Switch is default (%c)", *__fmt);
			}
			break;
		}

		if (theStringSize >= SOCKET_PRINTF_BUFFER) {
			printf("\n String buffer is full!");
		}
		else if (theStringSize < SOCKET_PRINTF_BUFFER &&
				theStringSize > 0)
		{
			int theReturnCode = 0;

			if (ftpData->clients[clientId].dataChannelIsTls != 1)
			{
				theReturnCode = write(ftpData->clients[clientId].workerData.socketConnection, theBuffer, theStringSize);
			}
			else if (ftpData->clients[clientId].dataChannelIsTls == 1)
			{

				#ifdef OPENSSL_ENABLED
				if (ftpData->clients[clientId].workerData.passiveModeOn == 1){
					theReturnCode = SSL_write(ftpData->clients[clientId].workerData.serverSsl, theBuffer, theStringSize);
					printf("%s", theBuffer);
				}
				else if (ftpData->clients[clientId].workerData.activeModeOn == 1){
					theReturnCode = SSL_write(ftpData->clients[clientId].workerData.clientSsl, theBuffer, theStringSize);
					printf("%s", theBuffer);
				}
				#endif
			}



			if (theReturnCode > 0)
			{
				bytesWritten += theReturnCode;
			}
			else
			{
				bytesWritten = theReturnCode;
				break;
			}
		}
		else if(theStringSize == 0)
		{
			printf("\n Nothing to write.. ");
		}

		++__fmt;
	}

	va_end(args);
	return bytesWritten;
}

/* Return the higher socket available*/
int getMaximumSocketFd(int mainSocket, ftpDataType * ftpData)
{
    int toReturn = mainSocket;
    int i = 0;

    for (i = 0; i < ftpData->ftpParameters.maxClients; i++)
    {
        if (ftpData->clients[i].socketDescriptor > toReturn) {
            toReturn = ftpData->clients[i].socketDescriptor;
        }
    }
    //Must be incremented by one
    toReturn++;
    return toReturn;
}

int createSocket(ftpDataType * ftpData)
{
  printf("\nCreating main socket on port %d", ftpData->ftpParameters.port);
  int sock, errorCode;
  struct sockaddr_in temp;

  //Socket creation
  sock = socket(AF_INET, SOCK_STREAM, 0);
  temp.sin_family = AF_INET;
  temp.sin_addr.s_addr = INADDR_ANY;
  temp.sin_port = htons(ftpData->ftpParameters.port);

  //No blocking socket
  errorCode = fcntl(sock, F_SETFL, O_NONBLOCK);

    int reuse = 1;
    
#ifdef SO_REUSEADDR
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
        perror("setsockopt(SO_REUSEADDR) failed");
#endif

#ifdef SO_REUSEPORT
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) 
        perror("setsockopt(SO_REUSEPORT) failed");
#endif
  //Bind socket
  errorCode = bind(sock,(struct sockaddr*) &temp,sizeof(temp));

  //Number of client allowed
  errorCode = listen(sock, ftpData->ftpParameters.maxClients + 1);
 
  return sock;
}

int createPassiveSocket(int port)
{
  int sock, returnCode;
  struct sockaddr_in temp;

  //Socket creation
  sock = socket(AF_INET, SOCK_STREAM, 0);
  temp.sin_family = AF_INET;
  temp.sin_addr.s_addr = INADDR_ANY;
  temp.sin_port = htons(port);

  int reuse = 1;

#ifdef SO_REUSEADDR
   if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
        perror("setsockopt(SO_REUSEADDR) failed");
#endif

#ifdef SO_REUSEPORT
   if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) 
       perror("setsockopt(SO_REUSEPORT) failed");
#endif

  //Bind socket
  returnCode = bind(sock,(struct sockaddr*) &temp,sizeof(temp));

  if (returnCode == -1)
      return returnCode;

  //Number of client allowed
  returnCode = listen(sock, 1);

  if (returnCode == -1)
      return returnCode;  

  return sock;
}

int createActiveSocket(int port, char *ipAddress)
{
  int sockfd;
  struct sockaddr_in serv_addr;

  printf("\n Connection socket is going to start ip: %s:%d \n", ipAddress, port);
  //sleep(100);
  memset(&serv_addr, 0, sizeof(struct sockaddr_in)); 
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port); 
  if(inet_pton(AF_INET, ipAddress, &serv_addr.sin_addr)<=0)
  {
      printf("\n inet_pton error occured\n");
      return -1;
  } 

  if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
      printf("\n2 Error : Could not create socket \n");
      return -1;
  }
  else
  {
      printf("\n sockfd = %d \n", sockfd);
  }
  
  
  int reuse = 1;
#ifdef SO_REUSEADDR
   if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
        perror("setsockopt(SO_REUSEADDR) failed");
#endif

#ifdef SO_REUSEPORT
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) 
       perror("setsockopt(SO_REUSEPORT) failed");
#endif
  

  if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
  {
     printf("\n3 Error : Connect Failed \n");
     return -1;
  }

  printf("\n Connection socket %d is going to start ip: %s:%d \n",sockfd, ipAddress, port);

  return sockfd;
}

void fdInit(ftpDataType * ftpData)
{
    FD_ZERO(&ftpData->connectionData.rset);
    FD_ZERO(&ftpData->connectionData.wset);
    FD_ZERO(&ftpData->connectionData.eset);
    FD_ZERO(&ftpData->connectionData.rsetAll);
    FD_ZERO(&ftpData->connectionData.wsetAll);
    FD_ZERO(&ftpData->connectionData.esetAll);    

    FD_SET(ftpData->connectionData.theMainSocket, &ftpData->connectionData.rsetAll);    
    FD_SET(ftpData->connectionData.theMainSocket, &ftpData->connectionData.wsetAll);
    FD_SET(ftpData->connectionData.theMainSocket, &ftpData->connectionData.esetAll);
}

void fdAdd(ftpDataType * ftpData, int index)
{
    FD_SET(ftpData->clients[index].socketDescriptor, &ftpData->connectionData.rsetAll);    
    FD_SET(ftpData->clients[index].socketDescriptor, &ftpData->connectionData.wsetAll);
    FD_SET(ftpData->clients[index].socketDescriptor, &ftpData->connectionData.esetAll);
    ftpData->connectionData.maxSocketFD = getMaximumSocketFd(ftpData->connectionData.theMainSocket, ftpData) + 1;
}

void fdRemove(ftpDataType * ftpData, int index)
{
    FD_CLR(ftpData->clients[index].socketDescriptor, &ftpData->connectionData.rsetAll);    
    FD_CLR(ftpData->clients[index].socketDescriptor, &ftpData->connectionData.wsetAll);
    FD_CLR(ftpData->clients[index].socketDescriptor, &ftpData->connectionData.esetAll);
}

void closeSocket(ftpDataType * ftpData, int processingSocket)
{
    //Close the socket
    shutdown(ftpData->clients[processingSocket].socketDescriptor, SHUT_RDWR);
    close(ftpData->clients[processingSocket].socketDescriptor);

    resetClientData(ftpData, processingSocket, 0);
    resetWorkerData(ftpData, processingSocket, 0);
    
    //Update client connecteds
    ftpData->connectedClients--;
    if (ftpData->connectedClients < 0) 
    {
        ftpData->connectedClients = 0;
    }

    printf("Client id: %d disconnected", processingSocket);
    printf("\nServer: Clients connected:%d", ftpData->connectedClients);
    return;
}

void closeClient(ftpDataType * ftpData, int processingSocket)
{
    printf("\nQUIT FLAG SET!\n");

    if (ftpData->clients[processingSocket].workerData.threadIsAlive == 1)
    {
		void *pReturn;
		pthread_cancel(ftpData->clients[processingSocket].workerData.workerThread);
		//pthread_join(ftpData->clients[processingSocket].workerData.workerThread, &pReturn);
		printf("\nQuit command received the Pasv Thread has been cancelled.");
    }

    FD_CLR(ftpData->clients[processingSocket].socketDescriptor, &ftpData->connectionData.rsetAll);    
    FD_CLR(ftpData->clients[processingSocket].socketDescriptor, &ftpData->connectionData.wsetAll);
    FD_CLR(ftpData->clients[processingSocket].socketDescriptor, &ftpData->connectionData.esetAll);

    closeSocket(ftpData, processingSocket);

    ftpData->connectionData.maxSocketFD = ftpData->connectionData.theMainSocket+1;
    ftpData->connectionData.maxSocketFD = getMaximumSocketFd(ftpData->connectionData.theMainSocket, ftpData) + 1;
    return;
}

void checkClientConnectionTimeout(ftpDataType * ftpData)
{
    int processingSock;
    for (processingSock = 0; processingSock < ftpData->ftpParameters.maxClients; processingSock++)
    {
        /* No connection active*/
        if (ftpData->clients[processingSock].socketDescriptor < 0 ||
            ftpData->clients[processingSock].socketIsConnected == 0) 
            {
                continue;
            }

        /* Max idle time check, close the connection if time is elapsed */
        if (ftpData->ftpParameters.maximumIdleInactivity != 0 &&
            (int)time(NULL) - ftpData->clients[processingSock].lastActivityTimeStamp > ftpData->ftpParameters.maximumIdleInactivity)
            {
                ftpData->clients[processingSock].closeTheClient = 1;
            }
    }
}

void flushLoginWrongTriesData(ftpDataType * ftpData)
{
    int i;
    //printf("\n flushLoginWrongTriesData size of the vector : %d", ftpData->loginFailsVector.Size);
    
    for (i = (ftpData->loginFailsVector.Size-1); i >= 0; i--)
    {
        //printf("\n last login fail attempt : %d", ((loginFailsDataType *) ftpData->loginFailsVector.Data[i])->failTimeStamp);
        
        if ( (time(NULL) - ((loginFailsDataType *) ftpData->loginFailsVector.Data[i])->failTimeStamp) > WRONG_PASSWORD_ALLOWED_RETRY_TIME)
        {
            //printf("\n Deleting element : %d", i);
            ftpData->loginFailsVector.DeleteAt(&ftpData->loginFailsVector, i, deleteLoginFailsData);
        }
    }
}

int selectWait(ftpDataType * ftpData)
{
    struct timeval selectMaximumLockTime;
    selectMaximumLockTime.tv_sec = 10;
    selectMaximumLockTime.tv_usec = 0;

    ftpData->connectionData.rset = ftpData->connectionData.rsetAll;
    ftpData->connectionData.wset = ftpData->connectionData.wsetAll;
    ftpData->connectionData.eset = ftpData->connectionData.esetAll;
    return select(ftpData->connectionData.maxSocketFD, &ftpData->connectionData.rset, NULL, &ftpData->connectionData.eset, &selectMaximumLockTime);
}

int isClientConnected(ftpDataType * ftpData, int cliendId)
{
    if (ftpData->clients[cliendId].socketDescriptor < 0 ||
        ftpData->clients[cliendId].socketIsConnected == 0) 
    {
        return 0;
    }

    return 1;
}

int getAvailableClientSocketIndex(ftpDataType * ftpData)
{
    int socketIndex;
    for (socketIndex = 0; socketIndex < ftpData->ftpParameters.maxClients; socketIndex++)
    {
        if (isClientConnected(ftpData, socketIndex) == 0) 
        {
            return socketIndex;
        }
    }

    /* no socket are available for a new client connection */
    return -1;
}

int evaluateClientSocketConnection(ftpDataType * ftpData)
{
    if (FD_ISSET(ftpData->connectionData.theMainSocket, &ftpData->connectionData.rset))
    {
        int availableSocketIndex;
        if ((availableSocketIndex = getAvailableClientSocketIndex(ftpData)) != -1) //get available socket  
        {
            if ((ftpData->clients[availableSocketIndex].socketDescriptor = accept(ftpData->connectionData.theMainSocket, (struct sockaddr *)&ftpData->clients[availableSocketIndex].client_sockaddr_in, (socklen_t*)&ftpData->clients[availableSocketIndex].sockaddr_in_size))!=-1)
            {
                int error, numberOfConnectionFromSameIp, i;
                numberOfConnectionFromSameIp = 0;
                ftpData->connectedClients++;
                ftpData->clients[availableSocketIndex].socketIsConnected = 1;

                error = fcntl(ftpData->clients[availableSocketIndex].socketDescriptor, F_SETFL, O_NONBLOCK);

                fdAdd(ftpData, availableSocketIndex);

                error = getsockname(ftpData->clients[availableSocketIndex].socketDescriptor, (struct sockaddr *)&ftpData->clients[availableSocketIndex].server_sockaddr_in, (socklen_t*)&ftpData->clients[availableSocketIndex].sockaddr_in_server_size);
                inet_ntop(AF_INET,
                          &(ftpData->clients[availableSocketIndex].server_sockaddr_in.sin_addr),
                          ftpData->clients[availableSocketIndex].serverIpAddress,
                          INET_ADDRSTRLEN);
                printf("\n Server IP: %s", ftpData->clients[availableSocketIndex].serverIpAddress);
                printf("Server: New client connected with id: %d", availableSocketIndex);
                printf("\nServer: Clients connected: %d", ftpData->connectedClients);
                sscanf (ftpData->clients[availableSocketIndex].serverIpAddress,"%d.%d.%d.%d",   &ftpData->clients[availableSocketIndex].serverIpAddressInteger[0],
                                                                                                &ftpData->clients[availableSocketIndex].serverIpAddressInteger[1],
                                                                                                &ftpData->clients[availableSocketIndex].serverIpAddressInteger[2],
                                                                                                &ftpData->clients[availableSocketIndex].serverIpAddressInteger[3]);

                inet_ntop(AF_INET,
                          &(ftpData->clients[availableSocketIndex].client_sockaddr_in.sin_addr),
                          ftpData->clients[availableSocketIndex].clientIpAddress,
                          INET_ADDRSTRLEN);
                printf("\n Client IP: %s", ftpData->clients[availableSocketIndex].clientIpAddress);
                ftpData->clients[availableSocketIndex].clientPort = (int) ntohs(ftpData->clients[availableSocketIndex].client_sockaddr_in.sin_port);      
                printf("\nClient port is: %d\n", ftpData->clients[availableSocketIndex].clientPort);

                ftpData->clients[availableSocketIndex].connectionTimeStamp = (int)time(NULL);
                ftpData->clients[availableSocketIndex].lastActivityTimeStamp = (int)time(NULL);
                
                for (i = 0; i <ftpData->ftpParameters.maxClients; i++)
                {
                    if (i == availableSocketIndex)
                    {
                        continue;
                    }
                    
                    if (strcmp(ftpData->clients[availableSocketIndex].clientIpAddress, ftpData->clients[i].clientIpAddress) == 0) {
                        numberOfConnectionFromSameIp++;
                    }
                }
                if (ftpData->ftpParameters.maximumConnectionsPerIp > 0 &&
                    numberOfConnectionFromSameIp >= ftpData->ftpParameters.maximumConnectionsPerIp)
                {
                	int theReturnCode = socketPrintf(ftpData, availableSocketIndex, "sss", "530 too many connection from your ip address ", ftpData->clients[availableSocketIndex].clientIpAddress, " \r\n");
                    ftpData->clients[availableSocketIndex].closeTheClient = 1;
                }
                else
                {
                	int returnCode = socketPrintf(ftpData, availableSocketIndex, "s", ftpData->welcomeMessage);
                	if (returnCode <= 0)
                	{
                		ftpData->clients[availableSocketIndex].closeTheClient = 1;
                	}
                }
                
                return 1;
            }
            else
            {
                //Errors while accepting, socket will be closed
                ftpData->clients[availableSocketIndex].closeTheClient = 1;
                printf("\n2 Errno = %d", errno);
                return 1;
            }
        }
        else
        {
            int socketRefuseFd, socketRefuse_in_size;
            socketRefuse_in_size = sizeof(struct sockaddr_in);
            struct sockaddr_in socketRefuse_sockaddr_in;
            if ((socketRefuseFd = accept(ftpData->connectionData.theMainSocket, (struct sockaddr *)&socketRefuse_sockaddr_in, (socklen_t*)&socketRefuse_in_size))!=-1)
            {
                char *messageToWrite = "10068 Server reached the maximum number of connection, please try later.\r\n";
                write(socketRefuseFd, messageToWrite, strlen(messageToWrite));
                shutdown(socketRefuseFd, SHUT_RDWR);
                close(socketRefuseFd);
            }

            return 0;
        }
    }
    else
    {
        //No new socket
        return 0;
    }
}
