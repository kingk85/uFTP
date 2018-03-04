/*
 * The MIT License
 *
 * Copyright 2018 ugo.
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

#include "../ftpData.h"
#include "connection.h"
#include <unistd.h>
#include <pthread.h>




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
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
        perror("setsockopt(SO_REUSEADDR) failed");

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) 
        perror("setsockopt(SO_REUSEPORT) failed");

  //Bind socket
  errorCode = bind(sock,(struct sockaddr*) &temp,sizeof(temp));

  //Number of client allowed
  errorCode = listen(sock, ftpData->ftpParameters.maxClients + 1);
 
  return sock;
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

void closeSocket(ftpDataType * ftpData, int processingSocket)
{
    //Close the socket
    shutdown(ftpData->clients[processingSocket].socketDescriptor, SHUT_RDWR);
    close(ftpData->clients[processingSocket].socketDescriptor);

    resetClientData(&ftpData->clients[processingSocket], 0);
    resetWorkerData(&ftpData->clients[processingSocket].workerData, 0);
    
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
        pthread_join(ftpData->clients[processingSocket].workerData.workerThread, &pReturn);
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