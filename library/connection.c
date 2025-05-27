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
#define _REENTRANT
#include <pthread.h>
#include <stdarg.h>

#include "../debugHelper.h"
#include "../ftpData.h"
#include "connection.h"
#include "log.h"

#include "debug_defines.h"

static int is_ipv4_mapped_ipv6(const char *ip);

int is_ipv4_mapped_ipv6(const char *ip) {
  size_t prefix_len = strlen("::ffff:");

  // Check if the address starts with the mapped address prefix
  if (strncmp(ip, "::ffff:", prefix_len) != 0) {
    return 0;
  }

  // Check if the remaining part is a valid IPv4 address using existing logic
  return 1;
}

int socketPrintf(ftpDataType * ftpData, int clientId, const char *__restrict __fmt, ...)
{
	#define COMMAND_BUFFER								9600
	#define SOCKET_PRINTF_BUFFER						2048
	ssize_t bytesWritten = 0;
	char theBuffer[SOCKET_PRINTF_BUFFER+1];
	char commandBuffer[COMMAND_BUFFER+1];
	int theStringSize = 0, theCommandSize = 0;
	memset(&theBuffer, 0, SOCKET_PRINTF_BUFFER+1);
	memset(&commandBuffer, 0, COMMAND_BUFFER+1);
	//my_printf("\nWriting to socket id %d, TLS %d: ", clientId, ftpData->clients[clientId].tlsIsEnabled);

	//pthread_mutex_lock(&ftpData->clients[clientId].writeMutex);

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
				memset(&theBuffer, 0, SOCKET_PRINTF_BUFFER+1);
				theStringSize = snprintf(theBuffer, SOCKET_PRINTF_BUFFER, "%d", theInteger);
			}
			break;

			case 'c':
			case 'C':
			{
				int theCharInteger = va_arg(args, int);
				memset(&theBuffer, 0, SOCKET_PRINTF_BUFFER+1);
				theStringSize = snprintf(theBuffer, SOCKET_PRINTF_BUFFER, "%c", theCharInteger);
			}
			break;

			case 'f':
			case 'F':
			{
				float theDouble = va_arg(args, double);
				memset(&theBuffer, 0, SOCKET_PRINTF_BUFFER+1);
				theStringSize = snprintf(theBuffer, SOCKET_PRINTF_BUFFER, "%f", theDouble);
			}
			break;

			case 's':
			case 'S':
			{
				char * theString = va_arg(args, char *);
				memset(&theBuffer, 0, SOCKET_PRINTF_BUFFER+1);
				theStringSize = snprintf(theBuffer, SOCKET_PRINTF_BUFFER, "%s", theString);
			}
			break;

			case 'l':
			case 'L':
			{
				long long int theLongLongInt = va_arg(args, long long int);
				memset(&theBuffer, 0, SOCKET_PRINTF_BUFFER+1);
				theStringSize = snprintf(theBuffer, SOCKET_PRINTF_BUFFER, "%lld",  theLongLongInt);
			}
			break;

			default:
			{
				my_printf("\n Switch is default (%c)", *__fmt);
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

	if (ftpData->clients[clientId].socketIsConnected != 1 ||
		ftpData->clients[clientId].socketDescriptor < 0)
	{
		my_printf("\n Client is not connected!");
		return -1;
	}

	if (ftpData->clients[clientId].tlsIsEnabled != 1)
	{
		//my_printf("\nwriting[%d] %s",theCommandSize, commandBuffer);
		//fflush(0);
		bytesWritten = write(ftpData->clients[clientId].socketDescriptor, commandBuffer, theCommandSize);
	}
	else if (ftpData->clients[clientId].tlsIsEnabled == 1)
	{
		#ifdef OPENSSL_ENABLED
		bytesWritten = SSL_write(ftpData->clients[clientId].ssl, commandBuffer, theCommandSize);
		#endif
	}

	//my_printf("\n%s", commandBuffer);

	//pthread_mutex_unlock(&ftpData->clients[clientId].writeMutex);

	return bytesWritten;
}

int socketWorkerPrintf(ftpDataType * ftpData, int clientId, const char *__restrict __fmt, ...)
{
	#define COMMAND_BUFFER								9600
	#define SOCKET_PRINTF_BUFFER2						4096

	int bytesWritten = 0, i = 0, theStringToWriteSize = 0;
	char theBuffer[SOCKET_PRINTF_BUFFER2+1];
	char writeBuffer[COMMAND_BUFFER+1];
	int theStringSize = 0;

	memset(&theBuffer, 0, SOCKET_PRINTF_BUFFER2+1);
	memset(&writeBuffer, 0, COMMAND_BUFFER+1);

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
				memset(&theBuffer, 0, SOCKET_PRINTF_BUFFER2+1);
				theStringSize = snprintf(theBuffer, SOCKET_PRINTF_BUFFER2, "%d", theInteger);
			}
			break;

			case 'c':
			case 'C':
			{
				int theCharInteger = va_arg(args, int);
				memset(&theBuffer, 0, SOCKET_PRINTF_BUFFER2+1);
				theStringSize = snprintf(theBuffer, SOCKET_PRINTF_BUFFER2, "%c", theCharInteger);
			}
			break;

			case 'f':
			case 'F':
			{
				float theDouble = va_arg(args, double);
				memset(&theBuffer, 0, SOCKET_PRINTF_BUFFER2+1);
				theStringSize = snprintf(theBuffer, SOCKET_PRINTF_BUFFER2, "%f", theDouble);
			}
			break;

			case 's':
			case 'S':
			{
				char * theString = va_arg(args, char *);
				memset(&theBuffer, 0, SOCKET_PRINTF_BUFFER2+1);
				theStringSize = snprintf(theBuffer, SOCKET_PRINTF_BUFFER2, "%s", theString);
			}
			break;

			case 'l':
			case 'L':
			{
				long long int theLongLongInt = va_arg(args, long long int);
				memset(&theBuffer, 0, SOCKET_PRINTF_BUFFER2+1);
				theStringSize = snprintf(theBuffer, SOCKET_PRINTF_BUFFER2, "%lld",  theLongLongInt);
			}
			break;

			default:
			{
				my_printf("\n Switch is default (%c)", *__fmt);
			}
			break;
		}
		++__fmt;


		for (i = 0; i <theStringSize; i++)
		{
			//Write the buffer
			if (theStringToWriteSize >= COMMAND_BUFFER)
			{
				my_printf("\nwriting:\n%s", writeBuffer);

				ssize_t theReturnCode = 0;
				if (ftpData->clients[clientId].dataChannelIsTls != 1)
				{
					theReturnCode = write(ftpData->clients[clientId].workerData.socketConnection, writeBuffer, theStringToWriteSize);
				}
				else if (ftpData->clients[clientId].dataChannelIsTls == 1)
				{
					#ifdef OPENSSL_ENABLED
					if (ftpData->clients[clientId].workerData.passiveModeOn == 1){
						theReturnCode = SSL_write(ftpData->clients[clientId].workerData.serverSsl, writeBuffer, theStringToWriteSize);
						//my_printf("%s", writeBuffer);
					}
					else if (ftpData->clients[clientId].workerData.activeModeOn == 1){
						theReturnCode = SSL_write(ftpData->clients[clientId].workerData.clientSsl, writeBuffer, theStringToWriteSize);
						//my_printf("%s", writeBuffer);
					}
					#endif
				}

				if (theReturnCode > 0)
				{
					bytesWritten += theReturnCode;
				}

				if (theReturnCode < 0)
				{
					my_printf("\nWrite error");
					va_end(args);
					return theReturnCode;
				}

				memset(&writeBuffer, 0, COMMAND_BUFFER+1);
				theStringToWriteSize = 0;
			}

			if (theStringToWriteSize < COMMAND_BUFFER)
			{
				writeBuffer[theStringToWriteSize++] = theBuffer[i];
			}
		}
	}
	va_end(args);


	//my_printf("\nData to write: %s (%d bytes)", writeBuffer, theStringToWriteSize);
	//Write the buffer
	if (theStringToWriteSize > 0)
	{

		my_printf("\nwriting:\n%s", writeBuffer);
		//my_printf("\nwriting data size %d", theStringToWriteSize);
		int theReturnCode = 0;

		if (ftpData->clients[clientId].dataChannelIsTls != 1)
		{
			theReturnCode = write(ftpData->clients[clientId].workerData.socketConnection, writeBuffer, theStringToWriteSize);
		}
		else if (ftpData->clients[clientId].dataChannelIsTls == 1)
		{
			#ifdef OPENSSL_ENABLED
			if (ftpData->clients[clientId].workerData.passiveModeOn == 1){
				theReturnCode = SSL_write(ftpData->clients[clientId].workerData.serverSsl, writeBuffer, theStringToWriteSize);
				//my_printf("%s", writeBuffer);
			}
			else if (ftpData->clients[clientId].workerData.activeModeOn == 1){
				theReturnCode = SSL_write(ftpData->clients[clientId].workerData.clientSsl, writeBuffer, theStringToWriteSize);
				//my_printf("%s", writeBuffer);
			}
			#endif
		}

		if (theReturnCode > 0)
		{
			bytesWritten += theReturnCode;
		}

		if (theReturnCode < 0)
		{
			return theReturnCode;
		}

		memset(&writeBuffer, 0, COMMAND_BUFFER+1);
		theStringToWriteSize = 0;
	}

	//my_printf("\nbytesWritten = %d", bytesWritten);

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

#ifdef IPV6_ENABLED

int isPortInUse(int port) {
    int sockfd;
    struct sockaddr_in6 addr;

    sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1; // Assume port is in use if we can't create a socket
    }

    int reuse = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    addr.sin6_addr = in6addr_any;

    int result = bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
    close(sockfd);  // Always close after test

    if (result == 0) {
        return 0; // Port is free
    } else if (errno == EADDRINUSE) {
        return 1; // Port is in use
    } else {
        perror("bind");
        return 1; // Other error, treat as in-use
    }
}


int createSocket(ftpDataType * ftpData)
{
  //my_printf("\nCreating main socket on port %d", ftpData->ftpParameters.port);
  int sock = -1, errorCode = -1;
  struct sockaddr_in6 serveraddr;

  //Socket creation IPV6
  if ((sock = socket(AF_INET6, SOCK_STREAM, 0)) < 0)
  {
	perror("socket() failed");
	addLog("Socket creation failed", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
	return -1;
  }

  //No blocking socket
  errorCode = fcntl(sock, F_SETFL, O_NONBLOCK);

  int reuse = 1;

#ifdef SO_REUSEADDR
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse)) < 0) 
	{
		perror("setsockopt(SO_REUSEADDR) failed");
		my_printfError("setsockopt(SO_REUSEADDR) failed");
		addLog("socketopt failed", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
	}
#endif

reuse = 1;
#ifdef SO_REUSEPORT
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) 
	{
		perror("setsockopt(SO_REUSEADDR) failed");
		my_printfError("setsockopt(SO_REUSEADDR) failed");
		addLog("setsocket error", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
	}
#endif


	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin6_family = AF_INET6;
	serveraddr.sin6_port   = htons(ftpData->ftpParameters.port);
	serveraddr.sin6_addr   = in6addr_any;

	if (bind(sock, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0)
	{
		close(sock);
		perror("bind() failed");
		addLog("bind failed", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
		return -1;
	}

  //Number of client allowed
  errorCode = listen(sock, ftpData->ftpParameters.maxClients + 1);
  if (errorCode < 0)
  {
	  addLog("listen error", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);	
	  if (sock != -1)
	  {
		close(sock);
	  }
	  return -1;
  }
 
  return sock;
}

int createPassiveSocket(int port)
{
    int sock, returnCode;
    struct sockaddr_in6 serveraddr;
    int max_retries = 12;       // number of bind retries
    int retry_delay_sec = 1;   // delay between retries

    if ((sock = socket(AF_INET6, SOCK_STREAM, 0)) < 0)
    {
        perror("socket() failed");
        addLog("socket failed", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
        return -1;
    }

    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin6_family = AF_INET6;
    serveraddr.sin6_port   = htons(port);
    serveraddr.sin6_addr   = in6addr_any;

    int reuse = 1;
#ifdef SO_REUSEADDR
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
    {
        perror("setsockopt(SO_REUSEADDR) failed");
        my_printfError("setsockopt(SO_REUSEADDR) failed");
        addLog("setsocketerror", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
    }
#endif

#ifdef SO_REUSEPORT
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0)
    {
        perror("setsockopt(SO_REUSEPORT) failed");
        my_printfError("setsockopt(SO_REUSEPORT) failed");
        addLog("setsocketerror", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
    }
#endif

    // Retry bind if fails with EADDRINUSE
    for (int i = 0; i < max_retries; i++)
    {
        returnCode = bind(sock, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
        if (returnCode == 0)
		{
			if(i > 0)
				printf("\n Success After: %d attempts", i);
			break;
		}

        if (errno == EADDRINUSE)
        {
            my_printf("Bind failed with EADDRINUSE on port: %d, retrying %d/%d...\n",port,  i + 1, max_retries);
            sleep(retry_delay_sec); // wait before retrying
        }
        else
        {
            // Other bind errors: fail immediately
            perror("bind() failed");
            addLog("bind failed", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
            close(sock);
            return -1;
        }
    }

    if (returnCode != 0)
    {
        my_printf("Bid failed after %d retries, errno=%d\n", max_retries, errno);
		addLog("bind failed failed after all attempts!", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
        close(sock);
        return -1;
    }

    // Listen
    returnCode = listen(sock, 1);
    if (returnCode == -1)
    {
        addLog("listen failed", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
        my_printf("\nCould not listen %d errno = %d", sock, errno);
        if (sock != -1)
            close(sock);
        return -1;
    }

    return sock;
}

#else

int isPortInUse(int port) {
    int sockfd;
    struct sockaddr_in addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1; // Assume port is in use if we can't create a socket
    }

    int reuse = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    int result = bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
    close(sockfd);  // Always close after test

    if (result == 0) {
        return 0; // Port is free
    } else if (errno == EADDRINUSE) {
        return 1; // Port is in use
    } else {
        perror("bind");
        return 1; // Other error, treat as in-use
    }
}

int createSocket(ftpDataType * ftpData)
{
  //my_printf("\nCreating main socket on port %d", ftpData->ftpParameters.port);
  int sock, errorCode;
  struct sockaddr_in temp;

  //Socket creation
  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == -1)
  {
	  return -1;
  }
  temp.sin_family = AF_INET;
  temp.sin_addr.s_addr = INADDR_ANY;
  temp.sin_port = htons(ftpData->ftpParameters.port);

  //No blocking socket
  errorCode = fcntl(sock, F_SETFL, O_NONBLOCK);

    int reuse = 1;
    
#ifdef SO_REUSEADDR
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) 
	{
		perror("setsockopt(SO_REUSEADDR) failed");
		my_printfError("setsockopt(SO_REUSEADDR) failed");
		addLog("socketopt failed", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
	}

#endif

#ifdef SO_REUSEPORT
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) 
	{
		perror("setsockopt(SO_REUSEADDR) failed");
		my_printfError("setsockopt(SO_REUSEADDR) failed");
		addLog("setsocket error", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
	}
#endif
  //Bind socket
  errorCode = bind(sock,(struct sockaddr*) &temp,sizeof(temp));
  if (errorCode == -1)
  {
	  if (sock != -1)
	  {
		close(sock);
	  }
	  return -1;
  }

  //Number of client allowed
  errorCode = listen(sock, ftpData->ftpParameters.maxClients + 1);
  if (errorCode == -1)
  {
	  if (sock != -1)
	  {
		close(sock);
	  }
	  return -1;
  }
 
  return sock;
}

int createPassiveSocket(int port)
{
    int sock, returnCode;
    struct sockaddr_in serveraddr;
    int max_retries = 12;       // number of bind retries
    int retry_delay_sec = 1;    // delay between retries

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket() failed");
        addLog("socket failed", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
        return -1;
    }

    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(port);
    serveraddr.sin_addr.s_addr = INADDR_ANY;

    int reuse = 1;
#ifdef SO_REUSEADDR
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
    {
        perror("setsockopt(SO_REUSEADDR) failed");
        my_printfError("setsockopt(SO_REUSEADDR) failed");
        addLog("setsocketerror", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
    }
#endif

#ifdef SO_REUSEPORT
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0)
    {
        perror("setsockopt(SO_REUSEPORT) failed");
        my_printfError("setsockopt(SO_REUSEPORT) failed");
        addLog("setsocketerror", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
    }
#endif

    // Retry bind if it fails with EADDRINUSE
    for (int i = 0; i < max_retries; i++)
    {
        returnCode = bind(sock, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
        if (returnCode == 0)
        {
            if (i > 0)
                printf("\n Success After: %d attempts", i);
            break;
        }

        if (errno == EADDRINUSE)
        {
            my_printf("Bind failed with EADDRINUSE on port: %d, retrying %d/%d...\n", port, i + 1, max_retries);
            sleep(retry_delay_sec);
        }
        else
        {
            perror("bind() failed");
            addLog("bind failed", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
            close(sock);
            return -1;
        }
    }

    if (returnCode != 0)
    {
        my_printf("Bind failed after %d retries, errno=%d\n", max_retries, errno);
        addLog("bind failed after all attempts!", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
        close(sock);
        return -1;
    }

    // Start listening
    returnCode = listen(sock, 1);
    if (returnCode == -1)
    {
        addLog("listen failed", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
        my_printf("\nCould not listen %d errno = %d", sock, errno);
        close(sock);
        return -1;
    }

    return sock;
}

#endif

#ifdef IPV6_ENABLED
int createActiveSocketV6(int port, char *ipAddress)
{
	int sockfd;
	struct sockaddr_in6 serv_addr6;
	struct sockaddr *serv_addr_any;

    // Creating socket
    if ((sockfd = socket(AF_INET6, SOCK_STREAM, 0)) < 0) 
	{
		my_printfError("Socket creation failed");
		addLog("Socket creation failed", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
        return -1;
    }

  int reuse = 1;
#ifdef SO_REUSEADDR
   if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
	{
		perror("setsockopt(SO_REUSEADDR) failed");
		my_printfError("setsockopt(SO_REUSEADDR) failed");
		addLog("set socket error", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
	}
#endif

#ifdef SO_REUSEPORT
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) 
	{
		perror("setsockopt(SO_REUSEADDR) failed");
		my_printfError("setsockopt(SO_REUSEADDR) failed");
		addLog("setsockopt error", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
	}
#endif

    // Prepare the sockaddr structure
    if (inet_pton(AF_INET6, ipAddress, &serv_addr6.sin6_addr) == 1) 
	{
        serv_addr6.sin6_family = AF_INET6;
        serv_addr6.sin6_port = htons(port);
        serv_addr_any = (struct sockaddr *)&serv_addr6;
    } 
	else 
	{
		my_printfError("Invalid ip address");
		addLog("Invalid ip address", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
        return -1;
    }

    // Connect to server
    if (connect(sockfd, serv_addr_any, sizeof(serv_addr6)) < 0) 
	{
		my_printfError("Connection failed");
		addLog("Connection failed", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
		return -1;
    }

  return sockfd;
}
#endif

int createActiveSocket(int port, char *ipAddress)
{
  int sockfd;
  struct sockaddr_in serv_addr;

  my_printf("\n Connection socket is going to start ip: %s:%d \n", ipAddress, port);
  memset(&serv_addr, 0, sizeof(struct sockaddr_in)); 
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port); 
  if(inet_pton(AF_INET, ipAddress, &serv_addr.sin_addr)<=0)
  {
      my_printf("\n inet_pton error occured at address: %s:%d\n", ipAddress, port);
      return -1;
  } 

  if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
      my_printf("\n2 Error : Could not create socket \n");
      return -1;
  }
  else
  {
      my_printf("\ncreateActiveSocket created socket = %d \n", sockfd);
  }
  
  
  int reuse = 1;
#ifdef SO_REUSEADDR
   if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
	{
		perror("setsockopt(SO_REUSEADDR) failed");
		my_printfError("setsockopt(SO_REUSEADDR) failed");
		addLog("set socket error", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
	}
#endif

#ifdef SO_REUSEPORT
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) 
	{
		perror("setsockopt(SO_REUSEADDR) failed");
		my_printfError("setsockopt(SO_REUSEADDR) failed");
		addLog("setsockopt error", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
	}
#endif
  

  if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
  {
     my_printf("\n3 Error : Connect Failed \n");

   	  if (sockfd != -1)
   	  {
   		close(sockfd);
   	  }

     return -1;
  }

 // my_printf("\n Connection socket %d is going to start ip: %s:%d \n",sockfd, ipAddress, port);

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
	int theReturnCode = 0;

#ifdef OPENSSL_ENABLED

	if (ftpData->clients[processingSocket].dataChannelIsTls == 1)
	{
		if(ftpData->clients[processingSocket].workerData.passiveModeOn == 1)
		{
			my_printf("\nSSL worker Shutdown 1");
			theReturnCode = SSL_shutdown(ftpData->clients[processingSocket].ssl);
			my_printf("\nnSSL worker Shutdown 1 return code : %d", theReturnCode);

			if (theReturnCode < 0)
			{
				my_printf("SSL_shutdown failed return code %d", theReturnCode);
			}
			else if (theReturnCode == 0)
			{
				my_printf("\nSSL worker Shutdown 2");
				theReturnCode = SSL_shutdown(ftpData->clients[processingSocket].ssl);
				my_printf("\nnSSL worker Shutdown 2 return code : %d", theReturnCode);

				if (theReturnCode <= 0)
				{
					my_printf("SSL_shutdown (2nd time) failed");
				}
			}
		}
	}
#endif

    //Close the socket
    shutdown(ftpData->clients[processingSocket].socketDescriptor, SHUT_RDWR);
    theReturnCode = close(ftpData->clients[processingSocket].socketDescriptor);

    resetClientData(ftpData, processingSocket, 0);
    //resetWorkerData(ftpData, processingSocket, 0);
    
    //Update client connecteds
    ftpData->connectedClients--;
    if (ftpData->connectedClients < 0) 
    {
        ftpData->connectedClients = 0;
    }

    //my_printf("Client id: %d disconnected", processingSocket);
    //my_printf("\nServer: Clients connected:%d", ftpData->connectedClients);
    return;
}

void closeClient(ftpDataType * ftpData, int processingSocket)
{
   // my_printf("\nQUIT FLAG SET!\n");

    if (ftpData->clients[processingSocket].workerData.threadIsAlive == 1)
    {
    	cancelWorker(ftpData, processingSocket);
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
				addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC); 
            }
    }
}

void flushLoginWrongTriesData(ftpDataType * ftpData)
{
    int i;
    //my_printf("\n flushLoginWrongTriesData size of the vector : %d", ftpData->loginFailsVector.Size);
    
    for (i = (ftpData->loginFailsVector.Size-1); i >= 0; i--)
    {
        //my_printf("\n last login fail attempt : %d", ((loginFailsDataType *) ftpData->loginFailsVector.Data[i])->failTimeStamp);
        
        if ( (time(NULL) - ((loginFailsDataType *) ftpData->loginFailsVector.Data[i])->failTimeStamp) > WRONG_PASSWORD_ALLOWED_RETRY_TIME)
        {
            //my_printf("\n Deleting element : %d", i);
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


#ifdef IPV6_ENABLED

#warning IPV6 IS ENABLED
int evaluateClientSocketConnection(ftpDataType * ftpData)
{
	char str[INET6_ADDRSTRLEN];

    if (FD_ISSET(ftpData->connectionData.theMainSocket, &ftpData->connectionData.rset))
    {
        int availableSocketIndex;
        if ((availableSocketIndex = getAvailableClientSocketIndex(ftpData)) != -1) //get available socket  
        {
            if ((ftpData->clients[availableSocketIndex].socketDescriptor = accept(ftpData->connectionData.theMainSocket, (struct sockaddr *)&ftpData->clients[availableSocketIndex].client_sockaddr_in, (socklen_t*)&ftpData->clients[availableSocketIndex].sockaddr_in_size)) !=- 1)
            {
                int error, numberOfConnectionFromSameIp, i;
                numberOfConnectionFromSameIp = 0;
                ftpData->connectedClients++;
                ftpData->clients[availableSocketIndex].socketIsConnected = 1;

                error = fcntl(ftpData->clients[availableSocketIndex].socketDescriptor, F_SETFL, O_NONBLOCK);

                fdAdd(ftpData, availableSocketIndex);

				// -  - //
				ftpData->clients[availableSocketIndex].sockaddr_in_server_size = sizeof(ftpData->clients[availableSocketIndex].server_sockaddr_in);
				ftpData->clients[availableSocketIndex].sockaddr_in_size = sizeof(ftpData->clients[availableSocketIndex].client_sockaddr_in);	

				getpeername(ftpData->clients[availableSocketIndex].socketDescriptor, (struct sockaddr *)&ftpData->clients[availableSocketIndex].client_sockaddr_in, &ftpData->clients[availableSocketIndex].sockaddr_in_size);
				if(inet_ntop(AF_INET6, &ftpData->clients[availableSocketIndex].client_sockaddr_in.sin6_addr, ftpData->clients[availableSocketIndex].clientIpAddress, sizeof(ftpData->clients[availableSocketIndex].clientIpAddress))) 
				{
					ftpData->clients[availableSocketIndex].clientPort = (int) ntohs(ftpData->clients[availableSocketIndex].client_sockaddr_in.sin6_port);
				}


				getsockname(ftpData->clients[availableSocketIndex].socketDescriptor, (struct sockaddr *)&ftpData->clients[availableSocketIndex].server_sockaddr_in, &ftpData->clients[availableSocketIndex].sockaddr_in_server_size);
				if(inet_ntop(AF_INET6, &ftpData->clients[availableSocketIndex].server_sockaddr_in.sin6_addr, ftpData->clients[availableSocketIndex].serverIpAddress, sizeof(ftpData->clients[availableSocketIndex].serverIpAddress))) 
				{
					;
				}

				if (is_ipv4_mapped_ipv6(ftpData->clients[availableSocketIndex].clientIpAddress))
				{

					sscanf (ftpData->clients[availableSocketIndex].serverIpAddress,"::ffff:%d.%d.%d.%d", &ftpData->clients[availableSocketIndex].serverIpV4AddressInteger[0],
																									&ftpData->clients[availableSocketIndex].serverIpV4AddressInteger[1],
																									&ftpData->clients[availableSocketIndex].serverIpV4AddressInteger[2],
																									&ftpData->clients[availableSocketIndex].serverIpV4AddressInteger[3]);
				}
				else
				{
					;
				}

				// Check if it's an IPv4-mapped address
				if (is_ipv4_mapped_ipv6(ftpData->clients[availableSocketIndex].clientIpAddress))
				{
					ftpData->clients[availableSocketIndex].isIpV6 = 0;
				}
				else 
				{
					ftpData->clients[availableSocketIndex].isIpV6 = 1;
				}


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
					addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC); 
                }
                else
                {
                	int returnCode = socketPrintf(ftpData, availableSocketIndex, "s", ftpData->welcomeMessage);
                	if (returnCode <= 0)
                	{
                		ftpData->clients[availableSocketIndex].closeTheClient = 1;
						addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC); 
                	}
                }
                
                return 1;
            }
            else
            {
                //Errors while accepting, socket will be closed
                ftpData->clients[availableSocketIndex].closeTheClient = 1;
				//addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC); 
                //my_printf("\n2 Errno = %d", errno);
                return 1;
            }
        }
        else
        {
            int socketRefuseFd;
            struct sockaddr_in6 socketRefuse_sockaddr_in;
			socklen_t socketRefuse_in_size = sizeof(socketRefuse_sockaddr_in);
            if ((socketRefuseFd = accept(ftpData->connectionData.theMainSocket, (struct sockaddr *)&socketRefuse_sockaddr_in, &socketRefuse_in_size))!=-1)
            {
            	int theReturnCode = 0;
                char *messageToWrite = "10068 Server reached the maximum number of connection, please try later.\r\n";
                write(socketRefuseFd, messageToWrite, strlen(messageToWrite));
                shutdown(socketRefuseFd, SHUT_RDWR);
                theReturnCode = close(socketRefuseFd);
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

#else

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
                //my_printf("\n Server IP: %s", ftpData->clients[availableSocketIndex].serverIpAddress);
                //my_printf("Server: New client connected with id: %d", availableSocketIndex);
                //my_printf("\nServer: Clients connected: %d", ftpData->connectedClients);
                sscanf (ftpData->clients[availableSocketIndex].serverIpAddress,"%d.%d.%d.%d",   &ftpData->clients[availableSocketIndex].serverIpV4AddressInteger[0],
                                                                                                &ftpData->clients[availableSocketIndex].serverIpV4AddressInteger[1],
                                                                                                &ftpData->clients[availableSocketIndex].serverIpV4AddressInteger[2],
                                                                                                &ftpData->clients[availableSocketIndex].serverIpV4AddressInteger[3]);

                inet_ntop(AF_INET,
                          &(ftpData->clients[availableSocketIndex].client_sockaddr_in.sin_addr),
                          ftpData->clients[availableSocketIndex].clientIpAddress,
                          INET_ADDRSTRLEN);
                //my_printf("\n Client IP: %s", ftpData->clients[availableSocketIndex].clientIpAddress);
                ftpData->clients[availableSocketIndex].clientPort = (int) ntohs(ftpData->clients[availableSocketIndex].client_sockaddr_in.sin_port);      
                //my_printf("\nClient port is: %d\n", ftpData->clients[availableSocketIndex].clientPort);

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
					addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC); 
                }
                else
                {
                	int returnCode = socketPrintf(ftpData, availableSocketIndex, "s", ftpData->welcomeMessage);
                	if (returnCode <= 0)
                	{
                		ftpData->clients[availableSocketIndex].closeTheClient = 1;
						addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC); 
                	}
                }
                
                return 1;
            }
            else
            {
                //Errors while accepting, socket will be closed
                ftpData->clients[availableSocketIndex].closeTheClient = 1;
				//addLog("Closing the client", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC); 
                //my_printf("\n2 Errno = %d", errno);
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
            	int theReturnCode = 0;
                char *messageToWrite = "10068 Server reached the maximum number of connection, please try later.\r\n";
                write(socketRefuseFd, messageToWrite, strlen(messageToWrite));
                shutdown(socketRefuseFd, SHUT_RDWR);
                theReturnCode = close(socketRefuseFd);
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

#endif

#ifdef OPENSSL_ENABLED
int acceptSSLConnection(int theSocketId, ftpDataType * ftpData)
{
    SSL *ssl = ftpData->clients[theSocketId].workerData.serverSsl;
    int sockfd = ftpData->clients[theSocketId].workerData.socketConnection;

    my_printf("\nSSL SSL_set_fd start");
    
    int rc = SSL_set_fd(ssl, sockfd);
    if (rc == 0)
    {
        my_printf("\nSSL ERRORS ON SSL_set_fd");
        ftpData->clients[theSocketId].closeTheClient = 1;
        addLog("Closing client SSL_set_fd", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
        return -1;
    }
    my_printf("\nSSL SSL_set_fd end");

    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1)
    {
        perror("fcntl get flags");
        ftpData->clients[theSocketId].closeTheClient = 1;
        return -1;
    }

    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        perror("fcntl set nonblocking");
        ftpData->clients[theSocketId].closeTheClient = 1;
        return -1;
    }

    my_printf("\nSSL accept start");

    // Reuse the session from control connection
    SSL_SESSION *session = SSL_get_session(ftpData->clients[theSocketId].ssl);

    if (session != NULL) 
    {
        unsigned int len;
        const unsigned char *id = SSL_SESSION_get_id(session, &len);

        my_printf("Trying to reuse SSL Session ID: ");
        for (unsigned int i = 0; i < len; i++) {
            my_printf("%02X", id[i]);
        }
        my_printf("\n");

        SSL_set_session(ssl, session);
    } else {
        my_printf("\nNo session available for reuse. Accepting fresh handshake.\n");
    }



    SSL_set_accept_state(ssl);

    int max_attempts = 500; // 500*10ms = 5 sec timeout
    while (max_attempts--)
    {
        rc = SSL_accept(ssl);

        if (rc == 1)
        {
            my_printf("\n------------------------------------------- SSL_accept success");
            break;
        }

        int err = SSL_get_error(ssl, rc);
        //my_printf("\nSSL_accept err: %d\n", err);

        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        {
            usleep(10000); // 10 ms
            //my_printf("\nSSL_accept waiting ...");
            continue;
        }
        else
        {
            my_printf("\n-------------------------------------------SSL_accept failed:");
            ERR_print_errors_fp(stderr);
            ftpData->clients[theSocketId].closeTheClient = 1;
            addLog("Closing client SSL_accept", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
            return -1;
        }

    }

    if (max_attempts <= 0)
    {
        my_printf("\nSSL_accept timeout");
        ftpData->clients[theSocketId].closeTheClient = 1;
        return -1;
    }

    if (SSL_session_reused(ssl)) {
        my_printf("\n**** FTPS data connection reused control TLS session.\n");
    } else {
        my_printf("\n**** FTPS data connection did NOT reuse TLS session.\n");
    }

    if (fcntl(sockfd, F_SETFL, flags) == -1)
    {
        perror("fcntl set blocking");
        ftpData->clients[theSocketId].closeTheClient = 1;
        return -1;
    }   

    return 1;
}
#endif