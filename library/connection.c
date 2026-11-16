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
#include <time.h>
#include <poll.h>
#include <stdarg.h>

#include "../debugHelper.h"
#include "../ftpData.h"
#include "connection.h"
#include "openSsl.h"
#include "log.h"

#include "debug_defines.h"

#ifdef IPV6_ENABLED
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
#endif

void logClientf(ftpDataType *ftpData, int clientId, int isAccessRecord, const char *file, int line,
                const char *function, const char *prefix, const char *fmt, ...)
{
    char message[2048];
    int used;
    va_list args;
    clientDataType *client = &ftpData->clients[clientId];

    used = snprintf(message, sizeof(message), "%s[%d %s %s] ", prefix, clientId,
                    client->clientIpAddress[0] != '\0' ? client->clientIpAddress : "-",
                    (client->login.userLoggedIn == 1 && client->logUserName[0] != '\0') ? client->logUserName : "-");
    if (used < 0 || used >= (int)sizeof(message))
        return;

    va_start(args, fmt);
    vsnprintf(message + used, sizeof(message) - used, fmt, args);
    va_end(args);

    logMessageRecord(message, file, line, function, isAccessRecord);
}

#ifdef OPENSSL_ENABLED
/* Why a TLS handshake on the control connection failed: the OpenSSL error queue, or
   the system error (connection closed or reset by the client) */
void logTlsHandshakeFailure(ftpDataType *ftpData, int clientId, int sslError)
{
    char reason[200] = "";
    unsigned long queued = ERR_get_error();

    if (queued != 0)
        ERR_error_string_n(queued, reason, sizeof(reason));
    else if (sslError == SSL_ERROR_SYSCALL)
        snprintf(reason, sizeof(reason), "%s", errno != 0 ? strerror(errno) : "connection closed by the client");
    else if (sslError == SSL_ERROR_ZERO_RETURN)
        snprintf(reason, sizeof(reason), "connection closed by the client");
    else
        snprintf(reason, sizeof(reason), "TLS error %d", sslError);

    ERR_clear_error();
    LOG_CLIENT(ftpData, clientId, LOG_ERROR_PREFIX, "TLS handshake failed: %s", reason);
}
#endif

void setCloseReason(ftpDataType *ftpData, int clientId, const char *reason)
{
    if (ftpData->clients[clientId].closeReason == NULL)
        ftpData->clients[clientId].closeReason = reason;
}

void markClientForClosing(ftpDataType *ftpData, int clientId, const char *reason)
{
    setCloseReason(ftpData, clientId, reason);
    ftpData->clients[clientId].closeTheClient = 1;
}

/* Text address (ipv4 or ipv6) to ipv6 binary form, ipv4 becomes ipv4-mapped
   (::ffff:a.b.c.d): addresses can then be compared whatever the socket family.
   Returns 1, or 0 if theAddress is not an address. */
int ipAddressToBinary(const char *theAddress, struct in6_addr *binary)
{
    struct in_addr ipv4;

    if (theAddress == NULL)
        return 0;

    if (inet_pton(AF_INET, theAddress, &ipv4) == 1)
    {
        memset(binary, 0, sizeof(struct in6_addr));
        binary->s6_addr[10] = 0xff;
        binary->s6_addr[11] = 0xff;
        memcpy(&binary->s6_addr[12], &ipv4, sizeof(ipv4));
        return 1;
    }

    return inet_pton(AF_INET6, theAddress, binary) == 1;
}

/* 1 if two text addresses are the same host (an ipv4 address and its ipv4-mapped
   ipv6 form are the same) */
int isSameIpAddress(const char *firstAddress, const char *secondAddress)
{
    struct in6_addr first, second;

    if (ipAddressToBinary(firstAddress, &first) == 0 || ipAddressToBinary(secondAddress, &second) == 0)
        return 0;

    return memcmp(&first, &second, sizeof(struct in6_addr)) == 0;
}

/* 1 if the peer of a socket (sockaddr_in or sockaddr_in6) is the host theAddress
   (text form), so a dual stack socket and an ipv4 control connection match. */
int isPeerFromAddress(const struct sockaddr *peer, const char *theAddress)
{
    char peerText[INET6_ADDRSTRLEN];

    if (peer == NULL)
        return 0;

    if (peer->sa_family == AF_INET)
    {
        if (inet_ntop(AF_INET, &((const struct sockaddr_in *)peer)->sin_addr, peerText, sizeof(peerText)) == NULL)
            return 0;
    }
    else if (peer->sa_family == AF_INET6)
    {
        if (inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)peer)->sin6_addr, peerText, sizeof(peerText)) == NULL)
            return 0;
    }
    else
    {
        return 0;
    }

    return isSameIpAddress(peerText, theAddress);
}

/* One item of the format string of socketPrintf() / socketWorkerPrintf():
   d = int, c = char, f = double, l = long long, s = string.

   Returns the bytes to copy and sets *length. Numbers are written into buffer; a
   string is returned as it is, with its real length (it used to be copied
   through snprintf into buffer, and the value returned by snprintf, the length the
   string WOULD have had, was then used to read from buffer: with a longer string the
   copy ran past the buffer and sent stack memory to the client). */
static const char *formatReplyItem(char theFormat, va_list *args, char *buffer, size_t bufferSize, int *length)
{
	int written = 0;

	switch (theFormat)
	{
		case 'd':
		case 'D':
			written = snprintf(buffer, bufferSize, "%d", va_arg(*args, int));
			break;

		case 'c':
		case 'C':
			written = snprintf(buffer, bufferSize, "%c", va_arg(*args, int));
			break;

		case 'f':
		case 'F':
			written = snprintf(buffer, bufferSize, "%f", (float)va_arg(*args, double));
			break;

		case 'l':
		case 'L':
			written = snprintf(buffer, bufferSize, "%lld", va_arg(*args, long long int));
			break;

		case 's':
		case 'S':
		{
			const char *theString = va_arg(*args, char *);

			if (theString == NULL)
				theString = "(null)";

			*length = (int)strlen(theString);
			return theString;
		}

		default:
			my_printf("\n Switch is default (%c)", theFormat);
			buffer[0] = '\0';
			break;
	}

	/* snprintf returns the untruncated length, or a negative value on error */
	if (written < 0)
		written = 0;
	if ((size_t)written > bufferSize - 1)
		written = (int)(bufferSize - 1);

	*length = written;
	return buffer;
}

/* write() of a whole reply on the control socket, which is non-blocking. A single
   write() used to be enough: a full send buffer (EAGAIN, the client not reading for a
   moment) closed the client at once, and a partial write lost the rest of the reply
   without an error. Now it waits for the socket, like the TLS replies, up to
   CONTROL_WRITE_TIMEOUT_MS. Returns the bytes written (all) or -1 with errno set. */
static ssize_t writeControlBounded(int fd, const char *buffer, size_t length, int timeoutMs)
{
    size_t written = 0;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long long int deadline = (long long int)now.tv_sec * 1000 + now.tv_nsec / 1000000 + timeoutMs;

    while (written < length)
    {
        ssize_t result = write(fd, buffer + written, length - written);

        if (result > 0)
        {
            written += (size_t)result;
            continue;
        }

        if (result < 0 && errno == EINTR)
            continue;

        if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            clock_gettime(CLOCK_MONOTONIC, &now);
            long long int remaining = deadline - ((long long int)now.tv_sec * 1000 + now.tv_nsec / 1000000);
            struct pollfd descriptor = { .fd = fd, .events = POLLOUT, .revents = 0 };

            if (remaining <= 0)
            {
                errno = ETIMEDOUT;
                return -1;
            }

            if (poll(&descriptor, 1, (int)remaining) < 0 && errno != EINTR)
                return -1;
            continue;
        }

        return -1;
    }

    return (ssize_t)written;
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

	/* bytes of the current item to copy, see formatReplyItem() */
	const char *theSource = theBuffer;

	va_list args;
	va_start(args, __fmt);
	while (*__fmt != '\0')
	{
		int i = 0;
		theStringSize = 0;
		theSource = formatReplyItem(*__fmt, &args, theBuffer, sizeof(theBuffer), &theStringSize);

		for (i = 0; i <theStringSize; i++)
		{
			if (theCommandSize < COMMAND_BUFFER)
			{
				commandBuffer[theCommandSize++] = theSource[i];
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

	/* The control thread and the data worker (227/229/200/226/550 replies) both write
	   here: one reply at a time, and never two SSL calls on the same SSL object at once
	   (OpenSSL objects are not thread safe). Cancellation is disabled while the mutex
	   is held: a worker cancelled inside write() would leave it locked for ever. */
	int previousCancelState;
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previousCancelState);
	pthread_mutex_lock(&ftpData->clients[clientId].writeMutex);

	if (ftpData->clients[clientId].tlsIsEnabled != 1)
	{
		bytesWritten = writeControlBounded(ftpData->clients[clientId].socketDescriptor, commandBuffer,
		                                   (size_t)theCommandSize, CONTROL_WRITE_TIMEOUT_MS);
	}
	else if (ftpData->clients[clientId].tlsIsEnabled == 1)
	{
		#ifdef OPENSSL_ENABLED
		/* The control socket is non-blocking: under load (many parallel
		   transfers, as FileZilla does) SSL_write() can return
		   WANT_READ/WANT_WRITE. It used to be a fatal error and the client
		   was closed ("reply could not be sent: TLS error 3"). */
		bytesWritten = tlsWriteBounded(ftpData->clients[clientId].ssl,
		                               ftpData->clients[clientId].socketDescriptor,
		                               commandBuffer, theCommandSize,
		                               CONTROL_WRITE_TIMEOUT_MS);
		#endif
	}

	/* the cause, before anything else can change errno or the OpenSSL error queue */
	char failureCause[160] = "";
	if (bytesWritten <= 0)
	{
		if (ftpData->clients[clientId].tlsIsEnabled == 1)
		{
			#ifdef OPENSSL_ENABLED
			snprintf(failureCause, sizeof(failureCause), "TLS write: %s", strerror(errno));
			#endif
		}
		else
		{
			snprintf(failureCause, sizeof(failureCause), "%s", bytesWritten < 0 ? strerror(errno) : "nothing written");
		}
	}

	pthread_mutex_unlock(&ftpData->clients[clientId].writeMutex);
	pthread_setcancelstate(previousCancelState, NULL);

	/* Every caller closes the client after a failed reply: say it once, here, with the
	   client and the cause (it used to be "socketPrintfError" in dozens of places) */
	if (bytesWritten <= 0)
	{
		setCloseReason(ftpData, clientId, "the reply could not be sent");
		LOG_CLIENT(ftpData, clientId, LOG_ERROR_PREFIX, "reply could not be sent: %s", failureCause);
	}

	return bytesWritten;
}

/* How long a TLS data block may wait for the client to take it: the idle timeout of
   the server (one hour if it is disabled). A client that reads nothing for that long
   is closed by the idle timeout anyway; a shorter limit failed the downloads of
   clients that pause for a few seconds (slow disk, slow link, throttling). The limit
   starts again at every block. */
int dataWriteTimeoutMs(ftpDataType *ftpData)
{
    int seconds = ftpData->ftpParameters.maximumIdleInactivity;

    if (seconds <= 0 || seconds > 86400)
        seconds = 3600;

    return seconds * 1000;
}

/* Writes a block on the data channel, plain or TLS. Plain write() can be
   partial; SSL_write() on a non-blocking socket can return WANT_READ/WANT_WRITE
   and the old code ignored both cases. Returns the bytes written (the whole
   block) or -1. */
static ssize_t writeDataChannelBuffer(ftpDataType *ftpData, int clientId, const char *buffer, int length)
{
    if (ftpData->clients[clientId].dataChannelIsTls != 1)
    {
        ssize_t total = 0;

        while (total < length)
        {
            ssize_t written = write(ftpData->clients[clientId].workerData.socketConnection,
                                    buffer + total, length - total);
            if (written > 0)
            {
                total += written;
                continue;
            }
            if (written < 0 && errno == EINTR)
                continue;
            return -1;
        }
        return total;
    }

#ifdef OPENSSL_ENABLED
    {
        SSL *dataSsl = NULL;

        if (ftpData->clients[clientId].workerData.passiveModeOn == 1)
            dataSsl = ftpData->clients[clientId].workerData.serverSsl;
        else if (ftpData->clients[clientId].workerData.activeModeOn == 1)
            dataSsl = ftpData->clients[clientId].workerData.clientSsl;

        if (dataSsl == NULL)
            return -1;

        return tlsWriteBounded(dataSsl, ftpData->clients[clientId].workerData.socketConnection,
                               buffer, length, dataWriteTimeoutMs(ftpData));
    }
#else
    return -1;
#endif
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

	/* bytes of the current item to copy, see formatReplyItem() */
	const char *theSource = theBuffer;

	va_list args;
	va_start(args, __fmt);
	while (*__fmt != '\0')
	{
		theStringSize = 0;

		theSource = formatReplyItem(*__fmt, &args, theBuffer, sizeof(theBuffer), &theStringSize);
		++__fmt;


		for (i = 0; i <theStringSize; i++)
		{
			//Write the buffer
			if (theStringToWriteSize >= COMMAND_BUFFER)
			{
				my_printf("\nwriting:\n%s", writeBuffer);

				ssize_t theReturnCode = writeDataChannelBuffer(ftpData, clientId, writeBuffer, theStringToWriteSize);

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
				writeBuffer[theStringToWriteSize++] = theSource[i];
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
		ssize_t theReturnCode = writeDataChannelBuffer(ftpData, clientId, writeBuffer, theStringToWriteSize);

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


/* The listening socket of the control connections, or -1 with errno set (the caller logs it) */
int createSocket(ftpDataType * ftpData)
{
  //my_printf("\nCreating main socket on port %d", ftpData->ftpParameters.port);
  int sock = -1, errorCode = -1;
  struct sockaddr_in6 serveraddr;

  //Socket creation IPV6
  if ((sock = socket(AF_INET6, SOCK_STREAM, 0)) < 0)
  {
	perror("socket() failed");
	LOG_ERROR("Socket creation failed");
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
		LOG_ERROR("socketopt failed");
	}
#endif

reuse = 1;
#ifdef SO_REUSEPORT
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) 
	{
		perror("setsockopt(SO_REUSEADDR) failed");
		my_printfError("setsockopt(SO_REUSEADDR) failed");
		LOG_ERROR("setsocket error");
	}
#endif


	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin6_family = AF_INET6;
	serveraddr.sin6_port   = htons(ftpData->ftpParameters.port);
	serveraddr.sin6_addr   = in6addr_any;

	if (bind(sock, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0)
	{
		int bindError = errno;
		close(sock);
		perror("bind() failed");
		errno = bindError;
		return -1;
	}

  //Number of client allowed
  errorCode = listen(sock, ftpData->ftpParameters.maxClients + 1);
  if (errorCode < 0)
  {
	  int listenError = errno;
	  close(sock);
	  errno = listenError;
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
        LOG_ERROR("socket failed");
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
        LOG_ERROR("setsocketerror");
    }
#endif

#ifdef SO_REUSEPORT
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0)
    {
        perror("setsockopt(SO_REUSEPORT) failed");
        my_printfError("setsockopt(SO_REUSEPORT) failed");
        LOG_ERROR("setsocketerror");
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
            LOG_ERROR("bind failed");
            close(sock);
            return -1;
        }
    }

    if (returnCode != 0)
    {
        my_printf("Bind failed after %d retries, errno=%d\n", max_retries, errno);
		LOGF("%sBind failed after %d retries, errno=%d\n", LOG_ERROR_PREFIX, max_retries, errno);
        close(sock);
        return -1;
    }

    // Listen
    returnCode = listen(sock, 1);
    if (returnCode == -1)
    {
        LOG_ERROR("listen failed");
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

/* The listening socket of the control connections, or -1 with errno set (the caller logs it) */
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
		LOG_ERROR("socketopt failed");
	}

#endif

#ifdef SO_REUSEPORT
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) 
	{
		perror("setsockopt(SO_REUSEADDR) failed");
		my_printfError("setsockopt(SO_REUSEADDR) failed");
		LOG_ERROR("setsocket error");
	}
#endif
  //Bind socket
  errorCode = bind(sock,(struct sockaddr*) &temp,sizeof(temp));
  if (errorCode == -1)
  {
	  int bindError = errno;
	  close(sock);
	  errno = bindError;
	  return -1;
  }

  //Number of client allowed
  errorCode = listen(sock, ftpData->ftpParameters.maxClients + 1);
  if (errorCode == -1)
  {
	  int listenError = errno;
	  close(sock);
	  errno = listenError;
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
        LOG_ERROR("socket failed");
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
        LOG_ERROR("setsocketerror");
    }
#endif

#ifdef SO_REUSEPORT
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0)
    {
        perror("setsockopt(SO_REUSEPORT) failed");
        my_printfError("setsockopt(SO_REUSEPORT) failed");
        LOG_ERROR("setsocketerror");
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
            LOG_ERROR("bind failed");
            close(sock);
            return -1;
        }
    }

    if (returnCode != 0)
    {
        my_printf("bind failed after %d retries, errno=%d\n", max_retries, errno);
        LOGF("%sbind failed after %d retries, errno=%d\n", LOG_ERROR_PREFIX, max_retries, errno);
        close(sock);
        return -1;
    }

    // Start listening
    returnCode = listen(sock, 1);
    if (returnCode == -1)
    {
        LOG_ERROR("listen failed");
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
		LOG_ERROR("Socket creation failed");
        return -1;
    }

  int reuse = 1;
#ifdef SO_REUSEADDR
   if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
	{
		perror("setsockopt(SO_REUSEADDR) failed");
		my_printfError("setsockopt(SO_REUSEADDR) failed");
		LOG_ERROR("set socket error");
	}
#endif

#ifdef SO_REUSEPORT
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) 
	{
		perror("setsockopt(SO_REUSEADDR) failed");
		my_printfError("setsockopt(SO_REUSEADDR) failed");
		LOG_ERROR("setsockopt error");
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
		close(sockfd);
		errno = EINVAL;
        return -1;
    }

    // Connect to server (errno is kept for the caller, which logs it with the client)
    if (connect(sockfd, serv_addr_any, sizeof(serv_addr6)) < 0) 
	{
		int connectError = errno;
		my_printfError("Connection failed");
		close(sockfd);
		errno = connectError;
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
		LOG_ERROR("set socket error");
	}
#endif

#ifdef SO_REUSEPORT
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) 
	{
		perror("setsockopt(SO_REUSEADDR) failed");
		my_printfError("setsockopt(SO_REUSEADDR) failed");
		LOG_ERROR("setsockopt error");
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

#ifdef OPENSSL_ENABLED
	/* The condition used to be dataChannelIsTls (the protection of the data
	   channel) and the shutdown was attempted only in passive mode. Whenever
	   the control connection uses TLS, close it properly (see
	   tlsShutdownBounded()). */
	if (ftpData->clients[processingSocket].tlsIsEnabled == 1 &&
	    ftpData->clients[processingSocket].ssl != NULL)
	{
		/* Our close_notify is sent, the one of the client is not waited for (it is
		   not required, RFC 8446 6.1, and many clients never send it). This runs in
		   the control thread: waiting here, even for a short time, let any client
		   that stays connected after QUIT slow down everybody else. */
		tlsShutdownBounded(ftpData->clients[processingSocket].ssl,
		                   ftpData->clients[processingSocket].socketDescriptor, 0, 0, NULL);
	}
#endif

    //Close the socket
    shutdown(ftpData->clients[processingSocket].socketDescriptor, SHUT_RDWR);
    close(ftpData->clients[processingSocket].socketDescriptor);

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
    clientDataType *client = &ftpData->clients[processingSocket];

    /* refused connections (too many from an address) are not logged one by one */
    if (client->accessLogged == 1)
    {
        LOG_ACCESS(ftpData, processingSocket, "connection closed: %s (after %d s)",
                   client->closeReason != NULL ? client->closeReason : "closed by the server",
                   (int)time(NULL) - (int)client->connectionTimeStamp);
    }

    if (ftpData->clients[processingSocket].workerData.threadIsAlive == 1)
    {
    	handleThreadReuse(ftpData, processingSocket);
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
    int now = (int)time(NULL);

    for (processingSock = 0; processingSock < ftpData->ftpParameters.maxClients; processingSock++)
    {
        const char *theReason = NULL;

        /* No connection active*/
        if (ftpData->clients[processingSock].socketDescriptor < 0 ||
            ftpData->clients[processingSock].socketIsConnected == 0) 
            {
                continue;
            }

        /* Max idle time check, close the connection if time is elapsed */
        if (ftpData->ftpParameters.maximumIdleInactivity != 0 &&
            now - (int)ftpData->clients[processingSock].lastActivityTimeStamp > ftpData->ftpParameters.maximumIdleInactivity)
        {
            theReason = "421 Timeout, closing control connection.\r\n";
            setCloseReason(ftpData, processingSock, "idle timeout (IDLE_MAX_TIMEOUT)");
        }
        /* Login time check: activity does not extend it, otherwise a client could hold a
           slot forever without authenticating by sending NOOP (or USER, AUTH...) */
        else if (ftpData->ftpParameters.loginTimeout != 0 &&
                 ftpData->clients[processingSock].login.userLoggedIn == 0 &&
                 now - (int)ftpData->clients[processingSock].loginTimerStart > ftpData->ftpParameters.loginTimeout)
        {
            theReason = "421 Login timeout, closing control connection.\r\n";
            setCloseReason(ftpData, processingSock, "login not completed in time (LOGIN_TIMEOUT)");
        }

        if (theReason != NULL && ftpData->clients[processingSock].closeTheClient == 0)
        {
            /* RFC 959: 421 when the server closes the control connection. Not sent in
               the middle of a TLS handshake, where it would only corrupt it. */
            if (ftpData->clients[processingSock].tlsIsNegotiating == 0)
            {
                socketPrintf(ftpData, processingSock, "s", theReason);
            }

            ftpData->clients[processingSock].closeTheClient = 1;
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

int evaluateClientSocketConnection(ftpDataType * ftpData)
{

    if (FD_ISSET(ftpData->connectionData.theMainSocket, &ftpData->connectionData.rset))
    {
        int availableSocketIndex;
        if ((availableSocketIndex = getAvailableClientSocketIndex(ftpData)) != -1) //get available socket  
        {
            if ((ftpData->clients[availableSocketIndex].socketDescriptor = accept(ftpData->connectionData.theMainSocket, (struct sockaddr *)&ftpData->clients[availableSocketIndex].client_sockaddr_in, (socklen_t*)&ftpData->clients[availableSocketIndex].sockaddr_in_size)) !=- 1)
            {
                int numberOfConnectionFromSameIp, i;
                numberOfConnectionFromSameIp = 0;
                ftpData->connectedClients++;
                ftpData->clients[availableSocketIndex].socketIsConnected = 1;

                fcntl(ftpData->clients[availableSocketIndex].socketDescriptor, F_SETFL, O_NONBLOCK);

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
                ftpData->clients[availableSocketIndex].loginTimerStart = (int)time(NULL);
                
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
                	socketPrintf(ftpData, availableSocketIndex, "sss", "530 too many connection from your ip address ", ftpData->clients[availableSocketIndex].clientIpAddress, " \r\n");
                    markClientForClosing(ftpData, availableSocketIndex, "too many connections from the address");
					LOGF("%stoo many connection from ip address: %s maximum allowed: %d", LOG_SECURITY_PREFIX, ftpData->clients[availableSocketIndex].clientIpAddress, ftpData->ftpParameters.maximumConnectionsPerIp); 
                }
                else
                {
                    ftpData->clients[availableSocketIndex].accessLogged = 1;
                    LOG_CLIENT(ftpData, availableSocketIndex, LOG_ACCESS_PREFIX, "connection opened");

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
                LOGF("%sCan not accept a connection: %s", LOG_ERROR_PREFIX, strerror(errno));
                ftpData->clients[availableSocketIndex].closeTheClient = 1;
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
                int numberOfConnectionFromSameIp, i;
                numberOfConnectionFromSameIp = 0;
                ftpData->connectedClients++;
                ftpData->clients[availableSocketIndex].socketIsConnected = 1;

                fcntl(ftpData->clients[availableSocketIndex].socketDescriptor, F_SETFL, O_NONBLOCK);

                fdAdd(ftpData, availableSocketIndex);

                getsockname(ftpData->clients[availableSocketIndex].socketDescriptor, (struct sockaddr *)&ftpData->clients[availableSocketIndex].server_sockaddr_in, (socklen_t*)&ftpData->clients[availableSocketIndex].sockaddr_in_server_size);
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
                ftpData->clients[availableSocketIndex].loginTimerStart = (int)time(NULL);
                
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
                	socketPrintf(ftpData, availableSocketIndex, "sss", "530 too many connection from your ip address ", ftpData->clients[availableSocketIndex].clientIpAddress, " \r\n");
                    markClientForClosing(ftpData, availableSocketIndex, "too many connections from the address");
					LOGF("%stoo many connection from ip address: %s maximum allowed: %d", LOG_SECURITY_PREFIX, ftpData->clients[availableSocketIndex].clientIpAddress, ftpData->ftpParameters.maximumConnectionsPerIp);
                }
                else
                {
                    ftpData->clients[availableSocketIndex].accessLogged = 1;
                    LOG_CLIENT(ftpData, availableSocketIndex, LOG_ACCESS_PREFIX, "connection opened");

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
                LOGF("%sCan not accept a connection: %s", LOG_ERROR_PREFIX, strerror(errno));
                ftpData->clients[availableSocketIndex].closeTheClient = 1;
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

#endif

#ifdef OPENSSL_ENABLED
/* The data connection of a client can not be used any more (the client closed it during
   the TLS handshake, or never started TLS). Only the data connection is closed, by the
   worker; the session stays and the client can open a new data connection.

   If a transfer command had already been accepted (150 sent), it gets its final reply
   (426): the client used to wait for it for ever. The flag is changed under the mutex
   used to give commands to the worker, so a command arriving right now is either seen
   here or refused with 425. */
static void abandonDataConnection(ftpDataType *ftpData, int theSocketId, const char *reason)
{
    pthread_mutex_lock(&ftpData->clients[theSocketId].conditionMutex);
    ftpData->clients[theSocketId].workerData.socketIsReadyForConnection = 0;
    int commandAccepted = ftpData->clients[theSocketId].workerData.commandReceived;
    pthread_mutex_unlock(&ftpData->clients[theSocketId].conditionMutex);

    if (commandAccepted == 1)
    {
        LOG_ACCESS(ftpData, theSocketId, "transfer aborted: %s", reason);
        ftpData->clients[theSocketId].workerData.commandProcessed = 1;
        snprintf(ftpData->clients[theSocketId].workerData.theCommandResponse, STRING_SZ_SMALL,
                 "426 Connection closed; transfer aborted\r\n");
    }
}

static long long int monotonicMs(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long long int)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

int acceptSSLConnection(int theSocketId, ftpDataType * ftpData)
{
    SSL *ssl = ftpData->clients[theSocketId].workerData.serverSsl;
    int sockfd = ftpData->clients[theSocketId].workerData.socketConnection;

    my_printf("\nSSL SSL_set_fd start");
    
    int rc = SSL_set_fd(ssl, sockfd);
    if (rc == 0)
    {
        my_printf("\nSSL ERRORS ON SSL_set_fd");
        markClientForClosing(ftpData, theSocketId, "TLS setup of the data connection failed (SSL_set_fd)");
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

    /* The server side of a handshake never calls SSL_set_session(): that is a client
       API and it corrupts the ServerHello (clients abort with "unsolicited extension").
       A client that wants to resume the session of the control connection offers it
       in its ClientHello and the session cache of the SSL_CTX takes care of it. */

    SSL_set_accept_state(ssl);

    /* The error queue is thread-local: start the handshake with it empty so
       that the reason of a failure below is the one of this handshake. */
    ERR_clear_error();

    /* Some clients start TLS only after the 150 reply, which needs the transfer
       command: TLS_DATA_HANDSHAKE_TIMEOUT_MS leaves room for that and for slow links.
       The wait is in the data worker and delays nobody else; usleep() is a
       cancellation point, so a new PASV or ABOR still stops the worker at once. */
    long long int deadline = monotonicMs() + TLS_DATA_HANDSHAKE_TIMEOUT_MS;

    while (1)
    {
        rc = SSL_accept(ssl);

        if (rc == 1)
        {
            my_printf("\n------------------------------------------- SSL_accept success");
            break;
        }

        int err = SSL_get_error(ssl, rc);

        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        {
            if (monotonicMs() >= deadline)
            {
                /* It used to close the whole session, after 5 seconds */
                LOG_CLIENT(ftpData, theSocketId, LOG_DEBUG_PREFIX,
                           "TLS handshake of the data connection not completed in %d s, data connection closed",
                           TLS_DATA_HANDSHAKE_TIMEOUT_MS / 1000);
                ERR_clear_error();
                abandonDataConnection(ftpData, theSocketId, "TLS handshake of the data connection not completed in time");
                return -1;
            }

            usleep(10000); // 10 ms
            continue;
        }
        else
        {
            unsigned long tlsErrorCode = ERR_peek_last_error();
            int clientAbort = 0;

            /* A client that closes the data connection before or during the
               handshake (for example after a transfer command was refused) is
               not a reason to close the control connection too. */
            #ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
            if (ERR_GET_REASON(tlsErrorCode) == SSL_R_UNEXPECTED_EOF_WHILE_READING)
                clientAbort = 1;
            #endif
            if (err == SSL_ERROR_ZERO_RETURN ||
                (err == SSL_ERROR_SYSCALL && tlsErrorCode == 0))
                clientAbort = 1;

            if (clientAbort)
            {
                LOG_CLIENT(ftpData, theSocketId, LOG_DEBUG_PREFIX,
                           "TLS handshake of the data connection aborted by the client");
                ERR_clear_error();
                abandonDataConnection(ftpData, theSocketId, "data connection closed by the client before the TLS handshake");
                return -1;
            }

            my_printf("\n-------------------------------------------SSL_accept failed:");
            char tlsError[160] = "";
            ERR_error_string_n(tlsErrorCode, tlsError, sizeof(tlsError));
            LOG_CLIENT(ftpData, theSocketId, LOG_ERROR_PREFIX, "TLS handshake of the data connection failed: %s", tlsError);
            ERR_print_errors_fp(stderr);
            markClientForClosing(ftpData, theSocketId, "TLS handshake of the data connection failed");
            return -1;
        }
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