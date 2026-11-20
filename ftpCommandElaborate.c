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
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <poll.h>
#include <errno.h>
#include <arpa/inet.h>
#include <strings.h>
#include <ctype.h>

#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#define _REENTRANT
#include <pthread.h>
#include <limits.h>

#include "ftpData.h"
#include "ftpServer.h"
#include "library/fileManagement.h"
#include "library/configRead.h"
#include "library/openSsl.h"
#include "library/connection.h"
#include "library/dynamicMemory.h"
#include "library/auth.h"
#include "library/addressKey.h"
#include "library/serverHelpers.h"
#include "dataChannel/dataChannel.h"
#include "ftpCommandsElaborate.h"

#include "debugHelper.h"
#include "library/log.h"

#define EPRT_PARSE_OK                  0
#define EPRT_PARSE_SYNTAX_ERROR       -1
#define EPRT_PARSE_UNSUPPORTED_PROTO  -2

/* RFC 2428 section 2: EPRT<space><d><net-prt><d><net-addr><d><tcp-port><d>
   where <d> is any printable ASCII character (33-126), usually '|'. */
static int parse_eprt(const char *eprtArg, int *address_type, char *address, size_t addressSize, int *port)
{
    const char *cursor = eprtArg;
    char delimiter;
    long protocol = 0, thePort = 0;
    size_t addressLen = 0;
    int digits;
    unsigned char addressBinary[sizeof(struct in6_addr)];

    if (eprtArg == NULL || address_type == NULL || address == NULL || port == NULL || addressSize == 0)
        return EPRT_PARSE_SYNTAX_ERROR;

    delimiter = *cursor;
    if (delimiter < 33 || delimiter > 126)
        return EPRT_PARSE_SYNTAX_ERROR;
    cursor++;

    /* net-prt */
    for (digits = 0; isdigit((unsigned char)*cursor) && digits < 4; digits++, cursor++)
        protocol = (protocol * 10) + (*cursor - '0');

    if (digits == 0 || *cursor != delimiter)
        return EPRT_PARSE_SYNTAX_ERROR;
    cursor++;

    /* net-addr */
    while (*cursor != '\0' && *cursor != delimiter)
    {
        if (addressLen + 1 >= addressSize)
            return EPRT_PARSE_SYNTAX_ERROR;
        address[addressLen++] = *cursor++;
    }
    address[addressLen] = '\0';

    if (addressLen == 0 || *cursor != delimiter)
        return EPRT_PARSE_SYNTAX_ERROR;
    cursor++;

    /* tcp-port */
    for (digits = 0; isdigit((unsigned char)*cursor) && digits < 6; digits++, cursor++)
        thePort = (thePort * 10) + (*cursor - '0');

    if (digits == 0)
        return EPRT_PARSE_SYNTAX_ERROR;

    /* closing delimiter (tolerated if missing), then nothing else */
    if (*cursor == delimiter)
        cursor++;

    if (*cursor != '\0')
        return EPRT_PARSE_SYNTAX_ERROR;

    if (protocol != 1 && protocol != 2)
        return EPRT_PARSE_UNSUPPORTED_PROTO;

    if (inet_pton(protocol == 1 ? AF_INET : AF_INET6, address, addressBinary) != 1)
        return EPRT_PARSE_SYNTAX_ERROR;

    if (thePort < 1 || thePort > 65535)
        return EPRT_PARSE_SYNTAX_ERROR;

    *address_type = (int)protocol;
    *port = (int)thePort;
    return EPRT_PARSE_OK;
}


static int ftpReplyOrError(ftpDataType *ftpData, int clientId, const char *formatSpecifier, const char *message);

/* RFC 2428 section 3: after EPSV ALL only EPSV may set up a data connection */
#define EPSV_ALL_REFUSAL "501 Not allowed after EPSV ALL, use EPSV\r\n"
static int replyMissingOrWrongPath(ftpDataType *data, int socketId, const char *theArgument);
static int isAllDigits(const char *theString);
static int isDataAddressAllowed(ftpDataType *data, int socketId, const char *theAddress, int thePort);
static void quoteFtpString(const char *theString, char *quoted, size_t quotedSize);
static int absoluteToFtpPath(const char *absolutePath, loginDataType *login, char *ftpPath, size_t ftpPathSize);
#ifdef OPENSSL_ENABLED
static int resetSessionForAuth(ftpDataType *data, int socketId);
#endif
static int userIsBlocked(ftpDataType *data, const char *theUserName);
static int replyIfDiskIsFull(ftpDataType *data, int socketId, const char *command, int *functionReturnCode);
static int accountIsFull(ftpDataType *data, int socketId, int limit);
static int replyAccountIsFull(ftpDataType *data, int socketId);
static int dataWorkerHasCommand(ftpDataType *data, int socketId);
static int replyIfDataChannelNotUsable(ftpDataType *data, int socketId, int *functionReturnCode);
static int replyParentDirectoryMissing(ftpDataType *data, int socketId, const char *command, const char *thePath);
static int giveCommandToDataWorker(ftpDataType *data, int socketId);
static int parseListingCommand(ftpDataType *data, int socketId, char *theCommandName);
static int startDataChannel(ftpDataType *data, int socketId, char *label);

/* Access record of a change to the file system: path(s) as seen on the server and, if
   the system call failed (result -1), its error. Called right after the call, before
   errno can change. */
static void logFileOperation(ftpDataType *data, int socketId, const char *operation,
                             const char *path, const char *secondPath, int result)
{
    if (result == -1)
    {
        const char *reason = strerror(errno);
        LOG_ACCESS(data, socketId, "%s %s%s%s failed: %s", operation, path,
                   secondPath != NULL ? " -> " : "", secondPath != NULL ? secondPath : "", reason);
    }
    else
    {
        LOG_ACCESS(data, socketId, "%s %s%s%s", operation, path,
                   secondPath != NULL ? " -> " : "", secondPath != NULL ? secondPath : "");
    }
}

/* The login is complete: the name is kept for the log lines (also read by the data
   worker, so a fixed copy: login.name is freed by USER and AUTH) */
static void logLoginSucceeded(ftpDataType *data, int socketId)
{
    snprintf(data->clients[socketId].logUserName, sizeof(data->clients[socketId].logUserName), "%s",
             data->clients[socketId].login.name.text != NULL ? data->clients[socketId].login.name.text : "?");
    LOG_ACCESS(data, socketId, "login ok, home %s, %s", data->clients[socketId].login.homePath.text,
               data->clients[socketId].tlsIsEnabled == 1 ? "over TLS" : "in clear text");
}

/* Elaborate the User login command */
int parseCommandUser(ftpDataType * data, int socketId)
{
    int returnCode;
    char *theUserName;
    theUserName = getFtpCommandArg("USER", data->clients[socketId].theCommandReceived, 0);

	if (data->ftpParameters.forceTLS == 1 && data->clients[socketId].tlsIsEnabled == 0)
	{
		returnCode = socketPrintf(data, socketId, "s", "534 Policy Requires SSL.\r\n");
	}
	else
	{
		if (strnlen(theUserName, 1) >= 1)
		{
            /* A blocked name gets the reply of any other name: the client must not learn that it
               is in the list. The name replaces the one of a previous USER (PASS would log that
               user in), and PASS refuses it like a name that does not exist. */
            setDynamicStringDataType(&data->clients[socketId].login.name, theUserName, strlen(theUserName), &data->clients[socketId].memoryTable);
            returnCode = socketPrintf(data, socketId, "s", "331 User ok, Waiting for the password.\r\n");

            /* a logged in user starting a new login gets a new LOGIN_TIMEOUT; a client
               that is not logged in does not (sending USER again must not extend it) */
            if (data->clients[socketId].login.userLoggedIn == 1)
            {
                LOG_ACCESS(data, socketId, "logout (new USER command)");
                data->clients[socketId].loginTimerStart = (int)time(NULL);
            }

            data->clients[socketId].login.userLoggedIn = 0;
		}
		else
		{
			returnCode = socketPrintf(data, socketId, "s", "501 Invalid username.\r\n");
		}
	}

	if (returnCode <= 0) 
    {
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }
		

	return FTP_COMMAND_PROCESSED;
}

/* Elaborate the User login command */
int parseCommandSite(ftpDataType *data, int socketId)
{
    int returnCode, setPermissionsReturnCode;
    char *theCommand;
    theCommand = getFtpCommandArg("SITE", data->clients[socketId].theCommandReceived, 0);

    if (strnlen(theCommand, 1) == 0)
    {
        returnCode = socketPrintf(data, socketId, "s", "501 SITE requires a subcommand, try SITE HELP\r\n");
    }
    else if (strncasecmp(theCommand, "HELP", 4) == 0 && (theCommand[4] == '\0' || theCommand[4] == ' '))
    {
        returnCode = socketPrintf(data, socketId, "s",
            "214-The following SITE commands are recognized:\r\n"
            " CHMOD HELP\r\n"
            "214 Help OK.\r\n");
    }
    else if (compareStringCaseInsensitive(theCommand, "CHMOD", strlen("CHMOD")) == 1)
    {
        setPermissionsReturnCode = setPermissions(theCommand, &data->clients[socketId].login, &data->clients[socketId].memoryTable);

        if (setPermissionsReturnCode == FTP_CHMODE_COMMAND_RETURN_CODE_OK)
            LOG_ACCESS(data, socketId, "SITE %s", theCommand);
        else if (setPermissionsReturnCode == FTP_CHMODE_COMMAND_RETURN_CODE_NO_PERMISSIONS)
            LOG_ACCESS(data, socketId, "SITE %s failed", theCommand);
        else if (setPermissionsReturnCode == FTP_CHMODE_COMMAND_RETURN_CODE_SPECIAL_BITS)
            LOG_ACCESS(data, socketId, "SITE %s refused: setuid and setgid bits are not allowed", theCommand);

        switch (setPermissionsReturnCode)
        {
            case FTP_CHMODE_COMMAND_RETURN_CODE_OK:
            {
                returnCode = socketPrintf(data, socketId, "s", "200 Permissions changed\r\n");
            }
            break;

            case FTP_CHMODE_COMMAND_RETURN_CODE_NO_FILE:
            {
                returnCode = socketPrintf(data, socketId, "s", "550 chmod no such file\r\n");
            }
            break;

            case FTP_CHMODE_COMMAND_RETURN_CODE_NO_PERMISSIONS:
            {
                returnCode = socketPrintf(data, socketId, "s", "550 Some errors occurred while changing file permissions.\r\n");
            }
            break;

            case FTP_CHMODE_COMMAND_RETURN_CODE_SYNTAX_ERROR:
            {
                returnCode = socketPrintf(data, socketId, "s", "501 Syntax: SITE CHMOD <octal mode> <pathname>\r\n");
            }
            break;

            case FTP_CHMODE_COMMAND_RETURN_CODE_SPECIAL_BITS:
            {
                returnCode = socketPrintf(data, socketId, "s", "550 setuid and setgid bits are not allowed\r\n");
            }
            break;

            case FTP_CHMODE_COMMAND_RETURN_NAME_TOO_LONG:
            default:
                return FTP_COMMAND_PROCESSED_WRITE_ERROR;
        }
    }
    else
    {
        returnCode = socketPrintf(data, socketId, "s", "500 unknown extension\r\n");

    }

	if (returnCode <= 0) 
    {
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }

    return FTP_COMMAND_PROCESSED;
}

/* RFC 959: 452 when the free space of the disk is below MIN_FREE_SPACE_MB. Before the 150, so
   the client does not even start sending. Returns 1 if the reply has been sent. */
static int replyIfDiskIsFull(ftpDataType *data, int socketId, const char *command, int *functionReturnCode)
{
    if (FILE_FreeSpaceIsBelow(data->clients[socketId].fileToStor.text,
                              (long long int)data->ftpParameters.minimumFreeSpaceMb << 20) == 0)
    {
        return 0;
    }

    LOG_ACCESS(data, socketId, "%s %s refused (452): the free space of the disk is below MIN_FREE_SPACE_MB (%d MB)",
               command, data->clients[socketId].fileToStor.text, data->ftpParameters.minimumFreeSpaceMb);
    cleanDynamicStringDataType(&data->clients[socketId].fileToStor, 0, &data->clients[socketId].memoryTable);
    *functionReturnCode = ftpReplyOrError(data, socketId, "s", "452 Insufficient storage space in system.\r\n");
    return 1;
}

/* 1 if the name is in the list of the blocked users (BLOCK_USER_n) */
static int userIsBlocked(ftpDataType *data, const char *theUserName)
{
    for (int i = 0; i < data->ftpParameters.blockedUsersVector.Size; i++)
    {
        if (strncmp(theUserName, data->ftpParameters.blockedUsersVector.Data[i], CLIENT_COMMAND_STRING_SIZE-6) == 0)
        {
            return 1;
        }
    }

    return 0;
}

/* 1 if the user of this connection already has `limit` sessions, from any address (0 = no
   limit). Only the sessions that are logged in and not being closed are counted. */
static int accountIsFull(ftpDataType *data, int socketId, int limit)
{
    int sessions = 0;

    if (limit <= 0)
        return 0;

    for (int i = 0; i < data->ftpParameters.maxClients; i++)
    {
        if (i != socketId &&
            isClientConnected(data, i) == 1 &&
            data->clients[i].closeTheClient == 0 &&
            data->clients[i].login.userLoggedIn == 1 &&
            strcmp(data->clients[i].login.name.text, data->clients[socketId].login.name.text) == 0)
        {
            sessions++;
        }
    }

    return sessions >= limit;
}

/* The password was right, but the account has all the sessions it may have: the login is
   refused (not counted as a failed one) and the connection is closed. */
static int replyAccountIsFull(ftpDataType *data, int socketId)
{
    LOG_CLIENT(data, socketId, LOG_SECURITY_PREFIX, "login refused: user %s has too many connections",
               data->clients[socketId].login.name.text);
    markClientForClosing(data, socketId, "too many connections for the account");
    return ftpReplyOrError(data, socketId, "s", "530 Too many connections for this account, please try later.\r\n");
}

int parseCommandPass(ftpDataType *data, int socketId)
{
    int returnCode;
    char *thePass;
    loginFailsDataType element;
    int searchPosition = -1;

    if (data->clients[socketId].login.name.textLen <= 0)
    {
        return ftpReplyOrError(data, socketId, "s", "503 Login with USER first.\r\n");
    }

    thePass = getFtpCommandArg("PASS", data->clients[socketId].theCommandReceived, 0);

    /* the address is always terminated: it is compared with strcmp. An IPv6 address is counted
       as its network (the first 64 bits), see addressKey.h */
    memset(&element, 0, sizeof(element));
    addressKey(data->clients[socketId].clientIpAddress, element.ipAddress, sizeof(element.ipAddress));
    element.failTimeStamp = time(NULL);
    element.failureNumbers = 1;

    searchPosition = data->loginFailsVector.SearchElement(&data->loginFailsVector, &element);

    if (searchPosition != -1)
    {
        if (element.failTimeStamp - ((loginFailsDataType *)data->loginFailsVector.Data[searchPosition])->failTimeStamp < WRONG_PASSWORD_ALLOWED_RETRY_TIME)
        {
            if (((loginFailsDataType *)data->loginFailsVector.Data[searchPosition])->failureNumbers >= data->ftpParameters.maximumUserAndPassowrdLoginTries)
            {
                markClientForClosing(data, socketId, "too many failed logins from the address");
                returnCode = socketPrintf(data, socketId, "s", "530 Too many login failure detected, your ip will be blacklisted for 5 minutes\r\n");

                LOGF("%sIp %s blocked due too many password errors. Trying to login as user: %s ", LOG_SECURITY_PREFIX, data->clients[socketId].clientIpAddress, data->clients[socketId].login.name.text);

                if (returnCode <= 0) 
                {
                    return FTP_COMMAND_PROCESSED_WRITE_ERROR;
                }
                return FTP_COMMAND_PROCESSED;
            }
        }
    }

    if (strnlen(thePass, 1) >= 1)
    {

        // my_printf("\nLogin try with user %s, password %s", data->clients[socketId].login.name.text, thePass);

        int nameIsBlocked = userIsBlocked(data, data->clients[socketId].login.name.text);

        if (nameIsBlocked == 1)
        {
            LOG_CLIENT(data, socketId, LOG_SECURITY_PREFIX, "login refused: user %s is blocked", data->clients[socketId].login.name.text);
        }

        // PAM AUTH METHOD IF ENABLED (never for a blocked name)
#ifdef PAM_SUPPORT_ENABLED
        if (nameIsBlocked == 0 && data->ftpParameters.pamAuthEnabled == 1)
        {
            loginCheck(data->clients[socketId].login.name.text, thePass, &data->clients[socketId].login, &data->clients[socketId].memoryTable);
            if (data->clients[socketId].login.userLoggedIn == 1)
            {
                if (accountIsFull(data, socketId, data->ftpParameters.maximumConnectionsPerAccount) == 1)
                {
                    data->clients[socketId].login.userLoggedIn = 0;
                    return replyAccountIsFull(data, socketId);
                }

                // my_printf("\n User logged with PAM ok!");
                logLoginSucceeded(data, socketId);
                return ftpReplyOrError(data, socketId, "s", "230 Login Ok.\r\n");
            }
        }
#endif

        int searchUserNameIndex;
        searchUserNameIndex = (nameIsBlocked == 1) ? -1 : searchUser(data->clients[socketId].login.name.text, &data->ftpParameters.usersVector);

        if (searchUserNameIndex < 0 ||
            (passwordMatches(((usersParameters_DataType *)data->ftpParameters.usersVector.Data[searchUserNameIndex])->password, thePass) != 1))
        {
            /* A wrong password for a hashed user costs about 20 ms: without this a name that does
               not exist, or a plain text one, would answer at once and the time of the reply
               would tell which names exist. */
            if (data->ftpParameters.hashedPasswordsPresent == 1 &&
                (searchUserNameIndex < 0 ||
                 passwordIsHashed(((usersParameters_DataType *)data->ftpParameters.usersVector.Data[searchUserNameIndex])->password) == 0))
            {
                passwordDummyVerify(thePass, data->ftpParameters.hashedPasswordsIterations);
            }

            // Record the login fail!
            if (searchPosition == -1)
            {
                if (data->ftpParameters.maximumUserAndPassowrdLoginTries != 0)
                    data->loginFailsVector.PushBack(&data->loginFailsVector, &element, sizeof(loginFailsDataType));
            }
            else
            {
                ((loginFailsDataType *)data->loginFailsVector.Data[searchPosition])->failureNumbers++;
                ((loginFailsDataType *)data->loginFailsVector.Data[searchPosition])->failTimeStamp = time(NULL);
            }
            LOG_CLIENT(data, socketId, LOG_SECURITY_PREFIX, "login failed for user %s", data->clients[socketId].login.name.text);
            returnCode = socketPrintf(data, socketId, "s", "530 Invalid username or password\r\n");
            if (returnCode <= 0) 
            {
                return FTP_COMMAND_PROCESSED_WRITE_ERROR;
            }
        }
        else if (accountIsFull(data, socketId,
                               ((usersParameters_DataType *)data->ftpParameters.usersVector.Data[searchUserNameIndex])->maximumConnections >= 0 ?
                               ((usersParameters_DataType *)data->ftpParameters.usersVector.Data[searchUserNameIndex])->maximumConnections :
                               data->ftpParameters.maximumConnectionsPerAccount) == 1)
        {
            return replyAccountIsFull(data, socketId);
        }
        else
        {
            setDynamicStringDataType(&data->clients[socketId].login.password, thePass, strlen(thePass), &data->clients[socketId].memoryTable);
            setDynamicStringDataType(&data->clients[socketId].login.absolutePath, ((usersParameters_DataType *)data->ftpParameters.usersVector.Data[searchUserNameIndex])->homePath, strlen(((usersParameters_DataType *)data->ftpParameters.usersVector.Data[searchUserNameIndex])->homePath), &data->clients[socketId].memoryTable);
            setDynamicStringDataType(&data->clients[socketId].login.homePath, ((usersParameters_DataType *)data->ftpParameters.usersVector.Data[searchUserNameIndex])->homePath, strlen(((usersParameters_DataType *)data->ftpParameters.usersVector.Data[searchUserNameIndex])->homePath), &data->clients[socketId].memoryTable);
            setDynamicStringDataType(&data->clients[socketId].login.ftpPath, "/", strlen("/"), &data->clients[socketId].memoryTable);

            data->clients[socketId].login.ownerShip.ownerShipSet = ((usersParameters_DataType *)data->ftpParameters.usersVector.Data[searchUserNameIndex])->ownerShip.ownerShipSet;
            data->clients[socketId].login.ownerShip.gid = ((usersParameters_DataType *)data->ftpParameters.usersVector.Data[searchUserNameIndex])->ownerShip.gid;
            data->clients[socketId].login.ownerShip.uid = ((usersParameters_DataType *)data->ftpParameters.usersVector.Data[searchUserNameIndex])->ownerShip.uid;
            data->clients[socketId].login.userLoggedIn = 1;
            logLoginSucceeded(data, socketId);

            my_printf("\ndata->clients[socketId].login.ownerShip.ownerShipSet = %d", data->clients[socketId].login.ownerShip.ownerShipSet);
            my_printf("\ndata->clients[socketId].login.ownerShip.gid = %d", data->clients[socketId].login.ownerShip.gid);
            my_printf("\ndata->clients[socketId].login.ownerShip.uid = %d", data->clients[socketId].login.ownerShip.uid);

            returnCode = socketPrintf(data, socketId, "s", "230 Login Ok.\r\n");
    
            if (returnCode <= 0) 
            {
                return FTP_COMMAND_PROCESSED_WRITE_ERROR;
            }
        }

        return FTP_COMMAND_PROCESSED;
    }
    else
    {

        // Record the login fail!
        if (searchPosition == -1)
        {
            if (data->ftpParameters.maximumUserAndPassowrdLoginTries != 0)
                data->loginFailsVector.PushBack(&data->loginFailsVector, &element, sizeof(loginFailsDataType));
        }
        else
        {
            ((loginFailsDataType *)data->loginFailsVector.Data[searchPosition])->failureNumbers++;
            ((loginFailsDataType *)data->loginFailsVector.Data[searchPosition])->failTimeStamp = time(NULL);
        }

        LOG_CLIENT(data, socketId, LOG_SECURITY_PREFIX, "login failed for user %s (empty password)", data->clients[socketId].login.name.text);
        return ftpReplyOrError(data, socketId, "s", "530 Invalid username or password\r\n");
    }
}

int parseCommandAuth(ftpDataType *data, int socketId)
{
    my_printf("-- AUTH TLS --");

#ifndef OPENSSL_ENABLED
    return ftpReplyOrError(data, socketId, "s", "502 Security extensions not implemented.\r\n");
#else
    int returnCode;

    /* RFC 4217: the only mechanism is TLS ("TLS-C" is its synonym) */
    char *theAuthArg = getFtpCommandArg("AUTH", data->clients[socketId].theCommandReceived, 0);

    if (strnlen(theAuthArg, 1) == 0)
    {
        return ftpReplyOrError(data, socketId, "s", "501 AUTH requires a mechanism name\r\n");
    }

    if (strcasecmp(theAuthArg, "TLS") != 0 && strcasecmp(theAuthArg, "TLS-C") != 0)
    {
        return ftpReplyOrError(data, socketId, "s", "504 Security mechanism not supported, use AUTH TLS\r\n");
    }

    /* RFC 4217 section 4.2: an accepted AUTH resets the whole session
       state, not only the login flag. Done before the 234 reply, so that nothing set
       up on the clear text connection is used once TLS is active. */
    if (resetSessionForAuth(data, socketId) != 0)
    {
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }

    returnCode = socketPrintf(data, socketId, "s", "234 AUTH TLS OK..\r\n");

    if (returnCode <= 0) 
    {
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }

    returnCode = SSL_set_fd(data->clients[socketId].ssl, data->clients[socketId].socketDescriptor);

    if (returnCode <= 0) 
    {
        LOG_ERROR("SSL_set_fd error on the control connection");
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }

    data->clients[socketId].tlsNegotiatingTimeStart = (int)time(NULL);
    int returnCodeTls = SSL_accept(data->clients[socketId].ssl);

    if (returnCodeTls <= 0)
    {
        int sslError = SSL_get_error(data->clients[socketId].ssl, returnCodeTls);
        if (sslError != SSL_ERROR_WANT_READ && sslError != SSL_ERROR_WANT_WRITE)
        {
            /* Fatal handshake error (e.g. peer closed): drop the client */
            data->clients[socketId].tlsIsEnabled = 0;
            data->clients[socketId].tlsIsNegotiating = 0;
            logTlsHandshakeFailure(data, socketId, sslError);
            markClientForClosing(data, socketId, "TLS handshake failed");
            return FTP_COMMAND_PROCESSED;
        }

        // my_printf("\nSSL NOT YET ACCEPTED: %d", returnCodeTls);
        data->clients[socketId].tlsIsEnabled = 0;
        data->clients[socketId].tlsIsNegotiating = 1;
    }
    else
    {
        // my_printf("\nSSL ACCEPTED");
        data->clients[socketId].tlsIsEnabled = 1;
        data->clients[socketId].tlsIsNegotiating = 0;
        LOG_ACCESS(data, socketId, "TLS established (%s)", SSL_get_version(data->clients[socketId].ssl));
    }

    return FTP_COMMAND_PROCESSED;
#endif
}

int parseCommandPwd(ftpDataType *data, int socketId)
{
    // my_printf("\n pwd is %s", data->clients[socketId].login.ftpPath.text);
    int returnCode;
    char quotedPath[(PATH_MAX * 2) + 1];

    /* RFC 959 appendix II: double quotes inside the pathname are doubled */
    quoteFtpString(data->clients[socketId].login.ftpPath.text, quotedPath, sizeof(quotedPath));
    returnCode = socketPrintf(data, socketId, "sss", "257 \"", quotedPath, "\" is your current location\r\n");

    if (returnCode <= 0) 
    {
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }

    return FTP_COMMAND_PROCESSED;
}

int parseCommandSyst(ftpDataType *data, int socketId)
{
    return ftpReplyOrError(data, socketId, "s", "215 UNIX Type: L8\r\n");
}

/* The MLST line of FEAT (RFC 3659 section 7.8): every fact the server knows, with a * on the ones in use */
static const struct { const char *name; int bit; } mlstFactTable[] = {
    {"type", MLST_FACT_TYPE}, {"size", MLST_FACT_SIZE}, {"modify", MLST_FACT_MODIFY}, {"perm", MLST_FACT_PERM},
    {"unix.mode", MLST_FACT_UNIX_MODE}, {"unix.uid", MLST_FACT_UNIX_UID}, {"unix.gid", MLST_FACT_UNIX_GID}
};
#define MLST_FACT_COUNT ((int)(sizeof(mlstFactTable) / sizeof(mlstFactTable[0])))

/* "type*;size;..." for FEAT (withStars = 1) or "type;size;" (the facts in use, for OPTS MLST) */
static void mlstFactsToText(char *out, size_t outSize, int facts, int withStars)
{
    size_t length = 0;
    int i;

    out[0] = '\0';

    for (i = 0; i < MLST_FACT_COUNT && length < outSize; i++)
    {
        int enabled = (facts & mlstFactTable[i].bit) != 0;

        if (withStars == 0 && enabled == 0)
        {
            continue;
        }

        length += (size_t)snprintf(out + length, outSize - length, "%s%s;", mlstFactTable[i].name, (withStars && enabled) ? "*" : "");
    }
}

int parseCommandFeat(ftpDataType *data, int socketId)
{
    char mlstLine[160];
    char factsText[128];

    mlstFactsToText(factsText, sizeof(factsText), data->clients[socketId].mlstFacts, 1);
    snprintf(mlstLine, sizeof(mlstLine), " MLST %s\r\n", factsText);

    if (socketPrintf(data, socketId, "sss",
        "211-Extensions supported:\r\n"
        " PASV\r\n"
        " EPSV\r\n"
        " EPRT\r\n"
        " UTF8\r\n"
#ifdef OPENSSL_ENABLED
        " AUTH TLS\r\n"
        " PBSZ\r\n"
        " PROT\r\n"
#endif
        " SIZE\r\n"
        " MDTM\r\n",
        mlstLine,
        " LANG EN*\r\n"
        " HOST\r\n"
        " REST STREAM\r\n"
        "211 End.\r\n") <= 0)
    {
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }

    return FTP_COMMAND_PROCESSED;
}

/* RFC 2640 section 3: the server has its messages in English only. No argument or an English
   tag ("en", "en-US", ...) is accepted, any other language is not available (504). */
int parseCommandLang(ftpDataType *data, int socketId)
{
    char *theTag = getFtpCommandArg("LANG", data->clients[socketId].theCommandReceived, 0);
    size_t i, length = strlen(theTag);

    if (length == 0)
    {
        return ftpReplyOrError(data, socketId, "s", "200 Language set to the default (en)\r\n");
    }

    for (i = 0; i < length; i++)
    {
        if (!isalnum((unsigned char)theTag[i]) && theTag[i] != '-')
        {
            return ftpReplyOrError(data, socketId, "s", "501 Syntax error in the language tag\r\n");
        }
    }

    if (strcasecmp(theTag, "en") == 0 || strncasecmp(theTag, "en-", 3) == 0)
    {
        return ftpReplyOrError(data, socketId, "s", "200 Language set to English\r\n");
    }

    return ftpReplyOrError(data, socketId, "s", "504 Language not available, only English\r\n");
}

/* RFC 7151: HOST <name> names the virtual host the client wants, before USER. The server has no
   virtual hosts and serves every name the same way: the name is checked and accepted. */
int parseCommandHost(ftpDataType *data, int socketId)
{
    char *theHost = getFtpCommandArg("HOST", data->clients[socketId].theCommandReceived, 0);
    size_t i, length = strlen(theHost);

    if (data->clients[socketId].login.userLoggedIn == 1 || data->clients[socketId].login.name.textLen > 0)
    {
        return ftpReplyOrError(data, socketId, "s", "503 HOST must come before USER\r\n");
    }

    if (length == 0 || length > 255)
    {
        return ftpReplyOrError(data, socketId, "s", "501 Invalid host name\r\n");
    }

    /* a name, an IPv4 address or an IPv6 address in brackets */
    for (i = 0; i < length; i++)
    {
        if (!isalnum((unsigned char)theHost[i]) && strchr(".-_:[]", theHost[i]) == NULL)
        {
            return ftpReplyOrError(data, socketId, "s", "501 Invalid host name\r\n");
        }
    }

    LOGF("%sHOST %s", LOG_DEBUG_PREFIX, theHost);
    return ftpReplyOrError(data, socketId, "s", "220 Host accepted\r\n");
}

int parseCommandProt(ftpDataType *data, int socketId)
{
    int returnCode;
    char *theProtArg = getFtpCommandArg("PROT", data->clients[socketId].theCommandReceived, 0);

    /* RFC 4217 section 5: after CCC the control connection is in clear text,
       anyone on the path could send "PROT C" and get the data in clear text too */
    if (data->clients[socketId].controlChannelCleared == 1)
    {
        return ftpReplyOrError(data, socketId, "s", "503 PROT is not accepted after CCC\r\n");
    }

    // Check that PBSZ was previously set before allowing PROT
    if (data->clients[socketId].pbszIsSet == 0)
    {
        return ftpReplyOrError(data, socketId, "s", "503 PROT requires prior PBSZ command\r\n");
    }

    if (theProtArg[0] == '\0')
    {
        returnCode = socketPrintf(data, socketId, "s", "501 PROT requires a protection level\r\n");
    }
    else if (theProtArg[1] != '\0')
    {
        returnCode = socketPrintf(data, socketId, "s", "504 Protection level not recognized\r\n");
    }
    else if (theProtArg[0] == 'C' || theProtArg[0] == 'c')
    {
        // Clear data channel (no protection)
        my_printf("\n---------------- Set data channel to clear");
        data->clients[socketId].dataChannelIsTls = 0;
        returnCode = socketPrintf(data, socketId, "scs", "200 PROT set to ", theProtArg[0], "\r\n");
    }
    else if (theProtArg[0] == 'P' || theProtArg[0] == 'p')
    {
        // Private (encrypted) data channel
        my_printf("\n---------------- Set data channel to private");
        data->clients[socketId].dataChannelIsTls = 1;
        returnCode = socketPrintf(data, socketId, "scs", "200 PROT set to ", theProtArg[0], "\r\n");
    }
    else if (theProtArg[0] == 'S' || theProtArg[0] == 's' || theProtArg[0] == 'E' || theProtArg[0] == 'e')
    {
        // RFC 4217: Safe and Confidential are valid levels that TLS does not provide
        returnCode = socketPrintf(data, socketId, "scs", "536 Protection level ", theProtArg[0], " is not supported by TLS\r\n");
    }
    else
    {
        returnCode = socketPrintf(data, socketId, "s", "504 Protection level not recognized\r\n");
    }

    if (returnCode <= 0) 
    {
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }

    return FTP_COMMAND_PROCESSED;
}

int parseCommandCcc(ftpDataType *data, int socketId)
{
#ifdef OPENSSL_ENABLED
    int returnCode;

    if (!data->clients[socketId].tlsIsEnabled) {
        return ftpReplyOrError(data, socketId, "s", "533 Control connection not encrypted\r\n");
    }

    returnCode = socketPrintf(data, socketId, "s", "200 Control connection switched to plaintext\r\n");
    if (returnCode <= 0) 
    {
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }

    /* a data worker can be writing its 226 on the control connection at this very moment: two calls on
       the same SSL object, and the choice between SSL_write and write, must not overlap */
    pthread_mutex_lock(&data->clients[socketId].writeMutex);
    SSL_shutdown(data->clients[socketId].ssl);  // Clean shutdown
    data->clients[socketId].tlsIsEnabled = 0;   // Mark as plaintext
    pthread_mutex_unlock(&data->clients[socketId].writeMutex);
    LOG_ACCESS(data, socketId, "control connection back to clear text (CCC)");

    /* RFC 4217 section 5: no more PBSZ/PROT, transfers keep the current protection */
    data->clients[socketId].controlChannelCleared = 1;

    /* RFC 4217 section 12.3: the TLS shutdown is bidirectional. Our close_notify is sent
       above; the one of the client is read before going on in clear text, otherwise its
       bytes end up in front of the next command (controlChannel.c) */
    data->clients[socketId].cccShutdownPending = CCC_SHUTDOWN_WAITING;
    return FTP_COMMAND_PROCESSED;
#else
    return ftpReplyOrError(data, socketId, "s", "502 Command not supported\r\n");
#endif
}

int parseCommandPbsz(ftpDataType *data, int socketId)
{
    char *thePbszSize = getFtpCommandArg("PBSZ", data->clients[socketId].theCommandReceived, 0);

    /* RFC 4217 section 5: no PBSZ after CCC */
    if (data->clients[socketId].controlChannelCleared == 1)
    {
        return ftpReplyOrError(data, socketId, "s", "503 PBSZ is not accepted after CCC\r\n");
    }

    // PBSZ requires TLS session active
    if (data->clients[socketId].tlsIsEnabled == 0) 
    {
        return ftpReplyOrError(data, socketId, "s", "503 PBSZ requires an active TLS session\r\n");
    }

    // Only PBSZ 0 is supported
    if (!thePbszSize || strcmp(thePbszSize, "0") != 0) 
    {
        return ftpReplyOrError(data, socketId, "s", "501 Only PBSZ 0 is supported\r\n");
    }

    data->clients[socketId].pbszIsSet = 1;

    // Successful PBSZ negotiation
    return ftpReplyOrError(data, socketId, "s", "200 PBSZ=0\r\n");
}

/* RFC 959 TYPE: Image, ASCII Non-print and Local 8 are accepted. Data is always
   transferred as an unmodified 8 bit stream. */
int parseCommandType(ftpDataType *data, int socketId)
{
    char *theType = getFtpCommandArg("TYPE", data->clients[socketId].theCommandReceived, 0);

    if (strnlen(theType, 1) == 0)
    {
        return ftpReplyOrError(data, socketId, "s", "501 TYPE requires a parameter\r\n");
    }

    if (strcasecmp(theType, "I") == 0 ||
        strcasecmp(theType, "A") == 0 ||
        strcasecmp(theType, "A N") == 0 ||
        strcasecmp(theType, "L 8") == 0)
    {
        return ftpReplyOrError(data, socketId, "s", "200 TYPE is now 8-bit binary\r\n");
    }

    if (strcasecmp(theType, "E") == 0 || strncasecmp(theType, "E ", 2) == 0 ||
        strncasecmp(theType, "A ", 2) == 0 || strncasecmp(theType, "L ", 2) == 0)
    {
        return ftpReplyOrError(data, socketId, "s", "504 TYPE not implemented for that parameter\r\n");
    }

    return ftpReplyOrError(data, socketId, "s", "501 Unrecognized TYPE parameter\r\n");
}

/* RFC 959 STRU: File and Record structure (Page structure is not implemented) */
int parseCommandStru(ftpDataType *data, int socketId)
{
    char *theStructure = getFtpCommandArg("STRU", data->clients[socketId].theCommandReceived, 0);

    if (strnlen(theStructure, 1) == 0)
    {
        return ftpReplyOrError(data, socketId, "s", "501 STRU requires a parameter\r\n");
    }

    if (strcasecmp(theStructure, "F") == 0)
    {
        data->clients[socketId].recordStructure = 0;
        return ftpReplyOrError(data, socketId, "s", "200 STRU set to File\r\n");
    }

    if (strcasecmp(theStructure, "R") == 0)
    {
        data->clients[socketId].recordStructure = 1;
        return ftpReplyOrError(data, socketId, "s", "200 STRU set to Record\r\n");
    }

    if (strcasecmp(theStructure, "P") == 0)
    {
        return ftpReplyOrError(data, socketId, "s", "504 Only STRU F and STRU R are implemented\r\n");
    }

    return ftpReplyOrError(data, socketId, "s", "501 Unrecognized STRU parameter\r\n");
}

/* RFC 959 MODE: only Stream mode is supported */
int parseCommandMode(ftpDataType *data, int socketId)
{
    char *theMode = getFtpCommandArg("MODE", data->clients[socketId].theCommandReceived, 0);

    if (strnlen(theMode, 1) == 0)
    {
        return ftpReplyOrError(data, socketId, "s", "501 MODE requires a parameter\r\n");
    }

    if (strcasecmp(theMode, "S") == 0)
    {
        return ftpReplyOrError(data, socketId, "s", "200 MODE set to Stream\r\n");
    }

    if (strcasecmp(theMode, "B") == 0 || strcasecmp(theMode, "C") == 0)
    {
        return ftpReplyOrError(data, socketId, "s", "504 Only MODE S is implemented\r\n");
    }

    return ftpReplyOrError(data, socketId, "s", "501 Unrecognized MODE parameter\r\n");
}

/* RFC 1123 4.1.2.13: HELP is part of the minimum implementation */
int parseCommandHelp(ftpDataType *data, int socketId)
{
    return ftpReplyOrError(data, socketId, "s",
        "214-The following commands are recognized:\r\n"
        " USER PASS ACCT QUIT AUTH PBSZ PROT CCC  FEAT OPTS SYST HELP\r\n"
        " NOOP STAT SITE TYPE STRU MODE PORT PASV EPRT EPSV ABOR REST\r\n"
        " RETR STOR APPE LIST NLST DELE RNFR RNTO MKD  XMKD RMD  XRMD\r\n"
        " CWD  CDUP XCUP PWD  XPWD SIZE MDTM ALLO MLST MLSD LANG HOST\r\n"
        "214 Help OK.\r\n");
}

/* RFC 959: storage is never preallocated, ALLO is accepted and ignored */
int parseCommandAllo(ftpDataType *data, int socketId)
{
    return ftpReplyOrError(data, socketId, "s", "202 ALLO command superfluous at this site\r\n");
}

/* Commands defined by RFC 959 that this server does not provide (REIN, STOU, SMNT) */
int parseCommandNotImplemented(ftpDataType *data, int socketId)
{
    return ftpReplyOrError(data, socketId, "s", "502 Command not implemented\r\n");
}

int parseCommandPasv(ftpDataType *data, int socketId)
{
    if (data->clients[socketId].epsvAllUsed == 1)
    {
        return ftpReplyOrError(data, socketId, "s", EPSV_ALL_REFUSAL);
    }

    /* Create worker thread */

    if(data->clients[socketId].isIpV6 == 1)
    {
		return ftpReplyOrError(data, socketId, "s", "500 Server use IPV6, use EPSV instead.\r\n");
    }

    if (replaceDataWorker(data, socketId) != 0)
    {
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }

    data->clients[socketId].workerData.passiveModeOn = 1;
    data->clients[socketId].workerData.extendedPassiveModeOn = 0;
    data->clients[socketId].workerData.activeModeOn = 0;

    return startDataChannel(data, socketId, "worker-args-1");
}

int parseCommandEpsv(ftpDataType *data, int socketId)
{
    char *theArgument = getFtpCommandArg("EPSV", data->clients[socketId].theCommandReceived, 0);

    if (strnlen(theArgument, 1) != 0)
    {
        /* RFC 2428 section 3: ALL promises that no other data connection command will be
           used. No data connection is set up. */
        if (strcasecmp(theArgument, "ALL") == 0)
        {
            data->clients[socketId].epsvAllUsed = 1;
            return ftpReplyOrError(data, socketId, "s", "200 EPSV ALL accepted, only EPSV is allowed from now on\r\n");
        }

        /* A network protocol (1 = IPv4, 2 = IPv6): the data connection always uses the
           protocol of the control connection, so any other one is 522 (RFC 2428 section 2) */
        if (isAllDigits(theArgument) != 1 || strlen(theArgument) > 3)
        {
            return ftpReplyOrError(data, socketId, "s", "501 Syntax error in EPSV parameters\r\n");
        }

        if (atoi(theArgument) != (data->clients[socketId].isIpV6 == 1 ? 2 : 1))
        {
            return ftpReplyOrError(data, socketId, "s",
                data->clients[socketId].isIpV6 == 1 ? "522 Network protocol not supported, use (2)\r\n"
                                                    : "522 Network protocol not supported, use (1)\r\n");
        }
    }

    /* Create worker thread */
    // my_printf("\n data->clients[%d].workerData.workerThread = %d",socketId,  (int)data->clients[socketId].workerData.workerThread);

    // my_printf("\n data->clients[%d].workerData.threadHasBeenCreated = %d", socketId,  data->clients[socketId].workerData.threadHasBeenCreated);
    if (replaceDataWorker(data, socketId) != 0)
    {
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }

    data->clients[socketId].workerData.passiveModeOn = 1;
    data->clients[socketId].workerData.extendedPassiveModeOn = 1;
    data->clients[socketId].workerData.activeModeOn = 0;

    return startDataChannel(data, socketId, "worker-args-2");
}

int parseCommandPort(ftpDataType *data, int socketId)
{
    char *theIpAndPort;
    int ipAddressBytes[4] = {0, 0, 0, 0};
    int portBytes[2] = {0, 0};
    int scannedItems, thePort;
    char trailingChar;
    char theAddress[INET_ADDRSTRLEN];

    if (data->clients[socketId].epsvAllUsed == 1)
    {
        return ftpReplyOrError(data, socketId, "s", EPSV_ALL_REFUSAL);
    }

    theIpAndPort = getFtpCommandArg("PORT", data->clients[socketId].theCommandReceived, 0);

    /* Exactly six comma separated numbers, each one a byte (RFC 959 host-port) */
    scannedItems = sscanf(theIpAndPort, "%d,%d,%d,%d,%d,%d%c", &ipAddressBytes[0], &ipAddressBytes[1], &ipAddressBytes[2], &ipAddressBytes[3], &portBytes[0], &portBytes[1], &trailingChar);

    if (scannedItems != 6 ||
        ipAddressBytes[0] < 0 || ipAddressBytes[0] > 255 ||
        ipAddressBytes[1] < 0 || ipAddressBytes[1] > 255 ||
        ipAddressBytes[2] < 0 || ipAddressBytes[2] > 255 ||
        ipAddressBytes[3] < 0 || ipAddressBytes[3] > 255 ||
        portBytes[0] < 0 || portBytes[0] > 255 ||
        portBytes[1] < 0 || portBytes[1] > 255)
    {
        return ftpReplyOrError(data, socketId, "s", "501 Syntax error in PORT parameters\r\n");
    }

    thePort = (portBytes[0] * 256) + portBytes[1];
    snprintf(theAddress, sizeof(theAddress), "%d.%d.%d.%d", ipAddressBytes[0], ipAddressBytes[1], ipAddressBytes[2], ipAddressBytes[3]);

    if (isDataAddressAllowed(data, socketId, theAddress, thePort) == 0)
    {
        return ftpReplyOrError(data, socketId, "s", "504 PORT refused: only the client address and ports above 1023 are allowed\r\n");
    }

    /* Stop the previous worker first: its cleanup resets the worker data, target port included */
    if (replaceDataWorker(data, socketId) != 0)
    {
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }

    data->clients[socketId].workerData.addressType = 1;
    data->clients[socketId].workerData.connectionPort = thePort;
    snprintf(data->clients[socketId].workerData.activeIpAddress, CLIENT_BUFFER_STRING_SIZE, "%s", theAddress);

    data->clients[socketId].workerData.passiveModeOn = 0;
    data->clients[socketId].workerData.extendedPassiveModeOn = 0;
    data->clients[socketId].workerData.activeModeOn = 1;

    my_printf("\n Port command received port: %d", data->clients[socketId].workerData.connectionPort);

    return startDataChannel(data, socketId, "worker-args-3");
}

int parseCommandAbor(ftpDataType *data, int socketId)
{
    /*
     426 ABORT
    226-Transfer aborted
    226 3.406 seconds (measured here), 1.58 Mbytes per second
    226 Since you see this ABOR must've succeeded
    */
    int returnCode;
    if (data->clients[socketId].workerData.threadIsAlive == 1)
    {

        if (replaceDataWorker(data, socketId) != 0)
        {
            return FTP_COMMAND_PROCESSED_WRITE_ERROR;
        }

        returnCode = socketPrintf(data, socketId, "s", "426 ABORT\r\n");
        if (returnCode <= 0) 
        {
            return FTP_COMMAND_PROCESSED_WRITE_ERROR;
        }

        returnCode = socketPrintf(data, socketId, "s", "226 Transfer aborted\r\n");
        if (returnCode <= 0)
        {
            return FTP_COMMAND_PROCESSED_WRITE_ERROR;
        }
    }
    else
    {
        returnCode = socketPrintf(data, socketId, "s", "226 Since you see this ABOR must've succeeded\r\n");
        if (returnCode <= 0)
        {
            return FTP_COMMAND_PROCESSED_WRITE_ERROR;
        }
    }

    return FTP_COMMAND_PROCESSED;
}

int parseCommandList(ftpDataType *data, int socketId)
{
    return parseListingCommand(data, socketId, "LIST");
}

/* STAT [<path>]. Runs in the control thread and is allowed while a transfer is in
   progress, so it uses its own path and options: it used to free and rewrite
   listPath and workerData.ftpCommand, which a LIST/NLST worker may be reading. */
int parseCommandStat(ftpDataType *data, int socketId)
{
    int returnCode = 0;
    int functionReturnCode = FTP_COMMAND_PROCESSED;
    char *theNameToList = NULL;
    int theFiles = 0;
    dynamicStringDataType statPath;
    ftpCommandDataType statCommand;

    theNameToList = getFtpCommandArg("STAT", data->clients[socketId].theCommandReceived, 1);

    if (strnlen(theNameToList, 1) == 0)
    {
        my_printf("\nNo stat argument");
        returnCode = socketPrintf(data, socketId, "sssssdsss",
                                    "211-FTP server status:\r\n",
                                    "     Logged in as ",
                                    data->clients[socketId].login.name.text,
                                    "\r\n",
                                    "     Session timeout in seconds is ",
                                    data->ftpParameters.maximumIdleInactivity,
                                    "\r\n",
                                    "     uFTP "UFTP_SERVER_VERSION"\r\n",
                                    "211 End of status\r\n");

        if (returnCode <= 0)
        {
            return FTP_COMMAND_PROCESSED_WRITE_ERROR;
        }

        return FTP_COMMAND_PROCESSED;
    }

    cleanDynamicStringDataType(&statPath, 1, &data->clients[socketId].memoryTable);
    cleanDynamicStringDataType(&statCommand.commandArgs, 1, &data->clients[socketId].memoryTable);
    cleanDynamicStringDataType(&statCommand.commandOps, 1, &data->clients[socketId].memoryTable);

    getFtpCommandArgWithOptions("STAT", data->clients[socketId].theCommandReceived, &statCommand, &data->clients[socketId].memoryTable);

    if (getSafePath(&statPath, theNameToList, &data->clients[socketId].login, &data->clients[socketId].memoryTable) != 1 ||
        (FILE_IsDirectory(statPath.text, 0) == 0 && FILE_IsFile(statPath.text, 0) == 0))
    {
        /* one reply only: it used to answer 550 and then list the current directory too */
        LOGF("%sSTAT wrong path: %s", LOG_DEBUG_PREFIX, theNameToList);
        functionReturnCode = ftpReplyOrError(data, socketId, "s", "550 wrong path\r\n");
    }
    else if ((checkUserFilePermissions(statPath.text, data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid) & FILE_PERMISSION_R) != FILE_PERMISSION_R)
    {
        LOGF("%sSTAT no permissions: %s", LOG_SECURITY_PREFIX, statPath.text);
        functionReturnCode = ftpReplyOrError(data, socketId, "s", "550 no permissions.\r\n");
    }
    else
    {
        /* the multi-line reply is written as one block: the 226 of a transfer that ends
           meanwhile (sent by the data worker) must not land in the middle of it */
        pthread_mutex_lock(&data->clients[socketId].writeMutex);

        if (socketPrintf(data, socketId, "s", "213-Status follow:\r\n") <= 0 ||
            writeListDataInfoToSocket(data, socketId, statPath.text, statCommand.commandOps.text, &theFiles, COMMAND_TYPE_STAT, &data->clients[socketId].memoryTable) <= 0 ||
            socketPrintf(data, socketId, "sds", "213 End of status ", theFiles, " matches total\r\n") <= 0)
        {
            functionReturnCode = FTP_COMMAND_PROCESSED_WRITE_ERROR;
        }

        pthread_mutex_unlock(&data->clients[socketId].writeMutex);
    }

    cleanDynamicStringDataType(&statPath, 0, &data->clients[socketId].memoryTable);
    cleanDynamicStringDataType(&statCommand.commandArgs, 0, &data->clients[socketId].memoryTable);
    cleanDynamicStringDataType(&statCommand.commandOps, 0, &data->clients[socketId].memoryTable);

    return functionReturnCode;
}

int parseCommandNlst(ftpDataType *data, int socketId)
{
    return parseListingCommand(data, socketId, "NLST");
}

/* RFC 3659: MLSD <directory> sends the machine readable listing on the data connection */
int parseCommandMlsd(ftpDataType *data, int socketId)
{
    return parseListingCommand(data, socketId, "MLSD");
}

/* RFC 3659: MLST [<path>] answers on the control connection with the facts of one file or
   directory. Like STAT it does not need the data worker and is allowed during a transfer. */
int parseCommandMlst(ftpDataType *data, int socketId)
{
    int functionReturnCode = FTP_COMMAND_PROCESSED;
    char *theNameToList = getFtpCommandArg("MLST", data->clients[socketId].theCommandReceived, 0);
    dynamicStringDataType mlstPath;
    struct stat info;
    char facts[256];
    DYNMEM_MemoryTable_DataType **memoryTable = &data->clients[socketId].memoryTable;

    cleanDynamicStringDataType(&mlstPath, 1, memoryTable);

    if (strnlen(theNameToList, 1) == 0)
    {
        setDynamicStringDataType(&mlstPath, data->clients[socketId].login.absolutePath.text, data->clients[socketId].login.absolutePath.textLen, memoryTable);
    }
    else if (getSafePath(&mlstPath, theNameToList, &data->clients[socketId].login, memoryTable) != 1)
    {
        cleanDynamicStringDataType(&mlstPath, 0, memoryTable);
    }

    if (mlstPath.text == NULL || stat(mlstPath.text, &info) != 0 ||
        FTP_FormatMlsxFacts(facts, sizeof(facts), &info, 0, 0, 0) == 0)
    {
        LOGF("%sMLST wrong path: %s", LOG_DEBUG_PREFIX, theNameToList);
        functionReturnCode = ftpReplyOrError(data, socketId, "s", "550 wrong path\r\n");
    }
    else if ((checkUserFilePermissions(mlstPath.text, data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid) & FILE_PERMISSION_R) != FILE_PERMISSION_R)
    {
        LOGF("%sMLST no permissions: %s", LOG_SECURITY_PREFIX, mlstPath.text);
        functionReturnCode = ftpReplyOrError(data, socketId, "s", "550 no permissions.\r\n");
    }
    else if (FTP_FormatMlsxFacts(facts, sizeof(facts), &info, data->clients[socketId].mlstFacts,
                                 data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid) < 0)
    {
        functionReturnCode = ftpReplyOrError(data, socketId, "s", "550 listing not available\r\n");
    }
    else
    {
        /* one block, as STAT: the 226 of a transfer that ends meanwhile must not land in the middle */
        pthread_mutex_lock(&data->clients[socketId].writeMutex);

        if (socketPrintf(data, socketId, "ssss", "250-Listing ", strnlen(theNameToList, 1) == 0 ? "." : theNameToList, "\r\n ", facts) <= 0 ||
            socketPrintf(data, socketId, "sss", " ", strnlen(theNameToList, 1) == 0 ? "." : theNameToList, "\r\n250 End\r\n") <= 0)
        {
            functionReturnCode = FTP_COMMAND_PROCESSED_WRITE_ERROR;
        }

        pthread_mutex_unlock(&data->clients[socketId].writeMutex);
    }

    cleanDynamicStringDataType(&mlstPath, 0, memoryTable);

    return functionReturnCode;
}

/* RFC 959 4.1.3: REST is followed at once by the transfer command it is for. RETR, STOR and APPE take the offset when they
   arrive, whatever happens to them: a command that is refused (425, 550, no permission...) must not leave the offset for a
   later transfer that has nothing to do with it. */
static void takeRestartOffset(ftpDataType *data, int socketId)
{
    data->clients[socketId].workerData.transferRestartAtByte = data->clients[socketId].workerData.retrRestartAtByte;
    data->clients[socketId].workerData.retrRestartAtByte = 0;
}

int parseCommandRetr(ftpDataType *data, int socketId)
{
    int isSafePath = 0;
    char *theNameToRetr;
    int returnCode = 0;

    takeRestartOffset(data, socketId);

    if (replyIfDataChannelNotUsable(data, socketId, &returnCode) == 1)
    {
        return returnCode;
    }

    theNameToRetr = getFtpCommandArg("RETR", data->clients[socketId].theCommandReceived, 0);
    cleanDynamicStringDataType(&data->clients[socketId].fileToRetr, 0, &data->clients[socketId].memoryTable);

    if (strnlen(theNameToRetr, 1) > 0)
    {
        isSafePath = getSafePath(&data->clients[socketId].fileToRetr, theNameToRetr, &data->clients[socketId].login, &data->clients[socketId].memoryTable);
    }

    if (isSafePath == 1 &&
        FILE_IsFile(data->clients[socketId].fileToRetr.text, 1) == 1)
    {

        if ((checkUserFilePermissions(data->clients[socketId].fileToRetr.text, data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid) & FILE_PERMISSION_R) != FILE_PERMISSION_R)
        {
            LOGF("%sRETR no permissions file: %s", LOG_DEBUG_PREFIX, data->clients[socketId].fileToRetr.text);
            return ftpReplyOrError(data, socketId, "s", "550 no reading permission on the file\r\n");
        }

        return giveCommandToDataWorker(data, socketId);
    }
    else
    {
        LOGF("%sRETR not a file: %s", LOG_DEBUG_PREFIX, data->clients[socketId].fileToRetr.text);

        return ftpReplyOrError(data, socketId, "s", "550 Failed to open file.\r\n");
    }

    return FTP_COMMAND_PROCESSED;
}

int parseCommandStor(ftpDataType *data, int socketId)
{
    int isSafePath = 0;
    char *theNameToStor;
    int returnCode;

    takeRestartOffset(data, socketId);

    theNameToStor = getFtpCommandArg("STOR", data->clients[socketId].theCommandReceived, 0);
    if (strnlen(theNameToStor, 1) == 0)
    {
        return ftpReplyOrError(data, socketId, "s", "501 STOR requires a path\r\n");
    }

    // if file exist check for overwrite permission
    if (replyIfDataChannelNotUsable(data, socketId, &returnCode) == 1)
    {
        return returnCode;
    }

    int pathFailure = 0;
    cleanDynamicStringDataType(&data->clients[socketId].fileToStor, 0, &data->clients[socketId].memoryTable);
    isSafePath = getSafePathWithReason(&data->clients[socketId].fileToStor, theNameToStor, &data->clients[socketId].login, &data->clients[socketId].memoryTable, &pathFailure);

    if (isSafePath == 1)
    {
        if(FILE_IsFile(data->clients[socketId].fileToStor.text, 0) == 1)
        {
            if ((checkUserFilePermissions(data->clients[socketId].fileToStor.text, data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid) & FILE_PERMISSION_W) != FILE_PERMISSION_W)
            {
                cleanDynamicStringDataType(&data->clients[socketId].fileToStor, 0, &data->clients[socketId].memoryTable);
                return ftpReplyOrError(data, socketId, "s", "550 Error no permission to overwrite the file\r\n");
            }
        }


        if ((checkParentDirectoryPermissions(data->clients[socketId].fileToStor.text, data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid) & FILE_PERMISSION_W) != FILE_PERMISSION_W)
        {
            LOGF("%sSTOR no permissions file: %s", LOG_DEBUG_PREFIX, data->clients[socketId].fileToStor.text);

            returnCode = socketPrintf(data, socketId, "s", "550 No permissions to write the file\r\n");
            cleanDynamicStringDataType(&data->clients[socketId].fileToStor, 0, &data->clients[socketId].memoryTable);
            if (returnCode <= 0) 
            {
                return FTP_COMMAND_PROCESSED_WRITE_ERROR;
            }
                
            return FTP_COMMAND_PROCESSED;
        }

        if (replyIfDiskIsFull(data, socketId, "STOR", &returnCode) == 1)
        {
            return returnCode;
        }

        return giveCommandToDataWorker(data, socketId);
    }
    else
    {
        if (pathFailure == ENOENT)
        {
            return replyParentDirectoryMissing(data, socketId, "STOR", theNameToStor);
        }

        LOGF("%sSTOR wrong path file: %s", LOG_DEBUG_PREFIX, theNameToStor);

        returnCode = socketPrintf(data, socketId, "s", "550 Wrong path.\r\n");
        cleanDynamicStringDataType(&data->clients[socketId].fileToStor, 0, &data->clients[socketId].memoryTable);

        if (returnCode <= 0) 
        {
            return FTP_COMMAND_PROCESSED_WRITE_ERROR;
        }

        return FTP_COMMAND_PROCESSED;
    }

    return FTP_COMMAND_PROCESSED;
}

int parseCommandAppe(ftpDataType *data, int socketId)
{
    int isSafePath = 0;
    char *theNameToStor;
    int returnCode;

    takeRestartOffset(data, socketId);

    theNameToStor = getFtpCommandArg("APPE", data->clients[socketId].theCommandReceived, 0);
    if (strnlen(theNameToStor, 1) == 0)
    {
        return ftpReplyOrError(data, socketId, "s", "501 APPE requires a path\r\n");
    }

    if (replyIfDataChannelNotUsable(data, socketId, &returnCode) == 1)
    {
        return returnCode;
    }

    int pathFailure = 0;
    cleanDynamicStringDataType(&data->clients[socketId].fileToStor, 0, &data->clients[socketId].memoryTable);
    isSafePath = getSafePathWithReason(&data->clients[socketId].fileToStor, theNameToStor, &data->clients[socketId].login, &data->clients[socketId].memoryTable, &pathFailure);

    if (isSafePath == 1)
    {

        if(FILE_IsFile(data->clients[socketId].fileToStor.text, 0) == 1)
        {
            if ((checkUserFilePermissions(data->clients[socketId].fileToStor.text, data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid) & FILE_PERMISSION_W) != FILE_PERMISSION_W)
            {
                cleanDynamicStringDataType(&data->clients[socketId].fileToStor, 0, &data->clients[socketId].memoryTable);
                return ftpReplyOrError(data, socketId, "s", "550 no permission to append on file\r\n");
            }
        }


        if ((checkParentDirectoryPermissions(data->clients[socketId].fileToStor.text, data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid) & FILE_PERMISSION_W) != FILE_PERMISSION_W)
        {

            LOGF("%sAPPE no permission path: %s", LOG_DEBUG_PREFIX, data->clients[socketId].fileToStor.text);

            return ftpReplyOrError(data, socketId, "s", "550 No permissions to write the file\r\n");
        }

        if (replyIfDiskIsFull(data, socketId, "APPE", &returnCode) == 1)
        {
            return returnCode;
        }

        return giveCommandToDataWorker(data, socketId);
    }
    else
    {
        if (pathFailure == ENOENT)
        {
            return replyParentDirectoryMissing(data, socketId, "APPE", theNameToStor);
        }

        LOGF("%sAPPE wrong path: %s", LOG_DEBUG_PREFIX, theNameToStor);

        return ftpReplyOrError(data, socketId, "s", "550 Wrong path.\r\n");
    }

    return FTP_COMMAND_PROCESSED;
}

int parseCommandCwd(ftpDataType *data, int socketId)
{
    dynamicStringDataType absolutePathPrevious, ftpPathPrevious, theSafePath;
    int isSafePath = 0;
    int returnCode;
    char *thePath;

    cleanDynamicStringDataType(&absolutePathPrevious, 1, &data->clients[socketId].memoryTable);
    cleanDynamicStringDataType(&ftpPathPrevious, 1, &data->clients[socketId].memoryTable);
    cleanDynamicStringDataType(&theSafePath, 1, &data->clients[socketId].memoryTable);

    thePath = getFtpCommandArg("CWD", data->clients[socketId].theCommandReceived, 0);

    my_printf("\ncdw requested path: %s", thePath);

    if (strnlen(thePath, 1) > 0)
    {
        // my_printf("Memory data address 1st call : %lld", &data->clients[socketId].memoryTable);
        isSafePath = getSafePath(&theSafePath, thePath, &data->clients[socketId].login, &data->clients[socketId].memoryTable);
        //my_printf("\ncdw safe path: %s", theSafePath.text);
    }

    if (isSafePath)
    {
        my_printf("\n The Path requested for CWD IS:%s", theSafePath.text);
        setDynamicStringDataType(&absolutePathPrevious, data->clients[socketId].login.absolutePath.text, data->clients[socketId].login.absolutePath.textLen, &data->clients[socketId].memoryTable);
        setDynamicStringDataType(&ftpPathPrevious, data->clients[socketId].login.ftpPath.text, data->clients[socketId].login.ftpPath.textLen, &data->clients[socketId].memoryTable);

        cleanDynamicStringDataType(&data->clients[socketId].login.ftpPath, 0, &data->clients[socketId].memoryTable);
        cleanDynamicStringDataType(&data->clients[socketId].login.absolutePath, 0, &data->clients[socketId].memoryTable);
        setDynamicStringDataType(&data->clients[socketId].login.absolutePath, theSafePath.text, theSafePath.textLen, &data->clients[socketId].memoryTable);

        
        if (data->clients[socketId].login.absolutePath.textLen > data->clients[socketId].login.homePath.textLen)
        {
            char *theFtpPathPointer = data->clients[socketId].login.absolutePath.text;
            theFtpPathPointer += data->clients[socketId].login.homePath.textLen;
            if (theFtpPathPointer[0] != '/')
            {
                setDynamicStringDataType(&data->clients[socketId].login.ftpPath, "/", 1, &data->clients[socketId].memoryTable);
                appendToDynamicStringDataType(&data->clients[socketId].login.ftpPath, theFtpPathPointer, strlen(theFtpPathPointer), &data->clients[socketId].memoryTable);
            }
            else
            {
                setDynamicStringDataType(&data->clients[socketId].login.ftpPath, theFtpPathPointer, strlen(theFtpPathPointer), &data->clients[socketId].memoryTable);
            }
        }
        else
        {
            setDynamicStringDataType(&data->clients[socketId].login.ftpPath, "/", 1, &data->clients[socketId].memoryTable);
        }

        //		my_printf("\ndata->clients[socketId].login.absolutePath = %s", data->clients[socketId].login.absolutePath.text);
        //		my_printf("\ndata->clients[socketId].login.ftpPath = %s", data->clients[socketId].login.ftpPath.text);
        //        my_printf("\nChecking the directory: %s", data->clients[socketId].login.absolutePath.text);

        if (FILE_IsDirectory(data->clients[socketId].login.absolutePath.text, 1) == 1)
        {
            if ((checkUserFilePermissions(data->clients[socketId].login.absolutePath.text, data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid) & FILE_PERMISSION_R) == FILE_PERMISSION_R)
            {
                returnCode = socketPrintf(data, socketId, "sss", "250 OK. Current directory is  ", data->clients[socketId].login.ftpPath.text, "\r\n");

                if (returnCode <= 0) 
                {
                    return FTP_COMMAND_PROCESSED_WRITE_ERROR;
                }
            }
            else
            {
                LOGF("%sCWD no permissions: %s", LOG_DEBUG_PREFIX, data->clients[socketId].login.absolutePath.text);
                my_printfError("no permission to cwd: %s", data->clients[socketId].login.absolutePath.text);
                returnCode = socketPrintf(data, socketId, "sss", "550 Can't change directory to ", thePath, ": no permissions\r\n");

                if (returnCode <= 0) 
                {
                    return FTP_COMMAND_PROCESSED_WRITE_ERROR;
                }     

                setDynamicStringDataType(&data->clients[socketId].login.absolutePath, absolutePathPrevious.text, absolutePathPrevious.textLen, &data->clients[socketId].memoryTable);
                setDynamicStringDataType(&data->clients[socketId].login.ftpPath, ftpPathPrevious.text, ftpPathPrevious.textLen, &data->clients[socketId].memoryTable);
            }
        }
        else
        {
            my_printfError("CWD not a directory: %s", data->clients[socketId].login.absolutePath.text);
            /* the reply is the same, the log says which of the two it is */
            struct stat cwdTargetInfo;
            LOG_CLIENT(data, socketId, LOG_DEBUG_PREFIX, "CWD %s: %s",
                       stat(data->clients[socketId].login.absolutePath.text, &cwdTargetInfo) == 0 ? "target is not a directory" : "directory does not exist",
                       data->clients[socketId].login.absolutePath.text);

            returnCode = socketPrintf(data, socketId, "sss", "550 Can't change directory to ", thePath, ": No such file or directory\r\n");

            if (returnCode <= 0) 
            {
                return FTP_COMMAND_PROCESSED_WRITE_ERROR;
            }     

            setDynamicStringDataType(&data->clients[socketId].login.absolutePath, absolutePathPrevious.text, absolutePathPrevious.textLen, &data->clients[socketId].memoryTable);
            setDynamicStringDataType(&data->clients[socketId].login.ftpPath, ftpPathPrevious.text, ftpPathPrevious.textLen, &data->clients[socketId].memoryTable);
        }

        cleanDynamicStringDataType(&absolutePathPrevious, 0, &data->clients[socketId].memoryTable);
        cleanDynamicStringDataType(&ftpPathPrevious, 0, &data->clients[socketId].memoryTable);
        cleanDynamicStringDataType(&theSafePath, 0, &data->clients[socketId].memoryTable);

        if (returnCode <= 0) 
        {
            return FTP_COMMAND_PROCESSED_WRITE_ERROR;
        }

        return FTP_COMMAND_PROCESSED;
    }
    else
    {
        my_printfError("CWD wrong path: %s", data->clients[socketId].login.absolutePath.text);
        cleanDynamicStringDataType(&absolutePathPrevious, 0, &data->clients[socketId].memoryTable);
        cleanDynamicStringDataType(&ftpPathPrevious, 0, &data->clients[socketId].memoryTable);
        cleanDynamicStringDataType(&theSafePath, 0, &data->clients[socketId].memoryTable);

        if (strnlen(thePath, 1) == 0)
            returnCode = socketPrintf(data, socketId, "s", "501 CWD requires a directory name\r\n");
        else
            returnCode = socketPrintf(data, socketId, "s", "550 Wrong path.\r\n");

        LOGF("%sCWD wrong path: %s", LOG_DEBUG_PREFIX, data->clients[socketId].login.absolutePath.text);

        if (returnCode <= 0) 
        {
            return FTP_COMMAND_PROCESSED_WRITE_ERROR;
        }

        return FTP_COMMAND_PROCESSED;
    }
}

int parseCommandRest(ftpDataType *data, int socketId)
{
    int returnCode;
    char *theOffset = getFtpCommandArg("REST", data->clients[socketId].theCommandReceived, 0);
    size_t theOffsetLen = strlen(theOffset);

    /* RFC 3659 section 5: the argument is a decimal byte offset (18 digits fit a long long) */
    if (theOffsetLen == 0 || theOffsetLen > 18 || isAllDigits(theOffset) == 0)
    {
        return ftpReplyOrError(data, socketId, "s", "501 REST requires a byte offset\r\n");
    }

    data->clients[socketId].workerData.retrRestartAtByte = atoll(theOffset);
    returnCode = socketPrintf(data, socketId, "sss", "350 Restarting at ", theOffset, "\r\n");

    if (returnCode <= 0) 
    {
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }

    return FTP_COMMAND_PROCESSED;
}

int parseCommandMkd(ftpDataType *data, int socketId)
{
    int returnCode;
    int functionReturnCode = FTP_COMMAND_NOT_RECONIZED;
    int isSafePath;
    char *theDirectoryFilename = "";       /* the command is MKD or XMKD: this is only for the compiler */
    dynamicStringDataType mkdFileName;

    if (compareStringCaseInsensitive(data->clients[socketId].theCommandReceived, "MKD", strlen("MKD")) == 1)
        theDirectoryFilename = getFtpCommandArg("MKD", data->clients[socketId].theCommandReceived, 0);
    else if (compareStringCaseInsensitive(data->clients[socketId].theCommandReceived, "XMKD", strlen("XMKD")) == 1)
        theDirectoryFilename = getFtpCommandArg("XMKD", data->clients[socketId].theCommandReceived, 0);

    my_printf("\ntheDirectoryFilename mkd: %s", theDirectoryFilename);

    cleanDynamicStringDataType(&mkdFileName, 1, &data->clients[socketId].memoryTable);
    isSafePath = getSafePath(&mkdFileName, theDirectoryFilename, &data->clients[socketId].login, &data->clients[socketId].memoryTable);
    my_printf("\nmkdFileName.text: %s", mkdFileName.text);

    if (isSafePath == 1)
    {
        if ((checkParentDirectoryPermissions(mkdFileName.text, data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid) & FILE_PERMISSION_W) == FILE_PERMISSION_W)
        {
            int returnStatus;
            returnStatus = mkdir(mkdFileName.text, S_IRWXU | S_IRWXG | S_IRWXO);
            logFileOperation(data, socketId, "MKD", mkdFileName.text, NULL, returnStatus);

            if (returnStatus == -1)
            {
                returnCode = socketPrintf(data, socketId, "sss", "550 error while creating directory ", theDirectoryFilename, "\r\n");
                if (returnCode <= 0)
                {
                    functionReturnCode = FTP_COMMAND_PROCESSED_WRITE_ERROR;
                }
                else
                {
                    functionReturnCode = FTP_COMMAND_PROCESSED;
                }
            }
            else
            {
                if (data->clients[socketId].login.ownerShip.ownerShipSet == 1)
                {
                    returnStatus = FILE_doChownFromUidGid(mkdFileName.text, data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid);
                }
                /* RFC 959 appendix II: 257 carries the absolute pathname, with double quotes doubled */
                char createdFtpPath[PATH_MAX + 2];
                char quotedPath[(PATH_MAX * 2) + 5];

                if (absoluteToFtpPath(mkdFileName.text, &data->clients[socketId].login, createdFtpPath, sizeof(createdFtpPath)) == 1)
                    quoteFtpString(createdFtpPath, quotedPath, sizeof(quotedPath));
                else
                    quoteFtpString(theDirectoryFilename, quotedPath, sizeof(quotedPath));

                returnCode = socketPrintf(data, socketId, "sss", "257 \"", quotedPath, "\" The directory was successfully created\r\n");
                my_printf("\n\n ------------------ Directory created");
                if (returnCode <= 0)
                {
                    functionReturnCode = FTP_COMMAND_PROCESSED_WRITE_ERROR;
                }
                else
                {
                    functionReturnCode = FTP_COMMAND_PROCESSED;
                }
            }
        }
        else
        {
            LOGF("%sMKD no permissions to create: %s ", LOG_DEBUG_PREFIX, theDirectoryFilename);

            returnCode = socketPrintf(data, socketId, "sss", "550 no permition to create directory ", theDirectoryFilename, "\r\n");
            if (returnCode <= 0)
            {
                functionReturnCode = FTP_COMMAND_PROCESSED_WRITE_ERROR;
            }
            else
            {
                functionReturnCode = FTP_COMMAND_PROCESSED;
            }
        }
    }
    else
    {
        LOGF("MKD wrong path: %s", LOG_DEBUG_PREFIX, theDirectoryFilename);

        cleanDynamicStringDataType(&mkdFileName, 0, &data->clients[socketId].memoryTable);
        functionReturnCode = replyMissingOrWrongPath(data, socketId, theDirectoryFilename);
    }

    cleanDynamicStringDataType(&mkdFileName, 0, &data->clients[socketId].memoryTable);
    return functionReturnCode;
}

int parseCommandOpts(ftpDataType *data, int socketId)
{
    int returnCode;
    char *optionString = getFtpCommandArg("OPTS", data->clients[socketId].theCommandReceived, 0);

    my_printf("\noptionString: %s", optionString);

    if (!optionString || strlen(optionString) == 0)
    {
        returnCode = socketPrintf(data, socketId, "s", "501 Syntax error in parameters or arguments.\r\n");
        if (returnCode <= 0) LOG_ERROR("socketPrintfError");
        return FTP_COMMAND_PROCESSED;
    }

    // For example, parse only UTF8 ON/OFF options:
    if (strncasecmp(optionString, "UTF8 ON", 7) == 0)
    {
        // Enable UTF8 (set a flag in client/session data if needed)
        returnCode = socketPrintf(data, socketId, "s", "200 UTF8 mode enabled\r\n");
    }
    else if (strncasecmp(optionString, "UTF8 OFF", 8) == 0)
    {
        // Disable UTF8
        returnCode = socketPrintf(data, socketId, "s", "200 UTF8 mode disabled\r\n");
    }
    else if (strncasecmp(optionString, "MLST", 4) == 0 && (optionString[4] == '\0' || optionString[4] == ' '))
    {
        /* RFC 3659 section 7.9: the facts MLST and MLSD send. Unknown names are ignored,
           an empty list means no fact at all. */
        char list[128];
        char *item, *saved = NULL;
        int facts = 0, i;
        char reply[192];

        snprintf(list, sizeof(list), "%s", optionString + 4);

        for (item = strtok_r(list, "; ", &saved); item != NULL; item = strtok_r(NULL, "; ", &saved))
        {
            for (i = 0; i < MLST_FACT_COUNT; i++)
            {
                if (strcasecmp(item, mlstFactTable[i].name) == 0)
                {
                    facts |= mlstFactTable[i].bit;
                }
            }
        }

        data->clients[socketId].mlstFacts = facts;
        mlstFactsToText(list, sizeof(list), facts, 0);
        snprintf(reply, sizeof(reply), "200 MLST OPTS %s\r\n", list);
        returnCode = socketPrintf(data, socketId, "s", reply);
    }
    else
    {
        returnCode = socketPrintf(data, socketId, "s", "501 Option not supported.\r\n");
    }

    if (returnCode <= 0) 
    {
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }

    return FTP_COMMAND_PROCESSED;
}

int parseCommandDele(ftpDataType *data, int socketId)
{
    int functionReturnCode = 0;
    int returnCode;
    int isSafePath;
    int returnStatus = 0;
    char *theFileToDelete;
    dynamicStringDataType deleFileName;

    theFileToDelete = getFtpCommandArg("DELE", data->clients[socketId].theCommandReceived, 0);

    cleanDynamicStringDataType(&deleFileName, 1, &data->clients[socketId].memoryTable);
    /* unlink() removes a link itself, never what it points to */
    isSafePath = getSafePathNoFollow(&deleFileName, theFileToDelete, &data->clients[socketId].login, &data->clients[socketId].memoryTable);

    if (isSafePath == 1)
    {
        // my_printf("\nThe file to delete is: %s", deleFileName.text);
        if (FILE_IsFile(deleFileName.text, 0) == 1)
        {
            if ((checkUserFilePermissions(deleFileName.text, data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid) & FILE_PERMISSION_W) == FILE_PERMISSION_W)
            {
                returnStatus = remove(deleFileName.text);
                logFileOperation(data, socketId, "DELE", deleFileName.text, NULL, returnStatus);

                if (returnStatus == -1)
                {
                    returnCode = socketPrintf(data, socketId, "sss", "550 Could not delete the file: ", theFileToDelete, " some errors occurred\r\n");
                }
                else
                {
                    returnCode = socketPrintf(data, socketId, "sss", "250 Deleted ", theFileToDelete, "\r\n");
                }

                functionReturnCode = FTP_COMMAND_PROCESSED;

                if (returnCode <= 0) 
                {
                    return FTP_COMMAND_PROCESSED_WRITE_ERROR;
                }

            }
            else
            {
                LOGF("%sDELE no permissions on: %s ", LOG_DEBUG_PREFIX, deleFileName.text);

                returnCode = socketPrintf(data, socketId, "sss", "550 Could not delete the file: ", theFileToDelete, " no permissions\r\n");

                functionReturnCode = FTP_COMMAND_PROCESSED;

                if (returnCode <= 0) 
                {
                    functionReturnCode = FTP_COMMAND_PROCESSED_WRITE_ERROR;
                }

            }
        }
        else if (FILE_IsLink(deleFileName.text) == 1 && FILE_IsDirectory(deleFileName.text, 1) == 0)
        {
            returnStatus = remove(deleFileName.text);
            logFileOperation(data, socketId, "DELE", deleFileName.text, NULL, returnStatus);

            if (returnStatus == -1)
            {
                returnCode = socketPrintf(data, socketId, "sss", "550 Could not delete the file: ", theFileToDelete, " some errors occurred\r\n");
            }
            else
            {
                returnCode = socketPrintf(data, socketId, "sss", "250 Deleted ", theFileToDelete, "\r\n");
            }

            functionReturnCode = FTP_COMMAND_PROCESSED;

            if (returnCode <= 0) 
            {
                return FTP_COMMAND_PROCESSED_WRITE_ERROR;
            }
        }
        else
        {
            LOGF("%sDELE no file found: %s", LOG_DEBUG_PREFIX, deleFileName.text);
            returnCode = socketPrintf(data, socketId, "s", "550 Could not delete the file: No such file or file is a directory\r\n");
            functionReturnCode = FTP_COMMAND_PROCESSED;

            if (returnCode <= 0) 
            {
                functionReturnCode = FTP_COMMAND_PROCESSED_WRITE_ERROR;
            }
        }
    }
    else
    {
        functionReturnCode = replyMissingOrWrongPath(data, socketId, theFileToDelete);
    }

    cleanDynamicStringDataType(&deleFileName, 0, &data->clients[socketId].memoryTable);
    return functionReturnCode;
}

int parseCommandMdtm(ftpDataType *data, int socketId)
{
    int functionReturnCode = 0;
    int returnCode;
    int isSafePath;
    char *theFileToGetModificationDate;

    dynamicStringDataType mdtmFileName;
    char theResponse[LIST_DATA_TYPE_MODIFIED_DATA_STR_SIZE];
    memset(theResponse, 0, LIST_DATA_TYPE_MODIFIED_DATA_STR_SIZE);

    theFileToGetModificationDate = getFtpCommandArg("MDTM", data->clients[socketId].theCommandReceived, 0);

    cleanDynamicStringDataType(&mdtmFileName, 1, &data->clients[socketId].memoryTable);
    isSafePath = getSafePath(&mdtmFileName, theFileToGetModificationDate, &data->clients[socketId].login, &data->clients[socketId].memoryTable);

    my_printf("\ntheFileToGetModificationDate = %s", theFileToGetModificationDate);
    my_printf("\nmdtmFileName.text = %s", mdtmFileName.text);
    my_printf("\nisSafePath = %d", isSafePath);
    my_printf("\n Safe ok is file: %d, is directory: %d", FILE_IsFile(mdtmFileName.text, 0), FILE_IsDirectory(mdtmFileName.text, 0));

    if (isSafePath == 1)
    {
        my_printf("\n Safe ok is file: %d, is directory: %d", FILE_IsFile(mdtmFileName.text, 0), FILE_IsDirectory(mdtmFileName.text, 0));

        if (FILE_IsFile(mdtmFileName.text, 0) == 1 ||
            FILE_IsDirectory(mdtmFileName.text, 0) == 1)
        {
            time_t theTime = FILE_GetLastModifiedData(mdtmFileName.text);

            /* RFC 3659 section 2.3: time values are always UTC. FILE_GetLastModifiedData
               already shifts the time so that localtime_r yields the UTC fields. */
            struct tm newtime;
            localtime_r(&theTime, &newtime);

            strftime(theResponse, LIST_DATA_TYPE_MODIFIED_DATA_STR_SIZE, "213 %Y%m%d%H%M%S\r\n", &newtime);
            returnCode = socketPrintf(data, socketId, "s", theResponse);
            functionReturnCode = FTP_COMMAND_PROCESSED;

            if (returnCode <= 0) 
            {
                functionReturnCode = FTP_COMMAND_PROCESSED_WRITE_ERROR;
            }
        }
        else
        {
            LOGF("%sMDTM error can't check for file existence: %s", LOG_DEBUG_PREFIX, mdtmFileName.text);
            returnCode = socketPrintf(data, socketId, "s", "550 Can't check for file existence\r\n");
            functionReturnCode = FTP_COMMAND_PROCESSED;

            if (returnCode <= 0) 
            {
                functionReturnCode = FTP_COMMAND_PROCESSED_WRITE_ERROR;
            }
        }
    }
    else
    {
        LOGF("%sMDTM invalid path: %s ",LOG_DEBUG_PREFIX, mdtmFileName.text);
        functionReturnCode = replyMissingOrWrongPath(data, socketId, theFileToGetModificationDate);
    }

    cleanDynamicStringDataType(&mdtmFileName, 0, &data->clients[socketId].memoryTable);
    return functionReturnCode;
}

int parseCommandNoop(ftpDataType *data, int socketId)
{
    return ftpReplyOrError(data, socketId, "s", "200 Zzz...\r\n");
}

int notLoggedInMessage(ftpDataType *data, int socketId)
{
    return ftpReplyOrError(data, socketId, "s", "530 You aren't logged in\r\n");
}

int invalidCommandResponse(ftpDataType *data, int socketId)
{
    return ftpReplyOrError(data, socketId, "s", "500 Syntax error, command unrecognized.\r\n");
}

int parseCommandQuit(ftpDataType *data, int socketId)
{
    int returnCode;
    returnCode = socketPrintf(data, socketId, "s", "221 Logout.\r\n");

    if (returnCode <= 0) 
    {
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }

    markClientForClosing(data, socketId, "QUIT");
    return FTP_COMMAND_PROCESSED;
}

int parseCommandRmd(ftpDataType *data, int socketId)
{
    int functionReturnCode = 0;
    int returnCode;
    int isSafePath;
    int returnStatus = 0;
    char *theDirectoryFilename = "";       /* the command is RMD or XRMD: this is only for the compiler */
    dynamicStringDataType rmdFileName;

    if(compareStringCaseInsensitive(data->clients[socketId].theCommandReceived, "RMD", strlen("RMD")) == 1)
        theDirectoryFilename = getFtpCommandArg("RMD", data->clients[socketId].theCommandReceived, 0);
    else if(compareStringCaseInsensitive(data->clients[socketId].theCommandReceived, "XRMD", strlen("XRMD")) == 1)
        theDirectoryFilename = getFtpCommandArg("XRMD", data->clients[socketId].theCommandReceived, 0);


    cleanDynamicStringDataType(&rmdFileName, 1, &data->clients[socketId].memoryTable);
    isSafePath = getSafePath(&rmdFileName, theDirectoryFilename, &data->clients[socketId].login, &data->clients[socketId].memoryTable);

    if (isSafePath == 1)
    {
        if (FILE_IsDirectory(rmdFileName.text, 0) == 1)
        {
            if ((checkUserFilePermissions(rmdFileName.text, data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid) & FILE_PERMISSION_W) == FILE_PERMISSION_W)
            {


                returnStatus = rmdir(rmdFileName.text);
                logFileOperation(data, socketId, "RMD", rmdFileName.text, NULL, returnStatus);

                if (returnStatus == -1)
                {

                    returnCode = socketPrintf(data, socketId, "sss", "550 Could not remove the directory: ", strerror(errno)," \r\n");
                }
                else
                {
                    returnCode = socketPrintf(data, socketId, "s", "250 The directory was successfully removed\r\n");
                }

                functionReturnCode = FTP_COMMAND_PROCESSED;

                if (returnCode <= 0) 
                {
                    functionReturnCode = FTP_COMMAND_PROCESSED_WRITE_ERROR;
                }
            }
            else
            {
                LOGF("%sRMD error dir no permissions: %s", LOG_DEBUG_PREFIX, rmdFileName.text);
                returnCode = socketPrintf(data, socketId, "s", "550 Could not delete the directory: No permissions\r\n");
                functionReturnCode = FTP_COMMAND_PROCESSED;

                if (returnCode <= 0) 
                {
                    functionReturnCode = FTP_COMMAND_PROCESSED_WRITE_ERROR;
                }
            }
        }
        else
        {
            LOGF("%sRMD error dir not exist: %s ", LOG_DEBUG_PREFIX, rmdFileName.text);

            returnCode = socketPrintf(data, socketId, "s", "550 Could not delete the directory:No such directory\r\n");
            functionReturnCode = FTP_COMMAND_PROCESSED;

            if (returnCode <= 0) 
            {
                functionReturnCode = FTP_COMMAND_PROCESSED_WRITE_ERROR;
            }
        }
    }
    else
    {
        functionReturnCode = replyMissingOrWrongPath(data, socketId, theDirectoryFilename);
    }

    cleanDynamicStringDataType(&rmdFileName, 0, &data->clients[socketId].memoryTable);

    return functionReturnCode;
}

int parseCommandSize(ftpDataType *data, int socketId)
{
    int returnCode;
    int isSafePath;
    long long int theSize;
    char *theFileName;
    dynamicStringDataType getSizeFromFileName;

    theFileName = getFtpCommandArg("SIZE", data->clients[socketId].theCommandReceived, 0);

    cleanDynamicStringDataType(&getSizeFromFileName, 1, &data->clients[socketId].memoryTable);

    isSafePath = getSafePath(&getSizeFromFileName, theFileName, &data->clients[socketId].login, &data->clients[socketId].memoryTable);


    // handle broken link case
    if (isSafePath == 1)
    {

        /* FILE_IsFile is true for directories too (they can be opened): exclude them */
        /* one stat(): a file that disappears between a check and an open used to be answered "213 0" (an
           empty file), and a client that synchronises files would take it for one */
        struct stat sizeInfo;

        if (stat(getSizeFromFileName.text, &sizeInfo) == 0 && S_ISREG(sizeInfo.st_mode) &&
            access(getSizeFromFileName.text, R_OK) == 0)
        {
            theSize = (long long int)sizeInfo.st_size;
            returnCode = socketPrintf(data, socketId, "sls", "213 ", theSize, "\r\n");
        }
        else
        {
            LOGF("%sSIZE error file not exist: %s", LOG_DEBUG_PREFIX, getSizeFromFileName.text);

            returnCode = socketPrintf(data, socketId, "s", "550 Can't check for file existence\r\n");
        }
    }
    else
    {
        /* the path received: getSizeFromFileName is empty when the path was refused */
        LOGF("%sSIZE error file wrong path: %s", LOG_DEBUG_PREFIX, theFileName);

        if (strnlen(theFileName, 1) == 0)
            returnCode = socketPrintf(data, socketId, "s", "501 SIZE requires a file name\r\n");
        else
            returnCode = socketPrintf(data, socketId, "s", "550 Can't check for file existence\r\n");
    }
    cleanDynamicStringDataType(&getSizeFromFileName, 0, &data->clients[socketId].memoryTable);

    if (returnCode <= 0) 
    {
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }

    return FTP_COMMAND_PROCESSED;
}

int parseCommandRnfr(ftpDataType *data, int socketId)
{
    int returnCode;
    int isSafePath;
    char *theRnfrFileName;

    theRnfrFileName = getFtpCommandArg("RNFR", data->clients[socketId].theCommandReceived, 0);
    cleanDynamicStringDataType(&data->clients[socketId].renameFromFile, 0, &data->clients[socketId].memoryTable);
    cleanDynamicStringDataType(&data->clients[socketId].renameFromFileWd, 0, &data->clients[socketId].memoryTable);

    /* rename() moves a link itself, never what it points to */
    isSafePath = getSafePathNoFollow(&data->clients[socketId].renameFromFile, theRnfrFileName, &data->clients[socketId].login, &data->clients[socketId].memoryTable);

    if (isSafePath == 1 &&
        (FILE_IsFile(data->clients[socketId].renameFromFile.text, 0) == 1 ||
         FILE_IsDirectory(data->clients[socketId].renameFromFile.text, 0) == 1))
    {
        if (FILE_IsFile(data->clients[socketId].renameFromFile.text, 0) == 1 ||
            FILE_IsDirectory(data->clients[socketId].renameFromFile.text, 0) == 1)
        {
            if ((checkUserFilePermissions(data->clients[socketId].renameFromFile.text, data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid) & FILE_PERMISSION_W) == FILE_PERMISSION_W)
            {
                returnCode = socketPrintf(data, socketId, "s", "350 RNFR accepted - file exists, ready for destination\r\n");
                setDynamicStringDataType(&data->clients[socketId].renameFromFileWd, data->clients[socketId].login.ftpPath.text, data->clients[socketId].login.ftpPath.textLen, &data->clients[socketId].memoryTable);
            }
            else 
            {
                cleanDynamicStringDataType(&data->clients[socketId].renameFromFile, 0, &data->clients[socketId].memoryTable);
                returnCode = socketPrintf(data, socketId, "s", "550 no file permissions\r\n");
            }
        }
        else
        {
            cleanDynamicStringDataType(&data->clients[socketId].renameFromFile, 0, &data->clients[socketId].memoryTable);
            returnCode = socketPrintf(data, socketId, "s", "550 Sorry, but that file doesn't exist\r\n");
        }
    }
    else if (isSafePath == 1 && FILE_IsLink(data->clients[socketId].renameFromFile.text) == 1)
    {
        /* FILE_IsLink returns -1 when the path does not exist: only 1 means "is a link" */
    	returnCode = socketPrintf(data, socketId, "s", "350 RNFR accepted - file exists, ready for destination\r\n");
        setDynamicStringDataType(&data->clients[socketId].renameFromFileWd, data->clients[socketId].login.ftpPath.text, data->clients[socketId].login.ftpPath.textLen, &data->clients[socketId].memoryTable);
    }
    else if (strnlen(theRnfrFileName, 1) == 0)
    {
        cleanDynamicStringDataType(&data->clients[socketId].renameFromFile, 0, &data->clients[socketId].memoryTable);
        returnCode = socketPrintf(data, socketId, "s", "501 RNFR requires a file name\r\n");
    }
    else
    {
        LOGF("%sRNFR error renaming the file: %s", LOG_DEBUG_PREFIX, data->clients[socketId].renameFromFile.text);
        cleanDynamicStringDataType(&data->clients[socketId].renameFromFile, 0, &data->clients[socketId].memoryTable);
        returnCode = socketPrintf(data, socketId, "s", "550 Sorry, but that file doesn't exist\r\n");
    }

    if (returnCode <= 0) 
    {
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }

    return FTP_COMMAND_PROCESSED;
}

int parseCommandRnto(ftpDataType *data, int socketId)
{
    int returnCode = 0;
    int isSafePath;
    char *theRntoFileName;

    theRntoFileName = getFtpCommandArg("RNTO", data->clients[socketId].theCommandReceived, 0);
    cleanDynamicStringDataType(&data->clients[socketId].renameToFile, 0, &data->clients[socketId].memoryTable);

    isSafePath = getSafePathNoFollow(&data->clients[socketId].renameToFile, theRntoFileName, &data->clients[socketId].login, &data->clients[socketId].memoryTable);

    if (isSafePath == 1 &&
        data->clients[socketId].renameFromFile.textLen > 0 &&
        data->clients[socketId].renameFromFileWd.textLen == data->clients[socketId].login.ftpPath.textLen &&
        strcmp(data->clients[socketId].renameFromFileWd.text, data->clients[socketId].login.ftpPath.text) == 0)
    {
        if(FILE_IsFile(data->clients[socketId].renameToFile.text, 0) == 1)
        {
            if ((checkUserFilePermissions(data->clients[socketId].renameToFile.text, data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid) & FILE_PERMISSION_W) != FILE_PERMISSION_W)
            {
                cleanDynamicStringDataType(&data->clients[socketId].renameFromFile, 0, &data->clients[socketId].memoryTable);
                cleanDynamicStringDataType(&data->clients[socketId].renameFromFileWd, 0, &data->clients[socketId].memoryTable);
                cleanDynamicStringDataType(&data->clients[socketId].renameToFile, 0, &data->clients[socketId].memoryTable);
                return ftpReplyOrError(data, socketId, "s", "550 Error Renaming the file no permissions\r\n");
            }
        }

        if (FILE_IsFile(data->clients[socketId].renameFromFile.text, 0) == 1 ||
            FILE_IsDirectory(data->clients[socketId].renameFromFile.text, 0) == 1)
        {
            if ((checkUserFilePermissions(data->clients[socketId].renameFromFile.text, data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid) & FILE_PERMISSION_W) == FILE_PERMISSION_W &&
                (checkParentDirectoryPermissions(data->clients[socketId].renameToFile.text, data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid) & FILE_PERMISSION_W) == FILE_PERMISSION_W)
            {
                returnCode = rename(data->clients[socketId].renameFromFile.text, data->clients[socketId].renameToFile.text);
                logFileOperation(data, socketId, "RNFR/RNTO", data->clients[socketId].renameFromFile.text, data->clients[socketId].renameToFile.text, returnCode);
                if (returnCode == 0)
                {
                    returnCode = socketPrintf(data, socketId, "s", "250 File successfully renamed or moved\r\n");
                }
                else
                {
                    returnCode = socketPrintf(data, socketId, "s", "553 Error renaming the file\r\n");
                }
            }
            else
            {
                LOG_CLIENT(data, socketId, LOG_DEBUG_PREFIX, "RNTO refused: %s -> %s", data->clients[socketId].renameFromFile.text, data->clients[socketId].renameToFile.text);
                returnCode = socketPrintf(data, socketId, "s", "550 No permissions to rename the file\r\n");
            }
        }
        else if (FILE_IsLink(data->clients[socketId].renameFromFile.text) == 1)
        {
            if((checkParentDirectoryPermissions(data->clients[socketId].renameToFile.text, data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid) & FILE_PERMISSION_W) == FILE_PERMISSION_W)
            {
                returnCode = rename(data->clients[socketId].renameFromFile.text, data->clients[socketId].renameToFile.text);
                logFileOperation(data, socketId, "RNFR/RNTO", data->clients[socketId].renameFromFile.text, data->clients[socketId].renameToFile.text, returnCode);
                if (returnCode == 0)
                {
                    returnCode = socketPrintf(data, socketId, "s", "250 File successfully renamed or moved\r\n");
                }
                else
                {
                    returnCode = socketPrintf(data, socketId, "s", "553 Error renaming the file\r\n");
                }
            }
            else
            {
                LOG_CLIENT(data, socketId, LOG_DEBUG_PREFIX, "RNTO refused: %s -> %s", data->clients[socketId].renameFromFile.text, data->clients[socketId].renameToFile.text);
                returnCode = socketPrintf(data, socketId, "s", "550 No permissions to rename the file\r\n");
            }            
        }
        else
        {
            LOG_CLIENT(data, socketId, LOG_DEBUG_PREFIX, "RNTO refused: %s -> %s", data->clients[socketId].renameFromFile.text, data->clients[socketId].renameToFile.text);
            returnCode = socketPrintf(data, socketId, "s", "550 The file to rename does not exist anymore\r\n");
        }
    }
    else if (strnlen(theRntoFileName, 1) == 0)
    {
        returnCode = socketPrintf(data, socketId, "s", "501 RNTO requires a file name\r\n");
    }
    else if (data->clients[socketId].renameFromFile.textLen <= 0)
    {
        returnCode = socketPrintf(data, socketId, "s", "503 Need RNFR before RNTO\r\n");
    }
    else if (isSafePath != 1)
    {
        returnCode = socketPrintf(data, socketId, "s", "553 Destination file name not allowed\r\n");
    }
    else
    {
        returnCode = socketPrintf(data, socketId, "s", "503 Working directory changed after RNFR, send RNFR again\r\n");
    }

    cleanDynamicStringDataType(&data->clients[socketId].renameFromFile, 0, &data->clients[socketId].memoryTable);
    cleanDynamicStringDataType(&data->clients[socketId].renameFromFileWd, 0, &data->clients[socketId].memoryTable);
    cleanDynamicStringDataType(&data->clients[socketId].renameToFile, 0, &data->clients[socketId].memoryTable);

    if (returnCode <= 0) 
    {
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }
    else
    {
        return FTP_COMMAND_PROCESSED;
    }
}

int parseCommandCdup(ftpDataType *data, int socketId)
{
    int returnCode;

    returnCode = FILE_DirectoryToParent(&data->clients[socketId].login.absolutePath.text, &data->clients[socketId].memoryTable);
    returnCode = FILE_DirectoryToParent(&data->clients[socketId].login.ftpPath.text, &data->clients[socketId].memoryTable);
    data->clients[socketId].login.absolutePath.textLen = strlen(data->clients[socketId].login.absolutePath.text);
    data->clients[socketId].login.ftpPath.textLen = strlen(data->clients[socketId].login.ftpPath.text);

    if (strncmp(data->clients[socketId].login.absolutePath.text, data->clients[socketId].login.homePath.text, data->clients[socketId].login.homePath.textLen) != 0)
    {
        setDynamicStringDataType(&data->clients[socketId].login.absolutePath, data->clients[socketId].login.homePath.text, data->clients[socketId].login.homePath.textLen, &data->clients[socketId].memoryTable);
    }

    if (!returnCode)
    {
        returnCode = socketPrintf(data, socketId, "sss", "550 Already at root directory. ", data->clients[socketId].login.ftpPath.text, "\r\n");

        if (returnCode <= 0) 
        {
            return FTP_COMMAND_PROCESSED_WRITE_ERROR;
        }
        return FTP_COMMAND_PROCESSED;
    }

    returnCode = socketPrintf(data, socketId, "sss", "250 OK. Current directory is ", data->clients[socketId].login.ftpPath.text, "\r\n");

    if (returnCode <= 0) 
    {
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }

    return FTP_COMMAND_PROCESSED;
}

int parseCommandAcct(ftpDataType *data, int socketId)
{
    return ftpReplyOrError(data, socketId, "s", "502 ACCT not implemented.\r\n");
}

/* The file of a download is kept in the data of the worker: if the worker is cancelled (write() is a
   cancellation point) resetWorkerData() closes it. Open and close are done with the cancellation disabled, so
   there is no moment in which the file is open and nobody knows. */
static void closeRetrFile(ftpDataType *data, int theSocketId)
{
    int previousCancelState;
    FILE *file;

    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previousCancelState);
    file = data->clients[theSocketId].workerData.theRetrFile;
    data->clients[theSocketId].workerData.theRetrFile = NULL;
    if (file != NULL)
    {
        fclose(file);
    }
    pthread_setcancelstate(previousCancelState, NULL);
}

/* STRU R in stream mode (RFC 959 section 3.4.2): 0xFF is doubled, 0xFF 0x01 ends a record,
   0xFF 0x02 ends the file and 0xFF 0x03 both. A file of the file system has no records: it is sent as one. */
#define RECORD_ESCAPE 0xFF
#define RECORD_EOR 0x01
#define RECORD_EOF 0x02
#define RECORD_EOR_EOF 0x03

/* out must hold 2 * length bytes. Returns the length written. */
int recordEncode(const char *in, int length, char *out)
{
    int i, written = 0;

    for (i = 0; i < length; i++)
    {
        out[written++] = in[i];

        if ((unsigned char)in[i] == RECORD_ESCAPE)
        {
            out[written++] = (char)RECORD_ESCAPE;
        }
    }

    return written;
}

/* Decodes the block in place. *pendingEscape is 1 if the last byte of the previous block was 0xFF.
   *ended is set to 1 at the end-of-file marker (the bytes after it are not looked at).
   Returns the length of the data, or -1 for a marker that does not exist. */
int recordDecode(char *buffer, int length, int *pendingEscape, int *ended)
{
    int i, written = 0;

    for (i = 0; i < length && *ended == 0; i++)
    {
        unsigned char byte = (unsigned char)buffer[i];

        if (*pendingEscape == 0)
        {
            if (byte == RECORD_ESCAPE)
            {
                *pendingEscape = 1;
            }
            else
            {
                buffer[written++] = (char)byte;
            }

            continue;
        }

        *pendingEscape = 0;

        if (byte == RECORD_ESCAPE)
        {
            buffer[written++] = (char)RECORD_ESCAPE;
        }
        else if (byte == RECORD_EOF || byte == RECORD_EOR_EOF)
        {
            *ended = 1;
        }
        else if (byte != RECORD_EOR)
        {
            return -1;
        }
    }

    return written;
}

/* Sends length bytes of a download on the data connection. Returns the bytes written (less than
   length for a failure, with errno set). */
static long long int sendRetrBlock(ftpDataType *data, int theSocketId, const char *block, long long int length)
{
    long long int writtenSize = 0;

    if (data->clients[theSocketId].dataChannelIsTls != 1)
    {
        /* write() can be partial (signal, slow descriptor): send the whole
           block, not just the first part. */
        while (writtenSize < length)
        {
            ssize_t result = write(data->clients[theSocketId].workerData.socketConnection,
                                   block + writtenSize, length - writtenSize);
            if (result > 0)
            {
                writtenSize += result;
                continue;
            }
            if (result < 0 && errno == EINTR)
                continue;
            break;
        }
    }
    else
    {
#ifdef OPENSSL_ENABLED
        SSL *dataSsl = NULL;

        if (data->clients[theSocketId].workerData.passiveModeOn == 1 ||
            data->clients[theSocketId].workerData.activeModeOn == 1)
            dataSsl = data->clients[theSocketId].workerData.serverSsl;

        writtenSize = (dataSsl != NULL) ?
            tlsWriteBounded(dataSsl, data->clients[theSocketId].workerData.socketConnection,
                            block, (int)length, dataWriteTimeoutMs(data)) : -1;
#endif
    }

    return writtenSize;
}

/* Download in clear text with the file structure: the kernel copies the file into the socket, the
   bytes never come into the program (fread + write used 0.40 s of CPU per GB, sendfile() 0.09).
   *position is where the file is, in and out. Returns the bytes sent, -1 if sendfile() can not be
   used on this file (nothing was sent from the point reached: the caller goes on with read and write),
   or -2 for an error of the connection (errno is set). */
#ifdef LARGE_FILE_SUPPORT_ENABLED
typedef off64_t sendfileOffset;
#define SENDFILE_CALL sendfile64
#else
typedef off_t sendfileOffset;
#define SENDFILE_CALL sendfile
#endif

static long long int sendRetrFileWithSendfile(ftpDataType *data, int theSocketId, int fileDescriptor, sendfileOffset *position)
{
    long long int sent = 0;
    int socketDescriptor = data->clients[theSocketId].workerData.socketConnection;
    int socketFlags = fcntl(socketDescriptor, F_GETFL, 0);

    /* sendfile() is not a cancellation point and on a blocking socket it waits inside the kernel for as
       long as the client does not read: ABOR (pthread_cancel) would never reach the worker. On a
       non-blocking socket it returns EAGAIN and the wait is a poll(), which is one. */
    if (socketFlags == -1 || fcntl(socketDescriptor, F_SETFL, socketFlags | O_NONBLOCK) == -1)
    {
        return -1;
    }

    while (1)
    {
        /* with a client that reads fast sendfile() never waits: the cancellation of ABOR must still be seen */
        pthread_testcancel();

        ssize_t result = SENDFILE_CALL(socketDescriptor, fileDescriptor, position, TRANSFER_SENDFILE_BLOCK_SIZE);

        if (result > 0)
        {
            sent += result;
            data->clients[theSocketId].lastActivityTimeStamp = (int)time(NULL);
            continue;
        }

        if (result == 0)
        {
            fcntl(socketDescriptor, F_SETFL, socketFlags);
            return sent;            /* end of the file (also if it became shorter) */
        }

        if (errno == EINTR)
        {
            continue;
        }

        if (errno == EAGAIN)
        {
            struct pollfd waiting;

            waiting.fd = socketDescriptor;
            waiting.events = POLLOUT;
            waiting.revents = 0;
            poll(&waiting, 1, 1000);
            continue;
        }

        {
            int sendfileError = errno;

            fcntl(socketDescriptor, F_SETFL, socketFlags);
            errno = sendfileError;
        }

        if ((errno == EINVAL || errno == ENOSYS || errno == EOPNOTSUPP) && sent == 0)
        {
            return -1;
        }

        return -2;
    }
}

long long int writeRetrFile(ftpDataType *data, int theSocketId, long long int startFrom, FILE *retrFP)
{
    long long int readen = 0;
    long long int toReturn = 0, writtenSize = 0;

    /* On the heap, in the memory table of the worker (freed by its cleanup if the worker is cancelled): a big array on
       the stack of a thread that pthread_cancel unwinds makes AddressSanitizer report a false overflow. */
    char *buffer = (char *) DYNMEM_malloc(TRANSFER_BLOCK_SIZE, &data->clients[theSocketId].workerData.memoryTable, "retrBlock");

    if (buffer == NULL)
        return -1;

    {
        int previousCancelState;
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previousCancelState);
#ifdef LARGE_FILE_SUPPORT_ENABLED
        retrFP = fopen64(data->clients[theSocketId].fileToRetr.text, "rb");
#else
        retrFP = fopen(data->clients[theSocketId].fileToRetr.text, "rb");
#endif
        data->clients[theSocketId].workerData.theRetrFile = retrFP;
        pthread_setcancelstate(previousCancelState, NULL);
    }

    if (retrFP == NULL)
    {
        DYNMEM_free(buffer, &data->clients[theSocketId].workerData.memoryTable);
        return -1;
    }

    // File size check removed as it's not used

    if (startFrom > 0)
    {
        my_printf("\nCursor moved %lld", startFrom);

#ifdef LARGE_FILE_SUPPORT_ENABLED
        if (fseeko64(retrFP, startFrom, SEEK_SET) != 0)
#else
        if (fseeko(retrFP, startFrom, SEEK_SET) != 0)
#endif
        {
            closeRetrFile(data, theSocketId);
            retrFP = NULL;
            DYNMEM_free(buffer, &data->clients[theSocketId].workerData.memoryTable);
            return toReturn;
        }

        my_printf("\ncurrentPosition %lld", startFrom);
    }

    /* Clear text and file structure: sendfile(). The read buffer is of no use then, it stays allocated
       for the fallback and is freed with the rest. sendfile() takes the position as an argument and does not
       move the one of the FILE, which is where a fallback goes on (REST was already applied to it). */
    if (data->clients[theSocketId].dataChannelIsTls != 1 && data->clients[theSocketId].recordStructure != 1)
    {
        sendfileOffset position = (sendfileOffset)startFrom;
        long long int sentBySendfile;

        sentBySendfile = sendRetrFileWithSendfile(data, theSocketId, fileno(retrFP), &position);

        if (sentBySendfile >= 0)
        {
            closeRetrFile(data, theSocketId);
            retrFP = NULL;
            DYNMEM_free(buffer, &data->clients[theSocketId].workerData.memoryTable);
            return sentBySendfile;
        }

        if (sentBySendfile == -2)
        {
            int writeError = errno;
            closeRetrFile(data, theSocketId);
            retrFP = NULL;
            errno = writeError != 0 ? writeError : EIO;
            DYNMEM_free(buffer, &data->clients[theSocketId].workerData.memoryTable);
            return RETR_TRANSFER_FAILED;
        }
    }

    /* STRU R: the block is copied with the 0xFF doubled, so it can be twice as long */
    char *wire = NULL;
    const char *toSend;
    long long int toSendLength;

    if (data->clients[theSocketId].recordStructure == 1)
    {
        wire = (char *) DYNMEM_malloc(2 * TRANSFER_BLOCK_SIZE, &data->clients[theSocketId].workerData.memoryTable, "retrRecordBlock");

        if (wire == NULL)
        {
            closeRetrFile(data, theSocketId);
            retrFP = NULL;
            DYNMEM_free(buffer, &data->clients[theSocketId].workerData.memoryTable);
            return -1;
        }
    }

    while ((readen = (long long int)fread(buffer, sizeof(char), TRANSFER_BLOCK_SIZE, retrFP)) > 0)
    {
        my_printf("\nTRANSFER read %lld bytes: %.*s", readen, (int)readen, buffer);

        toSend = buffer;
        toSendLength = readen;

        if (wire != NULL)
        {
            toSendLength = recordEncode(buffer, (int)readen, wire);
            toSend = wire;
        }

        writtenSize = sendRetrBlock(data, theSocketId, toSend, toSendLength);

        /* a block sent only in part is a failure too: the file would have a hole */
        if (writtenSize < toSendLength)
        {
            int writeError = errno;
            my_printf("\nError %lld while writing retr file.", writtenSize);
            closeRetrFile(data, theSocketId);
            retrFP = NULL;
            errno = writeError != 0 ? writeError : EIO;
            DYNMEM_free(buffer, &data->clients[theSocketId].workerData.memoryTable);
            if (wire != NULL)
                DYNMEM_free(wire, &data->clients[theSocketId].workerData.memoryTable);
            return RETR_TRANSFER_FAILED;
        }
        else
        {
            toReturn += writtenSize;
            data->clients[theSocketId].lastActivityTimeStamp = (int)time(NULL);
        }
    }

    if (wire != NULL)
    {
        /* the file is one record: end of record and end of file */
        const char endMarker[2] = {(char)RECORD_ESCAPE, (char)RECORD_EOR_EOF};

        writtenSize = sendRetrBlock(data, theSocketId, endMarker, 2);
        DYNMEM_free(wire, &data->clients[theSocketId].workerData.memoryTable);

        if (writtenSize < 2)
        {
            int writeError = errno;
            closeRetrFile(data, theSocketId);
            retrFP = NULL;
            errno = writeError != 0 ? writeError : EIO;
            DYNMEM_free(buffer, &data->clients[theSocketId].workerData.memoryTable);
            return RETR_TRANSFER_FAILED;
        }

        toReturn += writtenSize;
    }

    closeRetrFile(data, theSocketId);
    retrFP = NULL;
    DYNMEM_free(buffer, &data->clients[theSocketId].workerData.memoryTable);
    return toReturn;
}

char *getFtpCommandArg(char *theCommand, char *theCommandString, int skipArgs)
{
    char *toReturn = theCommandString + strlen(theCommand);

    /* Pass spaces */
    while (toReturn[0] == ' ')
    {
        toReturn += 1;
    }

    /* Skip eventual secondary arguments */
    if (skipArgs == 1)
    {
        if (toReturn[0] == '-')
        {
            while (toReturn[0] != ' ' &&
                   toReturn[0] != '\r' &&
                   toReturn[0] != '\n' &&
                   toReturn[0] != 0)
            {
                toReturn += 1;
            }
        }

        /* Pass spaces */
        while (toReturn[0] == ' ')
        {
            toReturn += 1;
        }
    }

    return toReturn;
}

int getFtpCommandArgWithOptions(char *theCommand, char *theCommandString, ftpCommandDataType *ftpCommand, DYNMEM_MemoryTable_DataType **memoryTable)
{
#define CASE_ARG_MAIN 0
#define CASE_ARG_SECONDARY 1

    int i = 0;
    int isSecondArg = 0;
    char argMain[FTP_COMMAND_ELABORATE_CHAR_BUFFER+1];
    char argSecondary[FTP_COMMAND_ELABORATE_CHAR_BUFFER+1];
    memset(argMain, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER+1);
    memset(argSecondary, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER+1);

    int argMainIndex = 0;
    int argSecondaryIndex = 0;

    char *theCommandPointer = theCommandString;
    theCommandPointer += strlen(theCommand);

    /*Remove spaces*/
    while (theCommandPointer[0] == ' ')
    {
        theCommandPointer += 1;
    }

    if (theCommandPointer[i] == '-')
    {
        isSecondArg = 1;
        theCommandPointer++;
    }

    while (theCommandPointer[i] != '\r' &&
           theCommandPointer[i] != '\n' &&
           theCommandPointer[i] != 0)
    {
        switch (isSecondArg)
        {
        case CASE_ARG_MAIN:
        {
            if (argMainIndex < FTP_COMMAND_ELABORATE_CHAR_BUFFER)
                argMain[argMainIndex++] = theCommandPointer[i];
            i++;
        }
        break;

        case CASE_ARG_SECONDARY:
        {
            if (theCommandPointer[i] != ' ')
            {
                if (argSecondaryIndex < FTP_COMMAND_ELABORATE_CHAR_BUFFER)
                    argSecondary[argSecondaryIndex++] = theCommandPointer[i];
                i++;
            }
            else
            {
                isSecondArg = 0;
                while (theCommandPointer[0] == ' ')
                {
                    theCommandPointer += 1;
                }
            }
        }
        break;

        default:
            break;
        }
    }

    if (argMainIndex > 0)
        setDynamicStringDataType(&ftpCommand->commandArgs, argMain, argMainIndex, memoryTable);

    if (argSecondaryIndex > 0)
        setDynamicStringDataType(&ftpCommand->commandOps, argSecondary, argSecondaryIndex, memoryTable);

    return 1;
}

/* SITE CHMOD <octal mode> <pathname>. permissionsCommand starts at "CHMOD". */
int setPermissions(char *permissionsCommand, loginDataType *login, DYNMEM_MemoryTable_DataType **memoryTable)
{
    char thePermissionString[5];
    int thePermissionStringCursor = 0;
    int returnCodeSetPermissions;
    int toReturn = FTP_CHMODE_COMMAND_RETURN_CODE_OK;
    mode_t theMode;
    char *cursor = permissionsCommand + strlen("CHMOD");
    dynamicStringDataType theSafePath;

    while (*cursor == ' ')
        cursor++;

    /* the mode: one to four octal digits */
    while (*cursor >= '0' && *cursor <= '7')
    {
        if (thePermissionStringCursor >= 4)
            return FTP_CHMODE_COMMAND_RETURN_CODE_SYNTAX_ERROR;

        thePermissionString[thePermissionStringCursor++] = *cursor++;
    }
    thePermissionString[thePermissionStringCursor] = '\0';

    if (thePermissionStringCursor == 0 || *cursor != ' ')
        return FTP_CHMODE_COMMAND_RETURN_CODE_SYNTAX_ERROR;

    while (*cursor == ' ')
        cursor++;

    if (*cursor == '\0')
        return FTP_CHMODE_COMMAND_RETURN_CODE_SYNTAX_ERROR;

    /* setuid and setgid: the file would run with the owner of the server process (often
       root) for whoever executes it. The sticky bit is harmless and stays allowed. */
    theMode = (mode_t)strtol(thePermissionString, NULL, 8);
    if ((theMode & (S_ISUID | S_ISGID)) != 0)
        return FTP_CHMODE_COMMAND_RETURN_CODE_SPECIAL_BITS;

    /* Same path resolution of every other command: the target can not be outside
       the home of the user. */
    cleanDynamicStringDataType(&theSafePath, 1, memoryTable);

    if (getSafePath(&theSafePath, cursor, login, memoryTable) != 1 ||
        (FILE_IsFile(theSafePath.text, 0) != 1 && FILE_IsDirectory(theSafePath.text, 0) != 1))
    {
        LOGF("%sCHMOD not a file or directory: %s", LOG_DEBUG_PREFIX, cursor);
        cleanDynamicStringDataType(&theSafePath, 0, memoryTable);
        return FTP_CHMODE_COMMAND_RETURN_CODE_NO_FILE;
    }

    /* The rule of every other command that changes a file: the user must be allowed to
       write it. It used to check nothing, so a user could change the mode of a file it may
       not write (and then read it). */
    int userPermissions = checkUserFilePermissions(theSafePath.text, login->ownerShip.uid, login->ownerShip.gid);

    if (userPermissions < 0 || (userPermissions & FILE_PERMISSION_W) != FILE_PERMISSION_W)
    {
        cleanDynamicStringDataType(&theSafePath, 0, memoryTable);
        return FTP_CHMODE_COMMAND_RETURN_CODE_NO_PERMISSIONS;
    }

    /* The mode and nothing else: it used to change the owner and the group of the file too
       (the ones configured for the user), which made every SITE CHMOD fail when the server
       is not root. */
    returnCodeSetPermissions = chmod(theSafePath.text, theMode);

    if (returnCodeSetPermissions == -1)
    {
        toReturn = FTP_CHMODE_COMMAND_RETURN_CODE_NO_PERMISSIONS;
    }

    cleanDynamicStringDataType(&theSafePath, 0, memoryTable);
    return toReturn;
}

int parseCommandEprt(ftpDataType *data, int socketId)
{
    int returnCode;
    int theAddressType = 0, thePort = 0;
    char theAddress[INET6_ADDRSTRLEN];
    char *theEprtArg;

    if (data->clients[socketId].epsvAllUsed == 1)
    {
        return ftpReplyOrError(data, socketId, "s", EPSV_ALL_REFUSAL);
    }

    theEprtArg = getFtpCommandArg("EPRT", data->clients[socketId].theCommandReceived, 0);

    returnCode = parse_eprt(theEprtArg, &theAddressType, theAddress, sizeof(theAddress), &thePort);

    #ifndef IPV6_ENABLED
    if (returnCode == EPRT_PARSE_OK && theAddressType == 2)
    {
        LOG_DEBUG("EPRT ipv6 requested but not supported in this build");
        return ftpReplyOrError(data, socketId, "s", "522 Network protocol not supported, use (1)\r\n");
    }
    #endif

    if (returnCode == EPRT_PARSE_UNSUPPORTED_PROTO)
    {
        /* RFC 2428 section 2: 522 lists the supported address families */
        #ifdef IPV6_ENABLED
        return ftpReplyOrError(data, socketId, "s", "522 Network protocol not supported, use (1,2)\r\n");
        #else
        return ftpReplyOrError(data, socketId, "s", "522 Network protocol not supported, use (1)\r\n");
        #endif
    }

    if (returnCode != EPRT_PARSE_OK)
    {
        LOG_DEBUG("Error parsing EPRT");
        return ftpReplyOrError(data, socketId, "s", "501 command syntax error\r\n");
    }

    if (isDataAddressAllowed(data, socketId, theAddress, thePort) == 0)
    {
        return ftpReplyOrError(data, socketId, "s", "504 EPRT refused: only the client address and ports above 1023 are allowed\r\n");
    }

    /* Stop the previous worker first: its cleanup resets the worker data, target port included */
    if (replaceDataWorker(data, socketId) != 0)
    {
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }

    data->clients[socketId].workerData.addressType = theAddressType;
    data->clients[socketId].workerData.connectionPort = thePort;
    snprintf(data->clients[socketId].workerData.activeIpAddress, CLIENT_BUFFER_STRING_SIZE, "%s", theAddress);

    data->clients[socketId].workerData.passiveModeOn = 0;
    data->clients[socketId].workerData.extendedPassiveModeOn = 0;
    data->clients[socketId].workerData.activeModeOn = 1;

    return startDataChannel(data, socketId, "worker-args-4");
}


static int ftpReplyOrError(ftpDataType *ftpData, int clientId, const char *formatSpecifier, const char *message)
{
    int returnCode = socketPrintf(ftpData, clientId, formatSpecifier, message);

    if (returnCode <= 0)
    {
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }

    return FTP_COMMAND_PROCESSED;
}

/* Reply for a pathname argument that is missing (501) or not usable (550) */
static int replyMissingOrWrongPath(ftpDataType *data, int socketId, const char *theArgument)
{
    if (theArgument == NULL || theArgument[0] == '\0')
    {
        return ftpReplyOrError(data, socketId, "s", "501 Syntax error: a pathname is required\r\n");
    }

    return ftpReplyOrError(data, socketId, "s", "550 Wrong path.\r\n");
}

static int isAllDigits(const char *theString)
{
    if (theString == NULL || theString[0] == '\0')
        return 0;

    for (int i = 0; theString[i] != '\0'; i++)
    {
        if (!isdigit((unsigned char)theString[i]))
            return 0;
    }

    return 1;
}

/* RFC 2577 section 3 (FTP bounce protection): active data connections are opened
   only towards the client itself and never to a privileged port. */
static int isDataAddressAllowed(ftpDataType *data, int socketId, const char *theAddress, int thePort)
{
    if (thePort < 1024 || thePort > 65535)
    {
        LOGF("%sData connection to port %d refused, client %s", LOG_SECURITY_PREFIX, thePort, data->clients[socketId].clientIpAddress);
        return 0;
    }

    if (isSameIpAddress(data->clients[socketId].clientIpAddress, theAddress) == 0)
    {
        LOGF("%sData connection to %s refused, it is not the client address %s", LOG_SECURITY_PREFIX, theAddress, data->clients[socketId].clientIpAddress);
        return 0;
    }

    return 1;
}

/* RFC 959 appendix II: inside a quoted pathname every double quote is doubled */
static void quoteFtpString(const char *theString, char *quoted, size_t quotedSize)
{
    size_t quotedIndex = 0;

    if (quotedSize == 0)
        return;

    for (size_t i = 0; theString != NULL && theString[i] != '\0' && quotedIndex + 2 < quotedSize; i++)
    {
        if (theString[i] == '"')
            quoted[quotedIndex++] = '"';

        quoted[quotedIndex++] = theString[i];
    }

    quoted[quotedIndex] = '\0';
}

/* Convert a path of the server file system into the path seen by the ftp user.
   Returns 0 if absolutePath is not inside the user home. */
static int absoluteToFtpPath(const char *absolutePath, loginDataType *login, char *ftpPath, size_t ftpPathSize)
{
    const char *relativePath;

    if (absolutePath == NULL || login->homePath.text == NULL || login->homePath.textLen <= 0)
        return 0;

    if (strncmp(absolutePath, login->homePath.text, login->homePath.textLen) != 0)
        return 0;

    relativePath = absolutePath + login->homePath.textLen;

    /* the home must end at a path separator ("/home/user" is not inside "/home/us") */
    if (login->homePath.text[login->homePath.textLen - 1] != '/' && relativePath[0] != '/' && relativePath[0] != '\0')
        return 0;

    while (relativePath[0] == '/')
        relativePath++;

    return snprintf(ftpPath, ftpPathSize, "/%s", relativePath) < (int)ftpPathSize;
}

/* RFC 4217 section 4.2: after an accepted AUTH the server must reset "all transfer
   parameters, including (but not limited to): user identity, default data ports,
   TYPE, STRU, MODE, and current working directory". TYPE and MODE have no state in this
   server (always binary, stream); STRU R and the MLST facts do, and are reset.

   - the data channel worker is stopped: its listening socket and any data
     connection opened before AUTH are closed, so a later transfer can not be sent
     in clear text to an endpoint chosen before TLS;
   - the user identity, home, current directory and file ownership are cleared: a
     new USER is required, PASS alone answers 503;
   - PBSZ/PROT, a pending REST and a pending RNFR are dropped.

   - a new TLS object replaces the one of a previous AUTH (needed after CCC).

   Returns 0, or -1 if a reply could not be written or the TLS object not created.
   Only built with TLS support: without it AUTH always answers 502. */
#ifdef OPENSSL_ENABLED
static int resetSessionForAuth(ftpDataType *data, int socketId)
{
    /* also answers a PASV/EPSV/PORT/EPRT that was replaced before replying */
    if (replaceDataWorker(data, socketId) != 0)
        return -1;

    /* the user is logged out: a new LOGIN_TIMEOUT starts, but only if it was logged in
       (repeating AUTH while not logged in must not extend the time) */
    if (data->clients[socketId].login.userLoggedIn == 1)
    {
        LOG_ACCESS(data, socketId, "logout (AUTH TLS)");
        data->clients[socketId].loginTimerStart = (int)time(NULL);
    }

    /* After CCC the TLS object of the connection has been shut down and can not do a
       new handshake: the 234 reply was followed by a failed handshake. A fresh object
       is used for every AUTH. No other thread uses it now: the worker has just been
       stopped, and with TLS off socketPrintf() does not touch it. */
    SSL *freshSsl = SSL_new(data->serverCtx);
    if (freshSsl == NULL)
    {
        LOG_ERROR("SSL_new failed for a new AUTH");
        return -1;
    }

    pthread_mutex_lock(&data->clients[socketId].writeMutex);
    SSL_free(data->clients[socketId].ssl);
    data->clients[socketId].ssl = freshSsl;
    pthread_mutex_unlock(&data->clients[socketId].writeMutex);

    cleanLoginData(&data->clients[socketId].login, 0, &data->clients[socketId].memoryTable);
    data->clients[socketId].login.ownerShip.ownerShipSet = 0;
    data->clients[socketId].login.ownerShip.uid = 0;
    data->clients[socketId].login.ownerShip.gid = 0;

    data->clients[socketId].pbszIsSet = 0;
    data->clients[socketId].dataChannelIsTls = 0;
    data->clients[socketId].controlChannelCleared = 0;
    data->clients[socketId].cccShutdownPending = CCC_SHUTDOWN_DONE;
    data->clients[socketId].workerData.retrRestartAtByte = 0;
    data->clients[socketId].workerData.transferRestartAtByte = 0;
    /* STRU R and OPTS MLST are transfer parameters too (EPSV ALL is not: it is a promise of the client
       about the whole connection, RFC 2428) */
    data->clients[socketId].recordStructure = 0;
    data->clients[socketId].mlstFacts = MLST_FACTS_ALL;

    cleanDynamicStringDataType(&data->clients[socketId].renameFromFile, 0, &data->clients[socketId].memoryTable);
    cleanDynamicStringDataType(&data->clients[socketId].renameFromFileWd, 0, &data->clients[socketId].memoryTable);
    cleanDynamicStringDataType(&data->clients[socketId].renameToFile, 0, &data->clients[socketId].memoryTable);

    return 0;
}
#endif

/* 1 if the data worker of the client has already been given a transfer command
   (LIST, NLST, RETR, STOR, APPE) and may be running it. */
static int dataWorkerHasCommand(ftpDataType *data, int socketId)
{
    int hasCommand;

    pthread_mutex_lock(&data->clients[socketId].conditionMutex);
    hasCommand = data->clients[socketId].workerData.commandReceived;
    pthread_mutex_unlock(&data->clients[socketId].conditionMutex);

    return hasCommand == 1;
}

/* STOR/APPE into a directory that does not exist (yet). With parallel uploads the
   directory is often being created by another connection at that very moment: the
   file was refused with 550, a permanent error, and the clients did not retry (9 files
   lost in a production test of 3,886). 450 is the temporary error of RFC 959 for
   STOR: the client is invited to try again, and a retry finds the directory.
   The server can not tell this case from a mistyped path: there the client retries
   in vain, a few times, and then fails as it did before.
   The refusal is an access record, so that the retries can be counted in the log. */
static int replyParentDirectoryMissing(ftpDataType *data, int socketId, const char *command, const char *thePath)
{
    LOG_ACCESS(data, socketId, "%s %s refused (450): the directory does not exist", command, thePath);
    cleanDynamicStringDataType(&data->clients[socketId].fileToStor, 0, &data->clients[socketId].memoryTable);
    return ftpReplyOrError(data, socketId, "s", "450 Parent directory does not exist, try again later.\r\n");
}

/* First check of every transfer command (LIST, NLST, RETR, STOR, APPE).

   - No data connection has been set up with PASV/EPSV/PORT/EPRT: 425.
   - a data connection serves one transfer command. A second one sent while
     the first runs used to free and rewrite listPath, the LIST options and
     fileToRetr/fileToStor while the worker was reading them (use-after-free), and
     was then never executed anyway. It is refused without touching anything.

   Returns 1 and sets *functionReturnCode if the command was refused, 0 otherwise. */
static int replyIfDataChannelNotUsable(ftpDataType *data, int socketId, int *functionReturnCode)
{
    if (!data->clients[socketId].workerData.socketIsReadyForConnection)
    {
        *functionReturnCode = ftpReplyOrError(data, socketId, "s", "425 Use PORT or PASV first.\r\n");
        return 1;
    }

    if (dataWorkerHasCommand(data, socketId) == 1)
    {
        *functionReturnCode = ftpReplyOrError(data, socketId, "s", "425 Data connection already in use by another transfer\r\n");
        return 1;
    }

    return 0;
}

/* Hand the command just received to the data worker, which is waiting for it, and
   send the 150 reply. */
static int giveCommandToDataWorker(ftpDataType *data, int socketId)
{
    pthread_mutex_lock(&data->clients[socketId].conditionMutex);

    /* the worker may have given up meanwhile (data connection closed by the client
       during the TLS handshake): checked under the mutex it uses to say so, so that
       the command is either refused here or answered by the worker */
    if (!data->clients[socketId].workerData.socketIsReadyForConnection)
    {
        pthread_mutex_unlock(&data->clients[socketId].conditionMutex);
        return ftpReplyOrError(data, socketId, "s", "425 Use PORT or PASV first.\r\n");
    }

    memset(data->clients[socketId].workerData.theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE+1);
    strncpy(data->clients[socketId].workerData.theCommandReceived, data->clients[socketId].theCommandReceived, CLIENT_COMMAND_STRING_SIZE);
    data->clients[socketId].workerData.commandReceived = 1;

    /* The 150 is written BEFORE the worker is woken, with the mutex still held (the worker can
       not leave its wait without it): a small transfer used to end, and the worker to write the
       226, before this thread had written the 150. The client read the 226 as the answer of the
       command and every reply after it was one step late. The writing is of a few bytes on a
       non-blocking socket, and the worker never takes this mutex while it holds the write one. */
    int replyCode = ftpReplyOrError(data, socketId, "s", "150 Accepted data connection\r\n");

    pthread_cond_signal(&data->clients[socketId].conditionVariable);
    pthread_mutex_unlock(&data->clients[socketId].conditionMutex);

    return replyCode;
}

/* LIST and NLST: [-options] [path]. The path (the current directory if missing) is
   checked here, the listing is written by the data worker.

     -A  all files except "." and ".."
     -a  all files including those whose names start with "." */
static int parseListingCommand(ftpDataType *data, int socketId, char *theCommandName)
{
    int returnCode = 0;
    char *theNameToList;
    const char *theError = NULL;
    dynamicStringDataType *listPath = &data->clients[socketId].listPath;
    DYNMEM_MemoryTable_DataType **memoryTable = &data->clients[socketId].memoryTable;
    int isMlsd = (strcmp(theCommandName, "MLSD") == 0);

    if (replyIfDataChannelNotUsable(data, socketId, &returnCode) == 1)
    {
        return returnCode;
    }

    cleanDynamicStringDataType(&data->clients[socketId].workerData.ftpCommand.commandArgs, 0, &data->clients[socketId].workerData.memoryTable);
    cleanDynamicStringDataType(&data->clients[socketId].workerData.ftpCommand.commandOps, 0, &data->clients[socketId].workerData.memoryTable);

    /* MLSD has no options: a name that starts with "-" is a name */
    theNameToList = getFtpCommandArg(theCommandName, data->clients[socketId].theCommandReceived, isMlsd ? 0 : 1);
    if (!isMlsd)
    {
        getFtpCommandArgWithOptions(theCommandName, data->clients[socketId].theCommandReceived, &data->clients[socketId].workerData.ftpCommand, &data->clients[socketId].workerData.memoryTable);
    }

    cleanDynamicStringDataType(listPath, 0, memoryTable);

    if (strnlen(theNameToList, 1) == 0)
    {
        setDynamicStringDataType(listPath, data->clients[socketId].login.absolutePath.text, data->clients[socketId].login.absolutePath.textLen, memoryTable);
    }
    else if (getSafePath(listPath, theNameToList, &data->clients[socketId].login, memoryTable) == 0)
    {
        /* A path was given but refused (e.g. outside the home): 550, the current
           directory is not listed in its place */
        theError = "550 wrong path\r\n";
    }

    if (theError == NULL &&
        FILE_IsDirectory(listPath->text, 0) == 0 && FILE_IsFile(listPath->text, 0) == 0)
    {
        theError = "550 wrong path\r\n";
    }

    if (theError == NULL && isMlsd && FILE_IsDirectory(listPath->text, 0) == 0)
    {
        theError = "501 Not a directory\r\n";
    }

    if (theError == NULL &&
        (checkUserFilePermissions(listPath->text, data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid) & FILE_PERMISSION_R) != FILE_PERMISSION_R)
    {
        theError = "550 no permissions.\r\n";
    }

    if (theError != NULL)
    {
        LOGF("%s%s refused: %s", LOG_DEBUG_PREFIX, theCommandName, theNameToList);
        cleanDynamicStringDataType(listPath, 0, memoryTable);
        return ftpReplyOrError(data, socketId, "s", theError);
    }

    return giveCommandToDataWorker(data, socketId);
}

/* Start the data worker of PASV, EPSV, PORT and EPRT, which sends the reply. */
static int startDataChannel(ftpDataType *data, int socketId, char *label)
{
    int returnCode = startDataWorker(data, socketId, label);

    if (returnCode == 0)
    {
        /* pthread_create failed (the limit of threads of the system or of the user, no memory). The
           server used to stop here, dropping every session: now only this command is refused, and
           the client can try again later. RFC 959: 425. */
        LOG_CLIENT(data, socketId, LOG_ERROR_PREFIX, "PASV/EPSV/PORT/EPRT refused: the system can not create another thread (%s)", label);
        return ftpReplyOrError(data, socketId, "s", "425 Can't open data connection: the server is out of resources, try again later.\r\n");
    }

    return (returnCode == 1) ? FTP_COMMAND_PROCESSED : FTP_COMMAND_PROCESSED_WRITE_ERROR;
}
