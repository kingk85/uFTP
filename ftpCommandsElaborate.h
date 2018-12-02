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


#ifndef FTPCOMMANDSELABORATE_H
#define FTPCOMMANDSELABORATE_H

#define FTP_COMMAND_ELABORATE_CHAR_BUFFER       1024
#define FTP_COMMAND_ELABORATE_CHAR_BUFFER_BIG   4096
#define FTP_COMMAND_NOT_RECONIZED               0
#define FTP_COMMAND_PROCESSED                   1
#define FTP_COMMAND_PROCESSED_WRITE_ERROR       2


#define FTP_CHMODE_COMMAND_RETURN_CODE_OK               1
#define FTP_CHMODE_COMMAND_RETURN_CODE_NO_FILE          2
#define FTP_CHMODE_COMMAND_RETURN_CODE_NO_PERMISSIONS   3
#define FTP_CHMODE_COMMAND_RETURN_NAME_TOO_LONG         4
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "ftpData.h"

#ifdef __cplusplus
extern "C" {
#endif


/* Elaborate the User login command */
int parseCommandUser(ftpDataType * data, int socketId);
int parseCommandSite(ftpDataType * data, int socketId);
int parseCommandPass(ftpDataType * data, int socketId);

int parseCommandAuth(clientDataType *theClientData, SSL_CTX *);

int parseCommandPwd(ftpDataType * data, int socketId);
int parseCommandSyst(ftpDataType * data, int socketId);
int parseCommandFeat(ftpDataType * data, int socketId);
int parseCommandStruF(ftpDataType * data, int socketId);
int parseCommandTypeI(ftpDataType * data, int socketId);
int parseCommandModeS(ftpDataType * data, int socketId);
int parseCommandTypeA(ftpDataType * data, int socketId);
int parseCommandAbor(ftpDataType * data, int socketId);
int parseCommandPasv(ftpDataType * data, int socketId);
int parseCommandPort(ftpDataType * data, int socketId);
int parseCommandList(ftpDataType * data, int socketId);
int parseCommandNlst(ftpDataType * data, int socketId);
int parseCommandRetr(ftpDataType * data, int socketId);
int parseCommandMkd(ftpDataType * data, int socketId);
int parseCommandNoop(ftpDataType * data, int socketId);
int notLoggedInMessage(ftpDataType * data, int socketId);
int parseCommandRmd(ftpDataType * data, int socketId);
int parseCommandQuit(ftpDataType * data, int socketId);
int parseCommandSize(ftpDataType * data, int socketId);
int parseCommandStor(ftpDataType * data, int socketId);
int parseCommandCwd(ftpDataType * data, int socketId);
int parseCommandRest(ftpDataType * data, int socketId);
int parseCommandCdup(ftpDataType * data, int socketId);
int parseCommandDele(ftpDataType * data, int socketId);
int parseCommandOpts(ftpDataType * data, int socketId);
int parseCommandRnfr(ftpDataType * data, int socketId);
int parseCommandRnto(ftpDataType * data, int socketId);

long long int writeRetrFile(char * theFilename, int thePasvSocketConnection, long long int startFrom, FILE *retrFP);
char *getFtpCommandArg(char * theCommand, char *theCommandString, int skipArgs);
int getFtpCommandArgWithOptions(char * theCommand, char *theCommandString, ftpCommandDataType *ftpCommand);
int setPermissions(char * permissionsCommand, char * basePath, ownerShip_DataType ownerShip);

#ifdef __cplusplus
}
#endif

#endif /* FTPCOMMANDSELABORATE_H */

