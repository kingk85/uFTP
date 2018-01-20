/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   ftpCommandsElaborate.h
 * Author: ugo
 *
 * Created on 8 ottobre 2017, 12.40
 */

#ifndef FTPCOMMANDSELABORATE_H
#define FTPCOMMANDSELABORATE_H

#define FTP_COMMAND_ELABORATE_CHAR_BUFFER       1024
#include "ftpData.h"

#ifdef __cplusplus
extern "C" {
#endif


/* Elaborate the User login command */
int parseCommandUser(clientDataType *theClientData);
int parseCommandPass(clientDataType *theClientData);
int parseCommandAuth(clientDataType *theClientData);
int parseCommandPwd(clientDataType *theClientData);
int parseCommandSyst(clientDataType *theClientData);
int parseCommandFeat(clientDataType *theClientData);
int parseCommandTypeI(clientDataType *theClientData);
int parseCommandAbor(ftpDataType * data, int socketId);
int parseCommandPasv(ftpDataType * data, int socketId);
int parseCommandList(ftpDataType * data, int socketId);
int parseCommandNlst(ftpDataType * data, int socketId);
int parseCommandRetr(ftpDataType * data, int socketId);
int parseCommandMkd(clientDataType *theClientData);
int parseCommandNoop(clientDataType *theClientData);
int parseCommandRmd(clientDataType *theClientData);
int parseCommandQuit(ftpDataType * data, int socketId);
int parseCommandSize(clientDataType *theClientData);
int parseCommandStor(ftpDataType * data, int socketId);
int parseCommandCwd(clientDataType *theClientData);
int parseCommandCdup(clientDataType *theClientData);
int parseCommandDele(clientDataType *theClientData);

int parseCommandRnfr(clientDataType *theClientData);
int parseCommandRnto(clientDataType *theClientData);

int writeRetrFile(char * theFilename, int thePasvSocketConnection, int startFrom);
char *getFtpCommandArg(char * theCommand, char *theCommandString);

#ifdef __cplusplus
}
#endif

#endif /* FTPCOMMANDSELABORATE_H */

