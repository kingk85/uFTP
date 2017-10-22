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
int parseCommandPasv(ftpDataType * data, int socketId);
int parseCommandList(ftpDataType * data, int socketId);
int parseCommandRetr(ftpDataType * data, int socketId);
int parseCommandStor(ftpDataType * data, int socketId);
int parseCommandCwd(clientDataType *theClientData);
int parseCommandCdup(clientDataType *theClientData);

#ifdef __cplusplus
}
#endif

#endif /* FTPCOMMANDSELABORATE_H */

