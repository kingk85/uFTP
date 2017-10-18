/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   ftpServer.h
 * Author: ugo
 *
 * Created on 7 ottobre 2017, 17.37
 */

#ifndef FTPSERVER_H
#define FTPSERVER_H

#define MAX_FTP_CLIENTS                 10


void runFtpServer(void);
int createPassiveSocket(int port);

void *pasvThreadHandler(void * socketId);


#endif /* FTPSERVER_H */

