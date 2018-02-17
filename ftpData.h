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



/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   ftpData.h
 * Author: ugo
 *
 * Created on 8 ottobre 2017, 13.14
 */

#ifndef FTPDATA_H
#define FTPDATA_H

#include "library/dynamicVectors.h"
#include "library/configRead.h"

#define CLIENT_COMMAND_STRING_SIZE                  2048
#define CLIENT_BUFFER_STRING_SIZE                   2048

#define LIST_DATA_TYPE_MODIFIED_DATA_STR_SIZE       80


#ifdef __cplusplus
extern "C" {
#endif

struct dynamicStringData
{
    char * text;
    int textLen;
} typedef dynamicStringDataType;

struct ftpCommandData
{
    dynamicStringDataType commandArgs;
    dynamicStringDataType commandOps;
} typedef ftpCommandDataType;

struct loginData
{
    int userLoggedIn;
    dynamicStringDataType name;
    dynamicStringDataType password;
    dynamicStringDataType homePath;
    dynamicStringDataType ftpPath;
    dynamicStringDataType absolutePath;
    
} typedef loginDataType;

struct ipData
{
    int ip[4];
} typedef ipDataType;

struct workerData
{
    int threadIsAlive;
    int connectionPort;
    int passiveModeOn;
    int activeModeOn;

    pthread_t workerThread;
    int passiveListeningSocket;
    int socketConnection;
    int socketIsConnected;
    int bufferIndex;
    char buffer[CLIENT_BUFFER_STRING_SIZE];

    int activeIpAddressIndex;
    char activeIpAddress[CLIENT_BUFFER_STRING_SIZE];
    
    int commandIndex;
    char theCommandReceived[CLIENT_COMMAND_STRING_SIZE];    
    int commandReceived;

    unsigned long int retrRestartAtByte;
    int threadIsBusy;

    /* The PASV thread will wait the signal before start */
    pthread_mutex_t conditionMutex;
    pthread_cond_t conditionVariable;
    ftpCommandDataType    ftpCommand;
} typedef workerDataType;

struct clientData
{
    int clientProgressiveNumber;
    int socketDescriptor;
    int socketIsConnected;
    
    int bufferIndex;
    char buffer[CLIENT_BUFFER_STRING_SIZE];
    
    int socketCommandReceived;
    
    int commandIndex;
    char theCommandReceived[CLIENT_COMMAND_STRING_SIZE];
    
    dynamicStringDataType renameFromFile;
    dynamicStringDataType renameToFile;
    
    dynamicStringDataType fileToStor;
    dynamicStringDataType fileToRetr;
    dynamicStringDataType listPath;
    dynamicStringDataType nlistPath;
    
    //User authentication
    loginDataType login;
    workerDataType workerData;
    
    int sockaddr_in_size, sockaddr_in_server_size;
    struct sockaddr_in client_sockaddr_in, server_sockaddr_in;
    
    int clientPort;
    char clientIpAddress[INET_ADDRSTRLEN];

    int serverPort;
    char serverIpAddress[INET_ADDRSTRLEN];
    int serverIpAddressInteger[4];
    ftpCommandDataType    ftpCommand;
    int closeTheClient;

    unsigned long long int connectionTimeStamp;
    unsigned long long int lastActivityTimeStamp;
} typedef clientDataType;

struct ftpData
{
    int connectedClients;

    char welcomeMessage[1024];
    int theSocket;
    clientDataType *clients;
    ipDataType serverIp;
    ftpParameters_DataType ftpParameters;
} typedef ftpDataType;

struct ftpListData
{
    char *fileNameWithPath;
    char *fileNameNoPath;
    int numberOfSubDirectories;
    int isDirectory;
    int isFile;
    char *owner;
    char *groupOwner;
    int fileSize;
    char *inodePermissionString;
    char **fileList;
    time_t lastModifiedData;
    char lastModifiedDataString[LIST_DATA_TYPE_MODIFIED_DATA_STR_SIZE];
} typedef ftpListDataType;

void cleanLoginData(loginDataType *loginData, int init);
void cleanDynamicStringDataType(dynamicStringDataType *dynamicString, int init);
void setDynamicStringDataType(dynamicStringDataType *dynamicString, char *theString, int stringLen);
int getSafePath(dynamicStringDataType *safePath, char *theDirectoryName, loginDataType *theHomePath);
void appendToDynamicStringDataType(dynamicStringDataType *dynamicString, char *theString, int stringLen);
void setRandomicPort(ftpDataType *data, int socketPosition);
void getListDataInfo(char * thePath, DYNV_VectorGenericDataType *directoryInfo);
void deleteListDataInfoVector(void *TheElementToDelete);
void resetWorkerData(workerDataType *pasvData, int isInitialization);
void resetClientData(clientDataType *clientData, int isInitialization);
#ifdef __cplusplus
}
#endif

#endif /* FTPDATA_H */

