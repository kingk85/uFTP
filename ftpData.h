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

struct passiveData
{
    int threadIsAlive;
    int passivePort;
    int passiveModeOn;
    pthread_t pasvThread;
    int passiveSocket;
    int passiveSocketConnection;
    int passiveSocketIsConnected;
    int bufferIndex;
    char buffer[CLIENT_BUFFER_STRING_SIZE];
    
    int commandIndex;
    char theCommandReceived[CLIENT_COMMAND_STRING_SIZE];    
    int commandReceived;
    
    char theFileNameToStor[CLIENT_COMMAND_STRING_SIZE];
    int theFileNameToStorIndex;
    unsigned long int retrRestartAtByte;
    int threadIsBusy;
    
    /* The PASV thread will wait the signal before start */
    pthread_mutex_t conditionMutex;
    pthread_cond_t conditionVariable;
    
} typedef passiveDataType;

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
    
    //User authentication
    loginDataType login;
    passiveDataType pasvData;
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
void appendToDynamicStringDataType(dynamicStringDataType *dynamicString, char *theString, int stringLen);
void setRandomicPort(ftpDataType *data, int socketPosition);
void getListDataInfo(char * thePath, DYNV_VectorGenericDataType *directoryInfo);
void deleteListDataInfoVector(void *TheElementToDelete);
void resetPasvData(passiveDataType *pasvData, int isInitialization);
void resetClientData(clientDataType *clientData, int isInitialization);
#ifdef __cplusplus
}
#endif

#endif /* FTPDATA_H */

