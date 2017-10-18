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

#define CLIENT_COMMAND_STRING_SIZE                  2048
#define CLIENT_BUFFER_STRING_SIZE                   1024

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
    
    pthread_mutex_t lock;
    
    unsigned long int retrRestartAtByte;
    
} typedef passiveDataType;

struct clientData
{
    int socketDescriptor;
    int socketIsConnected;
    
    int bufferIndex;
    char buffer[CLIENT_BUFFER_STRING_SIZE];
    
    int socketCommandReceived;
    
    int commandIndex;
    char theCommandReceived[CLIENT_COMMAND_STRING_SIZE];
    
    //User authentication
    loginDataType login;
    passiveDataType pasvData;
} typedef clientDataType;

struct ftpData
{
    int connectedClients;
    int maxClients;
    char welcomeMessage[1024];
    int theSocket;

    clientDataType *clients;
    ipDataType serverIp;
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
    char *permissions;
    int fileSize;
    char *inodePermissionString;
    char **fileList;
    time_t lastModifiedData;
    char lastModifiedDataString[LIST_DATA_TYPE_MODIFIED_DATA_STR_SIZE];
} typedef ftpListDataType;

void cleanLoginData(loginDataType *loginData, int init);
void cleanDynamicStringDataType(dynamicStringDataType *dynamicString, int init);
void setDynamicStringDataType(dynamicStringDataType *dynamicString, char *theString, int stringLen);
void setRandomicPort(ftpDataType *data, int socketPosition);
void getListDataInfo(char * thePath, DYNV_VectorGenericDataType *directoryInfo);
void deleteListDataInfoVector(void *TheElementToDelete);

#ifdef __cplusplus
}
#endif

#endif /* FTPDATA_H */

