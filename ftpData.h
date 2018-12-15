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


#ifndef FTPDATA_H
#define FTPDATA_H

#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "library/dynamicVectors.h"


#define CLIENT_COMMAND_STRING_SIZE                  4096
#define CLIENT_BUFFER_STRING_SIZE                   4096
#define MAXIMUM_INODE_NAME							4096

#define LIST_DATA_TYPE_MODIFIED_DATA_STR_SIZE       1024

#define COMMAND_TYPE_LIST                           0
#define COMMAND_TYPE_NLST                           1
#define WRONG_PASSWORD_ALLOWED_RETRY_TIME           60

#ifdef __cplusplus
extern "C" {
#endif

/* Data structures */
struct parameter
{
    char* name;
    char* value;
} typedef parameter_DataType;

struct ownerShip
{
    int ownerShipSet;
    char* userOwnerString;
    char* groupOwnerString;
    uid_t uid;
    gid_t gid;
    
} typedef ownerShip_DataType;

struct usersParameters
{
    char* name;
    char* password;
    char* homePath;
    
    ownerShip_DataType ownerShip;
    
} typedef usersParameters_DataType;

struct ftpParameters
{
    int ftpIpAddress[4];
    int port;
    int maxClients;
    int daemonModeOn;
    int singleInstanceModeOn;
    DYNV_VectorGenericDataType usersVector;
    int maximumIdleInactivity;
    int maximumConnectionsPerIp;
    int maximumUserAndPassowrdLoginTries;

    char certificatePath[MAXIMUM_INODE_NAME];
    char privateCertificatePath[MAXIMUM_INODE_NAME];
} typedef ftpParameters_DataType;
    
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
    ownerShip_DataType ownerShip;
} typedef loginDataType;

struct ipData
{
    int ip[4];
} typedef ipDataType;

struct workerData
{
		#ifdef OPENSSL_ENABLED
		SSL *serverSsl;
		SSL *clientSsl;
		#endif

    int threadIsAlive;
    int threadHasBeenCreated;
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

    long long int retrRestartAtByte;

    /* The PASV thread will wait the signal before start */
    pthread_mutex_t conditionMutex;
    pthread_cond_t conditionVariable;
    ftpCommandDataType    ftpCommand;
    DYNV_VectorGenericDataType directoryInfo;
    FILE *theStorFile;
} typedef workerDataType;

struct clientData
{
	#ifdef OPENSSL_ENABLED
    SSL *ssl;
	#endif

    int tlsIsEnabled;
    int tlsIsNegotiating;
    unsigned long long int tlsNegotiatingTimeStart;
    int dataChannelIsTls;
    pthread_mutex_t writeMutex;
    
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

struct loginFails
{
    char ipAddress[INET_ADDRSTRLEN];
    unsigned long long int failTimeStamp;
    int failureNumbers;
} typedef loginFailsDataType;

struct ConnectionParameters
{
    int theMainSocket, maxSocketFD;
    fd_set rset, wset, eset, rsetAll, wsetAll, esetAll;
} typedef ConnectionData_DataType;

struct ftpData
{
	#ifdef OPENSSL_ENABLED
	SSL_CTX *serverCtx;
	SSL_CTX *clientCtx;
	#endif

    int connectedClients;
    char welcomeMessage[1024];
    ConnectionData_DataType connectionData;
    clientDataType *clients;
    ipDataType serverIp;
    ftpParameters_DataType ftpParameters;
    DYNV_VectorGenericDataType loginFailsVector;
} typedef ftpDataType;

struct ftpListData
{
    char *fileNameWithPath;
    char *fileNameNoPath;
    char *linkPath;
    char *finalStringPath;
    int numberOfSubDirectories;
    int isDirectory;
    int isFile;
    int isLink;
    char *owner;
    char *groupOwner;
    long long int fileSize;
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
int writeListDataInfoToSocket(ftpDataType *data, int clientId, int *filesNumber, int commandType);
int searchInLoginFailsVector(void *loginFailsVector, void *element);
void deleteLoginFailsData(void *element);
void deleteListDataInfoVector(void *TheElementToDelete);
void resetWorkerData(ftpDataType *data, int clientId, int isInitialization);
void resetClientData(ftpDataType *data, int clientId, int isInitialization);
int compareStringCaseInsensitive(char *stringIn, char* stringRef, int stringLenght);
int isCharInString(char *theString, int stringLen, char theChar);
void destroyConfigurationVectorElement(void * data);
#ifdef __cplusplus
}
#endif

#endif /* FTPDATA_H */

