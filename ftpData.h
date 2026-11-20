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

#include <sys/stat.h>
#include <netinet/in.h>
#define _REENTRANT
#include <pthread.h>
#include <sys/select.h>
#include <poll.h>

/* How the control channel waits for its clients: epoll on Linux, poll() elsewhere (BSD, macOS...).
   -D UFTP_USE_POLL forces poll() on Linux too (to test it). */
#if defined(__linux__) && !defined(UFTP_USE_POLL)
    #define UFTP_USE_EPOLL
    #include <sys/epoll.h>
#endif

#ifdef OPENSSL_ENABLED
	#include <openssl/ssl.h>
	#include <openssl/err.h>
#endif

#include "library/dynamicVectors.h"
#include "library/dynamicMemory.h"


#define STRING_SZ_SMALL                             100
#define STRING_SZ_LARGE                             4096

#define CLIENT_COMMAND_STRING_SIZE                  4096
#define CLIENT_BUFFER_STRING_SIZE                   4096
#define MAXIMUM_INODE_NAME							4096

#define LIST_DATA_TYPE_MODIFIED_DATA_STR_SIZE       1024

#define COMMAND_TYPE_LIST                           0
#define COMMAND_TYPE_NLST                           1
#define COMMAND_TYPE_STAT                           2
#define COMMAND_TYPE_MLSD                           3

/* Facts of MLST/MLSD (RFC 3659), the bits of a client's mlstFacts */
#define MLST_FACT_TYPE      1
#define MLST_FACT_SIZE      2
#define MLST_FACT_MODIFY    4
#define MLST_FACT_PERM      8
#define MLST_FACT_UNIX_MODE 16
#define MLST_FACT_UNIX_UID  32
#define MLST_FACT_UNIX_GID  64
#define MLST_FACTS_ALL      127
/* Seconds an address stays blocked after its last failed login (it was 60, while the
   reply, the sample configuration and the documentation say 5 minutes) */
#define WRONG_PASSWORD_ALLOWED_RETRY_TIME           300


#define IS_CMD(str, cmd) (compareStringCaseInsensitive(str, cmd, strlen(cmd)) == 1)
#define IS_NOT_CMD(str, cmd) (compareStringCaseInsensitive(str, cmd, strlen(cmd)) != 1)

#ifdef __cplusplus
extern "C" {
#endif

/* Data structures */
struct parameter
{
    char* name;
    char* value;
} typedef parameter_DataType;

#define OWNER_USER_NOT_FOUND    1
#define OWNER_GROUP_NOT_FOUND   2

struct ownerShip
{
    int ownerShipSet;
    /* OWNER_USER_NOT_FOUND / OWNER_GROUP_NOT_FOUND: the configured owner does not exist
       on the system, root is used in its place (logged at startup) */
    int ownerNotFound;
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
    /* MAX_CONNECTION_PER_ACCOUNT_n: -1 = not set, the global limit applies; 0 = no limit */
    int maximumConnections;
    
    ownerShip_DataType ownerShip;
    
} typedef usersParameters_DataType;

struct ftpParameters
{
    int ftpIpAddressV4[4];
    int port;
    int maxClients;
    int daemonModeOn;
    int singleInstanceModeOn;
    int respawnProcessOn;
    /* PASV_PROMISCUOUS = true: accept passive data connections from any address
       (default false: only from the address of the control connection, RFC 2577) */
    int pasvPromiscuous;
    /* LOGIN_TIMEOUT: seconds a client may stay connected without completing the login
       (0 = no limit). Measured from the moment it entered the not-logged-in state. */
    int loginTimeout;
    DYNV_VectorGenericDataType usersVector;
    DYNV_VectorString_DataType blockedUsersVector;
    int maximumIdleInactivity;
    int maximumConnectionsPerIp;
    /* sessions of one user, from any address (0 = no limit); a user can have its own */
    int maximumConnectionsPerAccount;
    /* new connections per minute from one address (0 = no limit) */
    int maximumConnectionRatePerIp;
    /* an upload is refused, or stopped, when the free space of the disk goes below this (MB, 0 = no check) */
    int minimumFreeSpaceMb;
    /* 1 if a PASSWORD_n of the file is a hash: a wrong password then costs the same time for every name */
    int hashedPasswordsPresent;
    int hashedPasswordsIterations;     /* the highest of the iterations of the hashes: the dummy check of an unknown name costs the same */
    int maximumUserAndPassowrdLoginTries;
    char certificatePath[MAXIMUM_INODE_NAME];
    char privateCertificatePath[MAXIMUM_INODE_NAME];
    char logFolder[MAXIMUM_INODE_NAME];
    int maximumLogFileCount;
    int pamAuthEnabled;
    int forceTLS;

    /* If specified, use a port range for pasv connections */
    int connectionPortMin;
    int connectionPortMax;

    char natIpAddress[STRING_SZ_SMALL];

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
	#endif

    int threadIsAlive;
    /* set by the control thread when it wants this worker to end (new PASV/PORT, ABOR,
       client closed): the worker must not keep it waiting, see workerCleanup() */
    volatile int stopRequested;
    int threadHasBeenCreated;
    int connectionPort;
    int addressType;    
    int passiveModeOn;
    int extendedPassiveModeOn;
    int activeModeOn;

    pthread_t workerThread;
    int passiveListeningSocket;
    int socketConnection;
    int socketIsConnected;
    int socketIsReadyForConnection;
    int bufferIndex;
    char buffer[CLIENT_BUFFER_STRING_SIZE+1];

    int activeIpAddressIndex;
    char activeIpAddress[CLIENT_BUFFER_STRING_SIZE];
    
    int commandIndex;
    char theCommandReceived[CLIENT_COMMAND_STRING_SIZE+1];    
    int commandReceived;

    int commandProcessed;
    char theCommandResponse[STRING_SZ_SMALL+1];    

    long long int retrRestartAtByte;           /* set by REST, waits for the transfer command that follows it */
    /* The offset that RETR, STOR or APPE took from retrRestartAtByte when it arrived. The transfer thread reads this one:
       it never writes the field of the control thread (and a command that fails leaves no offset behind). */
    long long int transferRestartAtByte;

    /* The PASV thread will wait the signal before start */
    ftpCommandDataType    ftpCommand;
    DYNV_VectorGenericDataType directoryInfo;
    FILE *theStorFile;
    FILE *theRetrFile;      /* the file of a download in progress: closed by resetWorkerData() if the worker is stopped */
    DYNMEM_MemoryTable_DataType *memoryTable;
} typedef workerDataType;

#define CCC_SHUTDOWN_DONE     0   /* no closure alert expected */
#define CCC_SHUTDOWN_WAITING  1   /* CCC accepted, nothing received from the client yet */
#define CCC_SHUTDOWN_READING  2   /* the closure alert is being read (record not complete) */

struct clientData
{
	#ifdef OPENSSL_ENABLED
    SSL *ssl;
	#endif

    int isIpV6;
    /* 1 after EPSV ALL (RFC 2428 section 3): PASV, PORT and EPRT are refused */
    int epsvAllUsed;
    int tlsIsEnabled;
    int tlsIsNegotiating;
    /* where the control channel is in a Telnet sequence (RFC 854), see controlChannel.c */
    int telnetState;
    int pbszIsSet;
    /* 1 after an accepted CCC: PBSZ and PROT are refused until a new AUTH (RFC 4217
       section 5), the data protection chosen before CCC stays in force */
    int controlChannelCleared;
    /* Facts MLST and MLSD send (MLST_FACT_* bits), changed by OPTS MLST */
    int mlstFacts;
    /* 1 after STRU R (RFC 959 section 3.4.2): the data of RETR and STOR use record markers */
    int recordStructure;
    /* After CCC, until the TLS closure alert of the client has been read (or the
       client turned out to send clear text right away): CCC_SHUTDOWN_*, see
       controlChannel.c */
    int cccShutdownPending;
    unsigned long long int tlsNegotiatingTimeStart;
    int dataChannelIsTls;
    pthread_mutex_t writeMutex;
    
    int clientProgressiveNumber;
    int socketDescriptor;
    int socketIsConnected;
    int socketEventReady;                      /* activity seen by the last wait (data, error, hang up) */
    
    int bufferIndex;
    char buffer[CLIENT_BUFFER_STRING_SIZE+1];
    
    int socketCommandReceived;
    
    int commandIndex;
    char theCommandReceived[CLIENT_COMMAND_STRING_SIZE+1];
    
    dynamicStringDataType renameFromFile;
    dynamicStringDataType renameFromFileWd;
    dynamicStringDataType renameToFile;
    
    dynamicStringDataType fileToStor;
    dynamicStringDataType fileToRetr;
    dynamicStringDataType listPath;

    
    //User authentication
    loginDataType login;
    workerDataType workerData;
    
    socklen_t sockaddr_in_size, sockaddr_in_server_size;

    #ifdef IPV6_ENABLED
    struct sockaddr_in6 client_sockaddr_in, server_sockaddr_in;
    #else
    struct sockaddr_in client_sockaddr_in, server_sockaddr_in;
    #endif

    int clientPort;
    char clientIpAddress[INET6_ADDRSTRLEN];

    int serverPort;
    char serverIpAddress[INET6_ADDRSTRLEN];
    int serverIpV4AddressInteger[4];
    ftpCommandDataType    ftpCommand;
    int closeTheClient;
    /* why the connection is being closed, for the log (static string, NULL = not said) */
    const char *closeReason;
    /* 1 once "connection opened" has been logged: refused connections log nothing more */
    int accessLogged;
    /* copy of the name of the logged in user for the log lines, also read by the data
       worker: a fixed array, never freed (login.name is freed by USER and AUTH) */
    char logUserName[64];
    /* 1 between the start of a data channel worker and the moment it has sent its
       reply (227, 229 or 200), see replaceDataWorker() */
    int dataReplyPending;

    unsigned long long int connectionTimeStamp;
    /* when the client entered the not-logged-in state (connection, USER from a logged
       in user, accepted AUTH): LOGIN_TIMEOUT is counted from here */
    unsigned long long int loginTimerStart;
    unsigned long long int lastActivityTimeStamp;

    pthread_mutex_t conditionMutex;
    pthread_cond_t conditionVariable;

    DYNMEM_MemoryTable_DataType *memoryTable;
} typedef clientDataType;

struct loginFails
{
    /* Same size as clientIpAddress. With INET_ADDRSTRLEN (16) an ipv4-mapped
       address ("::ffff:127.0.0.1", 16 characters) had no room for the terminator, the
       comparison ran into failTimeStamp and failed attempts were never counted. */
    char ipAddress[INET6_ADDRSTRLEN];
    unsigned long long int failTimeStamp;
    int failureNumbers;
} typedef loginFailsDataType;

/* New connections of one address in the current minute. A table of a fixed size, indexed by a
   hash of the key: it does not grow with the number of addresses of a flood. */
#define CONNECTION_RATE_TABLE_SIZE  256
#define CONNECTION_RATE_WINDOW      60

struct connectionRate
{
    char key[INET6_ADDRSTRLEN];
    time_t windowStart;
    int count;
} typedef connectionRateType;

struct ConnectionParameters
{
    int theMainSocket;
    int mainSocketReady;                 /* set by waitForClientEvents(): a connection is waiting */
#ifdef UFTP_USE_EPOLL
    int epollFd;
    struct epoll_event *events;          /* room for every client and the listening socket */
#else
    struct pollfd *pollDescriptors;      /* the listening socket and the connected clients, built at every wait */
    int *pollClientIndex;                /* which client each entry is */
#endif
} typedef ConnectionData_DataType;

struct ftpData
{
	#ifdef OPENSSL_ENABLED
	SSL_CTX *serverCtx;
	#endif

    int connectedClients;
    char welcomeMessage[1024];
    ConnectionData_DataType connectionData;
    clientDataType *clients;
    ipDataType serverIp;
    ftpParameters_DataType ftpParameters;
    DYNV_VectorGenericDataType loginFailsVector;
    connectionRateType connectionRate[CONNECTION_RATE_TABLE_SIZE];
    DYNMEM_MemoryTable_DataType *generalDynamicMemoryTable;
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

void cleanLoginData(loginDataType *loginData, int init, DYNMEM_MemoryTable_DataType **memoryTable);
void cleanDynamicStringDataType(dynamicStringDataType *dynamicString, int init, DYNMEM_MemoryTable_DataType **memoryTable);


void setDynamicStringDataType(dynamicStringDataType *dynamicString, char *theString, int stringLen, DYNMEM_MemoryTable_DataType **memoryTable);
int getSafePath(dynamicStringDataType *safePath, char *theDirectoryName, loginDataType *theHomePath, DYNMEM_MemoryTable_DataType **memoryTable);
int getSafePathNoFollow(dynamicStringDataType *safePath, char *theDirectoryName, loginDataType *theHomePath, DYNMEM_MemoryTable_DataType **memoryTable);
int getSafePathWithReason(dynamicStringDataType *safePath, char *theDirectoryName, loginDataType *theHomePath, DYNMEM_MemoryTable_DataType **memoryTable, int *failureReason);
void appendToDynamicStringDataType(dynamicStringDataType *dynamicString, char *theString, int stringLen, DYNMEM_MemoryTable_DataType **memoryTable);


void setRandomicPort(ftpDataType *data, int socketPosition);
/* One MLST/MLSD entry without the name: "type=file;size=5;...;". Returns the length written, 0 if the
   entry is neither a file nor a directory (it is not listed), -1 if the buffer is too small. */
int FTP_FormatMlsxFacts(char *out, size_t outSize, const struct stat *info, int facts, int uid, int gid);
int FTP_WriteMlsdToSocket(ftpDataType *data, int clientId, char *thePath, int facts, int *filesNumber, DYNMEM_MemoryTable_DataType **memoryTable);
int writeListDataInfoToSocket(ftpDataType *data, int clientId, char *thePath, char *theOptions, int *filesNumber, int commandType, DYNMEM_MemoryTable_DataType **memoryTable);

int searchInLoginFailsVector(void *loginFailsVector, void *element);
void deleteLoginFailsData(void *element);
void deleteListDataInfoVector(DYNV_VectorGenericDataType *theVector);
void resetWorkerData(ftpDataType *data, int clientId, int isInitialization);
void resetClientData(ftpDataType *data, int clientId, int isInitialization);
int compareStringCaseInsensitive(char *stringIn, char* stringRef, int stringLenght);
int isCharInString(char *theString, int stringLen, char theChar);
void destroyConfigurationVectorElement(DYNV_VectorGenericDataType *theVector);
int isPortInUse(int port);
void handleThreadReuse(ftpDataType *data, int clientId);

#ifdef __cplusplus
}
#endif

#endif /* FTPDATA_H */

