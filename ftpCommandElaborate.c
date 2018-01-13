/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include "ftpServer.h"
#include "ftpCommandsElaborate.h"
#include "ftpData.h"
#include "logFunctions.h"

/* Elaborate the User login command */
int parseCommandUser(clientDataType *theClientData)
{
    int i, theNameIndex;
    char theName[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
    memset(theName, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
    theNameIndex = 0;

    for (i = strlen("USER")+1; i < theClientData->commandIndex; i++)
    {
        if (theClientData->theCommandReceived[i] == '\r' ||
            theClientData->theCommandReceived[i] == '\n' ||
            theClientData->theCommandReceived[i] == '\0')
            {
                break;
            }
        
        if (theClientData->theCommandReceived[i] != ' ' &&
            theNameIndex < FTP_COMMAND_ELABORATE_CHAR_BUFFER)
        {
            theName[theNameIndex++] = theClientData->theCommandReceived[i];
        }
    }
    printTimeStamp();
    printf("The Name: %s", theName);
    
    if (theNameIndex > 1)
    {
        char *theResponse = "331 User ok, Waiting for the password.\r\n";
        setDynamicStringDataType(&theClientData->login.name, theName, theNameIndex);
        write(theClientData->socketDescriptor, theResponse, strlen(theResponse));
        printf("\nUSER COMMAND OK, USERNAME IS: %s", theClientData->login.name.text);
        return 1;
    }
    else
    {
        return 0;
    }
}

int parseCommandPass(clientDataType *theClientData)
{
    int i, thePassIndex;
    char thePass[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
    memset(thePass, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
    thePassIndex = 0;

    for (i = strlen("PASS")+1; i < theClientData->commandIndex; i++)
    {
        if (theClientData->theCommandReceived[i] == '\r' ||
            theClientData->theCommandReceived[i] == '\0' ||
            theClientData->theCommandReceived[i] == '\n')
            {
                break;
            }
        
        if (theClientData->theCommandReceived[i] != ' ' &&
            thePassIndex < FTP_COMMAND_ELABORATE_CHAR_BUFFER)
        {
            thePass[thePassIndex++] = theClientData->theCommandReceived[i];
        }
    }
    printTimeStamp();
    printf("The Pass is: %s", thePass);

    if (thePassIndex > 1)
    {
        //430	Invalid username or password.
        char *theResponse = "230 Login Ok.\r\n";
        setDynamicStringDataType(&theClientData->login.password, thePass, thePassIndex);
        
        setDynamicStringDataType(&theClientData->login.absolutePath, "/home/ugo", strlen("/home/ugo"));
        setDynamicStringDataType(&theClientData->login.homePath, "/home/ugo", strlen("/home/ugo"));
        setDynamicStringDataType(&theClientData->login.ftpPath, "/", strlen("/"));
        
        write(theClientData->socketDescriptor, theResponse, strlen(theResponse));
        printTimeStamp();
        printf("PASS COMMAND OK, PASSWORD IS: %s", theClientData->login.password.text);
        printf("\nheClientData->login.homePath: %s", theClientData->login.homePath.text);
        printf("\nheClientData->login.ftpPath: %s", theClientData->login.ftpPath.text);
        printf("\nheClientData->login.absolutePath: %s", theClientData->login.absolutePath.text);
        
       return 1;
    }
    else
    {
        return 0;
    }
}

int parseCommandAuth(clientDataType *theClientData)
{
    int i, theAuthIndex;
    char theAuth[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
    memset(theAuth, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
    theAuthIndex = 0;

    for (i = strlen("AUTH")+1; i < theClientData->commandIndex; i++)
    {
        if (theClientData->theCommandReceived[i] == '\r' ||
            theClientData->theCommandReceived[i] == '\0' ||
            theClientData->theCommandReceived[i] == '\n')
            {
            break;
            }
        
        if (theClientData->theCommandReceived[i] != ' ' &&
            theAuthIndex < FTP_COMMAND_ELABORATE_CHAR_BUFFER)
        {
            theAuth[theAuthIndex++] = theClientData->theCommandReceived[i];
        }
    }
    printTimeStamp();
    printf("The Auth is: %s", theAuth);

    char *theResponse = "502 Auth command is not supported.\r\n";
    write(theClientData->socketDescriptor, theResponse, strlen(theResponse));
    return 1;
}

int parseCommandPwd(clientDataType *theClientData)
{
    int i, thePwdIndex;
    char thePwdResponse[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
    memset(thePwdResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
    thePwdIndex = 0;
    sprintf(thePwdResponse, "257 \"%s\" is your current location\r\n", theClientData->login.ftpPath.text);
    write(theClientData->socketDescriptor, thePwdResponse, strlen(thePwdResponse));
    return 1;
}

int parseCommandSyst(clientDataType *theClientData)
{
    char *theResponse = "215 UNIX Type: L8\r\n";
    write(theClientData->socketDescriptor, theResponse, strlen(theResponse));
    return 1;
}

int parseCommandFeat(clientDataType *theClientData)
{
    
    /*
    211-Extensions supported:
     EPRT
     IDLE
     MDTM
     SIZE
     MFMT
     REST STREAM
     MLST type*;size*;sizd*;modify*;UNIX.mode*;UNIX.uid*;UNIX.gid*;unique*;
     MLSD
     AUTH TLS
     PBSZ
     PROT
     UTF8
     TVFS
     ESTA
     PASV
     EPSV
     SPSV
     ESTP
    211 End.

     */
    char *theResponse = "211-Extensions supported:\r\n PASV\r\n211 End.\r\n";
    write(theClientData->socketDescriptor, theResponse, strlen(theResponse));
    return 1;
}

int parseCommandTypeI(clientDataType *theClientData)
{
    char *theResponse = "200 TYPE is now 8-bit binary\r\n";
    write(theClientData->socketDescriptor, theResponse, strlen(theResponse));
    return 1;
}

int parseCommandPasv(ftpDataType * data, int socketId)
{
    /* Create worker thread */
    if (data->clients[socketId].pasvData.threadIsAlive == 1)
    {
        void *pReturn;
        pthread_cancel(data->clients[socketId].pasvData.pasvThread);
        pthread_join(data->clients[socketId].pasvData.pasvThread, &pReturn);
        printf("\nThread has been cancelled.");
    }
    
    usleep(10000);
    pthread_create(&data->clients[socketId].pasvData.pasvThread, NULL, pasvThreadHandler, (void *) &data->clients[socketId].clientProgressiveNumber);
    usleep(10000);
    
    char theResponse[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
    memset(theResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
    sprintf(theResponse, "227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)\r\n",data->serverIp.ip[0], data->serverIp.ip[1], data->serverIp.ip[2], data->serverIp.ip[3], (data->clients[socketId].pasvData.passivePort / 256), (data->clients[socketId].pasvData.passivePort % 256));     
    write(data->clients[socketId].socketDescriptor, theResponse, strlen(theResponse));
    return 1;
}

int parseCommandAbor(ftpDataType * data, int socketId)
{
    char theResponse[FTP_COMMAND_ELABORATE_CHAR_BUFFER];

    /*
     426 ABORT
    226-Transfer aborted
    226 3.406 seconds (measured here), 1.58 Mbytes per second
    226 Since you see this ABOR must've succeeded
    */

    if (data->clients[socketId].pasvData.threadIsAlive == 1 &&
        data->clients[socketId].pasvData.threadIsBusy == 1)
    {
        void *pReturn;
        pthread_cancel(data->clients[socketId].pasvData.pasvThread);
        pthread_join(data->clients[socketId].pasvData.pasvThread, &pReturn);
        printf("\nThread has been cancelled due to ABOR request.");
        
        memset(theResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
        sprintf(theResponse, "426 ABORT\r\n");     
        write(data->clients[socketId].socketDescriptor, theResponse, strlen(theResponse));
        
        memset(theResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
        sprintf(theResponse, "226 Transfer aborted\r\n");     
        write(data->clients[socketId].socketDescriptor, theResponse, strlen(theResponse));
    }
    else
    {
        memset(theResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
        sprintf(theResponse, "226 Since you see this ABOR must've succeeded\r\n");     
        write(data->clients[socketId].socketDescriptor, theResponse, strlen(theResponse));
    }

    return 1;
}

int parseCommandList(ftpDataType * data, int socketId)
{
    pthread_mutex_lock(&data->clients[socketId].pasvData.conditionMutex);
    memset(data->clients[socketId].pasvData.theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);
    strcpy(data->clients[socketId].pasvData.theCommandReceived, data->clients[socketId].theCommandReceived);
    data->clients[socketId].pasvData.commandReceived = 1;
    pthread_mutex_unlock(&data->clients[socketId].pasvData.conditionMutex);
    pthread_cond_signal(&data->clients[socketId].pasvData.conditionVariable);
   return 1;
}

int parseCommandRetr(ftpDataType * data, int socketId)
{
    pthread_mutex_lock(&data->clients[socketId].pasvData.conditionMutex);
    memset(data->clients[socketId].pasvData.theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);
    strcpy(data->clients[socketId].pasvData.theCommandReceived, data->clients[socketId].theCommandReceived);
    data->clients[socketId].pasvData.commandReceived = 1;
    pthread_mutex_unlock(&data->clients[socketId].pasvData.conditionMutex);
    pthread_cond_signal(&data->clients[socketId].pasvData.conditionVariable);
    
    return 1;
}

int parseCommandStor(ftpDataType * data, int socketId)
{
    pthread_mutex_lock(&data->clients[socketId].pasvData.conditionMutex);
    //
    //Set new command received
    //    
    int i;
    memset(data->clients[socketId].pasvData.theFileNameToStor, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
    data->clients[socketId].pasvData.theFileNameToStorIndex = 0;

    for (i = strlen("STOR")+1; i < data->clients[socketId].commandIndex; i++)
    {
        if (data->clients[socketId].theCommandReceived[i] == '\r' ||
            data->clients[socketId].theCommandReceived[i] == '\0' ||
            data->clients[socketId].theCommandReceived[i] == '\n')
            {
                break;
            }
        
        if (data->clients[socketId].pasvData.theFileNameToStorIndex < FTP_COMMAND_ELABORATE_CHAR_BUFFER)
        {
            data->clients[socketId].pasvData.theFileNameToStor[data->clients[socketId].pasvData.theFileNameToStorIndex++] = data->clients[socketId].theCommandReceived[i];
        }
    }
    
    printf("data->clients[%d].pasvData.theFileNameToStor = %s", socketId, data->clients[socketId].pasvData.theFileNameToStor);

    memset(data->clients[socketId].pasvData.theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);
    strcpy(data->clients[socketId].pasvData.theCommandReceived, data->clients[socketId].theCommandReceived);
    data->clients[socketId].pasvData.commandReceived = 1;

    pthread_mutex_unlock(&data->clients[socketId].pasvData.conditionMutex);
    pthread_cond_signal(&data->clients[socketId].pasvData.conditionVariable);  
    
    return 1;
}

int parseCommandCwd(clientDataType *theClientData)
{
    dynamicStringDataType absolutePathPrevious, ftpPathPrevious;
    int i, thePathIndex;
    char thePath[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
    memset(thePath, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
    thePathIndex = 0;
    char *theResponse;
    
    cleanDynamicStringDataType(&absolutePathPrevious, 1);
    cleanDynamicStringDataType(&ftpPathPrevious, 1);
    
    setDynamicStringDataType(&absolutePathPrevious, theClientData->login.absolutePath.text, theClientData->login.absolutePath.textLen);
    setDynamicStringDataType(&ftpPathPrevious, theClientData->login.ftpPath.text, theClientData->login.ftpPath.textLen);
    
    for (i = strlen("CWD")+1; i < theClientData->commandIndex; i++)
    {
        if (theClientData->theCommandReceived[i] == '\r' ||
            theClientData->theCommandReceived[i] == '\0' ||
            theClientData->theCommandReceived[i] == '\n')
            {
            break;
            }
        
        if (thePathIndex < FTP_COMMAND_ELABORATE_CHAR_BUFFER)
        {
            thePath[thePathIndex++] = theClientData->theCommandReceived[i];
        }
    }

    printTimeStamp();
    printf("\n The Path requested for CWD IS: %s", thePath);
    fflush(0);

    if (thePathIndex > 0)
    {
        if (thePath[0] != '/')
        {
            if (theClientData->login.absolutePath.text[theClientData->login.absolutePath.textLen-1] != '/')
                appendToDynamicStringDataType(&theClientData->login.absolutePath, "/", 1);

            if (theClientData->login.ftpPath.text[theClientData->login.ftpPath.textLen-1] != '/')
                appendToDynamicStringDataType(&theClientData->login.ftpPath, "/", 1);

            appendToDynamicStringDataType(&theClientData->login.absolutePath, thePath, strlen(thePath));
            appendToDynamicStringDataType(&theClientData->login.ftpPath, thePath, strlen(thePath));
        }
        else if (thePath[0] == '/')
        {
            cleanDynamicStringDataType(&theClientData->login.ftpPath, 0);
            cleanDynamicStringDataType(&theClientData->login.absolutePath, 0);
            
            setDynamicStringDataType(&theClientData->login.ftpPath, thePath, strlen(thePath));
            setDynamicStringDataType(&theClientData->login.absolutePath, theClientData->login.homePath.text, theClientData->login.homePath.textLen);

            appendToDynamicStringDataType(&theClientData->login.absolutePath, thePath, strlen(thePath));            
        }

        if (FILE_IsDirectory(theClientData->login.absolutePath.text) == 1)
        {
            theResponse = (char *) malloc (strlen("250 OK. Current directory is ")+theClientData->login.ftpPath.textLen+1);
            strcpy(theResponse, "250 OK. Current directory is ");
            strcat(theResponse, theClientData->login.ftpPath.text);
        }
        else
        {
            printf("\n%s does not exist", theClientData->login.absolutePath.text);
            setDynamicStringDataType(&theClientData->login.absolutePath, absolutePathPrevious.text, absolutePathPrevious.textLen);
            setDynamicStringDataType(&theClientData->login.ftpPath, ftpPathPrevious.text, ftpPathPrevious.textLen);

            theResponse = (char *) malloc (strlen("550 Can't change directory to  : No such file or directory")+10+strlen(theClientData->login.ftpPath.text));
            strcpy(theResponse, "550 Can't change directory to ");
            strcat(theResponse, theClientData->login.ftpPath.text);
            strcat(theResponse, ": No such file or directory");      
        }

        FILE_AppendToString(&theResponse, thePath);
        FILE_AppendToString(&theResponse, " \r\n");
        
   
        write(theClientData->socketDescriptor, theResponse, strlen(theResponse));
        printTimeStamp();
        printf("USER COMMAND OK, NEW PATH IS: %s", theClientData->login.absolutePath.text);
        printf("\nUSER COMMAND OK, NEW LOCAL PATH IS: %s", theClientData->login.ftpPath.text);
        
        cleanDynamicStringDataType(&absolutePathPrevious, 0);
        cleanDynamicStringDataType(&ftpPathPrevious, 0);
        fflush(0);
        free(theResponse);
        return 1;
    }
    else
    {
        return 0;
    }    
}

int parseCommandRest(clientDataType *theClientData)
{
    int i, theSizeIndex;
    char theSize[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
    memset(theSize, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
    theSizeIndex = 0;
    
    char *theResponse;
    theResponse = (char *) malloc (strlen("350 Restarting at ")+1);
    strcpy(theResponse, "350 Restarting at ");
    
    for (i = strlen("REST")+1; i < theClientData->commandIndex; i++)
    {
        if (theClientData->theCommandReceived[i] == '\r' ||
            theClientData->theCommandReceived[i] == '\0' ||
            theClientData->theCommandReceived[i] == '\n')
            {
            break;
            }
        
        if (theSizeIndex < FTP_COMMAND_ELABORATE_CHAR_BUFFER &&
            (theClientData->theCommandReceived[i] == '0' ||
            theClientData->theCommandReceived[i] == '1' ||
            theClientData->theCommandReceived[i] == '2' ||
            theClientData->theCommandReceived[i] == '3' ||
            theClientData->theCommandReceived[i] == '4' ||
            theClientData->theCommandReceived[i] == '5' ||
            theClientData->theCommandReceived[i] == '6' ||
            theClientData->theCommandReceived[i] == '7' ||
            theClientData->theCommandReceived[i] == '8' ||
            theClientData->theCommandReceived[i] == '9' ))
        {
            theSize[theSizeIndex++] = theClientData->theCommandReceived[i];
        }
    }
    printTimeStamp();
    printf(" REST set to: %s", theSize);
    fflush(0);
    
    FILE_AppendToString(&theResponse, theSize);
    FILE_AppendToString(&theResponse, " \r\n");
    theClientData->pasvData.retrRestartAtByte = atoll(theSize);
    write(theClientData->socketDescriptor, theResponse, strlen(theResponse));    
    free(theResponse);
    
    return 1;
}

int parseCommandMkd(clientDataType *theClientData)
{
    int returnStatus = 0;
    char *theDirectoryFilename;
    dynamicStringDataType theResponse;
    dynamicStringDataType mkdFileName;
    
    theDirectoryFilename = getFtpCommandArg("MKD", theClientData->theCommandReceived);
    
    
    cleanDynamicStringDataType(&theResponse, 1);
    cleanDynamicStringDataType(&mkdFileName, 1);
    
    if (theDirectoryFilename[0] == '/')
    {
        setDynamicStringDataType(&mkdFileName, theDirectoryFilename, strlen(theDirectoryFilename));
    }
    else
    {
        setDynamicStringDataType(&mkdFileName, theClientData->login.absolutePath.text, theClientData->login.absolutePath.textLen);
        appendToDynamicStringDataType(&mkdFileName, "/", 1);
        appendToDynamicStringDataType(&mkdFileName, theDirectoryFilename, strlen(theDirectoryFilename));
    }
    
    if (strlen(theDirectoryFilename) > 0)
    {
        printf("\nThe directory to make is: %s", mkdFileName.text);
        returnStatus = mkdir(mkdFileName.text, S_IRWXU | S_IRWXG | S_IRWXO);
    }
    
    setDynamicStringDataType(&theResponse, "257 \"", strlen("257 \""));
    appendToDynamicStringDataType(&theResponse, theDirectoryFilename, strlen(theDirectoryFilename));
    appendToDynamicStringDataType(&theResponse, "\" : The directory was successfully created\r\n", strlen("\" : The directory was successfully created\r\n"));

    write(theClientData->socketDescriptor, theResponse.text, theResponse.textLen);
    
    cleanDynamicStringDataType(&theResponse, 0);
    cleanDynamicStringDataType(&mkdFileName, 0);
    
    return 1;
}



int parseCommandDele(clientDataType *theClientData)
{
    int returnStatus = 0;
    char *theFileToDelete;
    dynamicStringDataType theResponse;
    dynamicStringDataType deleFileName;
    
    theFileToDelete = getFtpCommandArg("DELE", theClientData->theCommandReceived);
    
    
    cleanDynamicStringDataType(&theResponse, 1);
    cleanDynamicStringDataType(&deleFileName, 1);
    
    if (theFileToDelete[0] == '/')
    {
        setDynamicStringDataType(&deleFileName, theFileToDelete, strlen(theFileToDelete));
    }
    else
    {
        setDynamicStringDataType(&deleFileName, theClientData->login.absolutePath.text, theClientData->login.absolutePath.textLen);
        appendToDynamicStringDataType(&deleFileName, "/", 1);
        appendToDynamicStringDataType(&deleFileName, theFileToDelete, strlen(theFileToDelete));
    }
    
    if (strlen(theFileToDelete) > 0)
    {
        printf("\nThe file to delete is: %s", deleFileName.text);
        returnStatus = remove(deleFileName.text);
    }
    
    setDynamicStringDataType(&theResponse, "250 Deleted ", strlen("250 Deleted "));
    appendToDynamicStringDataType(&theResponse, theFileToDelete, strlen(theFileToDelete));
    appendToDynamicStringDataType(&theResponse, "\r\n", strlen("\r\n"));

    write(theClientData->socketDescriptor, theResponse.text, theResponse.textLen);
    cleanDynamicStringDataType(&theResponse, 0);
    cleanDynamicStringDataType(&deleFileName, 0);
    return 1;
}


int parseCommandNoop(clientDataType *theClientData)
{
    //200 Zzz...
    char *theResponse = "200 Zzz...\r\n";
    write(theClientData->socketDescriptor, theResponse, strlen(theResponse));
    return 1;
}

int parseCommandRmd(clientDataType *theClientData)
{
    int returnStatus = 0;
    char *theDirectoryFilename;
    dynamicStringDataType theResponse;
    dynamicStringDataType mkdFileName;
    
    theDirectoryFilename = getFtpCommandArg("RMD", theClientData->theCommandReceived);
    
    cleanDynamicStringDataType(&theResponse, 1);
    cleanDynamicStringDataType(&mkdFileName, 1);
    
    if (theDirectoryFilename[0] == '/')
    {
        setDynamicStringDataType(&mkdFileName, theDirectoryFilename, strlen(theDirectoryFilename));
    }
    else
    {
        setDynamicStringDataType(&mkdFileName, theClientData->login.absolutePath.text, theClientData->login.absolutePath.textLen);
        appendToDynamicStringDataType(&mkdFileName, "/", 1);
        appendToDynamicStringDataType(&mkdFileName, theDirectoryFilename, strlen(theDirectoryFilename));
    }
    
    if (strlen(theDirectoryFilename) > 0)
    {
        printf("\nThe directory to delete is: %s", mkdFileName.text);
        returnStatus = rmdir(mkdFileName.text);
    }
    
    setDynamicStringDataType(&theResponse, "250 The directory was successfully removed\r\n", strlen("250 The directory was successfully removed\r\n"));
    write(theClientData->socketDescriptor, theResponse.text, theResponse.textLen);
    
    cleanDynamicStringDataType(&theResponse, 0);
    cleanDynamicStringDataType(&mkdFileName, 0);
    
    return 1;
}


int parseCommandSize(clientDataType *theClientData)
{
    // to be continued
    unsigned long long int theSize;
    int returnStatus = 0;
    char *theFileName;
    dynamicStringDataType theResponse;
    dynamicStringDataType getSizeFromFileName;
    
    theFileName = getFtpCommandArg("SIZE", theClientData->theCommandReceived);

    cleanDynamicStringDataType(&theResponse, 1);
    cleanDynamicStringDataType(&getSizeFromFileName, 1);
    
    if (theFileName[0] == '/')
    {
        setDynamicStringDataType(&getSizeFromFileName, theFileName, strlen(theFileName));
    }
    else
    {
        setDynamicStringDataType(&getSizeFromFileName, theClientData->login.absolutePath.text, theClientData->login.absolutePath.textLen);
        appendToDynamicStringDataType(&getSizeFromFileName, "/", 1);
        appendToDynamicStringDataType(&getSizeFromFileName, theFileName, strlen(theFileName));
    }
    
    if (strlen(theFileName) > 0)
    {
        printf("\nThe file to get the size is: %s", getSizeFromFileName.text);
        
        if (FILE_IsFile(getSizeFromFileName.text)==1)
        {
            char theFileSizeResponse[2014];
            memset(theFileSizeResponse, 0 ,1024);
            
            theSize = FILE_GetFileSizeFromPath(getSizeFromFileName.text);
            sprintf(theFileSizeResponse, "213 %lld\r\n", theSize);
            setDynamicStringDataType(&theResponse, theFileSizeResponse, strlen(theFileSizeResponse));
        }
        else
        {
            setDynamicStringDataType(&theResponse, "550 Can't check for file existence\r\n", strlen("550 Can't check for file existence\r\n"));
        }
    }
    
    write(theClientData->socketDescriptor, theResponse.text, theResponse.textLen);
    cleanDynamicStringDataType(&theResponse, 0);
    cleanDynamicStringDataType(&getSizeFromFileName, 0);
    
    return 1;
}

int parseCommandCdup(clientDataType *theClientData)
{
        int i;

        char *theResponse;
        theResponse = (char *) malloc (strlen("250 OK. Current directory is ")+1);
        strcpy(theResponse, "250 OK. Current directory is ");
        
        FILE_DirectoryToParent(&theClientData->login.absolutePath.text);
        FILE_DirectoryToParent(&theClientData->login.ftpPath.text);
        theClientData->login.absolutePath.textLen = strlen(theClientData->login.absolutePath.text);
        theClientData->login.ftpPath.textLen = strlen(theClientData->login.ftpPath.text);
        
        if(strncmp(theClientData->login.absolutePath.text, theClientData->login.homePath.text, theClientData->login.homePath.textLen) != 0)
        {
            setDynamicStringDataType(&theClientData->login.absolutePath, theClientData->login.homePath.text, theClientData->login.homePath.textLen);
        }
        
        FILE_AppendToString(&theResponse, theClientData->login.ftpPath.text);
        FILE_AppendToString(&theResponse, " \r\n");

        write(theClientData->socketDescriptor, theResponse, strlen(theResponse));
        printTimeStamp();
        printf("USER COMMAND OK, NEW PATH IS: %s", theClientData->login.absolutePath.text);
        printf("\nUSER COMMAND OK, NEW LOCAL PATH IS: %s", theClientData->login.ftpPath.text);
        
        free(theResponse);
        return 1;
    
}

int writeRetrFile(char * theFilename, int thePasvSocketConnection, int startFrom)
{
    long int readen = 0;
    long int toReturn = 0;
    long int currentPosition = 0;
    FILE *retrFP;
    long long int theFileSize;
    char buffer[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
    
    printf("\nOpening: %s", theFilename);
    
    retrFP = fopen(theFilename, "rb");
    if (retrFP == NULL)
    {
        fclose(retrFP);
        return toReturn;
    }

    theFileSize = FILE_GetFileSize(retrFP);
    
    if (startFrom > 0)
    {
        
        printf("\nSeek startFrom: %d", startFrom);
        
        currentPosition = (long int) lseek(fileno(retrFP), startFrom, SEEK_SET);
        
        printf("\nSeek result: %d", currentPosition);

        if (currentPosition == -1)
        {
            fclose(retrFP);
            return toReturn;
        }
    }
    
    while ((readen = (long int) fread(buffer, sizeof(char), FTP_COMMAND_ELABORATE_CHAR_BUFFER, retrFP)) > 0)
    {
      toReturn = toReturn + write(thePasvSocketConnection, buffer, readen);
    }
    
    printf("\n Bytes written: %d", toReturn);
    
    fclose(retrFP);
    return toReturn;
}


char *getFtpCommandArg(char * theCommand, char *theCommandString)
{
    char *toReturn = theCommandString + strlen(theCommand);
    
    while (toReturn[0] == ' ')
    {
        toReturn += 1;
    }
    
    return toReturn;
}