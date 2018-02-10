/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include "ftpServer.h"
#include "ftpCommandsElaborate.h"
#include "ftpData.h"
#include "library/logFunctions.h"
#include "library/fileManagement.h"

/* Elaborate the User login command */
int parseCommandUser(clientDataType *theClientData)
{
    char *theName;
    theName = getFtpCommandArg("USER", theClientData->theCommandReceived);

    printTimeStamp();
    printf("The Name: %s", theName);

    if (strlen(theName) >= 1)
    {
        char *theResponse = "331 User ok, Waiting for the password.\r\n";
        setDynamicStringDataType(&theClientData->login.name, theName, strlen(theName));
        write(theClientData->socketDescriptor, theResponse, strlen(theResponse));
        printf("\nUSER COMMAND OK, USERNAME IS: %s", theClientData->login.name.text);
        return 1;
    }
    else
    {
        char *theResponse = "430 Invalid username.\r\n";
        write(theClientData->socketDescriptor, theResponse, strlen(theResponse));
        return 1;
    }
}

int parseCommandPass(ftpDataType * data, int socketId)
{
    char *thePass;
    thePass = getFtpCommandArg("PASS", data->clients[socketId].theCommandReceived);
    
    printTimeStamp();
    printf("The Pass is: %s", thePass);

    if (strlen(thePass) >= 1)
    {
        int searchUserNameIndex;
        searchUserNameIndex = searchUser(data->clients[socketId].login.name.text, &data->ftpParameters.usersVector);

        if (searchUserNameIndex < 0 ||
            (strcmp(((usersParameters_DataType *) data->ftpParameters.usersVector.Data[searchUserNameIndex])->password, thePass) != 0))
        {
            char *theResponse = "430 Invalid username or password\r\n";
            write(data->clients[socketId].socketDescriptor, theResponse, strlen(theResponse));
            printf("\nLogin Error recorded no such username or password");
        }
        else
        {
            char *theResponse = "230 Login Ok.\r\n";
            setDynamicStringDataType(&data->clients[socketId].login.password, thePass, strlen(thePass));
            setDynamicStringDataType(&data->clients[socketId].login.absolutePath, ((usersParameters_DataType *) data->ftpParameters.usersVector.Data[searchUserNameIndex])->homePath, strlen(((usersParameters_DataType *) data->ftpParameters.usersVector.Data[searchUserNameIndex])->homePath));
            setDynamicStringDataType(&data->clients[socketId].login.homePath, ((usersParameters_DataType *) data->ftpParameters.usersVector.Data[searchUserNameIndex])->homePath, strlen(((usersParameters_DataType *) data->ftpParameters.usersVector.Data[searchUserNameIndex])->homePath));
            setDynamicStringDataType(&data->clients[socketId].login.ftpPath, "/", strlen("/"));
            data->clients[socketId].login.userLoggedIn = 1;

            write(data->clients[socketId].socketDescriptor, theResponse, strlen(theResponse));
            printTimeStamp();
            
            printf("PASS COMMAND OK, PASSWORD IS: %s", data->clients[socketId].login.password.text);
            printf("\nheClientData->login.homePath: %s", data->clients[socketId].login.homePath.text);
            printf("\nheClientData->login.ftpPath: %s", data->clients[socketId].login.ftpPath.text);
            printf("\nheClientData->login.absolutePath: %s", data->clients[socketId].login.absolutePath.text);
        }
        
       return 1;
    }
    else
    {
        char *theResponse = "430 Invalid username or password\r\n";
        write(data->clients[socketId].socketDescriptor, theResponse, strlen(theResponse));
        return 1;
    }
}

int parseCommandAuth(clientDataType *theClientData)
{
    char *theAuth;
    theAuth = getFtpCommandArg("AUTH", theClientData->theCommandReceived);    
    printTimeStamp();
    printf("The Auth is: %s", theAuth);
    char *theResponse = "502 Security extensions not implemented.\r\n";
    write(theClientData->socketDescriptor, theResponse, strlen(theResponse));
    return 1;
}

int parseCommandPwd(clientDataType *theClientData)
{
    char thePwdResponse[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
    memset(thePwdResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
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

int parseCommandTypeA(clientDataType *theClientData)
{
    char *theResponse = "200 TYPE is now 8-bit binary\r\n";
    write(theClientData->socketDescriptor, theResponse, strlen(theResponse));
    return 1;
}

int parseCommandTypeI(clientDataType *theClientData)
{
    char *theResponse = "200 TYPE is now 8-bit binary\r\n";
    write(theClientData->socketDescriptor, theResponse, strlen(theResponse));
    return 1;
}

int parseCommandStruF(clientDataType *theClientData)
{
    char *theResponse = "200 TYPE is now 8-bit binary\r\n";
    write(theClientData->socketDescriptor, theResponse, strlen(theResponse));
    return 1;
}

int parseCommandModeS(clientDataType *theClientData)
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

    pthread_create(&data->clients[socketId].pasvData.pasvThread, NULL, pasvThreadHandler, (void *) &data->clients[socketId].clientProgressiveNumber);

    //char theResponse[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
    //memset(theResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
    //sprintf(theResponse, "227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)\r\n",data->serverIp.ip[0], data->serverIp.ip[1], data->serverIp.ip[2], data->serverIp.ip[3], (data->clients[socketId].pasvData.passivePort / 256), (data->clients[socketId].pasvData.passivePort % 256));
    //write(data->clients[socketId].socketDescriptor, theResponse, strlen(theResponse));
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
    /*
      -1 List one file per line
      -A List all files except "." and ".."
      -a List all files including those whose names start with "."
      -C List entries by columns
      -d List directory entries instead of directory contents
      -F Append file type indicator (one of "*", "/", "=", "@" or "|") to names
      -h Print file sizes in human-readable format (e.g. 1K, 234M, 2G)
      -L List files pointed to by symlinks
      -l Use a long listing format
      -n List numeric UIDs/GIDs instead of user/group names
      -R List subdirectories recursively
      -r Sort filenames in reverse order
      -S Sort by file size
      -t Sort by modification time 
     */
    
    
 
    
    int isSafePath = 0;
    char *theNameToList;
    
    theNameToList = getFtpCommandArg("LIST", data->clients[socketId].theCommandReceived);
    getFtpCommandArgWithOptions("LIST", data->clients[socketId].theCommandReceived, &data->clients[socketId].pasvData.ftpCommand);
 
    printf("\nLIST COMMAND ARG: %s", data->clients[socketId].pasvData.ftpCommand.commandArgs.text);
    printf("\nLIST COMMAND OPS: %s", data->clients[socketId].pasvData.ftpCommand.commandOps.text);
    
    cleanDynamicStringDataType(&data->clients[socketId].pasvData.ftpCommand.commandArgs, 0);
    cleanDynamicStringDataType(&data->clients[socketId].pasvData.ftpCommand.commandOps, 0);    
    cleanDynamicStringDataType(&data->clients[socketId].listPath, 0);

    if (strlen(theNameToList) > 0)
    {
        isSafePath = getSafePath(&data->clients[socketId].listPath, theNameToList, &data->clients[socketId].login);
    }

    if (isSafePath == 0)
    {
        cleanDynamicStringDataType(&data->clients[socketId].listPath, 0);
        setDynamicStringDataType(&data->clients[socketId].listPath, data->clients[socketId].login.absolutePath.text, data->clients[socketId].login.absolutePath.textLen);
    }

    pthread_mutex_lock(&data->clients[socketId].pasvData.conditionMutex);
    memset(data->clients[socketId].pasvData.theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);
    strcpy(data->clients[socketId].pasvData.theCommandReceived, data->clients[socketId].theCommandReceived);
    data->clients[socketId].pasvData.commandReceived = 1;
    pthread_mutex_unlock(&data->clients[socketId].pasvData.conditionMutex);
    pthread_cond_signal(&data->clients[socketId].pasvData.conditionVariable);
   return 1;
}

int parseCommandNlst(ftpDataType * data, int socketId)
{
    int isSafePath = 0;
    char *theNameToNlist;
    theNameToNlist = getFtpCommandArg("NLIST", data->clients[socketId].theCommandReceived);
    cleanDynamicStringDataType(&data->clients[socketId].nlistPath, 0);

    if (strlen(theNameToNlist) > 0)
    {
        isSafePath = getSafePath(&data->clients[socketId].nlistPath, theNameToNlist, &data->clients[socketId].login);
    }

    if (isSafePath == 0)
    {
        cleanDynamicStringDataType(&data->clients[socketId].nlistPath, 0);
        setDynamicStringDataType(&data->clients[socketId].nlistPath, data->clients[socketId].login.absolutePath.text, data->clients[socketId].login.absolutePath.textLen);
    }
    
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
    int isSafePath = 0;
    char *theNameToRetr;
    theNameToRetr = getFtpCommandArg("RETR", data->clients[socketId].theCommandReceived);
    cleanDynamicStringDataType(&data->clients[socketId].fileToRetr, 0);
    
    if (strlen(theNameToRetr) > 0)
    {
        isSafePath = getSafePath(&data->clients[socketId].fileToRetr, theNameToRetr, &data->clients[socketId].login);
    }

    if (isSafePath == 1 &&
        FILE_IsFile(data->clients[socketId].fileToRetr.text) == 1)
    {
        pthread_mutex_lock(&data->clients[socketId].pasvData.conditionMutex);
        memset(data->clients[socketId].pasvData.theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);
        strcpy(data->clients[socketId].pasvData.theCommandReceived, data->clients[socketId].theCommandReceived);
        data->clients[socketId].pasvData.commandReceived = 1;
        pthread_mutex_unlock(&data->clients[socketId].pasvData.conditionMutex);
        pthread_cond_signal(&data->clients[socketId].pasvData.conditionVariable);
        return 1;
    }
    else
    {
        return 0;
    }

    return 1;
}

int parseCommandStor(ftpDataType * data, int socketId)
{
    int isSafePath = 0;
    char *theNameToStor;
    theNameToStor = getFtpCommandArg("STOR", data->clients[socketId].theCommandReceived);
    cleanDynamicStringDataType(&data->clients[socketId].fileToStor, 0);
    
    if (strlen(theNameToStor) > 0)
    {
        isSafePath = getSafePath(&data->clients[socketId].fileToStor, theNameToStor, &data->clients[socketId].login);
    }

    if (isSafePath == 1)
    {
        pthread_mutex_lock(&data->clients[socketId].pasvData.conditionMutex);
        printf("data->clients[%d].fileToStor = %s", socketId, data->clients[socketId].fileToStor.text);
        memset(data->clients[socketId].pasvData.theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);
        strcpy(data->clients[socketId].pasvData.theCommandReceived, data->clients[socketId].theCommandReceived);
        data->clients[socketId].pasvData.commandReceived = 1;
        pthread_mutex_unlock(&data->clients[socketId].pasvData.conditionMutex);
        pthread_cond_signal(&data->clients[socketId].pasvData.conditionVariable);
    }
    else
    {
        return 0;
    }
    
    return 1;
}

int parseCommandCwd(clientDataType *theClientData)
{
    dynamicStringDataType absolutePathPrevious, ftpPathPrevious, theSafePath;
    int isSafePath;
    char *thePath;
    char *theResponse;

    cleanDynamicStringDataType(&absolutePathPrevious, 1);
    cleanDynamicStringDataType(&ftpPathPrevious, 1);
    cleanDynamicStringDataType(&theSafePath, 1);

    thePath = getFtpCommandArg("CWD", theClientData->theCommandReceived);

    if (strlen(thePath) > 0)
    {
        isSafePath = getSafePath(&theSafePath, thePath, &theClientData->login);
    }

    if (isSafePath == 1)
    {
        printf("\n The Path requested for CWD IS:%s", theSafePath.text);
        setDynamicStringDataType(&absolutePathPrevious, theClientData->login.absolutePath.text, theClientData->login.absolutePath.textLen);
        setDynamicStringDataType(&ftpPathPrevious, theClientData->login.ftpPath.text, theClientData->login.ftpPath.textLen);
        
        if (theSafePath.text[0] != '/')
        {
            if (theClientData->login.absolutePath.text[theClientData->login.absolutePath.textLen-1] != '/')
                appendToDynamicStringDataType(&theClientData->login.absolutePath, "/", 1);

            if (theClientData->login.ftpPath.text[theClientData->login.ftpPath.textLen-1] != '/')
                appendToDynamicStringDataType(&theClientData->login.ftpPath, "/", 1);

            appendToDynamicStringDataType(&theClientData->login.absolutePath, theSafePath.text, theSafePath.textLen);
            appendToDynamicStringDataType(&theClientData->login.ftpPath, theSafePath.text, theSafePath.textLen);
        }
        else if (theSafePath.text[0] == '/')
        {
            cleanDynamicStringDataType(&theClientData->login.ftpPath, 0);
            cleanDynamicStringDataType(&theClientData->login.absolutePath, 0);

            setDynamicStringDataType(&theClientData->login.ftpPath, theSafePath.text, theSafePath.textLen);
            setDynamicStringDataType(&theClientData->login.absolutePath, theClientData->login.homePath.text, theClientData->login.homePath.textLen);

            if (strlen(theSafePath.text)> 0)
            {
                char *theDirPointer = theSafePath.text;
                
                if (theClientData->login.absolutePath.text[theClientData->login.absolutePath.textLen-1] == '/')
                {
                    while(theDirPointer[0] == '/')
                        theDirPointer++;
                }
                
                if (strlen(theDirPointer) > 0)
                    appendToDynamicStringDataType(&theClientData->login.absolutePath, theDirPointer, strlen(theDirPointer));
            }
        }

        if (FILE_IsDirectory(theClientData->login.absolutePath.text) == 1)
        {
            printf("\nDirectory ok found, theClientData->login.ftpPath.text = %s", theClientData->login.ftpPath.text);
            int theSizeToMalloc = strlen("250 OK. Current directory is ")+theClientData->login.ftpPath.textLen+1;
            theResponse = (char *) malloc (theSizeToMalloc);
            memset(theResponse, 0, theSizeToMalloc);
            strcpy(theResponse, "250 OK. Current directory is ");
            strcat(theResponse, theClientData->login.ftpPath.text);
        }
        else
        {
            printf("\n%s does not exist", theClientData->login.absolutePath.text);
            setDynamicStringDataType(&theClientData->login.absolutePath, absolutePathPrevious.text, absolutePathPrevious.textLen);
            setDynamicStringDataType(&theClientData->login.ftpPath, ftpPathPrevious.text, ftpPathPrevious.textLen);
            int theSizeToMalloc = strlen("550 Can't change directory to  : No such file or directory")+10+strlen(theClientData->login.ftpPath.text);
            theResponse = (char *) malloc (theSizeToMalloc);
            memset(theResponse, 0, theSizeToMalloc);
            strcpy(theResponse, "550 Can't change directory to ");
            strcat(theResponse, theClientData->login.ftpPath.text);
            strcat(theResponse, ": No such file or directory");      
        }

        FILE_AppendToString(&theResponse, " \r\n");

        write(theClientData->socketDescriptor, theResponse, strlen(theResponse));
        printTimeStamp();
        printf("\nCwd response : %s", theResponse);
        printf("\nUSER COMMAND OK, NEW PATH IS: %s", theClientData->login.absolutePath.text);
        printf("\nUSER COMMAND OK, NEW LOCAL PATH IS: %s", theClientData->login.ftpPath.text);
        
        cleanDynamicStringDataType(&absolutePathPrevious, 0);
        cleanDynamicStringDataType(&ftpPathPrevious, 0);
        cleanDynamicStringDataType(&theSafePath, 0);
        free(theResponse);
        return 1;
    }
    else
    {
        cleanDynamicStringDataType(&absolutePathPrevious, 0);
        cleanDynamicStringDataType(&ftpPathPrevious, 0);
        cleanDynamicStringDataType(&theSafePath, 0);
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
    int isSafePath;
    char *theDirectoryFilename;
    dynamicStringDataType theResponse;
    dynamicStringDataType mkdFileName;
    
    theDirectoryFilename = getFtpCommandArg("MKD", theClientData->theCommandReceived);
    
    cleanDynamicStringDataType(&theResponse, 1);
    cleanDynamicStringDataType(&mkdFileName, 1);
    
    isSafePath = getSafePath(&mkdFileName, theDirectoryFilename, &theClientData->login);
    
    if (isSafePath == 1)
    {
        int returnStatus;
        printf("\nThe directory to make is: %s", mkdFileName.text);
        returnStatus = mkdir(mkdFileName.text, S_IRWXU | S_IRWXG | S_IRWXO);
        setDynamicStringDataType(&theResponse, "257 \"", strlen("257 \""));
        appendToDynamicStringDataType(&theResponse, theDirectoryFilename, strlen(theDirectoryFilename));
        appendToDynamicStringDataType(&theResponse, "\" : The directory was successfully created\r\n", strlen("\" : The directory was successfully created\r\n"));
        write(theClientData->socketDescriptor, theResponse.text, theResponse.textLen);
    }
    else
    {
        cleanDynamicStringDataType(&theResponse, 0);
        cleanDynamicStringDataType(&mkdFileName, 0);
        return 0;
    }

    cleanDynamicStringDataType(&theResponse, 0);
    cleanDynamicStringDataType(&mkdFileName, 0);    
    return 1;
}

int parseCommandDele(clientDataType *theClientData)
{
    int isSafePath;
    int returnStatus = 0;
    char *theFileToDelete;
    dynamicStringDataType theResponse;
    dynamicStringDataType deleFileName;

    theFileToDelete = getFtpCommandArg("DELE", theClientData->theCommandReceived);

    cleanDynamicStringDataType(&theResponse, 1);
    cleanDynamicStringDataType(&deleFileName, 1);
    
    isSafePath = getSafePath(&deleFileName, theFileToDelete, &theClientData->login);
    
    if (isSafePath == 1)
    {
        printf("\nThe file to delete is: %s", deleFileName.text);
        returnStatus = remove(deleFileName.text);
        setDynamicStringDataType(&theResponse, "250 Deleted ", strlen("250 Deleted "));
        appendToDynamicStringDataType(&theResponse, theFileToDelete, strlen(theFileToDelete));
        appendToDynamicStringDataType(&theResponse, "\r\n", strlen("\r\n"));
        write(theClientData->socketDescriptor, theResponse.text, theResponse.textLen);
    }
    else
    {
        cleanDynamicStringDataType(&theResponse, 0);
        cleanDynamicStringDataType(&deleFileName, 0);
        return 0;
    }
    

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

int notLoggedInMessage(clientDataType *theClientData)
{
    char *theResponse = "530 You aren't logged in\r\n";
    write(theClientData->socketDescriptor, theResponse, strlen(theResponse));
    return 1;
}

int parseCommandQuit(ftpDataType * data, int socketId)
{
    char *theResponse = "221 Logout.\r\n";
    write(data->clients[socketId].socketDescriptor, theResponse, strlen(theResponse));
    data->clients[socketId].closeTheClient = 1;
    return 1;
}

int parseCommandRmd(clientDataType *theClientData)
{
    int isSafePath;
    int returnStatus = 0;
    char *theDirectoryFilename;
    dynamicStringDataType theResponse;
    dynamicStringDataType rmdFileName;
    
    theDirectoryFilename = getFtpCommandArg("RMD", theClientData->theCommandReceived);
    
    cleanDynamicStringDataType(&theResponse, 1);
    cleanDynamicStringDataType(&rmdFileName, 1);
    
    isSafePath = getSafePath(&rmdFileName, theDirectoryFilename, &theClientData->login);
    
    if (isSafePath == 1)
    {
        printf("\nThe directory to delete is: %s", rmdFileName.text);
        returnStatus = rmdir(rmdFileName.text);
        setDynamicStringDataType(&theResponse, "250 The directory was successfully removed\r\n", strlen("250 The directory was successfully removed\r\n"));
        write(theClientData->socketDescriptor, theResponse.text, theResponse.textLen);
    }
    else
    {
        cleanDynamicStringDataType(&theResponse, 0);
        cleanDynamicStringDataType(&rmdFileName, 0);
        return 0;
    }

    cleanDynamicStringDataType(&theResponse, 0);
    cleanDynamicStringDataType(&rmdFileName, 0);

    return 1;
}

int parseCommandSize(clientDataType *theClientData)
{
    int isSafePath;
    unsigned long long int theSize;
    char *theFileName;
    dynamicStringDataType theResponse;
    dynamicStringDataType getSizeFromFileName;
    
    theFileName = getFtpCommandArg("SIZE", theClientData->theCommandReceived);

    cleanDynamicStringDataType(&theResponse, 1);
    cleanDynamicStringDataType(&getSizeFromFileName, 1);
    
    isSafePath = getSafePath(&getSizeFromFileName, theFileName, &theClientData->login);
    
    
    if (isSafePath == 1)
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
    else
    {
        setDynamicStringDataType(&theResponse, "550 Can't check for file existence\r\n", strlen("550 Can't check for file existence\r\n"));
    }
    
    write(theClientData->socketDescriptor, theResponse.text, theResponse.textLen);
    cleanDynamicStringDataType(&theResponse, 0);
    cleanDynamicStringDataType(&getSizeFromFileName, 0);
    
    return 1;
}

int parseCommandRnfr(clientDataType *theClientData)
{
    int isSafePath;
    char *theRnfrFileName;
    dynamicStringDataType theResponse;

    theRnfrFileName = getFtpCommandArg("RNFR", theClientData->theCommandReceived);
    cleanDynamicStringDataType(&theClientData->renameFromFile, 0);
    cleanDynamicStringDataType(&theResponse, 1);
    
    isSafePath = getSafePath(&theClientData->renameFromFile, theRnfrFileName, &theClientData->login);
    
    if (isSafePath == 1&&
        (FILE_IsFile(theClientData->renameFromFile.text) == 1 ||
         FILE_IsDirectory(theClientData->renameFromFile.text) == 1))
    {
        printf("\nThe file to check is: %s", theClientData->renameFromFile.text);
        
        if (FILE_IsFile(theClientData->renameFromFile.text) == 1 ||
            FILE_IsDirectory(theClientData->renameFromFile.text) == 1)
        {
            setDynamicStringDataType(&theResponse, "350 RNFR accepted - file exists, ready for destination\r\n", strlen("350 RNFR accepted - file exists, ready for destination\r\n"));
        }
        else
        {
            setDynamicStringDataType(&theResponse, "550 Sorry, but that file doesn't exist\r\n", strlen("550 Sorry, but that file doesn't exist\r\n"));
        }
    }
    else
    {
        setDynamicStringDataType(&theResponse, "550 Sorry, but that file doesn't exist\r\n", strlen("550 Sorry, but that file doesn't exist\r\n"));
    }

    write(theClientData->socketDescriptor, theResponse.text, theResponse.textLen);
    cleanDynamicStringDataType(&theResponse, 0);
    return 1;
}

int parseCommandRnto(clientDataType *theClientData)
{
    int isSafePath;
    char *theRntoFileName;
    dynamicStringDataType theResponse;

    theRntoFileName = getFtpCommandArg("RNTO", theClientData->theCommandReceived);
    cleanDynamicStringDataType(&theClientData->renameToFile, 0);
    cleanDynamicStringDataType(&theResponse, 1);
    
    isSafePath = getSafePath(&theClientData->renameToFile, theRntoFileName, &theClientData->login);


    if (isSafePath == 1 &&
        theClientData->renameFromFile.textLen > 0)
    {
        printf("\nThe file to check is: %s", theClientData->renameFromFile.text);
        
        if (FILE_IsFile(theClientData->renameFromFile.text) == 1 ||
            FILE_IsDirectory(theClientData->renameFromFile.text) == 1)
        {
            int returnCode = 0;
            returnCode = rename (theClientData->renameFromFile.text, theClientData->renameToFile.text);
            if (returnCode == 0) 
            {
                setDynamicStringDataType(&theResponse, "250 File successfully renamed or moved\r\n", strlen("250 File successfully renamed or moved\r\n"));
            }
            else
            {
                setDynamicStringDataType(&theResponse, "503 Error Renaming the file\r\n", strlen("503 Error Renaming the file\r\n"));
            }
        }
        else
        {
            setDynamicStringDataType(&theResponse, "503 Need RNFR before RNTO\r\n", strlen("503 Need RNFR before RNTO\r\n"));
        }
    }
    else
    {
        setDynamicStringDataType(&theResponse, "503 Error Renaming the file\r\n", strlen("503 Need RNFR before RNTO\r\n"));
    }

    write(theClientData->socketDescriptor, theResponse.text, theResponse.textLen);
    cleanDynamicStringDataType(&theResponse, 0);
    return 1;
}

int parseCommandCdup(clientDataType *theClientData)
{
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
        printf("\nSeek result: %ld", currentPosition);
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

    printf("\n Bytes written: %ld", toReturn);

    fclose(retrFP);
    return toReturn;
}

char *getFtpCommandArg(char * theCommand, char *theCommandString)
{
    char *toReturn = theCommandString + strlen(theCommand);

   /* Pass spaces */ 
    while (toReturn[0] == ' ')
    {
        toReturn += 1;
    }

    /* Skip eventual secondary arguments */
    if (toReturn[0] == '-')
    {
        while (toReturn[0] != ' ' &&
               toReturn[0] != '\r' &&
               toReturn[0] != '\n' &&
               toReturn[0] != 0)
            {
                toReturn += 1;
            }
    }

    /* Pass spaces */ 
    while (toReturn[0] == ' ')
    {
        toReturn += 1;
    }

    return toReturn;
}

int getFtpCommandArgWithOptions(char * theCommand, char *theCommandString, ftpCommandDataType *ftpCommand)
{
    #define CASE_ARG_MAIN   0
    #define CASE_ARG_SECONDARY   1

    int i = 0;
    int isSecondArg = 0;
    char argMain[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
    char argSecondary[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
    memset (argMain, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
    memset (argSecondary, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);

    int argMainIndex = 0;
    int argSecondaryIndex = 0;

    char *theCommandPointer = theCommandString;
    theCommandPointer += strlen(theCommand);
    
    /*Remove spaces*/
    while (theCommandPointer[0] == ' ')
    {
        theCommandPointer += 1;
    }
    
    if (theCommandPointer[i] == '-') 
    {
        isSecondArg = 1;
        theCommandPointer++;
    }
    
    while (theCommandPointer[i] != '\r' &&
           theCommandPointer[i] != '\n' &&
           theCommandPointer[i] != 0)
    {
        switch(isSecondArg)
        {
            case CASE_ARG_MAIN:
            {
                if (argMainIndex < FTP_COMMAND_ELABORATE_CHAR_BUFFER)
                    argMain[argMainIndex++] = theCommandPointer[i];
                i++;
            }
            break;
                
            case CASE_ARG_SECONDARY:
            {
                if (theCommandPointer[i] != ' ')
                {
                    if (argSecondaryIndex < FTP_COMMAND_ELABORATE_CHAR_BUFFER)
                        argSecondary[argSecondaryIndex++] = theCommandPointer[i];
                    i++;
                }
                else 
                {
                    isSecondArg = 0;
                    while (theCommandPointer[0] == ' ')
                    {
                        theCommandPointer += 1;
                    }
                }
            }
            break;
        }
    }
    
    if (argMainIndex > 0)
        setDynamicStringDataType(&ftpCommand->commandArgs, argMain, argMainIndex);

    if (argSecondaryIndex > 0)
        setDynamicStringDataType(&ftpCommand->commandOps, argSecondary, argSecondaryIndex);
        
    return 1;
    
}