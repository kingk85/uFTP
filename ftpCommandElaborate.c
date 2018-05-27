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
#define _LARGEFILE64_SOURCE

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

#include "ftpData.h"
#include "ftpServer.h"
#include "library/logFunctions.h"
#include "library/fileManagement.h"
#include "library/configRead.h"
#include "ftpCommandsElaborate.h"


/* Elaborate the User login command */
int parseCommandUser(clientDataType *theClientData)
{
    int returnCode;
    char *theName;
    theName = getFtpCommandArg("USER", theClientData->theCommandReceived, 0);

    if (strlen(theName) >= 1)
    {
        setDynamicStringDataType(&theClientData->login.name, theName, strlen(theName));
        returnCode = dprintf(theClientData->socketDescriptor, "331 User ok, Waiting for the password.\r\n");
        //printf("\nUSER COMMAND OK, USERNAME IS: %s", theClientData->login.name.text);
        if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;

        return FTP_COMMAND_PROCESSED;
    }
    else
    {
        returnCode = dprintf(theClientData->socketDescriptor, "430 Invalid username.\r\n");
        if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
        return FTP_COMMAND_PROCESSED;
    }
}

/* Elaborate the User login command */
int parseCommandSite(clientDataType *theClientData)
{
    int returnCode;
    char *theCommand;
    theCommand = getFtpCommandArg("SITE", theClientData->theCommandReceived, 0);
    
    if(compareStringCaseInsensitive(theCommand, "CHMOD", strlen("CHMOD")) == 1)
    {
        setPermissions(theCommand, theClientData->login.absolutePath.text, theClientData->login.ownerShip);
        returnCode = dprintf(theClientData->socketDescriptor, "200 Permissions changed\r\n");
        if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }
    else
    {
        returnCode = dprintf(theClientData->socketDescriptor, "500 unknown extension\r\n");
        if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }

    //site chmod 777 test
    //200 Permissions changed on test
    //500 SITE ciao is an unknown extension    
 
    return 1;
}

int parseCommandPass(ftpDataType * data, int socketId)
{
    int returnCode;
    char *thePass;
    loginFailsDataType element;
    int searchPosition = -1;

    thePass = getFtpCommandArg("PASS", data->clients[socketId].theCommandReceived, 0);

    strcpy(element.ipAddress, data->clients[socketId].clientIpAddress);
    element.failTimeStamp = time(NULL);
    element.failureNumbers = 1;

    searchPosition = data->loginFailsVector.SearchElement(&data->loginFailsVector, &element);
    //printf("\nsearchPosition = %d", searchPosition);

    if (searchPosition != -1)
    {
        if (element.failTimeStamp - ((loginFailsDataType *) data->loginFailsVector.Data[searchPosition])->failTimeStamp < WRONG_PASSWORD_ALLOWED_RETRY_TIME)
        {
            if (((loginFailsDataType *) data->loginFailsVector.Data[searchPosition])->failureNumbers >= data->ftpParameters.maximumUserAndPassowrdLoginTries)
            {
                //printf("\n TOO MANY LOGIN FAILS! \n");
                data->clients[socketId].closeTheClient = 1;
                returnCode = dprintf(data->clients[socketId].socketDescriptor, "430 Too many login failure detected, your ip will be blacklisted for 5 minutes\r\n");
                if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
                return 1;
            }
        }
    }

    if (strlen(thePass) >= 1)
    {
        int searchUserNameIndex;
        searchUserNameIndex = searchUser(data->clients[socketId].login.name.text, &data->ftpParameters.usersVector);

        if (searchUserNameIndex < 0 ||
            (strcmp(((usersParameters_DataType *) data->ftpParameters.usersVector.Data[searchUserNameIndex])->password, thePass) != 0))
        {
            
            //Record the login fail!
            if (searchPosition == -1)
            {
                if (data->ftpParameters.maximumUserAndPassowrdLoginTries != 0)
                    data->loginFailsVector.PushBack(&data->loginFailsVector, &element, sizeof(loginFailsDataType));
            }
            else
            {
                ((loginFailsDataType *) data->loginFailsVector.Data[searchPosition])->failureNumbers++;
                ((loginFailsDataType *) data->loginFailsVector.Data[searchPosition])->failTimeStamp = time(NULL);
            }
            
            returnCode = dprintf(data->clients[socketId].socketDescriptor, "430 Invalid username or password\r\n");
            if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
        }
        else
        {
            setDynamicStringDataType(&data->clients[socketId].login.password, thePass, strlen(thePass));
            setDynamicStringDataType(&data->clients[socketId].login.absolutePath, ((usersParameters_DataType *) data->ftpParameters.usersVector.Data[searchUserNameIndex])->homePath, strlen(((usersParameters_DataType *) data->ftpParameters.usersVector.Data[searchUserNameIndex])->homePath));
            setDynamicStringDataType(&data->clients[socketId].login.homePath, ((usersParameters_DataType *) data->ftpParameters.usersVector.Data[searchUserNameIndex])->homePath, strlen(((usersParameters_DataType *) data->ftpParameters.usersVector.Data[searchUserNameIndex])->homePath));
            setDynamicStringDataType(&data->clients[socketId].login.ftpPath, "/", strlen("/"));

            data->clients[socketId].login.ownerShip.ownerShipSet = ((usersParameters_DataType *) data->ftpParameters.usersVector.Data[searchUserNameIndex])->ownerShip.ownerShipSet;
            data->clients[socketId].login.ownerShip.gid = ((usersParameters_DataType *) data->ftpParameters.usersVector.Data[searchUserNameIndex])->ownerShip.gid;
            data->clients[socketId].login.ownerShip.uid = ((usersParameters_DataType *) data->ftpParameters.usersVector.Data[searchUserNameIndex])->ownerShip.uid;
            data->clients[socketId].login.userLoggedIn = 1;

            returnCode = dprintf(data->clients[socketId].socketDescriptor, "230 Login Ok.\r\n");
            if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
        }

       return 1;
    }
    else
    {

        //Record the login fail!
        if (searchPosition == -1)
        {
            if (data->ftpParameters.maximumUserAndPassowrdLoginTries != 0)
                data->loginFailsVector.PushBack(&data->loginFailsVector, &element, sizeof(loginFailsDataType));
        }
        else
        {
            ((loginFailsDataType *) data->loginFailsVector.Data[searchPosition])->failureNumbers++;
            ((loginFailsDataType *) data->loginFailsVector.Data[searchPosition])->failTimeStamp = time(NULL);
        }

        returnCode = dprintf(data->clients[socketId].socketDescriptor, "430 Invalid username or password\r\n");
        if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
        return 1;
    }
}

int parseCommandAuth(clientDataType *theClientData)
{
    int returnCode;
    returnCode = dprintf(theClientData->socketDescriptor, "502 Security extensions not implemented.\r\n");
    if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    return 1;
}

int parseCommandPwd(clientDataType *theClientData)
{
    int returnCode;
    returnCode = dprintf(theClientData->socketDescriptor, "257 \"%s\" is your current location\r\n", theClientData->login.ftpPath.text);
    if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    return 1;
}

int parseCommandSyst(clientDataType *theClientData)
{
    int returnCode;
    returnCode = dprintf(theClientData->socketDescriptor, "215 UNIX Type: L8\r\n");
    if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
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
    int returnCode;
    returnCode = dprintf(theClientData->socketDescriptor, "211-Extensions supported:\r\n PASV\r\nUTF8\r\n211 End.\r\n");
    if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    return 1;
}

int parseCommandTypeA(clientDataType *theClientData)
{
    int returnCode;
    returnCode = dprintf(theClientData->socketDescriptor, "200 TYPE is now 8-bit binary\r\n");
    if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    return 1;
}

int parseCommandTypeI(clientDataType *theClientData)
{
    int returnCode;
    returnCode = dprintf(theClientData->socketDescriptor, "200 TYPE is now 8-bit binary\r\n");
    if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    return 1;
}

int parseCommandStruF(clientDataType *theClientData)
{
    int returnCode;
    returnCode = dprintf(theClientData->socketDescriptor, "200 TYPE is now 8-bit binary\r\n");
    if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    return 1;
}

int parseCommandModeS(clientDataType *theClientData)
{
    int returnCode;
    returnCode = dprintf(theClientData->socketDescriptor, "200 TYPE is now 8-bit binary\r\n");
    if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    return 1;
}

int parseCommandPasv(ftpDataType * data, int socketId)
{
    /* Create worker thread */
    void *pReturn;

    if (data->clients[socketId].workerData.threadIsAlive == 1) 
    {
        pthread_cancel(data->clients[socketId].workerData.workerThread);
    }
    pthread_join(data->clients[socketId].workerData.workerThread, &pReturn);
    //printf("\nThread has been cancelled.");
    data->clients[socketId].workerData.passiveModeOn = 1;
    data->clients[socketId].workerData.activeModeOn = 0;    
    pthread_create(&data->clients[socketId].workerData.workerThread, NULL, connectionWorkerHandle, (void *) &data->clients[socketId].clientProgressiveNumber);
    return 1;
}

int parseCommandPort(ftpDataType * data, int socketId)
{
    
    char *theIpAndPort;
    int ipAddressBytes[4];
    int portBytes[2];
    theIpAndPort = getFtpCommandArg("PORT", data->clients[socketId].theCommandReceived, 0);    
    sscanf(theIpAndPort, "%d,%d,%d,%d,%d,%d", &ipAddressBytes[0], &ipAddressBytes[1], &ipAddressBytes[2], &ipAddressBytes[3], &portBytes[0], &portBytes[1]);
    //printf("\ntheIpAndPort: %s", theIpAndPort);
    data->clients[socketId].workerData.connectionPort = (portBytes[0]*256)+portBytes[1];
    sprintf(data->clients[socketId].workerData.activeIpAddress, "%d.%d.%d.%d", ipAddressBytes[0],ipAddressBytes[1],ipAddressBytes[2],ipAddressBytes[3]);
    //printf("\ndata->clients[socketId].workerData.connectionPort: %d", data->clients[socketId].workerData.connectionPort);
    //printf("\ndata->clients[socketId].workerData.activeIpAddress: %s", data->clients[socketId].workerData.activeIpAddress);


    void *pReturn;
    if (data->clients[socketId].workerData.threadIsAlive == 1)
    {
        pthread_cancel(data->clients[socketId].workerData.workerThread);
    }
    pthread_join(data->clients[socketId].workerData.workerThread, &pReturn);
    //printf("\nThread has been cancelled.");

    data->clients[socketId].workerData.passiveModeOn = 0;
    data->clients[socketId].workerData.activeModeOn = 1;    

    pthread_create(&data->clients[socketId].workerData.workerThread, NULL, connectionWorkerHandle, (void *) &data->clients[socketId].clientProgressiveNumber);

    return 1;
}

int parseCommandAbor(ftpDataType * data, int socketId)
{
    /*
     426 ABORT
    226-Transfer aborted
    226 3.406 seconds (measured here), 1.58 Mbytes per second
    226 Since you see this ABOR must've succeeded
    */
    int returnCode;
    if (data->clients[socketId].workerData.threadIsAlive == 1)
    {
        void *pReturn;
        if (data->clients[socketId].workerData.threadIsAlive == 1)
        {
            pthread_cancel(data->clients[socketId].workerData.workerThread);
        }
        pthread_join(data->clients[socketId].workerData.workerThread, &pReturn);

        returnCode = dprintf(data->clients[socketId].socketDescriptor, "426 ABORT\r\n");
        if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
         
        returnCode = dprintf(data->clients[socketId].socketDescriptor, "226 Transfer aborted\r\n");
        if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }
    else
    {
        returnCode = dprintf(data->clients[socketId].socketDescriptor, "226 Since you see this ABOR must've succeeded\r\n");
        if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
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
    
    theNameToList = getFtpCommandArg("LIST", data->clients[socketId].theCommandReceived, 1);
    getFtpCommandArgWithOptions("LIST", data->clients[socketId].theCommandReceived, &data->clients[socketId].workerData.ftpCommand);
 
   // printf("\nLIST COMMAND ARG: %s", data->clients[socketId].workerData.ftpCommand.commandArgs.text);
   // printf("\nLIST COMMAND OPS: %s", data->clients[socketId].workerData.ftpCommand.commandOps.text);
    
    cleanDynamicStringDataType(&data->clients[socketId].workerData.ftpCommand.commandArgs, 0);
    cleanDynamicStringDataType(&data->clients[socketId].workerData.ftpCommand.commandOps, 0);    
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

    pthread_mutex_lock(&data->clients[socketId].workerData.conditionMutex);
    memset(data->clients[socketId].workerData.theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);
    strcpy(data->clients[socketId].workerData.theCommandReceived, data->clients[socketId].theCommandReceived);
    data->clients[socketId].workerData.commandReceived = 1;
    pthread_mutex_unlock(&data->clients[socketId].workerData.conditionMutex);
    pthread_cond_signal(&data->clients[socketId].workerData.conditionVariable);
   return 1;
}

int parseCommandNlst(ftpDataType * data, int socketId)
{
    int isSafePath = 0;
    char *theNameToNlist;
    theNameToNlist = getFtpCommandArg("NLIST", data->clients[socketId].theCommandReceived, 1);
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
    
    pthread_mutex_lock(&data->clients[socketId].workerData.conditionMutex);
    memset(data->clients[socketId].workerData.theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);
    strcpy(data->clients[socketId].workerData.theCommandReceived, data->clients[socketId].theCommandReceived);
    data->clients[socketId].workerData.commandReceived = 1;
    pthread_mutex_unlock(&data->clients[socketId].workerData.conditionMutex);
    pthread_cond_signal(&data->clients[socketId].workerData.conditionVariable);
    return 1;
}

int parseCommandRetr(ftpDataType * data, int socketId)
{
    int isSafePath = 0;
    char *theNameToRetr;
    
    
    //printf("\n\ndata->clients[socketId].theCommandReceived = %s", data->clients[socketId].theCommandReceived);
    theNameToRetr = getFtpCommandArg("RETR", data->clients[socketId].theCommandReceived, 0);
    cleanDynamicStringDataType(&data->clients[socketId].fileToRetr, 0);
    //printf("\n\ntheNameToRetr = %s", theNameToRetr);
    
    if (strlen(theNameToRetr) > 0)
    {
        isSafePath = getSafePath(&data->clients[socketId].fileToRetr, theNameToRetr, &data->clients[socketId].login);
        //printf("\n\ndata->clients[socketId].fileToRetr = %s", data->clients[socketId].fileToRetr);
    }

    if (isSafePath == 1 &&
        FILE_IsFile(data->clients[socketId].fileToRetr.text) == 1)
    {
        pthread_mutex_lock(&data->clients[socketId].workerData.conditionMutex);
        memset(data->clients[socketId].workerData.theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);
        strcpy(data->clients[socketId].workerData.theCommandReceived, data->clients[socketId].theCommandReceived);
        data->clients[socketId].workerData.commandReceived = 1;
        pthread_mutex_unlock(&data->clients[socketId].workerData.conditionMutex);
        pthread_cond_signal(&data->clients[socketId].workerData.conditionVariable);
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
    theNameToStor = getFtpCommandArg("STOR", data->clients[socketId].theCommandReceived, 0);
    cleanDynamicStringDataType(&data->clients[socketId].fileToStor, 0);
    
    if (strlen(theNameToStor) > 0)
    {
        isSafePath = getSafePath(&data->clients[socketId].fileToStor, theNameToStor, &data->clients[socketId].login);
    }

    if (isSafePath == 1)
    {
        pthread_mutex_lock(&data->clients[socketId].workerData.conditionMutex);
        //printf("data->clients[%d].fileToStor = %s", socketId, data->clients[socketId].fileToStor.text);
        memset(data->clients[socketId].workerData.theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);
        strcpy(data->clients[socketId].workerData.theCommandReceived, data->clients[socketId].theCommandReceived);
        data->clients[socketId].workerData.commandReceived = 1;
        pthread_mutex_unlock(&data->clients[socketId].workerData.conditionMutex);
        pthread_cond_signal(&data->clients[socketId].workerData.conditionVariable);
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
    int returnCode;
    char *thePath;

    cleanDynamicStringDataType(&absolutePathPrevious, 1);
    cleanDynamicStringDataType(&ftpPathPrevious, 1);
    cleanDynamicStringDataType(&theSafePath, 1);

    thePath = getFtpCommandArg("CWD", theClientData->theCommandReceived, 0);

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
            returnCode = dprintf(theClientData->socketDescriptor, "250 OK. Current directory is  %s\r\n", theClientData->login.ftpPath.text);
        }
        else
        {
            setDynamicStringDataType(&theClientData->login.absolutePath, absolutePathPrevious.text, absolutePathPrevious.textLen);
            setDynamicStringDataType(&theClientData->login.ftpPath, ftpPathPrevious.text, ftpPathPrevious.textLen);
            returnCode = dprintf(theClientData->socketDescriptor, "550 Can't change directory to %s: No such file or directory\r\n", theClientData->login.absolutePath.text);
        }

        if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;

        cleanDynamicStringDataType(&absolutePathPrevious, 0);
        cleanDynamicStringDataType(&ftpPathPrevious, 0);
        cleanDynamicStringDataType(&theSafePath, 0);
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
    int returnCode;
    int i, theSizeIndex;
    char theSize[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
    memset(theSize, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
    theSizeIndex = 0;
 
    
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

    theClientData->workerData.retrRestartAtByte = atoll(theSize);
    returnCode = dprintf(theClientData->socketDescriptor, "350 Restarting at %s\r\n", theSize);    
    if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    return 1;
}

int parseCommandMkd(clientDataType *theClientData)
{
    int returnCode;
    int isSafePath;
    char *theDirectoryFilename;
    dynamicStringDataType mkdFileName;

    theDirectoryFilename = getFtpCommandArg("MKD", theClientData->theCommandReceived, 0);
    
    cleanDynamicStringDataType(&mkdFileName, 1);
    
    isSafePath = getSafePath(&mkdFileName, theDirectoryFilename, &theClientData->login);
    
    if (isSafePath == 1)
    {
        int returnStatus;
        //printf("\nThe directory to make is: %s", mkdFileName.text);
        returnStatus = mkdir(mkdFileName.text, S_IRWXU | S_IRWXG | S_IRWXO);
        if (theClientData->login.ownerShip.ownerShipSet == 1)
        {
            FILE_doChownFromUidGid(mkdFileName.text, theClientData->login.ownerShip.uid, theClientData->login.ownerShip.gid);
        }

        returnCode = dprintf(theClientData->socketDescriptor, "257 \"%s\" : The directory was successfully created\r\n", theDirectoryFilename);
        if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }
    else
    {
        cleanDynamicStringDataType(&mkdFileName, 0);
        return 0;
    }

    cleanDynamicStringDataType(&mkdFileName, 0);    
    return 1;
}

int parseCommandOpts(clientDataType *theClientData)
{
    int returnCode;
    returnCode = dprintf(theClientData->socketDescriptor, "200 OK\r\n");
    if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    return 1;
}

int parseCommandDele(clientDataType *theClientData)
{
    int returnCode;
    int isSafePath;
    int returnStatus = 0;
    char *theFileToDelete;
    dynamicStringDataType theResponse;
    dynamicStringDataType deleFileName;

    theFileToDelete = getFtpCommandArg("DELE", theClientData->theCommandReceived, 0);

    cleanDynamicStringDataType(&deleFileName, 1);
    
    isSafePath = getSafePath(&deleFileName, theFileToDelete, &theClientData->login);
    
    if (isSafePath == 1)
    {
        //printf("\nThe file to delete is: %s", deleFileName.text);
        returnStatus = remove(deleFileName.text);
        returnCode = dprintf(theClientData->socketDescriptor, "250 Deleted %s\r\n", theFileToDelete);
        if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }
    else
    {
        cleanDynamicStringDataType(&deleFileName, 0);
        return 0;
    }
    


    cleanDynamicStringDataType(&deleFileName, 0);
    return 1;
}

int parseCommandNoop(clientDataType *theClientData)
{
    int returnCode;
    returnCode = dprintf(theClientData->socketDescriptor, "200 Zzz...\r\n");
    if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    return 1;
}

int notLoggedInMessage(clientDataType *theClientData)
{
    int returnCode;
    returnCode = dprintf(theClientData->socketDescriptor, "530 You aren't logged in\r\n");
    if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    return 1;
}

int parseCommandQuit(ftpDataType * data, int socketId)
{
    int returnCode;
    returnCode = dprintf(data->clients[socketId].socketDescriptor, "221 Logout.\r\n");
    if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    data->clients[socketId].closeTheClient = 1;
    return 1;
}

int parseCommandRmd(clientDataType *theClientData)
{
    int returnCode;
    int isSafePath;
    int returnStatus = 0;
    char *theDirectoryFilename;
    dynamicStringDataType rmdFileName;

    theDirectoryFilename = getFtpCommandArg("RMD", theClientData->theCommandReceived, 0);

    cleanDynamicStringDataType(&rmdFileName, 1);
    
    isSafePath = getSafePath(&rmdFileName, theDirectoryFilename, &theClientData->login);
    
    if (isSafePath == 1)
    {
        //printf("\nThe directory to delete is: %s", rmdFileName.text);
        returnStatus = rmdir(rmdFileName.text);
        returnCode = dprintf(theClientData->socketDescriptor, "250 The directory was successfully removed\r\n");
        if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }
    else
    {
        cleanDynamicStringDataType(&rmdFileName, 0);
        return 0;
    }

    cleanDynamicStringDataType(&rmdFileName, 0);

    return 1;
}

int parseCommandSize(clientDataType *theClientData)
{
    int returnCode;
    int isSafePath;
    long long int theSize;
    char *theFileName;
    dynamicStringDataType getSizeFromFileName;

    theFileName = getFtpCommandArg("SIZE", theClientData->theCommandReceived, 0);

    cleanDynamicStringDataType(&getSizeFromFileName, 1);
    
    isSafePath = getSafePath(&getSizeFromFileName, theFileName, &theClientData->login);

    if (isSafePath == 1)
    {

        if (FILE_IsFile(getSizeFromFileName.text)==1)
        {
            theSize = FILE_GetFileSizeFromPath(getSizeFromFileName.text);
            returnCode = dprintf(theClientData->socketDescriptor, "213 %lld\r\n", theSize);
        }
        else
        {
            returnCode = dprintf(theClientData->socketDescriptor, "550 Can't check for file existence\r\n");
        }
    }
    else
    {
        returnCode = dprintf(theClientData->socketDescriptor, "550 Can't check for file existence\r\n");
    }
    cleanDynamicStringDataType(&getSizeFromFileName, 0);
    if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    
    return 1;
}

int parseCommandRnfr(clientDataType *theClientData)
{
    int returnCode;
    int isSafePath;
    char *theRnfrFileName;

    theRnfrFileName = getFtpCommandArg("RNFR", theClientData->theCommandReceived, 0);
    cleanDynamicStringDataType(&theClientData->renameFromFile, 0);
    
    isSafePath = getSafePath(&theClientData->renameFromFile, theRnfrFileName, &theClientData->login);
    
    if (isSafePath == 1&&
        (FILE_IsFile(theClientData->renameFromFile.text) == 1 ||
         FILE_IsDirectory(theClientData->renameFromFile.text) == 1))
    {
        if (FILE_IsFile(theClientData->renameFromFile.text) == 1 ||
            FILE_IsDirectory(theClientData->renameFromFile.text) == 1)
        {
            returnCode = dprintf(theClientData->socketDescriptor, "350 RNFR accepted - file exists, ready for destination\r\n");
        }
        else
        {
            returnCode = dprintf(theClientData->socketDescriptor, "550 Sorry, but that file doesn't exist\r\n");
        }
    }
    else
    {
        returnCode = dprintf(theClientData->socketDescriptor, "550 Sorry, but that file doesn't exist\r\n");
    }
    

    if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    return 1;
}

int parseCommandRnto(clientDataType *theClientData)
{
    int returnCode;
    int isSafePath;
    char *theRntoFileName;

    theRntoFileName = getFtpCommandArg("RNTO", theClientData->theCommandReceived, 0);
    cleanDynamicStringDataType(&theClientData->renameToFile, 0);
    
    isSafePath = getSafePath(&theClientData->renameToFile, theRntoFileName, &theClientData->login);

    if (isSafePath == 1 &&
        theClientData->renameFromFile.textLen > 0)
    {

        if (FILE_IsFile(theClientData->renameFromFile.text) == 1 ||
            FILE_IsDirectory(theClientData->renameFromFile.text) == 1)
        {
            int returnCode = 0;
            returnCode = rename (theClientData->renameFromFile.text, theClientData->renameToFile.text);
            if (returnCode == 0) 
            {
                returnCode = dprintf(theClientData->socketDescriptor, "250 File successfully renamed or moved\r\n");
            }
            else
            {
                returnCode = dprintf(theClientData->socketDescriptor, "503 Error Renaming the file\r\n");
            }
        }
        else
        {
            returnCode = dprintf(theClientData->socketDescriptor, "503 Need RNFR before RNTO\r\n");
        }
    }
    else
    {
        returnCode = dprintf(theClientData->socketDescriptor, "503 Error Renaming the file\r\n");
    }

    if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    return 1;
}

int parseCommandCdup(clientDataType *theClientData)
{
        int returnCode;
        
        FILE_DirectoryToParent(&theClientData->login.absolutePath.text);
        FILE_DirectoryToParent(&theClientData->login.ftpPath.text);
        theClientData->login.absolutePath.textLen = strlen(theClientData->login.absolutePath.text);
        theClientData->login.ftpPath.textLen = strlen(theClientData->login.ftpPath.text);

        if(strncmp(theClientData->login.absolutePath.text, theClientData->login.homePath.text, theClientData->login.homePath.textLen) != 0)
        {
            setDynamicStringDataType(&theClientData->login.absolutePath, theClientData->login.homePath.text, theClientData->login.homePath.textLen);
        }

        returnCode = dprintf(theClientData->socketDescriptor, "250 OK. Current directory is %s\r\n", theClientData->login.ftpPath.text);

        if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
        return 1;
}

long long int writeRetrFile(char * theFilename, int thePasvSocketConnection, long long int startFrom, FILE *retrFP)
{
    long long int readen = 0;
    long long int toReturn = 0, writtenSize = 0;
    long long int currentPosition = 0;
    long long int theFileSize;
    char buffer[FTP_COMMAND_ELABORATE_CHAR_BUFFER];

    retrFP = fopen64(theFilename, "rb");
    if (retrFP == NULL)
    {
        return -1;
    }

    theFileSize = FILE_GetFileSize(retrFP);

    if (startFrom > 0)
    {
        //printf("\nSeek startFrom: %d", startFrom);
        currentPosition = (long long int) lseek64(fileno(retrFP), startFrom, SEEK_SET);
       // printf("\nSeek result: %ld", currentPosition);
        if (currentPosition == -1)
        {
            fclose(retrFP);
            retrFP = NULL;
            return toReturn;
        }
    }

    while ((readen = (long long int) fread(buffer, sizeof(char), FTP_COMMAND_ELABORATE_CHAR_BUFFER, retrFP)) > 0)
    {
      writtenSize = write(thePasvSocketConnection, buffer, readen);
 
      if (writtenSize <= 0)
      {
          fclose(retrFP);
          retrFP = NULL;
          return -1;
      }
      else
      {
            toReturn = toReturn + writtenSize;
      }
    }

    //printf("\n Bytes written: %ld", toReturn);

    fclose(retrFP);
    retrFP = NULL;
    return toReturn;
}

char *getFtpCommandArg(char * theCommand, char *theCommandString, int skipArgs)
{
    char *toReturn = theCommandString + strlen(theCommand);

   /* Pass spaces */ 
    while (toReturn[0] == ' ')
    {
        toReturn += 1;
    }

    /* Skip eventual secondary arguments */
    if(skipArgs == 1)
    {
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

int setPermissions(char * permissionsCommand, char * basePath, ownerShip_DataType ownerShip)
{
    #define STATUS_INCREASE 0
    #define STATUS_PERMISSIONS 1
    #define STATUS_LOCAL_PATH 2
    
    int permissionsCommandCursor = 0;
    int returnCode = 0;

    int status = STATUS_INCREASE;
    char thePermissionString[1024];
    char theLocalPath[1024];
    char theFinalCommand[2048];
    memset(theLocalPath, 0, 1024);
    memset(thePermissionString, 0, 1024);
    memset(theFinalCommand, 0, 2048);
    int thePermissionStringCursor = 0, theLocalPathCursor = 0;
    
    while (permissionsCommand[permissionsCommandCursor] != '\r' &&
           permissionsCommand[permissionsCommandCursor] != '\n' &&
           permissionsCommand[permissionsCommandCursor] != '\0')
    {
        switch (status)
        {
            case STATUS_INCREASE:
                if (permissionsCommandCursor == strlen("chmod"))
                {
                    status = STATUS_PERMISSIONS;
                }
            break;
            
            case STATUS_PERMISSIONS:
                if (permissionsCommand[permissionsCommandCursor] == ' ')
                {
                    status = STATUS_LOCAL_PATH;
                    break;
                }
                if (thePermissionStringCursor < 1024 )
                    thePermissionString[thePermissionStringCursor++] = permissionsCommand[permissionsCommandCursor];
            break;
            
            case STATUS_LOCAL_PATH:
                    if (theLocalPathCursor < 1024)
                        theLocalPath[theLocalPathCursor++] = permissionsCommand[permissionsCommandCursor];
            break;
        }

        permissionsCommandCursor++;
    }
    
    //printf("\n thePermissionString = %s ", thePermissionString);
    //printf("\n theLocalPathCursor = %s ", theLocalPath);

    //if (basePath[strlen(basePath)-1] != '/')
        //sprintf(theFinalCommand, "chmod %s %s/%s", thePermissionString, basePath, theLocalPath);
    //else
        //sprintf(theFinalCommand, "chmod %s %s%s", thePermissionString, basePath, theLocalPath);

    //printf("\ntheFinalCommand = %s ", theFinalCommand);

    //system(theFinalCommand);
    if (ownerShip.ownerShipSet == 1)
    {
        memset(theFinalCommand, 0, 2048);
        if (basePath[strlen(basePath)-1] != '/')
            sprintf(theFinalCommand, "%s/%s", basePath, theLocalPath);
        else
            sprintf(theFinalCommand, "%s%s", basePath, theLocalPath);

        FILE_doChownFromUidGid(theFinalCommand, ownerShip.uid, ownerShip.gid);
    }

    memset(theFinalCommand, 0, 2048);

    if (basePath[strlen(basePath)-1] != '/')
        sprintf(theFinalCommand, "%s/%s", basePath, theLocalPath);
    else
        sprintf(theFinalCommand, "%s%s", basePath, theLocalPath);

    returnCode = strtol(thePermissionString, 0, 8);
    if (chmod (theFinalCommand, returnCode) < 0)
    {
        printf("\n---> ERROR WHILE SETTING FILE PERMISSION");
    }

    return 1;
}