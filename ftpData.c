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


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <netinet/in.h>
#include <unistd.h>

#include "ftpServer.h"
#include "ftpCommandsElaborate.h"
#include "ftpData.h"
#include "library/configRead.h"
#include "library/fileManagement.h"

void cleanDynamicStringDataType(dynamicStringDataType *dynamicString, int init)
{
    if (init == 1)
    {
        dynamicString->text = 0;
        dynamicString->textLen = 0;
    }
    else
    {
        if (dynamicString->textLen != 0)
        {
            if (dynamicString->text != 0) {
                free(dynamicString->text);
            }
        }

        dynamicString->textLen = 0;
    }
}

void cleanLoginData(loginDataType *loginData, int init)
{
    loginData->userLoggedIn = 0;
    cleanDynamicStringDataType(&loginData->homePath, init);
    cleanDynamicStringDataType(&loginData->ftpPath, init);
    cleanDynamicStringDataType(&loginData->name, init);
    cleanDynamicStringDataType(&loginData->password, init);
    cleanDynamicStringDataType(&loginData->absolutePath, init);
}

void setDynamicStringDataType(dynamicStringDataType *dynamicString, char *theString, int stringLen)
{
    if (dynamicString->textLen == 0)
    {
        dynamicString->text = (char *) malloc ((sizeof(char) * stringLen) + 1);
        memset(dynamicString->text, 0, stringLen + 1);
        memcpy(dynamicString->text, theString, stringLen);
        dynamicString->textLen = stringLen;
    }
    else
    {
        if(stringLen != dynamicString->textLen) {
            dynamicString->text = (char *) realloc (dynamicString->text, (sizeof(char) * stringLen) + 1);
        }

        memset(dynamicString->text, 0, stringLen + 1);
        memcpy(dynamicString->text, theString, stringLen);
        dynamicString->textLen = stringLen; 
    }
}

int getSafePath(dynamicStringDataType *safePath, char *theDirectoryName, loginDataType *loginData)
{
    int theLen, i;
    char * theDirectoryNamePointer;
    theDirectoryNamePointer = theDirectoryName;
    
    if (theDirectoryName == NULL)
        return 0;
    
    theLen = strlen(theDirectoryName);
    
    if (theLen <= 0)
        return 0;
    
    if (theLen == 2 &&
        theDirectoryName[0] == '.' &&
        theDirectoryName[1] == '.')
        {
        return 0;
        }
    
    if (theLen == 3 &&
        ((theDirectoryName[0] == '.' &&
          theDirectoryName[1] == '.' &&
          theDirectoryName[2] == '/') ||
         (theDirectoryName[0] == '/' &&
          theDirectoryName[1] == '.' &&
          theDirectoryName[2] == '.')
         )
        )
        {
        return 0;
        }

    //Check for /../
    char theDirectoryToCheck[2048];
    int theDirectoryToCheckIndex = 0;
    memset(theDirectoryToCheck, 0, 2048);
    
    for (i = 0; i< theLen; i++)
    {
        if (theDirectoryName[i] == '/')
        {
        if (theDirectoryToCheckIndex == 2 &&
            theDirectoryToCheck[0] == '.' &&
            theDirectoryToCheck[1] == '.')
            {
            return 0;
            }

        theDirectoryToCheckIndex = 0;
        memset(theDirectoryToCheck, 0, 2048);
        continue;
        }
        
        if (theDirectoryToCheckIndex<2048)
            {
            theDirectoryToCheck[theDirectoryToCheckIndex++] = theDirectoryName[i];
            }
        else
            return 0; /* Directory size too long */
    }
    
    if (theDirectoryName[0] == '/')
    {
        while (theDirectoryNamePointer[0] == '/')
            theDirectoryNamePointer++;

        setDynamicStringDataType(safePath, loginData->homePath.text, loginData->homePath.textLen);
        appendToDynamicStringDataType(safePath, theDirectoryNamePointer, strlen(theDirectoryNamePointer));
    }
    else
    {
        setDynamicStringDataType(safePath, loginData->absolutePath.text, loginData->absolutePath.textLen);

        if (loginData->absolutePath.text[loginData->absolutePath.textLen-1] != '/')
        {
            appendToDynamicStringDataType(safePath, "/", 1);
        }
        
        appendToDynamicStringDataType(safePath, theDirectoryName, strlen(theDirectoryName));
    }
    
    return 1;
}

void appendToDynamicStringDataType(dynamicStringDataType *dynamicString, char *theString, int stringLen)
{
    int theNewSize = dynamicString->textLen + stringLen;
    dynamicString->text = realloc(dynamicString->text, theNewSize + 1);
    memset(dynamicString->text+dynamicString->textLen, 0, stringLen+1);
    memcpy(dynamicString->text+dynamicString->textLen, theString, stringLen);
    dynamicString->text[theNewSize] = '\0';
    dynamicString->textLen = theNewSize;
}

void setRandomicPort(ftpDataType *data, int socketPosition)
{
    static unsigned short int randomizeInteger = 0;
    unsigned short int randomicPort = 5000;
    int i;

    randomizeInteger += 1;
    
    if (randomizeInteger >  100 )
        randomizeInteger = 1;

    while(randomicPort < 10000)
        randomicPort = ((rand() + socketPosition + randomizeInteger) % (50000)) + 10000;
   i = 0;

   while (i < data->ftpParameters.maxClients)
   {
       if (randomicPort == data->clients[i].workerData.connectionPort ||
           randomicPort < 10000)
       {
        randomicPort = ((rand() + socketPosition + i + randomizeInteger) % (50000)) + 10000;
        i = 0;
       }
       else 
       {
        i++;
       }
   }
   
   
   data->clients[socketPosition].workerData.connectionPort = randomicPort;
   printf("data->clients[%d].workerData.connectionPort = %d", socketPosition, data->clients[socketPosition].workerData.connectionPort);
}

int writeListDataInfoToSocket(char * thePath, int theSocket, int *filesNumber, int commandType)
{
    int i, x, returnCode;
    int fileAndFoldersCount = 0;
    char **fileList = NULL;
    FILE_GetDirectoryInodeList(thePath, &fileList, &fileAndFoldersCount, 0);
    *filesNumber = fileAndFoldersCount;

    returnCode = dprintf(theSocket, "total %d\r\n", fileAndFoldersCount);
    if (returnCode <= 0)
    {
        return -1;
    }
    
    for (i = 0; i < fileAndFoldersCount; i++)
    {
        ftpListDataType data;
        data.owner = NULL;
        data.groupOwner = NULL;
        data.inodePermissionString = NULL;
        data.fileNameWithPath = NULL;
        data.finalStringPath = NULL;
        data.linkPath = NULL;       
        data.isFile = 0;
        data.isDirectory = 0;

        //printf("\nPROCESSING: %s", fileList[i]);
        
        if (FILE_IsDirectory(fileList[i]) == 1)
        {
            //printf("\nis directory");
            //fflush(0);
            data.isDirectory = 1;
            data.isFile = 0;
            data.isLink = 0;
            data.fileSize = 4096;
            data.numberOfSubDirectories = FILE_GetDirectoryInodeCount(fileList[i]);
        }
        else if (FILE_IsFile(fileList[i]) == 1)
        {
            //printf("\nis file");
            //fflush(0);
            data.isDirectory = 0;
            data.isFile = 1;
            data.isLink = 0;
            data.numberOfSubDirectories = 1; /* to Do*/
            data.fileSize = FILE_GetFileSizeFromPath(fileList[i]);
        }
        if (data.isDirectory == 0 && data.isFile == 0)
        {
            //printf("\nNot a directory, not a file, broken link");
            continue;
        }
        
      
        //printf("\nFILE SIZE : %lld", data.fileSize);

        data.owner = FILE_GetOwner(fileList[i]);
        data.groupOwner = FILE_GetGroupOwner(fileList[i]);
        data.fileNameWithPath = fileList[i];
        data.fileNameNoPath = FILE_GetFilenameFromPath(fileList[i]);
        data.inodePermissionString = FILE_GetListPermissionsString(fileList[i]);
        data.lastModifiedData = FILE_GetLastModifiedData(fileList[i]);

        if (strlen(data.fileNameNoPath) > 0)
        {
            data.finalStringPath = (char *) malloc (strlen(data.fileNameNoPath)+1);
            strcpy(data.finalStringPath, data.fileNameNoPath);
        }
        
        if (data.inodePermissionString != NULL &&
            strlen(data.inodePermissionString) > 0 &&
            data.inodePermissionString[0] == 'l')
            {
                int len = 0;
                data.isLink = 1;
                data.linkPath = (char *) malloc (CLIENT_COMMAND_STRING_SIZE*sizeof(char));
                if ((len = readlink (fileList[i], data.linkPath, CLIENT_COMMAND_STRING_SIZE)) > 0)
                {
                    data.linkPath[len] = 0;
                    FILE_AppendToString(&data.finalStringPath, " -> ");
                    FILE_AppendToString(&data.finalStringPath, data.linkPath);
                }
            }

        memset(data.lastModifiedDataString, 0, LIST_DATA_TYPE_MODIFIED_DATA_STR_SIZE);       
        strftime(data.lastModifiedDataString, LIST_DATA_TYPE_MODIFIED_DATA_STR_SIZE, "%b %d %Y", localtime(&data.lastModifiedData));
        
        
        switch (commandType)
        {
            case COMMAND_TYPE_LIST:
            {
                returnCode = dprintf(theSocket, "%s %d %s %s %lld %s %s\r\n", 
                data.inodePermissionString == NULL? "Uknown" : data.inodePermissionString
                ,data.numberOfSubDirectories
                ,data.owner == NULL? "Uknown" : data.owner
                ,data.groupOwner == NULL? "Uknown" : data.groupOwner
                ,data.fileSize
                ,data.lastModifiedDataString == NULL? "Uknown" : data.lastModifiedDataString
                ,data.finalStringPath == NULL? "Uknown" : data.finalStringPath);
                
            }
            break;
            
            case COMMAND_TYPE_NLST:
            {
            	returnCode = dprintf(theSocket, "%s\r\n",data.fileNameNoPath);
            }
            break;

            
            default:
            {
                printf("\nWarning switch default in function writeListDataInfoToSocket (%d)", commandType);
            }
            break;
        }
        
       
        if (data.fileNameWithPath != NULL)
            free(data.fileNameWithPath);
        
        if (data.linkPath != NULL)
            free(data.linkPath);

        if (data.finalStringPath != NULL)
            free(data.finalStringPath);

        if (data.owner != NULL)
            free(data.owner);
        
        if (data.groupOwner != NULL)
            free(data.groupOwner);
        
        if (data.inodePermissionString != NULL)
            free(data.inodePermissionString);
          
        if (returnCode <= 0)
        {
            for (x = i+1; x < fileAndFoldersCount; x++)
                free (fileList[x]);
            free (fileList);
            return -1;
        }
        
        }

		if (fileList != NULL)
		{
			free (fileList);
		}

        return 1;
    }

int searchInLoginFailsVector(void * loginFailsVector, void *element)
{
    int i = 0;
    //printf("((DYNV_VectorGenericDataType *)loginFailsVector)->Size = %d", ((DYNV_VectorGenericDataType *)loginFailsVector)->Size);

    for (i = 0; i < ((DYNV_VectorGenericDataType *)loginFailsVector)->Size; i++)
    {
        if (strcmp( ((loginFailsDataType *) element)->ipAddress, (((loginFailsDataType *) ((DYNV_VectorGenericDataType *)loginFailsVector)->Data[i])->ipAddress)) == 0)
        {
            //printf("\n\n***IP address found: %s in %d", ((loginFailsDataType *) element)->ipAddress, i);
            return i;
        }
    }

    return -1;
}

void deleteLoginFailsData(void *element)
{
    ; //NOP
}

void getListDataInfo(char * thePath, DYNV_VectorGenericDataType *directoryInfo)
{
    int i;
    int fileAndFoldersCount = 0;
    ftpListDataType data;
    FILE_GetDirectoryInodeList(thePath, &data.fileList, &fileAndFoldersCount, 0);
    
    //printf("\nNUMBER OF FILES: %d", fileAndFoldersCount);
    //fflush(0);
    
    for (i = 0; i < fileAndFoldersCount; i++)
    {
        data.owner = NULL;
        data.groupOwner = NULL;
        data.inodePermissionString = NULL;
        data.fileNameWithPath = NULL;
        data.finalStringPath = NULL;
        data.linkPath = NULL;       

        data.numberOfSubDirectories = 1; /* to Do*/
        data.isFile = 0;
        data.isDirectory = 0;
        
        
        //printf("\nPROCESSING: %s", data.fileList[i]);
        //fflush(0);
        
        if (FILE_IsDirectory(data.fileList[i]) == 1)
        {
            //printf("\nis file");
            //fflush(0);
            data.isDirectory = 1;
            data.isFile = 0;
            data.isLink = 0;
            data.fileSize = 4096;
        }
        else if (FILE_IsFile(data.fileList[i]) == 1)
        {
            //printf("\nis file");
            //fflush(0);
            data.isDirectory = 0;
            data.isFile = 1;
            data.isLink = 0;
            data.fileSize = FILE_GetFileSizeFromPath(data.fileList[i]);
        }
        if (data.isDirectory == 0 && data.isFile == 0)
        {
            printf("\nNot a directory, not a file, broken link");
            continue;
        }
        
        printf("\nFILE SIZE : %lld", data.fileSize);

        data.owner = FILE_GetOwner(data.fileList[i]);
        data.groupOwner = FILE_GetGroupOwner(data.fileList[i]);
        data.fileNameWithPath = data.fileList[i];
        data.fileNameNoPath = FILE_GetFilenameFromPath(data.fileList[i]);
        data.inodePermissionString = FILE_GetListPermissionsString(data.fileList[i]);
        data.lastModifiedData = FILE_GetLastModifiedData(data.fileList[i]);

        if (strlen(data.fileNameNoPath) > 0)
        {
            data.finalStringPath = (char *) malloc (strlen(data.fileNameNoPath)+1);
            strcpy(data.finalStringPath, data.fileNameNoPath);
        }
        
        if (data.inodePermissionString != NULL &&
            strlen(data.inodePermissionString) > 0 &&
            data.inodePermissionString[0] == 'l')
            {
                int len = 0;
                data.isLink = 1;
                data.linkPath = (char *) malloc (CLIENT_COMMAND_STRING_SIZE*sizeof(char));
                if ((len = readlink (data.fileList[i], data.linkPath, CLIENT_COMMAND_STRING_SIZE)) > 0)
                {
                    data.linkPath[len] = 0;
                    FILE_AppendToString(&data.finalStringPath, " -> ");
                    FILE_AppendToString(&data.finalStringPath, data.linkPath);
                }
            }

        memset(data.lastModifiedDataString, 0, LIST_DATA_TYPE_MODIFIED_DATA_STR_SIZE);       
        strftime(data.lastModifiedDataString, 80, "%b %d %Y", localtime(&data.lastModifiedData));

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

        directoryInfo->PushBack(directoryInfo, &data, sizeof(ftpListDataType));
    }
}

void deleteListDataInfoVector(void *TheElementToDelete)
{
    ftpListDataType *data = (ftpListDataType *)TheElementToDelete;

    if (data->owner != NULL)
    {
        free(data->owner);
    }
    
    if (data->groupOwner != NULL)
    {
        free(data->groupOwner);
    }

    if (data->inodePermissionString != NULL)
    {
        free(data->inodePermissionString);
    }

    if (data->fileNameWithPath != NULL)
    {
        free(data->fileNameWithPath);
    }

    if (data->finalStringPath != NULL)
    {
        free(data->finalStringPath);
    }

    if (data->linkPath != NULL)
    {
        free(data->linkPath);
    }
}

void resetWorkerData(workerDataType *workerData, int isInitialization)
{
      workerData->connectionPort = 0;
      workerData->passiveModeOn = 0;
      workerData->socketIsConnected = 0;
      workerData->commandIndex = 0;
      workerData->passiveListeningSocket = 0;
      workerData->socketConnection = 0;
      workerData->bufferIndex = 0;
      workerData->commandReceived = 0;
      workerData->retrRestartAtByte = 0;
      workerData->threadIsAlive = 0;
      workerData->activeModeOn = 0;
      workerData->passiveModeOn = 0;      
      workerData->activeIpAddressIndex = 0;

      memset(workerData->buffer, 0, CLIENT_BUFFER_STRING_SIZE);
      memset(workerData->activeIpAddress, 0, CLIENT_BUFFER_STRING_SIZE);
      memset(workerData->theCommandReceived, 0, CLIENT_BUFFER_STRING_SIZE);

      cleanDynamicStringDataType(&workerData->ftpCommand.commandArgs, isInitialization);
      cleanDynamicStringDataType(&workerData->ftpCommand.commandOps, isInitialization);

      /* wait main for action */
      if (isInitialization != 1)
      {
        pthread_mutex_destroy(&workerData->conditionMutex);
        pthread_cond_destroy(&workerData->conditionVariable);
        
        if (workerData->theStorFile != NULL) 
        {
            fclose(workerData->theStorFile);
            workerData->theStorFile = NULL;
        }
    
      }
      else
      {
        DYNV_VectorGeneric_Init(&workerData->directoryInfo);
        workerData->theStorFile = NULL;
        workerData->workerThread = 0;
      }

      if (pthread_mutex_init(&workerData->conditionMutex, NULL) != 0)
      {
          printf("\nworkerData->conditionMutex init failed\n");
          exit(0);
      }


      if (pthread_cond_init(&workerData->conditionVariable, NULL) != 0)
      {
          printf("\nworkerData->conditionVariable init failed\n");
          exit(0);
      }

    //Clear the dynamic vector structure
    int theSize = workerData->directoryInfo.Size;
    char ** lastToDestroy = NULL;
    if (theSize > 0)
    {
        lastToDestroy = ((ftpListDataType *)workerData->directoryInfo.Data[0])->fileList;
        workerData->directoryInfo.Destroy(&workerData->directoryInfo, deleteListDataInfoVector);
        free(lastToDestroy);
    }
}

void resetClientData(clientDataType *clientData, int isInitialization)
{
    if (isInitialization != 1)
    {
        if (clientData->workerData.threadIsAlive == 1)
        {
            void *pReturn;
            pthread_cancel(clientData->workerData.workerThread);
            pthread_join(clientData->workerData.workerThread, &pReturn);
        }
        else
        {
            void *pReturn = NULL;
            pthread_join(clientData->workerData.workerThread, &pReturn);
        }

        pthread_mutex_destroy(&clientData->writeMutex);
    }
    
    if (pthread_mutex_init(&clientData->writeMutex, NULL) != 0)
    {
        printf("\nclientData->writeMutex init failed\n");
        exit(0);
    }

    clientData->socketDescriptor = -1;
    clientData->socketCommandReceived = 0;
    clientData->socketIsConnected = 0;
    clientData->bufferIndex = 0;
    clientData->commandIndex = 0;
    clientData->closeTheClient = 0;
    clientData->sockaddr_in_size = sizeof(struct sockaddr_in);
    clientData->sockaddr_in_server_size = sizeof(struct sockaddr_in);
    
    clientData->serverIpAddressInteger[0] = 0;
    clientData->serverIpAddressInteger[1] = 0;
    clientData->serverIpAddressInteger[2] = 0;
    clientData->serverIpAddressInteger[3] = 0;
    
    
    memset(&clientData->client_sockaddr_in, 0, clientData->sockaddr_in_size);
    memset(&clientData->server_sockaddr_in, 0, clientData->sockaddr_in_server_size);
    memset(clientData->clientIpAddress, 0, INET_ADDRSTRLEN);
    memset(clientData->buffer, 0, CLIENT_BUFFER_STRING_SIZE);
    memset(clientData->theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);
    cleanLoginData(&clientData->login, isInitialization);
    
    //Rename from and to data init
    cleanDynamicStringDataType(&clientData->renameFromFile, isInitialization);
    cleanDynamicStringDataType(&clientData->renameToFile, isInitialization);
    cleanDynamicStringDataType(&clientData->fileToStor, isInitialization);
    cleanDynamicStringDataType(&clientData->fileToRetr, isInitialization);
    cleanDynamicStringDataType(&clientData->listPath, isInitialization);
    cleanDynamicStringDataType(&clientData->nlistPath, isInitialization);

    cleanDynamicStringDataType(&clientData->ftpCommand.commandArgs, isInitialization);
    cleanDynamicStringDataType(&clientData->ftpCommand.commandOps, isInitialization);

    clientData->connectionTimeStamp = 0;
    clientData->lastActivityTimeStamp = 0;
}

int compareStringCaseInsensitive(char * stringIn, char * stringRef, int stringLenght)
{
    int i = 0;
    char * alfaLowerCase = "qwertyuiopasdfghjklzxcvbnm ";
    char * alfaUpperCase = "QWERTYUIOPASDFGHJKLZXCVBNM ";

    int stringInIndex;
    int stringRefIndex;

    for (i = 0; i <stringLenght; i++)
    {
        stringInIndex  = isCharInString(alfaUpperCase, strlen(alfaUpperCase), stringIn[i]);
        if (stringInIndex == -1)
        {
            stringInIndex  = isCharInString(alfaLowerCase, strlen(alfaLowerCase), stringIn[i]);
        }

        stringRefIndex = isCharInString(alfaUpperCase, strlen(alfaUpperCase), stringRef[i]);
        if (stringRefIndex == -1)
        {
            stringRefIndex  = isCharInString(alfaLowerCase, strlen(alfaLowerCase), stringRef[i]);
        }

        if (stringRefIndex == -1 || stringInIndex == -1)
        {
            return 0;
        }

        if (stringRefIndex != stringInIndex)
        {
            return 0;
        }
    }

    return 1;
}

int isCharInString(char *theString, int stringLen, char theChar)
{
    int i;
    for (i = 0; i < stringLen; i++)
    {
        if (theString[i] == theChar)
        {
            return i;
        }
    }

    return -1;
}
