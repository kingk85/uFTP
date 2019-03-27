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
#include "library/connection.h"
#include "library/dynamicMemory.h"

void cleanDynamicStringDataType(dynamicStringDataType *dynamicString, int init, DYNMEM_MemoryTable_DataType **memoryTable)
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
            	DYNMEM_free(dynamicString->text, &*memoryTable);
            }
        }

        dynamicString->textLen = 0;
    }
}

void cleanLoginData(loginDataType *loginData, int init, DYNMEM_MemoryTable_DataType **memoryTable)
{
    loginData->userLoggedIn = 0;
    cleanDynamicStringDataType(&loginData->homePath, init, &*memoryTable);
    cleanDynamicStringDataType(&loginData->ftpPath, init, &*memoryTable);
    cleanDynamicStringDataType(&loginData->name, init, &*memoryTable);
    cleanDynamicStringDataType(&loginData->password, init, &*memoryTable);
    cleanDynamicStringDataType(&loginData->absolutePath, init, &*memoryTable);
}

void setDynamicStringDataType(dynamicStringDataType *dynamicString, char *theString, int stringLen, DYNMEM_MemoryTable_DataType **memoryTable)
{
    if (dynamicString->textLen == 0)
    {
    	//printf("\nMemory data address before memset call : %lld", memoryTable);
        dynamicString->text = (char *) DYNMEM_malloc (((sizeof(char) * stringLen) + 1), &*memoryTable, "setDynamicString");
        //printf("\nMemory data address after memset call : %lld", memoryTable);
        memset(dynamicString->text, 0, stringLen + 1);
        memcpy(dynamicString->text, theString, stringLen);
        dynamicString->textLen = stringLen;
    }
    else
    {
        if(stringLen != dynamicString->textLen)
        {
            dynamicString->text = (char *) DYNMEM_realloc (dynamicString->text, ((sizeof(char) * stringLen) + 1), &*memoryTable);
        }

        memset(dynamicString->text, 0, stringLen + 1);
        memcpy(dynamicString->text, theString, stringLen);
        dynamicString->textLen = stringLen; 
    }
}


int getSafePath(dynamicStringDataType *safePath, char *theDirectoryName, loginDataType *loginData, DYNMEM_MemoryTable_DataType **memoryTable)
{
	#define STRING_SIZE		4096
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
    char theDirectoryToCheck[STRING_SIZE];
    int theDirectoryToCheckIndex = 0;
    memset(theDirectoryToCheck, 0, STRING_SIZE);
    
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
        memset(theDirectoryToCheck, 0, STRING_SIZE);
        continue;
        }
        
        if (theDirectoryToCheckIndex<STRING_SIZE)
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

        //printf("\nMemory data address 2nd call : %lld", memoryTable);
        setDynamicStringDataType(safePath, loginData->homePath.text, loginData->homePath.textLen, &*memoryTable);
        //printf("\nMemory data address 3rd call : %lld", memoryTable);
        appendToDynamicStringDataType(safePath, theDirectoryNamePointer, strlen(theDirectoryNamePointer), &*memoryTable);
    }
    else
    {
        setDynamicStringDataType(safePath, loginData->absolutePath.text, loginData->absolutePath.textLen, &*memoryTable);

        if (loginData->absolutePath.text[loginData->absolutePath.textLen-1] != '/')
        {
            appendToDynamicStringDataType(safePath, "/", 1, &*memoryTable);
        }
        
        appendToDynamicStringDataType(safePath, theDirectoryName, strlen(theDirectoryName), &*memoryTable);
    }
    
    return 1;
}

void appendToDynamicStringDataType(dynamicStringDataType *dynamicString, char *theString, int stringLen, DYNMEM_MemoryTable_DataType **memoryTable)
{
	//printf("\nRealloc dynamicString->text = %lld", dynamicString->text);
    int theNewSize = dynamicString->textLen + stringLen;

    dynamicString->text = DYNMEM_realloc(dynamicString->text, theNewSize + 1, &*memoryTable);

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
   //printf("data->clients[%d].workerData.connectionPort = %d", socketPosition, data->clients[socketPosition].workerData.connectionPort);
}

int writeListDataInfoToSocket(ftpDataType *ftpData, int clientId, int *filesNumber, int commandType, DYNMEM_MemoryTable_DataType **memoryTable)
{
    int i, x, returnCode;
    int fileAndFoldersCount = 0;
    char **fileList = NULL;
    FILE_GetDirectoryInodeList(ftpData->clients[clientId].listPath.text, &fileList, &fileAndFoldersCount, 0, &*memoryTable);
    *filesNumber = fileAndFoldersCount;

    returnCode = socketWorkerPrintf(ftpData, clientId, "sds", "total ", fileAndFoldersCount ,"\r\n");
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

        data.owner = FILE_GetOwner(fileList[i], &*memoryTable);
        data.groupOwner = FILE_GetGroupOwner(fileList[i], &*memoryTable);
        data.fileNameWithPath = fileList[i];
        data.fileNameNoPath = FILE_GetFilenameFromPath(fileList[i]);
        data.inodePermissionString = FILE_GetListPermissionsString(fileList[i], &*memoryTable);
        data.lastModifiedData = FILE_GetLastModifiedData(fileList[i]);

        if (strlen(data.fileNameNoPath) > 0)
        {
            data.finalStringPath = (char *) DYNMEM_malloc (strlen(data.fileNameNoPath)+1, &*memoryTable, "dataFinalPath");
            strcpy(data.finalStringPath, data.fileNameNoPath);
        }
        
        if (data.inodePermissionString != NULL &&
            strlen(data.inodePermissionString) > 0 &&
            data.inodePermissionString[0] == 'l')
            {
                int len = 0;
                data.isLink = 1;
                data.linkPath = (char *) DYNMEM_malloc (CLIENT_COMMAND_STRING_SIZE*sizeof(char), &*memoryTable, "dataLinkPath");
                if ((len = readlink (fileList[i], data.linkPath, CLIENT_COMMAND_STRING_SIZE)) > 0)
                {
                    data.linkPath[len] = 0;
                    FILE_AppendToString(&data.finalStringPath, " -> ", &*memoryTable);
                    FILE_AppendToString(&data.finalStringPath, data.linkPath, &*memoryTable);
                }
            }

        memset(data.lastModifiedDataString, 0, LIST_DATA_TYPE_MODIFIED_DATA_STR_SIZE);       
        strftime(data.lastModifiedDataString, LIST_DATA_TYPE_MODIFIED_DATA_STR_SIZE, "%b %d %Y", localtime(&data.lastModifiedData));
        
        
        switch (commandType)
        {
            case COMMAND_TYPE_LIST:
            {
            			returnCode = socketWorkerPrintf(ftpData, clientId, "ssdssssslsssss",
                        data.inodePermissionString == NULL? "Unknown" : data.inodePermissionString
                        ," "
                        ,data.numberOfSubDirectories
                        ," "
                        ,data.owner == NULL? "Unknown" : data.owner
						," "
                        ,data.groupOwner == NULL? "Unknown" : data.groupOwner
						," "
                        ,data.fileSize
                        ," "
                        ,data.lastModifiedDataString == NULL? "Unknown" : data.lastModifiedDataString
						," "
                        ,data.finalStringPath == NULL? "Unknown" : data.finalStringPath
						,"\r\n");
            		/*
                returnCode = dprintf(theSocket, "%s %d %s %s %lld %s %s\r\n", 
                data.inodePermissionString == NULL? "Unknown" : data.inodePermissionString
                ,data.numberOfSubDirectories
                ,data.owner == NULL? "Unknown" : data.owner
                ,data.groupOwner == NULL? "Unknown" : data.groupOwner
                ,data.fileSize
                ,data.lastModifiedDataString == NULL? "Unknown" : data.lastModifiedDataString
                ,data.finalStringPath == NULL? "Unknown" : data.finalStringPath);
                */
            }
            break;
            
            case COMMAND_TYPE_NLST:
            {
            	returnCode = socketWorkerPrintf(ftpData, clientId, "ss", data.fileNameNoPath, "\r\n");
            }
            break;

            
            default:
            {
                printf("\nWarning switch default in function writeListDataInfoToSocket (%d)", commandType);
            }
            break;
        }
        
       
        if (data.fileNameWithPath != NULL)
            DYNMEM_free(data.fileNameWithPath, &*memoryTable);
        
        if (data.linkPath != NULL)
        	DYNMEM_free(data.linkPath, &*memoryTable);

        if (data.finalStringPath != NULL)
        	DYNMEM_free(data.finalStringPath, &*memoryTable);

        if (data.owner != NULL)
        	DYNMEM_free(data.owner, &*memoryTable);
        
        if (data.groupOwner != NULL)
        	DYNMEM_free(data.groupOwner, &*memoryTable);
        
        if (data.inodePermissionString != NULL)
        	DYNMEM_free(data.inodePermissionString, &*memoryTable);
          
        if (returnCode <= 0)
        {
            for (x = i+1; x < fileAndFoldersCount; x++)
            	DYNMEM_free (fileList[x], &*memoryTable);
            DYNMEM_free (fileList, &*memoryTable);
            return -1;
        }
        
        }

		if (fileList != NULL)
		{
			DYNMEM_free (fileList, &*memoryTable);
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

void getListDataInfo(char * thePath, DYNV_VectorGenericDataType *directoryInfo, DYNMEM_MemoryTable_DataType **memoryTable)
{
    int i;
    int fileAndFoldersCount = 0;
    ftpListDataType data;
    FILE_GetDirectoryInodeList(thePath, &data.fileList, &fileAndFoldersCount, 0, &*memoryTable);
    
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
            //printf("\nNot a directory, not a file, broken link");
            continue;
        }
        
       // printf("\nFILE SIZE : %lld", data.fileSize);

        data.owner = FILE_GetOwner(data.fileList[i], &*memoryTable);
        data.groupOwner = FILE_GetGroupOwner(data.fileList[i], &*memoryTable);
        data.fileNameWithPath = data.fileList[i];
        data.fileNameNoPath = FILE_GetFilenameFromPath(data.fileList[i]);
        data.inodePermissionString = FILE_GetListPermissionsString(data.fileList[i], &*memoryTable);
        data.lastModifiedData = FILE_GetLastModifiedData(data.fileList[i]);

        if (strlen(data.fileNameNoPath) > 0)
        {
            data.finalStringPath = (char *) DYNMEM_malloc (strlen(data.fileNameNoPath)+1, &*memoryTable, "FinalStringPath");
            strcpy(data.finalStringPath, data.fileNameNoPath);
        }
        
        if (data.inodePermissionString != NULL &&
            strlen(data.inodePermissionString) > 0 &&
            data.inodePermissionString[0] == 'l')
            {
                int len = 0;
                data.isLink = 1;
                data.linkPath = (char *) DYNMEM_malloc (CLIENT_COMMAND_STRING_SIZE*sizeof(char), &*memoryTable, "data.linkPath");
                if ((len = readlink (data.fileList[i], data.linkPath, CLIENT_COMMAND_STRING_SIZE)) > 0)
                {
                    data.linkPath[len] = 0;
                    FILE_AppendToString(&data.finalStringPath, " -> ", &*memoryTable);
                    FILE_AppendToString(&data.finalStringPath, data.linkPath, &*memoryTable);
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

void deleteListDataInfoVector(DYNV_VectorGenericDataType *theVector)
{

    int i;
    for (i = 0; i < theVector->Size; i++)
    {
		ftpListDataType *data = (ftpListDataType *)theVector->Data[i];

		if (data->owner != NULL)
		{
			DYNMEM_free(data->owner, &theVector->memoryTable);
		}
		if (data->groupOwner != NULL)
		{
			DYNMEM_free(data->groupOwner, &theVector->memoryTable);
		}
		if (data->inodePermissionString != NULL)
		{
			DYNMEM_free(data->inodePermissionString, &theVector->memoryTable);
		}
		if (data->fileNameWithPath != NULL)
		{
			DYNMEM_free(data->fileNameWithPath, &theVector->memoryTable);
		}
		if (data->finalStringPath != NULL)
		{
			DYNMEM_free(data->finalStringPath, &theVector->memoryTable);
		}
		if (data->linkPath != NULL)
		{
			DYNMEM_free(data->linkPath, &theVector->memoryTable);
		}
    }
}

void resetWorkerData(ftpDataType *data, int clientId, int isInitialization)
{

	  printf("\nReset of worker id: %d", clientId);
      data->clients[clientId].workerData.connectionPort = 0;
      data->clients[clientId].workerData.passiveModeOn = 0;
      data->clients[clientId].workerData.socketIsConnected = 0;
      data->clients[clientId].workerData.commandIndex = 0;
      data->clients[clientId].workerData.passiveListeningSocket = 0;
      data->clients[clientId].workerData.socketConnection = 0;
      data->clients[clientId].workerData.bufferIndex = 0;
      data->clients[clientId].workerData.commandReceived = 0;
      data->clients[clientId].workerData.retrRestartAtByte = 0;
      data->clients[clientId].workerData.threadIsAlive = 0;
      data->clients[clientId].workerData.activeModeOn = 0;
      data->clients[clientId].workerData.passiveModeOn = 0;
      data->clients[clientId].workerData.activeIpAddressIndex = 0;

      memset(data->clients[clientId].workerData.buffer, 0, CLIENT_BUFFER_STRING_SIZE);
      memset(data->clients[clientId].workerData.activeIpAddress, 0, CLIENT_BUFFER_STRING_SIZE);
      memset(data->clients[clientId].workerData.theCommandReceived, 0, CLIENT_BUFFER_STRING_SIZE);

      cleanDynamicStringDataType(&data->clients[clientId].workerData.ftpCommand.commandArgs, isInitialization, &data->clients[clientId].workerData.memoryTable);
      cleanDynamicStringDataType(&data->clients[clientId].workerData.ftpCommand.commandOps, isInitialization, &data->clients[clientId].workerData.memoryTable);

      /* wait main for action */
      if (isInitialization != 1)
      {
        if (data->clients[clientId].workerData.theStorFile != NULL)
        {
            fclose(data->clients[clientId].workerData.theStorFile);
            data->clients[clientId].workerData.theStorFile = NULL;
        }

			#ifdef OPENSSL_ENABLED
			SSL_free(data->clients[clientId].workerData.serverSsl);
			SSL_free(data->clients[clientId].workerData.clientSsl);
			#endif
      }
      else
      {
        DYNV_VectorGeneric_Init(&data->clients[clientId].workerData.directoryInfo);
        data->clients[clientId].workerData.theStorFile = NULL;
        data->clients[clientId].workerData.threadHasBeenCreated = 0;
      }


    //Clear the dynamic vector structure
    int theSize = data->clients[clientId].workerData.directoryInfo.Size;
    char ** lastToDestroy = NULL;
    if (theSize > 0)
    {
        lastToDestroy = ((ftpListDataType *)data->clients[clientId].workerData.directoryInfo.Data[0])->fileList;
        data->clients[clientId].workerData.directoryInfo.Destroy(&data->clients[clientId].workerData.directoryInfo, deleteListDataInfoVector);
        DYNMEM_free(lastToDestroy, &data->clients[clientId].workerData.memoryTable);
    }

		#ifdef OPENSSL_ENABLED
		data->clients[clientId].workerData.serverSsl = SSL_new(data->serverCtx);
		data->clients[clientId].workerData.clientSsl = SSL_new(data->clientCtx);
		#endif
}

void resetClientData(ftpDataType *data, int clientId, int isInitialization)
{
    if (isInitialization != 1)
    {
	if (data->clients[clientId].workerData.threadIsAlive == 1) {
		pthread_cancel(data->clients[clientId].workerData.workerThread);
    	do
		{
    		printf("\nQuit command received the Pasv Thread has been cancelled!!!");
    		usleep(10000);
		} while (ftpData->clients[clientId].workerData.threadIsAlive == 1);

	}
	pthread_mutex_destroy(&data->clients[clientId].conditionMutex);
	pthread_cond_destroy(&data->clients[clientId].conditionVariable);

	pthread_mutex_destroy(&data->clients[clientId].writeMutex);

	#ifdef OPENSSL_ENABLED
	SSL_free(data->clients[clientId].ssl);
	//SSL_free(data->clients[clientId].workerData.ssl);
	#endif
    }
    else
    {

    }

    if (pthread_mutex_init(&data->clients[clientId].writeMutex, NULL) != 0)
    {
        printf("\nclientData->writeMutex init failed\n");
        exit(0);
    }

	if (pthread_mutex_init(&data->clients[clientId].conditionMutex, NULL) != 0)
		  {
		  printf("\ndata->clients[clientId].workerData.conditionMutex init failed\n");
		  exit(0);
		  }

	if (pthread_cond_init(&data->clients[clientId].conditionVariable, NULL) != 0)
	{
		printf("\ndata->clients[clientId].workerData.conditionVariable init failed\n");
		exit(0);
	}

    data->clients[clientId].tlsIsNegotiating = 0;
    data->clients[clientId].tlsIsEnabled = 0;
    data->clients[clientId].dataChannelIsTls = 0;
    data->clients[clientId].socketDescriptor = -1;
    data->clients[clientId].socketCommandReceived = 0;
    data->clients[clientId].socketIsConnected = 0;
    data->clients[clientId].bufferIndex = 0;
    data->clients[clientId].commandIndex = 0;
    data->clients[clientId].closeTheClient = 0;
    data->clients[clientId].sockaddr_in_size = sizeof(struct sockaddr_in);
    data->clients[clientId].sockaddr_in_server_size = sizeof(struct sockaddr_in);
    
    data->clients[clientId].serverIpAddressInteger[0] = 0;
    data->clients[clientId].serverIpAddressInteger[1] = 0;
    data->clients[clientId].serverIpAddressInteger[2] = 0;
    data->clients[clientId].serverIpAddressInteger[3] = 0;
    
    
    memset(&data->clients[clientId].client_sockaddr_in, 0, data->clients[clientId].sockaddr_in_size);
    memset(&data->clients[clientId].server_sockaddr_in, 0, data->clients[clientId].sockaddr_in_server_size);
    memset(data->clients[clientId].clientIpAddress, 0, INET_ADDRSTRLEN);
    memset(data->clients[clientId].buffer, 0, CLIENT_BUFFER_STRING_SIZE);
    memset(data->clients[clientId].theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);
    cleanLoginData(&data->clients[clientId].login, isInitialization, &data->clients[clientId].memoryTable);
    
    //Rename from and to data init
    cleanDynamicStringDataType(&data->clients[clientId].renameFromFile, isInitialization, &data->clients[clientId].memoryTable);
    cleanDynamicStringDataType(&data->clients[clientId].renameToFile, isInitialization, &data->clients[clientId].memoryTable);
    cleanDynamicStringDataType(&data->clients[clientId].fileToStor, isInitialization, &data->clients[clientId].memoryTable);
    cleanDynamicStringDataType(&data->clients[clientId].fileToRetr, isInitialization, &data->clients[clientId].memoryTable);
    cleanDynamicStringDataType(&data->clients[clientId].listPath, isInitialization, &data->clients[clientId].memoryTable);
    cleanDynamicStringDataType(&data->clients[clientId].nlistPath, isInitialization, &data->clients[clientId].memoryTable);
    cleanDynamicStringDataType(&data->clients[clientId].ftpCommand.commandArgs, isInitialization, &data->clients[clientId].memoryTable);
    cleanDynamicStringDataType(&data->clients[clientId].ftpCommand.commandOps, isInitialization, &data->clients[clientId].memoryTable);

    data->clients[clientId].connectionTimeStamp = 0;
    data->clients[clientId].tlsNegotiatingTimeStart = 0;
    data->clients[clientId].lastActivityTimeStamp = 0;

	#ifdef OPENSSL_ENABLED
	//data->clients[clientId].workerData.ssl = SSL_new(data->ctx);
	data->clients[clientId].ssl = SSL_new(data->serverCtx);
	#endif

	//printf("\nclient memory table :%lld", data->clients[clientId].memoryTable);
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
