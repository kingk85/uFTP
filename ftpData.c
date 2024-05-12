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
#define _REENTRANT
#include <pthread.h>
#include <netinet/in.h>
#include <unistd.h>
#include <limits.h>

#include "ftpServer.h"
#include "ftpCommandsElaborate.h"
#include "ftpData.h"

#include "library/configRead.h"
#include "library/fileManagement.h"
#include "library/connection.h"
#include "library/dynamicMemory.h"

#include "debugHelper.h"
#include "library/log.h"


static int is_prefix(const char *str, const char *prefix);
static char *my_realpath(const char *path, char *resolved_path);

static char *my_realpath(const char *path, char *resolved_path) 
{
    char temp[PATH_MAX];
    char *token;
    char *rest = NULL;

    // Check if the path is absolute or relative
    if (path[0] == '/') 
    {
        strcpy(temp, path);
    } 
    else 
    {
        my_printfError("getcwd");
        addLog("getcwd error ", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
        return NULL;
    }

    // Process tokens separated by '/'
    token = strtok_r(temp, "/", &rest);
    while (token != NULL) 
    {
        if (strcmp(token, "..") == 0) 
        {
            // Remove the last directory if it's not the root directory
            char *last_slash = strrchr(resolved_path, '/');
            if (last_slash != NULL) {
                *last_slash = '\0';
            }
        }
        else if (strcmp(token, ".") != 0) 
        {
            // Add valid token to the resolved path
            strcat(resolved_path, "/");
            strcat(resolved_path, token);
        }
        token = strtok_r(NULL, "/", &rest);
    }

    return resolved_path;
}

static int is_prefix(const char *str, const char *prefix) {
  int i = 0;
  while (prefix[i] && str[i] && prefix[i] == str[i]) {
    i++;
  }
  // Check if prefix ended and characters in str matched till then
  return prefix[i] == '\0';
}

void cleanDynamicStringDataType(dynamicStringDataType *dynamicString, int init, DYNMEM_MemoryTable_DataType **memoryTable)
{
    if (init == 1)
    {
        dynamicString->text = 0;
        dynamicString->textLen = 0;
    }
    else
    {
        if (dynamicString->textLen != 0 && dynamicString->text != 0)
        {
            	DYNMEM_free(dynamicString->text, memoryTable);
        }

        dynamicString->textLen = 0;
    }
}

void cleanLoginData(loginDataType *loginData, int init, DYNMEM_MemoryTable_DataType **memoryTable)
{
    loginData->userLoggedIn = 0;
    cleanDynamicStringDataType(&loginData->homePath, init, memoryTable);
    cleanDynamicStringDataType(&loginData->ftpPath, init, memoryTable);
    cleanDynamicStringDataType(&loginData->name, init, memoryTable);
    cleanDynamicStringDataType(&loginData->password, init, memoryTable);
    cleanDynamicStringDataType(&loginData->absolutePath, init, memoryTable);
}

void setDynamicStringDataType(dynamicStringDataType *dynamicString, char *theString, int stringLen, DYNMEM_MemoryTable_DataType **memoryTable)
{
    if (dynamicString->textLen == 0)
    {
    	//my_printf("\nMemory data address before memset call : %lld", memoryTable);
        dynamicString->text = (char *) DYNMEM_malloc (((sizeof(char) * stringLen) + 1), memoryTable, "setDynamicString");
        //my_printf("\nMemory data address after memset call : %lld", memoryTable);
        memset(dynamicString->text, 0, stringLen + 1);
        memcpy(dynamicString->text, theString, stringLen);
        dynamicString->textLen = stringLen;
    }
    else
    {
        if(stringLen != dynamicString->textLen)
        {
            dynamicString->text = (char *) DYNMEM_realloc (dynamicString->text, ((sizeof(char) * stringLen) + 1), memoryTable);
        }

        memset(dynamicString->text, 0, stringLen + 1);
        memcpy(dynamicString->text, theString, stringLen);
        dynamicString->textLen = stringLen; 
    }
}

int getSafePath(dynamicStringDataType *safePath, char *theDirectoryName, loginDataType *loginData, DYNMEM_MemoryTable_DataType **memoryTable)
{
    size_t theLen;
    char * theDirectoryNamePointer;
    theDirectoryNamePointer = theDirectoryName;
    char theDirectoryToCheck[PATH_MAX];
    int theDirectoryToCheckIndex = 0;
    char resolved_path[PATH_MAX];
    char resolved_path_abs[PATH_MAX];

    memset(theDirectoryToCheck, 0, PATH_MAX);    
    memset(resolved_path, 0, PATH_MAX);
    memset(resolved_path_abs, 0, PATH_MAX);

    //No name provided return false
    if (theDirectoryName == NULL)
        return 0;
    
    theLen = strnlen(theDirectoryName, PATH_MAX);

    //Not a string
    if (theLen <= 0)
        return 0;

    my_printf("\ninput: %s", theDirectoryName);
    //Absolute path set in the request, start from home directory
    if (theDirectoryName[0] == '/')
    {
        while (theDirectoryNamePointer[0] == '/')
            theDirectoryNamePointer++;

        //Absolute requests must start from home path
        strncpy(theDirectoryToCheck, loginData->homePath.text, PATH_MAX);
        strncat(theDirectoryToCheck, theDirectoryNamePointer, PATH_MAX);
        my_printf("\nAbsolute string: %s", theDirectoryToCheck);
    }
    else
    {
        //Relative directory, start from the current path
        strncpy(theDirectoryToCheck, loginData->absolutePath.text, PATH_MAX);

        if (loginData->absolutePath.text[loginData->absolutePath.textLen-1] != '/')
        {
            strncat(theDirectoryToCheck, "/", PATH_MAX);
        }

        strncat(theDirectoryToCheck, theDirectoryNamePointer, PATH_MAX);
        my_printf("\nRelative string: %s", theDirectoryToCheck);
    }

    my_printf("\nrealpath input: %s", theDirectoryToCheck);
    if (strnlen(theDirectoryToCheck, 2) == 1 && theDirectoryToCheck[0] == '/')
    {
        setDynamicStringDataType(safePath, theDirectoryToCheck, strnlen(theDirectoryToCheck, PATH_MAX), memoryTable);
        return 1;
    }

    char* real_path = my_realpath(theDirectoryToCheck, resolved_path);
    if (real_path)
    {
        my_printf("\nResolved path: %s\n", real_path);
        my_printf("\nCheck if home path: %s\n", loginData->homePath.text);
        my_printf("\nIs in resolved path: %s\n", real_path);

        char* real_path_abs = my_realpath(loginData->homePath.text, resolved_path_abs);

        //Check if the home path is still set
        if (is_prefix(real_path, real_path_abs))
        {
            my_printf("\nCheck ok");
            setDynamicStringDataType(safePath, real_path, strnlen(real_path, PATH_MAX), memoryTable);
        }
        else
        {
            my_printfError("\nPath check error: %s check if is in: %s",loginData->homePath.text, real_path);
            addLog("Path check error ", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
            return 0;
        }
    }
    else 
    {
        addLog("Realpath error", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
        my_printfError("\nRealpath error input %s", theDirectoryName);
        my_printfError("\ntheDirectoryToCheck error input %s", theDirectoryToCheck);
        return 0;
    }

    return 1;
}

void appendToDynamicStringDataType(dynamicStringDataType *dynamicString, char *theString, int stringLen, DYNMEM_MemoryTable_DataType **memoryTable)
{
	//my_printf("\nRealloc dynamicString->text = %lld", dynamicString->text);
    int theNewSize = dynamicString->textLen + stringLen;

    dynamicString->text = DYNMEM_realloc(dynamicString->text, theNewSize + 1, memoryTable);

    memset(dynamicString->text+dynamicString->textLen, 0, stringLen+1);
    memcpy(dynamicString->text+dynamicString->textLen, theString, stringLen);

    dynamicString->text[theNewSize] = '\0';
    dynamicString->textLen = theNewSize;
}

void setRandomicPort(ftpDataType *data, int socketPosition)
{
    unsigned short int randomicPort = 5000;
    int i = 0;

  randomicPort = data->ftpParameters.connectionPortMin + (rand()%(data->ftpParameters.connectionPortMax - data->ftpParameters.connectionPortMin)); 

   while (i < data->ftpParameters.maxClients)
   {
       if (randomicPort == data->clients[i].workerData.connectionPort)
       {
        randomicPort = data->ftpParameters.connectionPortMin + (rand()%(data->ftpParameters.connectionPortMax - data->ftpParameters.connectionPortMin)); 
        i = 0;
       }
       else 
       {
        i++;
       }
   }

   data->clients[socketPosition].workerData.connectionPort = randomicPort;

   my_printf("\n  data->clients[%d].workerData.connectionPort = %d", socketPosition, data->clients[socketPosition].workerData.connectionPort);

}

int writeListDataInfoToSocket(ftpDataType *ftpData, int clientId, int *filesNumber, int commandType, DYNMEM_MemoryTable_DataType **memoryTable)
{
    // a --> include . and ..
    // A --> do not include . and ..
    // nothing --> no hidden no . and no ..
    my_printf("\nFILE_GetDirectoryInodeList arg path: %s", ftpData->clients[clientId].listPath.text);
    my_printf("\nftpData->clients[clientId].workerData.ftpCommand.commandArgs: %s", ftpData->clients[clientId].workerData.ftpCommand.commandArgs.text);
    my_printf("\nftpData->clients[clientId].workerData.ftpCommand.commandOps: %s", ftpData->clients[clientId].workerData.ftpCommand.commandOps.text);

    int i, x, returnCode;
    int fileAndFoldersCount = 0;
    char **fileList = NULL;
    FILE_GetDirectoryInodeList(ftpData->clients[clientId].listPath.text, &fileList, &fileAndFoldersCount, 0, ftpData->clients[clientId].workerData.ftpCommand.commandOps.text, 0, memoryTable);
    *filesNumber = fileAndFoldersCount;

    if (commandType != COMMAND_TYPE_STAT)
    {
        returnCode = socketWorkerPrintf(ftpData, clientId, "sds", "total ", fileAndFoldersCount ,"\r\n");
        if (returnCode <= 0)
        {

            for (x = 0; x < fileAndFoldersCount; x++)
            	DYNMEM_free (fileList[x], memoryTable);

            DYNMEM_free (fileList, memoryTable);
            return -1;
        }
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

        if (FILE_IsDirectory(fileList[i], 0) == 1)
        {
            data.isDirectory = 1;
            data.isFile = 0;
            data.isLink = 0;
            data.fileSize = 4096;
            data.numberOfSubDirectories = FILE_GetDirectoryInodeCount(fileList[i]);
        }
        else if (FILE_IsFile(fileList[i], 0) == 1)
        {
            data.isDirectory = 0;
            data.isFile = 1;
            data.isLink = 0;
            data.numberOfSubDirectories = 1; /* to Do*/
            data.fileSize = FILE_GetFileSizeFromPath(fileList[i]);
        }
        else if (FILE_IsLink(fileList[i]) == 1)
        {
            //List broken links
            data.isLink = 1;
            my_printf("\n%s **************************** neither a file or dir is link", fileList[i]);
        }
        else
        {
            my_printf("\n%s **************************************** inode not recognized", fileList[i]);
        }

        if (data.isDirectory == 0 && data.isFile == 0 && data.isLink == 0)
        {
            DYNMEM_free (fileList[i], memoryTable);
            continue;
        }

        data.owner = FILE_GetOwner(fileList[i], memoryTable);
        data.groupOwner = FILE_GetGroupOwner(fileList[i], memoryTable);
        data.fileNameWithPath = fileList[i];
        data.fileNameNoPath = FILE_GetFilenameFromPath(fileList[i]);
        data.inodePermissionString = FILE_GetListPermissionsString(fileList[i], memoryTable);
        data.lastModifiedData = FILE_GetLastModifiedData(fileList[i]);

        if (strlen(data.fileNameNoPath) > 0)
        {
            data.finalStringPath = (char *) DYNMEM_malloc (strlen(data.fileNameNoPath)+1, memoryTable, "dataFinalPath");
            strcpy(data.finalStringPath, data.fileNameNoPath);
        }

        if (data.isLink == 1)
        {
            if(data.inodePermissionString != NULL)
                my_printf("\n ************************** data.inodePermissionString = %s", data.inodePermissionString);
            else
                my_printf("\n ********************** void inode permission string");
        }

        if (data.isLink == 1 &&
            data.inodePermissionString != NULL &&
            strlen(data.inodePermissionString) > 0 &&
            data.inodePermissionString[0] == 'l')
            {
                int len = 0;
                data.isLink = 1;
                data.linkPath = (char *) DYNMEM_malloc (CLIENT_COMMAND_STRING_SIZE*sizeof(char), memoryTable, "dataLinkPath");
                if ((len = readlink (fileList[i], data.linkPath, CLIENT_COMMAND_STRING_SIZE)) > 0)
                {
                    data.linkPath[len] = 0;
                    FILE_AppendToString(&data.finalStringPath, " -> ", memoryTable);
                    FILE_AppendToString(&data.finalStringPath, data.linkPath, memoryTable);
                }
                
            }

        memset(data.lastModifiedDataString, 0, LIST_DATA_TYPE_MODIFIED_DATA_STR_SIZE);       

        struct tm newtime;
        localtime_r(&data.lastModifiedData, &newtime);
        strftime(data.lastModifiedDataString, LIST_DATA_TYPE_MODIFIED_DATA_STR_SIZE, "%b %d %Y", &newtime);
        
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

            case COMMAND_TYPE_STAT:
            {
                returnCode = socketPrintf(ftpData, clientId, "ssdssssslsssss",
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
            
            default:
            {
                my_printf("\nWarning switch default in function writeListDataInfoToSocket (%d)", commandType);
            }
            break;
        }
        
       
        if (data.fileNameWithPath != NULL)
            DYNMEM_free(data.fileNameWithPath, memoryTable);
        
        if (data.linkPath != NULL)
        	DYNMEM_free(data.linkPath, memoryTable);

        if (data.finalStringPath != NULL)
        	DYNMEM_free(data.finalStringPath, memoryTable);

        if (data.owner != NULL)
        	DYNMEM_free(data.owner, memoryTable);
        
        if (data.groupOwner != NULL)
        	DYNMEM_free(data.groupOwner, memoryTable);
        
        if (data.inodePermissionString != NULL)
        	DYNMEM_free(data.inodePermissionString, memoryTable);
          
        if (returnCode <= 0)
        {
            for (x = i+1; x < fileAndFoldersCount; x++)
            	DYNMEM_free (fileList[x], memoryTable);
            DYNMEM_free (fileList, memoryTable);
            return -1;
        }
        }

		if (fileList != NULL)
		{
			DYNMEM_free (fileList, memoryTable);
		}

        return 1;
    }

int searchInLoginFailsVector(void * loginFailsVector, void *element)
{
    int i = 0;
    //my_printf("((DYNV_VectorGenericDataType *)loginFailsVector)->Size = %d", ((DYNV_VectorGenericDataType *)loginFailsVector)->Size);

    for (i = 0; i < ((DYNV_VectorGenericDataType *)loginFailsVector)->Size; i++)
    {
        if (strcmp( ((loginFailsDataType *) element)->ipAddress, (((loginFailsDataType *) ((DYNV_VectorGenericDataType *)loginFailsVector)->Data[i])->ipAddress)) == 0)
        {
            //my_printf("\n\n***IP address found: %s in %d", ((loginFailsDataType *) element)->ipAddress, i);
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
    FILE_GetDirectoryInodeList(thePath, &data.fileList, &fileAndFoldersCount, 0, "Z", 0, memoryTable);
    
    //my_printf("\nNUMBER OF FILES: %d", fileAndFoldersCount);
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
        
        
        //my_printf("\nPROCESSING: %s", data.fileList[i]);
        //fflush(0);
        
        if (FILE_IsDirectory(data.fileList[i], 0) == 1)
        {
            //my_printf("\nis file");
            //fflush(0);
            data.isDirectory = 1;
            data.isFile = 0;
            data.isLink = 0;
            data.fileSize = 4096;
        }
        else if (FILE_IsFile(data.fileList[i], 0) == 1)
        {
            //my_printf("\nis file");
            //fflush(0);
            data.isDirectory = 0;
            data.isFile = 1;
            data.isLink = 0;
            data.fileSize = FILE_GetFileSizeFromPath(data.fileList[i]);
        }
        if (data.isDirectory == 0 && data.isFile == 0)
        {
            //my_printf("\nNot a directory, not a file, broken link");
            continue;
        }
        
       // my_printf("\nFILE SIZE : %lld", data.fileSize);

        data.owner = FILE_GetOwner(data.fileList[i], memoryTable);
        data.groupOwner = FILE_GetGroupOwner(data.fileList[i], memoryTable);
        data.fileNameWithPath = data.fileList[i];
        data.fileNameNoPath = FILE_GetFilenameFromPath(data.fileList[i]);
        data.inodePermissionString = FILE_GetListPermissionsString(data.fileList[i], memoryTable);
        data.lastModifiedData = FILE_GetLastModifiedData(data.fileList[i]);

        if (strlen(data.fileNameNoPath) > 0)
        {
            data.finalStringPath = (char *) DYNMEM_malloc (strlen(data.fileNameNoPath)+1, memoryTable, "FinalStringPath");
            strcpy(data.finalStringPath, data.fileNameNoPath);
        }
        
        if (data.inodePermissionString != NULL &&
            strlen(data.inodePermissionString) > 0 &&
            data.inodePermissionString[0] == 'l')
            {
                int len = 0;
                data.isLink = 1;
                data.linkPath = (char *) DYNMEM_malloc (CLIENT_COMMAND_STRING_SIZE*sizeof(char), memoryTable, "data.linkPath");
                if ((len = readlink (data.fileList[i], data.linkPath, CLIENT_COMMAND_STRING_SIZE)) > 0)
                {
                    data.linkPath[len] = 0;
                    FILE_AppendToString(&data.finalStringPath, " -> ", memoryTable);
                    FILE_AppendToString(&data.finalStringPath, data.linkPath, memoryTable);
                }
            }

        memset(data.lastModifiedDataString, 0, LIST_DATA_TYPE_MODIFIED_DATA_STR_SIZE);    
        
        struct tm newtime;
        localtime_r(&data.lastModifiedData, &newtime);   
        strftime(data.lastModifiedDataString, 80, "%b %d %Y", &newtime);

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

void cancelWorker(ftpDataType *data, int clientId)
{
	void *pReturn;
    addLog("Cancelling thread because is busy", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
	int returnCode = pthread_cancel(data->clients[clientId].workerData.workerThread);
    if (returnCode != 0)
    {
        addLog("Cancelling thread ERROR", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
    }
	returnCode = pthread_join(data->clients[clientId].workerData.workerThread, &pReturn);
    
	data->clients[clientId].workerData.threadHasBeenCreated = 0;
}

void resetWorkerData(ftpDataType *data, int clientId, int isInitialization)
{
	  my_printf("\nReset of worker id: %d", clientId);
      data->clients[clientId].workerData.connectionPort = 0;
      data->clients[clientId].workerData.passiveModeOn = 0;
      data->clients[clientId].workerData.socketIsConnected = 0;
      data->clients[clientId].workerData.socketIsReadyForConnection = 0;      
      data->clients[clientId].workerData.commandIndex = 0;
      data->clients[clientId].workerData.passiveListeningSocket = 0;
      data->clients[clientId].workerData.socketConnection = 0;
      data->clients[clientId].workerData.bufferIndex = 0;
      data->clients[clientId].workerData.commandReceived = 0;
      data->clients[clientId].workerData.retrRestartAtByte = 0;
      data->clients[clientId].workerData.threadIsAlive = 0;
      data->clients[clientId].workerData.activeModeOn = 0;
      data->clients[clientId].workerData.extendedPassiveModeOn = 0;
      data->clients[clientId].workerData.activeIpAddressIndex = 0;
      data->clients[clientId].workerData.threadHasBeenCreated = 0;

      memset(data->clients[clientId].workerData.buffer, 0, CLIENT_BUFFER_STRING_SIZE+1);
      memset(data->clients[clientId].workerData.activeIpAddress, 0, CLIENT_BUFFER_STRING_SIZE);
      memset(data->clients[clientId].workerData.theCommandReceived, 0, CLIENT_BUFFER_STRING_SIZE+1);

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

        	if (data->clients[clientId].workerData.serverSsl != NULL)
        	{
        		SSL_free(data->clients[clientId].workerData.serverSsl);
        		data->clients[clientId].workerData.serverSsl = NULL;
        	}


        	if (data->clients[clientId].workerData.clientSsl != NULL)
        	{
        		SSL_free(data->clients[clientId].workerData.clientSsl);
        		data->clients[clientId].workerData.clientSsl = NULL;
        	}


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
	if (data->clients[clientId].workerData.threadIsAlive == 1)
	{
		cancelWorker(data, clientId);
	}

	pthread_mutex_destroy(&data->clients[clientId].conditionMutex);
	pthread_cond_destroy(&data->clients[clientId].conditionVariable);

	pthread_mutex_destroy(&data->clients[clientId].writeMutex);

	#ifdef OPENSSL_ENABLED
	if (data->clients[clientId].ssl != NULL)
	{
		SSL_free(data->clients[clientId].ssl);
		data->clients[clientId].ssl = NULL;
	}
	#endif
    }


    if (pthread_mutex_init(&data->clients[clientId].writeMutex, NULL) != 0)
    {
        my_printf("\nclientData->writeMutex init failed\n");
        exit(0);
    }

	if (pthread_mutex_init(&data->clients[clientId].conditionMutex, NULL) != 0)
		  {
		  my_printf("\ndata->clients[clientId].workerData.conditionMutex init failed\n");
		  exit(0);
		  }

	if (pthread_cond_init(&data->clients[clientId].conditionVariable, NULL) != 0)
	{
		my_printf("\ndata->clients[clientId].workerData.conditionVariable init failed\n");
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
    
    
    memset(&data->clients[clientId].client_sockaddr_in, 0, data->clients[clientId].sockaddr_in_size);
    memset(&data->clients[clientId].server_sockaddr_in, 0, data->clients[clientId].sockaddr_in_server_size);
    memset(data->clients[clientId].clientIpAddress, 0, INET_ADDRSTRLEN);
    memset(data->clients[clientId].buffer, 0, CLIENT_BUFFER_STRING_SIZE+1);
    memset(data->clients[clientId].theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE+1);
    cleanLoginData(&data->clients[clientId].login, isInitialization, &data->clients[clientId].memoryTable);
    
    //Rename from and to data init
    cleanDynamicStringDataType(&data->clients[clientId].renameFromFile, isInitialization, &data->clients[clientId].memoryTable);
    cleanDynamicStringDataType(&data->clients[clientId].renameToFile, isInitialization, &data->clients[clientId].memoryTable);
    cleanDynamicStringDataType(&data->clients[clientId].fileToStor, isInitialization, &data->clients[clientId].memoryTable);
    cleanDynamicStringDataType(&data->clients[clientId].fileToRetr, isInitialization, &data->clients[clientId].memoryTable);
    cleanDynamicStringDataType(&data->clients[clientId].listPath, isInitialization, &data->clients[clientId].memoryTable);
    cleanDynamicStringDataType(&data->clients[clientId].listPath, isInitialization, &data->clients[clientId].memoryTable);
    cleanDynamicStringDataType(&data->clients[clientId].ftpCommand.commandArgs, isInitialization, &data->clients[clientId].memoryTable);
    cleanDynamicStringDataType(&data->clients[clientId].ftpCommand.commandOps, isInitialization, &data->clients[clientId].memoryTable);

    data->clients[clientId].connectionTimeStamp = 0;
    data->clients[clientId].tlsNegotiatingTimeStart = 0;
    data->clients[clientId].lastActivityTimeStamp = 0;

	#ifdef OPENSSL_ENABLED
	//data->clients[clientId].workerData.ssl = SSL_new(data->ctx);
	data->clients[clientId].ssl = SSL_new(data->serverCtx);
	#endif

	//my_printf("\nclient memory table :%lld", data->clients[clientId].memoryTable);
}

int compareStringCaseInsensitive(char * stringIn, char * stringRef, int stringLenght)
{
    int i = 0;
    char * alfaLowerCase = "qwertyuiopasdfghjklzxcvbnm .";
    char * alfaUpperCase = "QWERTYUIOPASDFGHJKLZXCVBNM .";

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

    if (stringIn[i] != '\0' &&stringIn[i] != ' ')
        return 0;

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
