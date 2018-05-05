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

#ifndef GEN_FILE_MANAGEMENT_TYPES
    #define _LARGEFILE64_SOURCE
    #include <stdio.h> 
    #include <time.h> 
    #include <sys/types.h>
    #include "dynamicVectors.h"

    #define FILE_MAX_LINE_LENGHT			512
    #define FILE_MAX_PAR_VAR_SIZE			256

    typedef struct FILE_StringParameterDataStruct
    {
    char Name[FILE_MAX_PAR_VAR_SIZE];
    char Value[FILE_MAX_PAR_VAR_SIZE];
    }
    FILE_StringParameter_DataType;

    typedef struct FILE_fileInfo_DataStruct
    {
        char    *fileName;
        char    *owner;
        char    *groupOwner;
        char    *permissions;
    }
    FILE_fileInfo_DataType;

    long long int  FILE_GetFileSize(FILE *theFilePointer);
    long int FILE_GetAvailableSpace(const char* ThePath);
    long long int FILE_GetFileSizeFromPath(char *TheFileName);
    int  FILE_IsFile(const char *theFileName);
    int  FILE_IsDirectory (char *directory_path);
    void FILE_GetDirectoryInodeList(char * DirectoryInodeName, char *** InodeList, int * filesandfolders, int recursive);
    int  FILE_GetDirectoryInodeCount(char * DirectoryInodeName);
    int  FILE_GetStringFromFile(char * filename, char **file_content);
    void FILE_ReadStringParameters(char * filename, DYNV_VectorGenericDataType *ParametersVector);
    int FILE_StringParametersLinearySearch(DYNV_VectorGenericDataType *TheVectorGeneric, void * name);
    int FILE_StringParametersBinarySearch(DYNV_VectorGenericDataType *TheVectorGeneric, void * Needle);
    char * FILE_GetFilenameFromPath(char * filename);
    char * FILE_GetListPermissionsString(char *file);
    char * FILE_GetOwner(char *fileName);
    char * FILE_GetGroupOwner(char *fileName);
    time_t FILE_GetLastModifiedData(char *path);
    void FILE_AppendToString(char ** sourceString, char *theString);
    void FILE_DirectoryToParent(char ** sourceString);
    int FILE_LockFile(int fd);
    int FILE_doChownFromUidGidString(const char *file_path, const char *user_name, const char *group_name);
    int FILE_doChownFromUidGid(const char *file_path, uid_t uid, gid_t gid);
    uid_t FILE_getUID(const char *user_name);
    gid_t FILE_getGID(const char *group_name);
#define	GEN_FILE_MANAGEMENT_TYPES
#endif
