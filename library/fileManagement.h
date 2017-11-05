#ifndef GEN_FILE_MANAGEMENT_TYPES

    #include <stdio.h> 
    #include <time.h> 
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

    int  FILE_GetFileSize(FILE *theFilePointer);
    long int FILE_GetAvailableSpace(const char* ThePath);
    int FILE_GetFileSizeFromPath(char *TheFileName);
    int  FILE_IsFile(const char *theFileName);
    int  FILE_IsDirectory (char *directory_path);
    void FILE_GetDirectoryInodeList(char * DirectoryInodeName, char *** InodeList, int * filesandfolders, int recursive);
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
    char *FILE_DirectoryToParent(char ** sourceString);
#define	GEN_FILE_MANAGEMENT_TYPES
#endif
