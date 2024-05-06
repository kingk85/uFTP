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

#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <limits.h>

#include "fileManagement.h"
#include "dynamicVectors.h"
#include "dynamicMemory.h"
#include "../debugHelper.h"

static int FILE_CompareString(const void * a, const void * b);
static int FILE_CompareString(const void * a, const void * b)
{
    return strcmp (*(const char **) a, *(const char **) b);
}

static int FILE_CompareStringParameter(const void * a, const void * b);

static int FILE_CompareStringParameter(const void * a, const void * b)
{
    const FILE_StringParameter_DataType * typeA = *(const FILE_StringParameter_DataType **)a;
    const FILE_StringParameter_DataType * typeB = *(const FILE_StringParameter_DataType **)b;
   //my_printf("Comparing  %s with %s",typeA->Name, typeB->Name);
    return strcmp(typeA->Name, typeB->Name);
}

static time_t convertToUTC(time_t inputTime);

time_t convertToUTC(time_t inputTime) 
{
    struct tm *utc_tm;
    time_t utc_time;
    utc_tm = gmtime(&inputTime);
    utc_time = mktime(utc_tm);

    //my_printf("\nLocal time: %ld", inputTime);
    //my_printf("\nutc_time time: %ld", utc_time);

    return utc_time;
}

int FILE_fdIsValid(int fd)
{
    return fcntl(fd, F_GETFD);
}

int FILE_CheckIfLinkExist(char * filename)
{

  if (access(filename, F_OK) == 0) 
  {
    return 1;
  }

    return 0;
}

/* Check if inode is a directory */
int FILE_IsDirectory(char *DirectoryPath, int checkExist)
{
    if(checkExist && FILE_CheckIfLinkExist(DirectoryPath) == 0)
        return 0;

    struct stat sb;
    if (stat(DirectoryPath, &sb) == 0 && S_ISDIR(sb.st_mode))
    {
        return 1;
    }
    else
    {
        return 0;
    }

    return 0;
}

long int FILE_GetAvailableSpace(const char* path)
{
    struct statvfs stat;

    if (statvfs(path, &stat) != 0)
    {
        // error happens, just quits here
        return -1;
    }

    // the available size is f_bsize * f_bavail
    return stat.f_bsize * stat.f_bavail;
}

/* Get the file size */
long long int FILE_GetFileSize(FILE *TheFilePointer)
{
#ifdef LARGE_FILE_SUPPORT_ENABLED
	//#warning LARGE FILE SUPPORT IS ENABLED!
    long long int Prev = 0, TheFileSize = 0;
    Prev = ftello64(TheFilePointer);
    fseeko64(TheFilePointer, 0, SEEK_END);
    TheFileSize = ftello64(TheFilePointer);
    fseeko64(TheFilePointer, Prev, SEEK_SET);
    return TheFileSize;
#endif

#ifndef LARGE_FILE_SUPPORT_ENABLED
	#warning LARGE FILE SUPPORT IS NOT ENABLED!
    long long int Prev = 0, TheFileSize = 0;
    Prev = ftell(TheFilePointer);
    fseek(TheFilePointer, 0, SEEK_END);
    TheFileSize = ftell(TheFilePointer);
    fseek(TheFilePointer, Prev, SEEK_SET);
    return TheFileSize;
#endif
}

long long int FILE_GetFileSizeFromPath(char *TheFileName)
{


#ifdef LARGE_FILE_SUPPORT_ENABLED
	//#warning LARGE FILE SUPPORT IS ENABLED!
  if (FILE_IsFile(TheFileName, 1) == 1)
  {
      FILE *TheFilePointer;
      TheFilePointer = fopen64(TheFileName, "rb");
      long long int Prev = 0, TheFileSize = 0;
      Prev = ftello64(TheFilePointer);
      fseeko64(TheFilePointer, 0L, SEEK_END);
      TheFileSize = ftello64(TheFilePointer);
      fseeko64(TheFilePointer, Prev, SEEK_SET);
      fclose(TheFilePointer);
      return TheFileSize;
  }
  else
  {
      return 0;
  }
#endif

#ifndef LARGE_FILE_SUPPORT_ENABLED
#warning LARGE FILE SUPPORT IS NOT ENABLED!
  if (FILE_IsFile(TheFileName, 1) == 1)
  {
      FILE *TheFilePointer;
      TheFilePointer = fopen(TheFileName, "rb");
      long long int Prev = 0, TheFileSize = 0;
      Prev = ftell(TheFilePointer);
      fseek(TheFilePointer, 0L, SEEK_END);
      TheFileSize = ftell(TheFilePointer);
      fseek(TheFilePointer, Prev, SEEK_SET);
      fclose(TheFilePointer);
      return TheFileSize;
  }
  else
  {
      return 0;
  }
#endif


}


int FILE_IsLink( char* path) 
{
  struct stat statbuf;
  if (lstat(path, &statbuf) == -1) {
    perror("lstat");
    return -1; // Error
  }
  return S_ISLNK(statbuf.st_mode);
}

/* Check if a file is valid */
int FILE_IsFile(char *TheFileName, int checkExist)
{
    FILE *TheFile;

    if(checkExist && FILE_CheckIfLinkExist(TheFileName) == 0)
        return 0;

    #ifdef LARGE_FILE_SUPPORT_ENABLED
	//#warning LARGE FILE SUPPORT IS ENABLED!
      TheFile = fopen64(TheFileName, "rb");
    #endif

    #ifndef LARGE_FILE_SUPPORT_ENABLED
#warning LARGE FILE SUPPORT IS NOT ENABLED!
      TheFile = fopen(TheFileName, "rb");
    #endif

    if (TheFile != NULL)
      {
          fclose(TheFile);
          return 1;
      }

    return 0;
}

void FILE_GetDirectoryInodeList(char * DirectoryInodeName, char *** InodeList, int * FilesandFolders, int Recursive, char * commandOps, int checkIfInodeExist, DYNMEM_MemoryTable_DataType ** memoryTable)
{
    int FileAndFolderIndex = *FilesandFolders;
    my_printf("\nLIST DETAILS OF: %s", DirectoryInodeName);
    my_printf("\ncommandOps: %s", commandOps);

    //Allocate the array for the 1st time
    if (*InodeList == NULL)
    {
        (*InodeList) = (char **) DYNMEM_malloc(sizeof(char *), memoryTable, "InodeList");
    }
    
    if (FILE_IsDirectory(DirectoryInodeName, 0))
    {
        DIR *TheDirectory;
        struct dirent *dir;
        TheDirectory = opendir(DirectoryInodeName);
        if (TheDirectory)
        {
            while ((dir = readdir(TheDirectory)) != NULL)
            {
                //
                if ((dir->d_name[0] == '.' && strnlen(dir->d_name, 2) == 1) && (commandOps == NULL || commandOps[0] != 'a'))
                    continue;

                // 
                if ((dir->d_name[0] == '.' && dir->d_name[1] == '.' && strnlen(dir->d_name, 3) == 2) && (commandOps == NULL || commandOps[0] != 'a'))
                    continue;                                

                //Skips all files and dir starting with .
                if ((dir->d_name[0] == '.' && commandOps == NULL) || (dir->d_name[0] == '.' && commandOps[0] != 'a'  && commandOps[0] != 'A'))
                    continue;

                char thePathToCheck[PATH_MAX];
                memset(thePathToCheck, 0, PATH_MAX);

                strcpy(thePathToCheck, DirectoryInodeName);
                strcat(thePathToCheck, "/");
                strcat(thePathToCheck, dir->d_name);

                printf("\n ************* thePathToCheck = %s", thePathToCheck);
                if (checkIfInodeExist == 1 && FILE_CheckIfLinkExist(thePathToCheck) == 0)
                {
                    printf("--> Not valid!");
                    continue;
                }

                //Set the row to needed size
                int ReallocSize = sizeof(char *) * (FileAndFolderIndex+1)+1;
                (*InodeList) = (char ** ) DYNMEM_realloc((*InodeList), ReallocSize, memoryTable);
                size_t nsize = strnlen(dir->d_name, 256) * sizeof(char) + strlen(DirectoryInodeName) * sizeof(char) + 2;

                //Allocate the path string size
                (*InodeList)[FileAndFolderIndex]  = (char *) DYNMEM_malloc (nsize , memoryTable, "InodeList");
                strcpy((*InodeList)[FileAndFolderIndex], DirectoryInodeName );
                strcat((*InodeList)[FileAndFolderIndex], "/" );
                strcat((*InodeList)[FileAndFolderIndex], dir->d_name );
                (*InodeList)[FileAndFolderIndex][ strlen(dir->d_name)  + strlen(DirectoryInodeName) + 1 ] = '\0';
                (*FilesandFolders)++;
                FileAndFolderIndex++;


                if (Recursive == 1 && FILE_IsDirectory((*InodeList)[*FilesandFolders-1], 0) == 1)
                {
                    FILE_GetDirectoryInodeList ( (*InodeList)[FileAndFolderIndex-1], InodeList, FilesandFolders, Recursive, "Z", 0, memoryTable);
                    FileAndFolderIndex = (*FilesandFolders);
                }

            }
            closedir(TheDirectory);
        }

        qsort ((*InodeList), *FilesandFolders, sizeof (const char *), FILE_CompareString);
    }
    else if (FILE_IsFile(DirectoryInodeName, 0))
    {
        //my_printf("\nAdding single file to inode list: %s", DirectoryInodeName);
        int ReallocSize = sizeof(char *) * (FileAndFolderIndex+1)+1;
        (*InodeList) = (char ** ) DYNMEM_realloc((*InodeList), ReallocSize, memoryTable);
        int nsize = strlen(DirectoryInodeName) * sizeof(char) + 2;

        (*InodeList)[FileAndFolderIndex]  = (char *) DYNMEM_malloc (nsize, memoryTable, "InodeList");
        strcpy((*InodeList)[FileAndFolderIndex], DirectoryInodeName );
        (*InodeList)[FileAndFolderIndex][strlen(DirectoryInodeName)] = '\0';
        (*FilesandFolders)++;
        FileAndFolderIndex++;
    }
    else
    {
        //my_printf("\n%s is not a file or a directory", DirectoryInodeName);
        //No valid path specified, returns zero elements
        (*FilesandFolders) = 0;
    }
}

int FILE_GetDirectoryInodeCount(char * DirectoryInodeName)
{
    int FileAndFolderIndex = 0;

    DIR *TheDirectory;
    struct dirent *dir;
    TheDirectory = opendir(DirectoryInodeName);

    if (TheDirectory)
    {
        while ((dir = readdir(TheDirectory)) != NULL)
        {
            if ( dir->d_name[0] == '.' && strnlen(dir->d_name, 2) == 1)
                continue;

            if ( dir->d_name[0] == '.' && dir->d_name[1] == '.' && strnlen(dir->d_name, 3) == 2)
                continue;                                

            FileAndFolderIndex++;

        }
        
        closedir(TheDirectory);
    }

    return FileAndFolderIndex;
}

int FILE_GetStringFromFile(char * filename, char **file_content, DYNMEM_MemoryTable_DataType ** memoryTable)
{
    long long int file_size = 0;
    int c, count;

    if (FILE_IsFile(filename, 1) == 0)
    {
        return 0;
    }


    #ifdef LARGE_FILE_SUPPORT_ENABLED
		//#warning LARGE FILE SUPPORT IS ENABLED!
        FILE *file = fopen64(filename, "rb");
    #endif

    #ifndef LARGE_FILE_SUPPORT_ENABLED
#warning LARGE FILE SUPPORT IS NOT ENABLED!
        FILE *file = fopen(filename, "rb");
    #endif

    if (file == NULL)
    {
        fclose(file);
        return 0;
    }

    file_size = FILE_GetFileSize(file);

    count = 0;
    *file_content  = (char *) DYNMEM_malloc((file_size * sizeof(char) + 100), memoryTable, "getstringfromfile");

    while ((c = fgetc(file)) != EOF)
    {
        (*file_content)[count++] = (char) c;
    }
    (*file_content)[count] = '\0';



    fclose(file);



    return count;
}

void FILE_ReadStringParameters(char * filename, DYNV_VectorGenericDataType *ParametersVector)
{
    FILE *File;
    char Line[FILE_MAX_LINE_LENGHT];
    int i;
    int c;
    char FirstChar = 0;
    char SeparatorChar = 0;
    char ParameterChar = 0;
    int BufferNameCursor = 0;
    int BufferValueCursor = 0;
    FILE_StringParameter_DataType TheParameter;

    memset (TheParameter.Name, 0, FILE_MAX_PAR_VAR_SIZE);
    memset (TheParameter.Value, 0, FILE_MAX_PAR_VAR_SIZE);

    File = fopen(filename, "r");
    if(File == NULL)
    {
        my_printf("error while opening file %s", filename);
    }
    else
    {
    //my_printf("Parameter initializing from file %s", filename);

    while(fgets(Line, FILE_MAX_LINE_LENGHT, File) != NULL)
            {
            //my_printf("LINE: %s", Line);
            i = 0;

            while (i<FILE_MAX_LINE_LENGHT)
            {
            c = Line[i++];
            if (((char) c == ' ' && FirstChar != '#') || (char) c == '\r' || (c == 9 && FirstChar != '#' ) || (c == 10) || (c == 13))
                    {
                    continue;
                    }

            if ((char) c == '\0' )
                    {
              if ((FirstChar != '#' && FirstChar != '=' && FirstChar != 0 ) && SeparatorChar == '=' && ParameterChar != 0 )
                    {
                    TheParameter.Name[BufferNameCursor] = '\0';
                    TheParameter.Value[BufferValueCursor] = '\0';
                    //my_printf("Adding name: %s value: %s", TheParameter.Name, TheParameter.Value);
                    //my_printf("TheParameter.Name[0] = %d", TheParameter.Name[0]);

                    ParametersVector->PushBack(ParametersVector, &TheParameter, sizeof(FILE_StringParameter_DataType));
                            BufferNameCursor = 0;
                            BufferValueCursor = 0;
                            memset (TheParameter.Name, 0, FILE_MAX_PAR_VAR_SIZE);
                            memset (TheParameter.Value, 0, FILE_MAX_PAR_VAR_SIZE);
                }

                    FirstChar = 0;
                    SeparatorChar = 0;
                    ParameterChar = 0;

                    if ((char) c == '\0')
                            {
                            break;
                            }
               }
               else
                    {
                     //my_printf("Checking chars");

                            //first char, parameter name
                            if (FirstChar == 0)
                                    {
                                    FirstChar = (char) c;
                                    //my_printf("FirstChar = %c", FirstChar);
                                    }
                            else if (FirstChar != 0 && SeparatorChar == 0 && (char) c == '=')
                                    {
                                    SeparatorChar = (char) c;
                                    //my_printf("SeparatorChar = %c", SeparatorChar);
                                    }
                            else if (FirstChar != 0 && SeparatorChar != 0 && ParameterChar == 0)
                                    {
                                    ParameterChar = (char) c;
                                    //my_printf("ParameterChar = %c", ParameterChar);
                                    }

                            //Get the parameter name
                            if ( FirstChar != '#' && FirstChar != 0 && SeparatorChar == 0 && BufferNameCursor < FILE_MAX_PAR_VAR_SIZE )
                                            TheParameter.Name[BufferNameCursor++] = (char) c;

                            //Get the parameter value
                            if ( FirstChar != '#' && FirstChar != 0 && SeparatorChar != 0 && ParameterChar != 0 && BufferValueCursor < FILE_MAX_PAR_VAR_SIZE )
                                            TheParameter.Value[BufferValueCursor++] = (char) c;
                    }
                }
            }

            fclose(File);
            }

   // my_printf("ParametersVector->Size %d", ParametersVector->Size);

    for (i = 0; i < ParametersVector->Size; i++)
            {
            //my_printf("ParametersVector->Data[%d])->Name = %s",i, ((FILE_StringParameter_DataType *)ParametersVector->Data[i])->Name);
            }

    qsort(ParametersVector->Data, ParametersVector->Size, sizeof(void *), FILE_CompareStringParameter);

    //my_printf("Sorted");
    for (i = 0; i < ParametersVector->Size; i++)
            {
            //my_printf("ParametersVector->Data[%d])->Name = %s",i, ((FILE_StringParameter_DataType *)ParametersVector->Data[i])->Name);
            }

}

int FILE_StringParametersLinearySearch(DYNV_VectorGenericDataType *TheVectorGeneric, void * name)
{

    for(int i = 0; i < TheVectorGeneric->Size; i++)
    {
        if(strcmp(((FILE_StringParameter_DataType *)TheVectorGeneric->Data[i])->Name, (char *) name) == 0)
        {
            return i;
        }
    }
    return -1;
}

int FILE_StringParametersBinarySearch(DYNV_VectorGenericDataType *TheVectorGeneric, void * Needle)
	{

	long long int CompareResult;

	if (TheVectorGeneric->Size <= 0)
		{
		return -1;
		}

	int littler = 0;
	int last = TheVectorGeneric->Size - 1;
	int middle = (littler + last) / 2;

	while (littler <= last)
		{
		CompareResult = strcmp(((FILE_StringParameter_DataType *)TheVectorGeneric->Data[middle])->Name, Needle);
		//my_printf("CompareResult = %d.\n", CompareResult);

		if ((CompareResult == 0))
			{
			//my_printf("%d found at location %d.\n", Needle, middle);
			return middle;
			}
			else if (CompareResult < 0)
			{
			littler = middle + 1;
			//my_printf("Needle bigger than middle  at %d .\n", middle);
			}
		else
			{
			last = middle - 1;
			//my_printf("Needle lower than middle  at %d.\n", middle);
			}

			middle = (littler + last)/2;
			}


    return -1;

	}

char * FILE_GetFilenameFromPath(char * FileName)
{
	char * TheStr = FileName;
	for (int i = 0; i< strlen(FileName); i++)
		{
		if (FileName[i] == '/' || FileName[i] == '\\')
		{
			TheStr = FileName+i+1;
			}
		}

	return TheStr;
}

char * FILE_GetListPermissionsString(char *file, DYNMEM_MemoryTable_DataType ** memoryTable) {
    struct stat st, stl;
    char *modeval = DYNMEM_malloc(sizeof(char) * 10 + 1, memoryTable, "getperm");
    if(stat(file, &st) == 0) 
    {
        mode_t perm = st.st_mode;
        modeval[0] = (S_ISDIR(st.st_mode)) ? 'd' : '-';
        modeval[1] = (perm & S_IRUSR) ? 'r' : '-';
        modeval[2] = (perm & S_IWUSR) ? 'w' : '-';
        modeval[3] = (perm & S_IXUSR) ? 'x' : '-';
        modeval[4] = (perm & S_IRGRP) ? 'r' : '-';
        modeval[5] = (perm & S_IWGRP) ? 'w' : '-';
        modeval[6] = (perm & S_IXGRP) ? 'x' : '-';
        modeval[7] = (perm & S_IROTH) ? 'r' : '-';
        modeval[8] = (perm & S_IWOTH) ? 'w' : '-';
        modeval[9] = (perm & S_IXOTH) ? 'x' : '-';
        modeval[10] = '\0';

        if(lstat(file, &stl) == 0 &&
          S_ISLNK(stl.st_mode))
        {
                modeval[0] = 'l'; // is a link
        }
    }
    else 
    {
        modeval[0] = '-';
        modeval[1] = 'r';
        modeval[2] = 'w';
        modeval[3] = 'x';
        modeval[4] = 'r';
        modeval[5] = 'w';
        modeval[6] = 'x';
        modeval[7] = 'r';
        modeval[8] = 'w';
        modeval[9] = 'x';
        modeval[10] = '\0';

        if(lstat(file, &stl) == 0 &&
          S_ISLNK(stl.st_mode))
        {
            modeval[0] = 'l'; // is a link
        }
    }

    return modeval;
}

int checkParentDirectoryPermissions(char *fileName, int uid, int gid)
{
	char theFileName[4096];
	memset(theFileName, 0, 4096);

	size_t theFileNameLen = 0;
	size_t theLen = strlen(fileName);
	size_t theParentLen = 0;

	for (size_t i = 0; i < theLen; i++)
	{
		if (fileName[i] == '/')
		{
			theParentLen = i;
		}
	}

	for (size_t i = 0; i < theParentLen; i++)
	{
		if (i < 4096)
			theFileName[theFileNameLen++] = fileName[i];
	}

	//my_printf ("\n checking parent permissions on : %s", theFileName);
	return checkUserFilePermissions(theFileName, uid, gid);
}

int checkUserFilePermissions(char *fileName, int uid, int gid)
{

	if (uid == 0 || gid == 0)
	{
		//my_printf("\n User is root");
		return FILE_PERMISSION_RW;
	}

	int filePermissions = FILE_PERMISSION_NO_RW;
    int returnCode = 0;
    char *toReturn;
    struct stat info;

    if ((returnCode = stat(fileName, &info)) == -1)
    {
    	return -1;
    }

    if (info.st_uid == uid ||
		info.st_gid == gid)
    {
		//my_printf("\n User is owner");
    	filePermissions = FILE_PERMISSION_RW;
    }
    else
    {
        mode_t perm = info.st_mode;
    	if (perm & S_IROTH){
    		//my_printf("\nfile can be readen");
    		filePermissions |= FILE_PERMISSION_R;
    	}

    	if (perm & S_IWOTH){
    		//my_printf("\nfile can be written");
    		filePermissions |= FILE_PERMISSION_W;
    	}
    }

    return filePermissions;
}

char * FILE_GetOwner(char *fileName, DYNMEM_MemoryTable_DataType **memoryTable)
{
    int returnCode = 0;
    char *toReturn;
    struct stat info;

    struct passwd pd;
    struct passwd* pwdptr=&pd;
    struct passwd* tempPwdPtr;
    char pwdbuffer[200];
    int  pwdlinelen = sizeof(pwdbuffer);

    if ((returnCode = stat(fileName, &info)) == -1)
        return NULL;

    if ((getpwuid_r(info.st_uid, pwdptr, pwdbuffer, pwdlinelen, &tempPwdPtr))!=0)
        return NULL;

    toReturn = (char *) DYNMEM_malloc (strlen(pd.pw_name) + 1, memoryTable, "getowner");
    strcpy(toReturn, pd.pw_name);

    return toReturn;
}

char * FILE_GetGroupOwner(char *fileName, DYNMEM_MemoryTable_DataType **memoryTable)
{
    char *toReturn;
    struct stat info;
    short int lp;
    struct group grp;
    struct group * grpptr=&grp;
    struct group * tempGrpPtr;
    char grpbuffer[200];
    int  grplinelen = sizeof(grpbuffer);

    if (stat(fileName, &info) == -1 )
        return NULL;

    if ((getgrgid_r(info.st_gid,grpptr,grpbuffer,grplinelen,&tempGrpPtr))!=0)
        return NULL;
    
    toReturn = (char *) DYNMEM_malloc (strlen(grp.gr_name) + 1, memoryTable, "getowner");
    strcpy(toReturn, grp.gr_name);
    
    return toReturn;
}


void FILE_AppendStringToFile(char *fileName, char *theString)
{
    FILE *fp = fopen(fileName, "a");
    if (fp == NULL)
    {
        my_printfError("\nError while opening file %s.", fileName);
    }

    fprintf(fp, "\n%s", theString);    
    fclose(fp);
}

time_t FILE_GetLastModifiedData(char *path)
{
    struct stat statbuf;
    if (stat(path, &statbuf) == -1)
    {
    	time_t theTime = 0;
    	return theTime;
    }

    return convertToUTC(statbuf.st_mtime);
}

void FILE_AppendToString(char ** sourceString, char *theString, DYNMEM_MemoryTable_DataType ** memoryTable)
{
    size_t theNewSize = strlen(*sourceString) + strlen(theString);
    *sourceString = DYNMEM_realloc(*sourceString, theNewSize + 10, memoryTable);
    strcat(*sourceString, theString);
    (*sourceString)[theNewSize] = '\0';
}

void FILE_DirectoryToParent(char ** sourceString, DYNMEM_MemoryTable_DataType ** memoryTable)
{
   //my_printf("\n");

   int theLastSlash = -1;
   size_t strLen = 0;

   strLen = strlen(*sourceString);
   //my_printf("\nThe directory = %s", (*sourceString));   
   //my_printf("\ndirectory to parent strLen = %d", strLen);

   for (size_t i = 0; i < strLen; i++)
   {
       //my_printf("%c", (*sourceString)[i]);
       if ( (*sourceString)[i] == '/')
       {
           theLastSlash = i;
       }
   }
   
   //my_printf("\n theLastSlash = %d", theLastSlash);

   if (theLastSlash > -1)
   {
       int theNewSize = theLastSlash;
       if (theLastSlash == 0)
       {
           theNewSize = 1;
       }

       //my_printf("\n theNewSize = %d", theNewSize);

       *sourceString = DYNMEM_realloc(*sourceString, theNewSize+1, &*memoryTable);
       (*sourceString)[theNewSize] = '\0';

       //my_printf("\nThe directory upped is = %s", (*sourceString));  
   }
}

int FILE_LockFile(int fd)
{
    struct flock fl;
    fl.l_type = F_WRLCK;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;
    return(fcntl(fd, F_SETLK, &fl));
}

int FILE_doChownFromUidGid(const char *file_path, uid_t uid, gid_t gid)
{
    if (chown(file_path, uid, gid) == -1)
    {
        return 0;
    }

    return 1;
}

int FILE_doChownFromUidGidString (  const char *file_path,
                    const char *user_name,
                    const char *group_name) 
{
    uid_t          uid;
    gid_t          gid;
    const struct group  *grp;
    uid = FILE_getUID(user_name);
    gid = FILE_getGID(group_name);

    if (chown(file_path, uid, gid) == -1)
    {
        return 0;
    }
    
    return 1;
}

uid_t FILE_getUID(const char *user_name)
{
    struct passwd pd;
    struct passwd* pwdptr=&pd;
    struct passwd* tempPwdPtr;
    char pwdbuffer[200];
    int  pwdlinelen = sizeof(pwdbuffer);

    if ((getpwnam_r(user_name, pwdptr, pwdbuffer, pwdlinelen, &tempPwdPtr))!=0)
        return 0;
    else
        return pd.pw_uid;

}

gid_t FILE_getGID(const char *group_name)
{
    short int lp;
    struct group grp;
    struct group * grpptr=&grp;
    struct group * tempGrpPtr;

    char grpbuffer[200];
    int  grplinelen = sizeof(grpbuffer);

    if ((getgrnam_r(group_name, grpptr, grpbuffer, grplinelen, &tempGrpPtr))!=0)
        return 0;
    else
        return grp.gr_gid;
}


void FILE_checkAllOpenedFD(void)
{
	int openedFd = 0;
    int ret;

	struct rlimit rl;
	if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
		my_printf("%s: can’t get file limit", "");

	if (rl.rlim_max == RLIM_INFINITY)
		rl.rlim_max = 1024;

	for (int i = 0; i < rl.rlim_max; i++)
	{
		ret = FILE_fdIsValid(i);
		//my_printf("\nret = %d", ret);
		if (ret != -1)
		{
			struct stat statbuf;
			fstat(i, &statbuf);
			if (S_ISSOCK(statbuf.st_mode))
			{
				//my_printf("\n fd %d is socket", i);
			}
			else if (S_ISDIR(statbuf.st_mode))
			{
				//my_printf("\n fd %d is dir", i);
			}

			openedFd++;
		}
	}
	//my_printf("\n\nOpened fd : %d", openedFd);
}
