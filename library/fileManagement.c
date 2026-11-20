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

int FILE_CheckIfLinkExist(const char * filename)
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

      /* the file was there a moment ago (FILE_IsFile): it can be gone, or no longer readable,
         when it is opened. It used to be used without looking: SIGSEGV */
      if (TheFilePointer == NULL)
      {
          return 0;
      }

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
  if (FILE_IsFile(TheFileName, 1) == 1)
  {
      FILE *TheFilePointer;
      TheFilePointer = fopen(TheFileName, "rb");
      long long int Prev = 0, TheFileSize = 0;

      if (TheFilePointer == NULL)
      {
          return 0;
      }

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
int FILE_IsFile(const char *TheFileName, int checkExist)
{
    FILE *TheFile;
    struct stat fileStat;

    if(checkExist && FILE_CheckIfLinkExist(TheFileName) == 0)
        return 0;

    /* Regular files only (links are followed): fopen() also succeeds on a directory
       and blocks on a FIFO without a writer. */
    if (TheFileName == NULL || stat(TheFileName, &fileStat) != 0 || !S_ISREG(fileStat.st_mode))
        return 0;

    #ifdef LARGE_FILE_SUPPORT_ENABLED
	//#warning LARGE FILE SUPPORT IS ENABLED!
      TheFile = fopen64(TheFileName, "rb");
    #endif

    #ifndef LARGE_FILE_SUPPORT_ENABLED
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

                /* Directory + "/" + entry name used to be joined with strcpy/strcat
                   into this PATH_MAX stack buffer with no length check. A directory whose
                   path is close to PATH_MAX (paths are accepted up to PATH_MAX - 1) overflowed
                   it, already with the "." and ".." entries of "LIST -a" / "STAT -a".
                   An entry whose full path does not fit can not be opened by the system
                   either (ENAMETOOLONG): it is skipped. */
                int thePathLength = snprintf(thePathToCheck, PATH_MAX, "%s/%s", DirectoryInodeName, dir->d_name);
                if (thePathLength < 0 || thePathLength >= PATH_MAX)
                {
                    my_printf("\nSkipping %s: path too long", dir->d_name);
                    continue;
                }


                if (checkIfInodeExist == 1 && FILE_CheckIfLinkExist(thePathToCheck) == 0)
                {

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
        FILE *file = fopen(filename, "rb");
    #endif

    if (file == NULL)
    {
        return 0;          /* it used to be fclose(NULL) */
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

/* The permission string of a listing from the results of stat() and lstat() that the caller has already made
   (a listing used to make eight system calls per file, the same information again and again). */
char * FILE_GetListPermissionsStringFromStat(const struct stat *st, int statOk, const struct stat *stl, int lstatOk, DYNMEM_MemoryTable_DataType ** memoryTable)
{
    char *modeval = DYNMEM_malloc(sizeof(char) * 10 + 1, memoryTable, "getperm");

    if (statOk)
    {
        mode_t perm = st->st_mode;
        modeval[0] = (S_ISDIR(st->st_mode)) ? 'd' : '-';
        modeval[1] = (perm & S_IRUSR) ? 'r' : '-';
        modeval[2] = (perm & S_IWUSR) ? 'w' : '-';
        modeval[3] = (perm & S_IXUSR) ? 'x' : '-';
        modeval[4] = (perm & S_IRGRP) ? 'r' : '-';
        modeval[5] = (perm & S_IWGRP) ? 'w' : '-';
        modeval[6] = (perm & S_IXGRP) ? 'x' : '-';
        modeval[7] = (perm & S_IROTH) ? 'r' : '-';
        modeval[8] = (perm & S_IWOTH) ? 'w' : '-';
        modeval[9] = (perm & S_IXOTH) ? 'x' : '-';
    }
    else
    {
        memcpy(modeval, "-rwxrwxrwx", 10);
    }
    modeval[10] = '\0';

    if (lstatOk && S_ISLNK(stl->st_mode))
        modeval[0] = 'l'; // is a link

    return modeval;
}

char * FILE_GetListPermissionsString(char *file, DYNMEM_MemoryTable_DataType ** memoryTable) {
    struct stat st, stl;
    int statOk = (stat(file, &st) == 0);
    int lstatOk = (lstat(file, &stl) == 0);

    return FILE_GetListPermissionsStringFromStat(&st, statOk, &stl, lstatOk, memoryTable);
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

/* 1 if the file system of `path` (a file, also one that does not exist yet) has less than
   minimumBytes available. The blocks reserved for root are not counted as free (f_bavail): the
   server runs as root and would use them. 0 if there is enough, or if it can not be asked. */
int FILE_FreeSpaceIsBelow(const char *path, long long int minimumBytes)
{
    struct statvfs info;
    char directory[PATH_MAX];
    char *lastSlash;

    if (minimumBytes <= 0)
    {
        return 0;
    }

    snprintf(directory, sizeof(directory), "%s", path);
    lastSlash = strrchr(directory, '/');

    if (lastSlash == directory)
    {
        directory[1] = '\0';
    }
    else if (lastSlash != NULL)
    {
        *lastSlash = '\0';
    }

    if (statvfs(directory, &info) != 0)
    {
        return 0;
    }

    return (unsigned long long int)info.f_bavail * info.f_frsize < (unsigned long long int)minimumBytes;
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

/* Name of a user or group id for the listings, or the id itself when the system does
   not know it (like ls). getpwuid_r/getgrgid_r return 0 with a null result when the id
   is not in /etc/passwd or /etc/group: the name used to be copied from the struct
   anyway, which had never been filled, and LIST crashed the server (files from
   containers, NFS, archives extracted with their owners, deleted users). */
static char *ownerNameOrId(const char *theName, unsigned long theId, DYNMEM_MemoryTable_DataType **memoryTable)
{
    char idText[24];
    char *toReturn;

    if (theName == NULL)
    {
        snprintf(idText, sizeof(idText), "%lu", theId);
        theName = idText;
    }

    toReturn = (char *) DYNMEM_malloc (strlen(theName) + 1, memoryTable, "getowner");
    strcpy(toReturn, theName);
    return toReturn;
}

/* The files of a directory almost always have the same owner: the last one is remembered, otherwise
   every file of a listing reads /etc/passwd again (about 100 microseconds each). A listing starts with
   FILE_ClearOwnerCache(): the control thread lives as long as the server and serves STAT, so what it
   remembered would get old. */
static __thread int cachedUidValid = 0;
static __thread uid_t cachedUid;
static __thread char cachedUserName[64];
static __thread int cachedGidValid = 0;
static __thread gid_t cachedGid;
static __thread char cachedGroupName[64];

void FILE_ClearOwnerCache(void)
{
    cachedUidValid = 0;
    cachedGidValid = 0;
}

char * FILE_GetOwnerFromId(uid_t uid, DYNMEM_MemoryTable_DataType **memoryTable)
{
    struct passwd pd;
    struct passwd *result = NULL;
    char pwdbuffer[1024];

    if (cachedUidValid == 1 && cachedUid == uid)
        return ownerNameOrId(cachedUserName[0] != 0 ? cachedUserName : NULL, (unsigned long)uid, memoryTable);

    /* an error (ERANGE for a very long entry, ...) is shown as the id too */
    if (getpwuid_r(uid, &pd, pwdbuffer, sizeof(pwdbuffer), &result) != 0)
        result = NULL;

    cachedUid = uid;
    cachedUidValid = 1;
    snprintf(cachedUserName, sizeof(cachedUserName), "%s", result != NULL ? result->pw_name : "");
    if (result != NULL && strlen(result->pw_name) >= sizeof(cachedUserName))
        cachedUidValid = 0;                 /* a name too long for the cache is not remembered */

    return ownerNameOrId(result != NULL ? result->pw_name : NULL, (unsigned long)uid, memoryTable);
}

char * FILE_GetGroupOwnerFromId(gid_t gid, DYNMEM_MemoryTable_DataType **memoryTable)
{
    struct group grp;
    struct group *result = NULL;
    char grpbuffer[1024];

    if (cachedGidValid == 1 && cachedGid == gid)
        return ownerNameOrId(cachedGroupName[0] != 0 ? cachedGroupName : NULL, (unsigned long)gid, memoryTable);

    if (getgrgid_r(gid, &grp, grpbuffer, sizeof(grpbuffer), &result) != 0)
        result = NULL;

    cachedGid = gid;
    cachedGidValid = 1;
    snprintf(cachedGroupName, sizeof(cachedGroupName), "%s", result != NULL ? result->gr_name : "");
    if (result != NULL && strlen(result->gr_name) >= sizeof(cachedGroupName))
        cachedGidValid = 0;

    return ownerNameOrId(result != NULL ? result->gr_name : NULL, (unsigned long)gid, memoryTable);
}

char * FILE_GetOwner(char *fileName, DYNMEM_MemoryTable_DataType **memoryTable)
{
    struct stat info;

    if (stat(fileName, &info) == -1)
        return NULL;

    return FILE_GetOwnerFromId(info.st_uid, memoryTable);
}

char * FILE_GetGroupOwner(char *fileName, DYNMEM_MemoryTable_DataType **memoryTable)
{
    struct stat info;

    if (stat(fileName, &info) == -1)
        return NULL;

    return FILE_GetGroupOwnerFromId(info.st_gid, memoryTable);
}

/* The modification time of a file as the listings show it (see FILE_GetLastModifiedData). */
time_t FILE_ConvertModifiedTime(time_t modified)
{
    return convertToUTC(modified);
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

int FILE_DirectoryToParent(char ** sourceString, DYNMEM_MemoryTable_DataType ** memoryTable)
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
   if (theLastSlash == 0 && strLen == 1)
   {
    return 0;
   }

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

   return 1;
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

/* Buffer for getpwnam_r/getgrnam_r: the size suggested by the system, at least 16 KB.
   It used to be 200 bytes: a longer entry (ERANGE) made a valid owner become root. */
static size_t lookupBufferSize(int name)
{
    long suggested = sysconf(name);
    return (suggested > 16384) ? (size_t)suggested : 16384;
}

/* uid of a user name. Returns 1 if the user exists, 0 otherwise (*uid untouched). */
int FILE_lookupUID(const char *user_name, uid_t *uid)
{
    struct passwd pd;
    struct passwd *result = NULL;
    size_t size = lookupBufferSize(_SC_GETPW_R_SIZE_MAX);
    char *buffer = malloc(size);

    if (buffer == NULL || user_name == NULL)
    {
        free(buffer);
        return 0;
    }

    /* a user that does not exist is not an error: 0 is returned with a null result,
       and the struct is not filled */
    int found = (getpwnam_r(user_name, &pd, buffer, size, &result) == 0 && result != NULL);
    if (found)
        *uid = pd.pw_uid;

    free(buffer);
    return found;
}

/* gid of a group name. Returns 1 if the group exists, 0 otherwise (*gid untouched). */
int FILE_lookupGID(const char *group_name, gid_t *gid)
{
    struct group grp;
    struct group *result = NULL;
    size_t size = lookupBufferSize(_SC_GETGR_R_SIZE_MAX);
    char *buffer = malloc(size);

    if (buffer == NULL || group_name == NULL)
    {
        free(buffer);
        return 0;
    }

    int found = (getgrnam_r(group_name, &grp, buffer, size, &result) == 0 && result != NULL);
    if (found)
        *gid = grp.gr_gid;

    free(buffer);
    return found;
}

