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
#include <errno.h>
#include <sys/stat.h>

#include "ftpServer.h"
#include "ftpCommandsElaborate.h"
#include "ftpData.h"

#include "library/configRead.h"
#include "library/fileManagement.h"
#include "library/connection.h"
#include "library/dynamicMemory.h"

#include "debugHelper.h"
#include "library/log.h"


static int resolveForCheck(const char *path, int followLastLink, char *resolved, int *failureReason);
static int isInsideHome(const char *resolvedPath, const char *resolvedHome);
static int missingPartIsInsideHome(const char *path, const char *resolvedHome);
static int getSafePathInternal(dynamicStringDataType *safePath, char *theDirectoryName, loginDataType *loginData, DYNMEM_MemoryTable_DataType **memoryTable, int followLastLink, int *failureReason);
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
        LOG_ERROR("getcwd");
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

/* Split "/a/b/c" into "/a/b" and "c". Returns 0 if there is no usable last component. */
static int splitLastComponent(const char *path, char *parent, char *name)
{
    const char *lastSlash = strrchr(path, '/');

    if (lastSlash == NULL || lastSlash[1] == '\0')
        return 0;

    if (strlen(lastSlash + 1) >= NAME_MAX + 1)
        return 0;

    strcpy(name, lastSlash + 1);

    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        return 0;

    if (lastSlash == path)
    {
        strcpy(parent, "/");
    }
    else
    {
        size_t parentLen = (size_t)(lastSlash - path);
        if (parentLen >= PATH_MAX)
            return 0;
        memcpy(parent, path, parentLen);
        parent[parentLen] = '\0';
    }

    return 1;
}

/* Join an already resolved directory and a name. Returns 0 if it does not fit. */
static int joinPath(const char *directory, const char *name, char *joined)
{
    int written = snprintf(joined, PATH_MAX, "%s/%s", strcmp(directory, "/") == 0 ? "" : directory, name);
    return written > 0 && written < PATH_MAX;
}

/* Where an operation on `path` really ends up on the file system, with every
   symbolic link resolved (realpath of the C library, unlike my_realpath which only
   folds "." and ".." in the text).

   - If the path exists, it is realpath(path).
   - If the last component does not exist yet (STOR, MKD, RNTO targets), it is
     realpath(parent) + "/" + name: the parent must exist.
   - If the last component is a dangling symbolic link, its target is followed
     (an open with O_CREAT would create the file there).
   - With followLastLink == 0 (DELE, RNFR, RNTO: unlink and rename act on the link
     itself) the last component is never followed.

   Returns 1 and fills `resolved` (PATH_MAX bytes), or 0. On failure
   *failureReason is set to an errno value when one is available (ENOENT for a
   missing parent, EACCES, ELOOP, ENAMETOOLONG, ...). */
static int resolveForCheck(const char *path, int followLastLink, char *resolved, int *failureReason)
{
    char current[PATH_MAX];
    char parent[PATH_MAX];
    char parentResolved[PATH_MAX];
    char name[NAME_MAX + 1];
    char joined[PATH_MAX];

    if (failureReason != NULL)
        *failureReason = 0;

    if (path == NULL || path[0] != '/' || strlen(path) >= PATH_MAX)
    {
        if (failureReason != NULL)
            *failureReason = EINVAL;
        return 0;
    }

    strcpy(current, path);

    for (int depth = 0; depth < 16; depth++)       /* bounded: link loops are rejected */
    {
        if (strcmp(current, "/") == 0)
        {
            strcpy(resolved, "/");
            return 1;
        }

        if (followLastLink == 1)
        {
            if (realpath(current, resolved) != NULL)
                return 1;

            if (errno != ENOENT)
            {
                if (failureReason != NULL)
                    *failureReason = errno;
                return 0;
            }
        }

        /* The last component is missing, a dangling link, or must not be followed */
        if (splitLastComponent(current, parent, name) == 0)
        {
            if (failureReason != NULL)
                *failureReason = ENAMETOOLONG;
            return 0;
        }

        if (realpath(parent, parentResolved) == NULL)
        {
            if (failureReason != NULL)
                *failureReason = errno;
            return 0;
        }

        if (joinPath(parentResolved, name, joined) == 0)
        {
            if (failureReason != NULL)
                *failureReason = ENAMETOOLONG;
            return 0;
        }

        if (followLastLink == 1)
        {
            struct stat linkStat;

            if (lstat(joined, &linkStat) == 0 && S_ISLNK(linkStat.st_mode))
            {
                char target[PATH_MAX];
                ssize_t targetLen = readlink(joined, target, sizeof(target) - 1);

                if (targetLen <= 0)
                {
                    if (failureReason != NULL)
                        *failureReason = errno != 0 ? errno : EINVAL;
                    return 0;
                }

                target[targetLen] = '\0';

                if (target[0] == '/')
                {
                    strcpy(current, target);
                }
                else if (joinPath(parentResolved, target, current) == 0)
                {
                    if (failureReason != NULL)
                        *failureReason = ENAMETOOLONG;
                    return 0;
                }

                continue;
            }
        }

        strcpy(resolved, joined);
        return 1;
    }

    if (failureReason != NULL)
        *failureReason = ELOOP;
    return 0;
}

/* A path that does not resolve because a directory is missing. 1 only if the part that
   is missing lies inside the home: the closest directory of the path that exists, once
   its links are resolved, is the home or something below it, and the path itself is not
   a (dangling) link. Otherwise 0.

   The answer decides between a temporary reply (450, directory still to be created) and
   a refusal (550). It must not depend on what exists outside the home: "450 for a
   directory that is missing, 550 for one that exists" would let a user find out which
   directories exist anywhere on the file system (../../etc/x or ../../nonexistent/x). */
static int missingPartIsInsideHome(const char *path, const char *resolvedHome)
{
    char prefix[PATH_MAX];
    char resolvedPrefix[PATH_MAX];
    struct stat linkInfo;

    if (lstat(path, &linkInfo) == 0)
        return 0;                               /* it exists, perhaps as a dangling link: not a missing directory */

    snprintf(prefix, sizeof(prefix), "%s", path);

    for (;;)
    {
        char *lastSlash = strrchr(prefix, '/');

        if (lastSlash == NULL)
            return 0;

        if (lastSlash == prefix)
            prefix[1] = '\0';                  /* the root */
        else
            *lastSlash = '\0';

        if (realpath(prefix, resolvedPrefix) != NULL)
            return isInsideHome(resolvedPrefix, resolvedHome);

        if (strcmp(prefix, "/") == 0)
            return 0;
    }
}

/* 1 if resolvedPath is the home or something below it. Both paths are resolved.
   A plain string prefix is not enough: "/srv/ftp/alice2" starts with "/srv/ftp/alice". */
static int isInsideHome(const char *resolvedPath, const char *resolvedHome)
{
    size_t homeLen = strlen(resolvedHome);

    if (strcmp(resolvedHome, "/") == 0)
        return 1;

    if (strncmp(resolvedPath, resolvedHome, homeLen) != 0)
        return 0;

    return resolvedPath[homeLen] == '\0' || resolvedPath[homeLen] == '/';
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

        /* The pointer used to be left pointing at the freed memory: code that checks
           text != NULL (or passes text on, like the LIST options to the data worker
           after "LIST -a" followed by a plain NLST) then read freed memory. */
        dynamicString->text = 0;
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

/* Path of a client argument, if it is inside the home of the user: links are followed */
int getSafePath(dynamicStringDataType *safePath, char *theDirectoryName, loginDataType *loginData, DYNMEM_MemoryTable_DataType **memoryTable)
{
    return getSafePathInternal(safePath, theDirectoryName, loginData, memoryTable, 1, NULL);
}

/* Same as getSafePath(), and says why the path was refused (*failureReason, an errno
   value, 0 if it was accepted):
   - ENOENT: a directory of the path does not exist. For STOR/APPE this can be a
     directory that another connection is just creating (parallel uploads), so the
     reply is temporary (450) and not permanent (550);
   - EACCES: the path resolves outside the home of the user;
   - another value: the system error that prevented the resolution (permissions, link
     loop, name too long...); EINVAL for an invalid argument. */
int getSafePathWithReason(dynamicStringDataType *safePath, char *theDirectoryName, loginDataType *loginData, DYNMEM_MemoryTable_DataType **memoryTable, int *failureReason)
{
    return getSafePathInternal(safePath, theDirectoryName, loginData, memoryTable, 1, failureReason);
}

/* Same, for the commands that act on the last component itself and not on what a
   link points to (DELE, RNFR, RNTO): the last component is not followed. */
int getSafePathNoFollow(dynamicStringDataType *safePath, char *theDirectoryName, loginDataType *loginData, DYNMEM_MemoryTable_DataType **memoryTable)
{
    return getSafePathInternal(safePath, theDirectoryName, loginData, memoryTable, 0, NULL);
}

static int getSafePathInternal(dynamicStringDataType *safePath, char *theDirectoryName, loginDataType *loginData, DYNMEM_MemoryTable_DataType **memoryTable, int followLastLink, int *failureReason)
{
    int unusedReason;
    if (failureReason == NULL)
        failureReason = &unusedReason;
    *failureReason = EINVAL;

    size_t theLen;
    char * theDirectoryNamePointer;
    theDirectoryNamePointer = theDirectoryName;
    char theDirectoryToCheck[PATH_MAX];
    char resolved_path[PATH_MAX];

    memset(theDirectoryToCheck, 0, PATH_MAX);    
    memset(resolved_path, 0, PATH_MAX);

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
        strncpy(theDirectoryToCheck, loginData->homePath.text, PATH_MAX - 1);
        theDirectoryToCheck[PATH_MAX - 1] = '\0';

        /* HOME configured without a trailing '/': "/dir" must become HOME/dir, not
           HOMEdir (a sibling directory with the same prefix, e.g. "/2" -> home2) */
        size_t homeTextLen = strlen(theDirectoryToCheck);
        if (homeTextLen > 0 && theDirectoryToCheck[homeTextLen - 1] != '/' && theDirectoryNamePointer[0] != '\0')
        {
            strncat(theDirectoryToCheck, "/", PATH_MAX - homeTextLen - 1);
        }

        size_t remaining = PATH_MAX - strlen(theDirectoryToCheck) - 1;
        strncat(theDirectoryToCheck, theDirectoryNamePointer, remaining);
        my_printf("\nAbsolute string: %s", theDirectoryToCheck);
    }
    else
    {
        //Relative directory, start from the current path
        strncpy(theDirectoryToCheck, loginData->absolutePath.text, PATH_MAX - 1);
        theDirectoryToCheck[PATH_MAX - 1] = '\0';

        if (loginData->absolutePath.text[loginData->absolutePath.textLen-1] != '/')
        {
            size_t remaining = PATH_MAX - strlen(theDirectoryToCheck) - 1;
            strncat(theDirectoryToCheck, "/", remaining);
        }

        size_t remaining = PATH_MAX - strlen(theDirectoryToCheck) - 1;
        strncat(theDirectoryToCheck, theDirectoryNamePointer, remaining);
        my_printf("\nRelative string: %s", theDirectoryToCheck);
    }

    my_printf("\nrealpath input: %s", theDirectoryToCheck);
    if (strnlen(theDirectoryToCheck, 2) == 1 && theDirectoryToCheck[0] == '/')
    {
        setDynamicStringDataType(safePath, theDirectoryToCheck, strnlen(theDirectoryToCheck, PATH_MAX), memoryTable);
        *failureReason = 0;
        return 1;
    }

    char* real_path = my_realpath(theDirectoryToCheck, resolved_path);
    if (real_path)
    {
        /* my_realpath only folds "." and ".." in the text (an empty result is the root) */
        if (real_path[0] == '\0')
            strcpy(real_path, "/");

        my_printf("\nResolved path: %s\n", real_path);

        /* The check is done on the paths as the file system resolves them, symbolic
           links included: the text of the path is not enough. */
        char resolvedHome[PATH_MAX];
        char resolvedTarget[PATH_MAX];

        if (realpath(loginData->homePath.text, resolvedHome) == NULL)
        {
            LOGF("%sHome path can not be resolved: %s", LOG_ERROR_PREFIX, loginData->homePath.text);
            *failureReason = EIO;       /* not a problem of the path of the client */
            return 0;
        }

        int resolveFailure = 0;
        int resolved = resolveForCheck(real_path, followLastLink, resolvedTarget, &resolveFailure);

        if (resolved == 1 && isInsideHome(resolvedTarget, resolvedHome) == 1)
        {
            my_printf("\nCheck ok");
            *failureReason = 0;
            /* the returned path is still the one seen through the home (PWD, replies) */
            setDynamicStringDataType(safePath, real_path, strnlen(real_path, PATH_MAX), memoryTable);
        }
        else if (resolved == 1)
        {
            /* The path exists but resolves outside the home: a security event. */
            my_printfError("\nPath check error: %s is not inside %s", real_path, resolvedHome);
            LOGF("%sPath outside the home refused: %s (home %s)", LOG_SECURITY_PREFIX, real_path, resolvedHome);
            *failureReason = EACCES;
            return 0;
        }
        else if (resolveFailure == ENOENT && missingPartIsInsideHome(real_path, resolvedHome) == 0)
        {
            /* A directory is missing, but outside the home (or the path is a dangling
               link): it is refused like any path outside the home, without saying
               whether the directory exists. */
            my_printfError("\nPath check error: %s is not inside %s", real_path, resolvedHome);
            LOGF("%sPath outside the home refused: %s (home %s)", LOG_SECURITY_PREFIX, real_path, resolvedHome);
            *failureReason = EACCES;
            return 0;
        }
        else
        {
            /* Nothing outside the home: the path could not be resolved (missing
               parent, dangling link, permissions, link loop...). Say why: the
               old message said "outside the home" for every failure. */
            const char *reasonText = resolveFailure != 0 ? strerror(resolveFailure) : "invalid path";
            my_printfError("\nPath check error: %s: %s", real_path, reasonText);
            LOGF("%sPath can not be resolved: %s (home %s): %s", LOG_DEBUG_PREFIX, real_path, resolvedHome, reasonText);
            *failureReason = resolveFailure != 0 ? resolveFailure : EINVAL;
            return 0;
        }
    }
    else 
    {
        LOGF("%sRealpath error: %s", LOG_DEBUG_PREFIX, theDirectoryName);
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
    unsigned short int randomicPort;
    int maxAttempts = data->ftpParameters.connectionPortMax - data->ftpParameters.connectionPortMin +1;
    int attempt = 0;
    int conflict;

    while (attempt++ < maxAttempts)
    {
        // Generate a random port in range
        randomicPort = data->ftpParameters.connectionPortMin + 
                       (rand() % (data->ftpParameters.connectionPortMax - data->ftpParameters.connectionPortMin + 1));

        // Check against other clients
        conflict = 0;
        for (int i = 0; i < data->ftpParameters.maxClients; ++i)
        {
            if (i != socketPosition && 
                data->clients[i].workerData.connectionPort == randomicPort)
            {
                conflict = 1;
                break;
            }
        }

        if (conflict)
            continue;

        // Check if port is in use on the system
        if (!isPortInUse(randomicPort))
        {
            data->clients[socketPosition].workerData.connectionPort = randomicPort;
            my_printf("\n data->clients[%d].workerData.connectionPort = %d", 
                      socketPosition, randomicPort);
            return;
        }
    }

    // If we’re here, we failed to find a port
    LOG_ERROR("Failed to find available random port");
    data->clients[socketPosition].workerData.connectionPort = 0;
}

/* The same rule as checkUserFilePermissions(): root, the owner and the group have read and write
   (the execute bit is not looked at), anybody else the "other" bits */
static void mlsxRights(const struct stat *info, int uid, int gid, int *canRead, int *canWrite)
{
    if (uid == 0 || gid == 0 || info->st_uid == (uid_t)uid || info->st_gid == (gid_t)gid)
    {
        *canRead = 1;
        *canWrite = 1;
        return;
    }

    *canRead = (info->st_mode & S_IROTH) != 0;
    *canWrite = (info->st_mode & S_IWOTH) != 0;
}

int FTP_FormatMlsxFacts(char *out, size_t outSize, const struct stat *info, int facts, int uid, int gid)
{
    int isDirectory = S_ISDIR(info->st_mode);
    int canRead, canWrite;
    size_t length = 0;
    int written;

    if (!isDirectory && !S_ISREG(info->st_mode))
    {
        return 0;
    }

    mlsxRights(info, uid, gid, &canRead, &canWrite);
    out[0] = '\0';

#define MLSX_APPEND(...) do { written = snprintf(out + length, outSize - length, __VA_ARGS__); \
                              if (written < 0 || (size_t)written >= outSize - length) return -1; \
                              length += (size_t)written; } while (0)

    if (facts & MLST_FACT_TYPE)
    {
        MLSX_APPEND("type=%s;", isDirectory ? "dir" : "file");
    }

    if (facts & MLST_FACT_SIZE)
    {
        MLSX_APPEND("size=%lld;", (long long int)info->st_size);
    }

    if (facts & MLST_FACT_MODIFY)
    {
        struct tm utc;
        char text[32];
        time_t modified = info->st_mtime;

        gmtime_r(&modified, &utc);
        strftime(text, sizeof(text), "%Y%m%d%H%M%S", &utc);
        MLSX_APPEND("modify=%s;", text);
    }

    if (facts & MLST_FACT_PERM)
    {
        char perm[16];
        int n = 0;

        if (isDirectory)
        {
            if (canRead) { perm[n++] = 'e'; perm[n++] = 'l'; }
            if (canWrite) { perm[n++] = 'c'; perm[n++] = 'm'; perm[n++] = 'p'; perm[n++] = 'd'; perm[n++] = 'f'; }
        }
        else
        {
            if (canRead) perm[n++] = 'r';
            if (canWrite) { perm[n++] = 'a'; perm[n++] = 'w'; perm[n++] = 'd'; perm[n++] = 'f'; }
        }

        perm[n] = '\0';
        MLSX_APPEND("perm=%s;", perm);
    }

    if (facts & MLST_FACT_UNIX_MODE)
    {
        MLSX_APPEND("unix.mode=%04o;", (unsigned int)(info->st_mode & 07777));
    }

    if (facts & MLST_FACT_UNIX_UID)
    {
        MLSX_APPEND("unix.uid=%u;", (unsigned int)info->st_uid);
    }

    if (facts & MLST_FACT_UNIX_GID)
    {
        MLSX_APPEND("unix.gid=%u;", (unsigned int)info->st_gid);
    }

#undef MLSX_APPEND

    return (int)length > 0 ? (int)length : 1;
}

/* MLSD: one line "facts name" per file or directory of thePath, hidden files included, "." and ".."
   not. Links are described by what they point to, dead links and names with a line break are not
   listed (they would break the line format). The same stat() per entry as LIST. */
int FTP_WriteMlsdToSocket(ftpDataType *ftpData, int clientId, char *thePath, int facts, int *filesNumber, DYNMEM_MemoryTable_DataType **memoryTable)
{
    int i, returnCode = 1;
    int fileAndFoldersCount = 0;
    char **fileList = NULL;

    FILE_GetDirectoryInodeList(thePath, &fileList, &fileAndFoldersCount, 0, "A", 0, memoryTable);
    *filesNumber = 0;

    for (i = 0; i < fileAndFoldersCount; i++)
    {
        struct stat info;
        char line[1024];            /* a name is at most 255 bytes, the facts about 120 */
        char *name = FILE_GetFilenameFromPath(fileList[i]);
        int length;

        if (returnCode > 0 && name != NULL && strpbrk(name, "\r\n") == NULL && stat(fileList[i], &info) == 0)
        {
            length = FTP_FormatMlsxFacts(line, sizeof(line) - 1, &info, facts, 
                                         ftpData->clients[clientId].login.ownerShip.uid,
                                         ftpData->clients[clientId].login.ownerShip.gid);
            if (length > 0 && length + (int)strlen(name) + 3 < (int)sizeof(line))
            {
                (*filesNumber)++;
                returnCode = socketWorkerPrintf(ftpData, clientId, "ssss", line, " ", name, "\r\n");
            }
        }

        DYNMEM_free(fileList[i], memoryTable);
    }

    if (fileList != NULL)
    {
        DYNMEM_free(fileList, memoryTable);
    }

    return returnCode > 0 ? 1 : -1;
}

/* thePath and theOptions are passed by the caller: the data worker passes
   the path and options it was given, STAT its own local copies. The function used to
   read the shared client fields listPath and workerData.ftpCommand, which the control
   thread frees and rewrites for every LIST/NLST/STAT. */
int writeListDataInfoToSocket(ftpDataType *ftpData, int clientId, char *thePath, char *theOptions, int *filesNumber, int commandType, DYNMEM_MemoryTable_DataType **memoryTable)
{
    // a --> include . and ..
    // A --> do not include . and ..
    // nothing --> no hidden no . and no ..
    my_printf("\nFILE_GetDirectoryInodeList arg path: %s", thePath);
    my_printf("\nFILE_GetDirectoryInodeList options: %s", theOptions);

    FILE_ClearOwnerCache();         /* the control thread (STAT) lives long: a name changed in /etc/passwd must show */

    int i, x, returnCode = -1;      /* -1: the unknown commandType of the default case counts as a failed write */
    int fileAndFoldersCount = 0;
    char **fileList = NULL;
    FILE_GetDirectoryInodeList(thePath, &fileList, &fileAndFoldersCount, 0, theOptions, 0, memoryTable);
    *filesNumber = fileAndFoldersCount;

    /* RFC 959: NLST returns pathnames and nothing else, the summary line is for LIST */
    if (commandType == COMMAND_TYPE_LIST)
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
        /* these were read without having been set for a file that is neither (a FIFO, a socket, a device): the
           entry was listed or not by chance, and a broken link was listed with a garbage size */
        data.isLink = 0;
        data.fileSize = 0;
        data.numberOfSubDirectories = 0;

        /* One stat() and one lstat() per file give everything a listing needs (type, size, owner, group,
           permissions, time): it used to make about sixteen system calls per file, opening and closing the
           file three times, and LIST of a big directory was slow. */
        struct stat fileStat, linkStat;
        int fileStatOk = (stat(fileList[i], &fileStat) == 0);
        int linkStatOk = (lstat(fileList[i], &linkStat) == 0);

        if (fileStatOk && S_ISDIR(fileStat.st_mode))
        {
            data.isDirectory = 1;
            data.isFile = 0;
            data.isLink = 0;
            data.fileSize = 4096;
            data.numberOfSubDirectories = FILE_GetDirectoryInodeCount(fileList[i]);
        }
        else if (fileStatOk && S_ISREG(fileStat.st_mode) && access(fileList[i], R_OK) == 0)
        {
            data.isDirectory = 0;
            data.isFile = 1;
            data.isLink = 0;
            data.numberOfSubDirectories = 1; /* to Do*/
            data.fileSize = (long long int)fileStat.st_size;
        }
        else if (linkStatOk && S_ISLNK(linkStat.st_mode))
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

        data.owner = fileStatOk ? FILE_GetOwnerFromId(fileStat.st_uid, memoryTable) : NULL;
        data.groupOwner = fileStatOk ? FILE_GetGroupOwnerFromId(fileStat.st_gid, memoryTable) : NULL;
        data.fileNameWithPath = fileList[i];
        data.fileNameNoPath = FILE_GetFilenameFromPath(fileList[i]);
        data.inodePermissionString = FILE_GetListPermissionsStringFromStat(&fileStat, fileStatOk, &linkStat, linkStatOk, memoryTable);
        data.lastModifiedData = fileStatOk ? FILE_ConvertModifiedTime(fileStat.st_mtime) : 0;

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
                if ((len = readlink (fileList[i], data.linkPath, CLIENT_COMMAND_STRING_SIZE - 1)) > 0)
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
                ,data.lastModifiedDataString
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
                ,data.lastModifiedDataString
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

void deleteListDataInfoVector(DYNV_VectorGenericDataType *theVector)
{
    for (int i = 0; i < theVector->Size; i++)
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
	  my_printf("\nReset of worker id: %d", clientId);
      data->clients[clientId].workerData.connectionPort = 0;
      data->clients[clientId].workerData.passiveModeOn = 0;
      data->clients[clientId].workerData.socketIsConnected = 0;
      data->clients[clientId].workerData.socketIsReadyForConnection = 0;      
      data->clients[clientId].workerData.commandIndex = 0;
      /* -1 = not open: 0 is a valid descriptor and must never be closed by mistake */
      data->clients[clientId].workerData.passiveListeningSocket = -1;
      data->clients[clientId].workerData.socketConnection = -1;
      data->clients[clientId].workerData.bufferIndex = 0;
      data->clients[clientId].workerData.commandReceived = 0;
      // data->clients[clientId].workerData.retrRestartAtByte = 0;
      data->clients[clientId].workerData.threadIsAlive = 0;
      data->clients[clientId].workerData.activeModeOn = 0;
      data->clients[clientId].workerData.extendedPassiveModeOn = 0;
      data->clients[clientId].workerData.activeIpAddressIndex = 0;
      data->clients[clientId].workerData.commandProcessed = 0;

      memset(data->clients[clientId].workerData.buffer, 0, CLIENT_BUFFER_STRING_SIZE+1);
      memset(data->clients[clientId].workerData.activeIpAddress, 0, CLIENT_BUFFER_STRING_SIZE);
      memset(data->clients[clientId].workerData.theCommandReceived, 0, CLIENT_BUFFER_STRING_SIZE+1);
      memset(data->clients[clientId].workerData.theCommandResponse, 0, STRING_SZ_SMALL+1);

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

        /* a download stopped half way (ABOR, QUIT, a new PASV, the client gone): the worker was cancelled
           in write() and the file it had opened was never closed (a descriptor and its buffer, at every stop) */
        if (data->clients[clientId].workerData.theRetrFile != NULL)
        {
            fclose(data->clients[clientId].workerData.theRetrFile);
            data->clients[clientId].workerData.theRetrFile = NULL;
        }

			#ifdef OPENSSL_ENABLED

        	if (data->clients[clientId].workerData.serverSsl != NULL)
        	{
        		SSL_free(data->clients[clientId].workerData.serverSsl);
        		data->clients[clientId].workerData.serverSsl = NULL;
        	}

			#endif
      }
      else
      {
        DYNV_VectorGeneric_Init(&data->clients[clientId].workerData.directoryInfo);
        data->clients[clientId].workerData.theStorFile = NULL;
        data->clients[clientId].workerData.theRetrFile = NULL;
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
    #if OPENSSL_VERSION_NUMBER >= 0x10101000L
    /* No TLS 1.3 session ticket on the data connection. A client that uploads starts to send
       the file right after its Finished; over a link with some latency the ticket of the
       server crosses with the data and GnuTLS clients (lftp, FileZilla) answer with a reset:
       426 and a file cut after the first TLS record. The control connection still sends the
       tickets, which are what a client resumes. */
    if (data->clients[clientId].workerData.serverSsl != NULL)
        SSL_set_num_tickets(data->clients[clientId].workerData.serverSsl, 0);
    #endif
    #endif
}

void resetClientData(ftpDataType *data, int clientId, int isInitialization)
{
    if (isInitialization != 1)
    {

        handleThreadReuse(data, clientId);
        
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


    /* Serialises everything written on (and read from, with TLS) the control
       connection: the control thread and the data worker both reply on it. Recursive,
       so a multi-line reply can hold it across several socketPrintf() calls. */
    pthread_mutexattr_t writeMutexAttributes;
    pthread_mutexattr_init(&writeMutexAttributes);
    pthread_mutexattr_settype(&writeMutexAttributes, PTHREAD_MUTEX_RECURSIVE);
    int writeMutexReturnCode = pthread_mutex_init(&data->clients[clientId].writeMutex, &writeMutexAttributes);
    pthread_mutexattr_destroy(&writeMutexAttributes);

    if (writeMutexReturnCode != 0)
    {
        my_printf("\nclientData->writeMutex init failed\n");
        LOGF_NOW("%swriteMutex init failed for client %d, exiting", LOG_FATAL_PREFIX, clientId);
        exit(0);
    }

	if (pthread_mutex_init(&data->clients[clientId].conditionMutex, NULL) != 0)
		  {
		  my_printf("\ndata->clients[clientId].workerData.conditionMutex init failed\n");
		  LOGF_NOW("%sconditionMutex init failed for client %d, exiting", LOG_FATAL_PREFIX, clientId);
		  exit(0);
		  }

	if (pthread_cond_init(&data->clients[clientId].conditionVariable, NULL) != 0)
	{
		my_printf("\ndata->clients[clientId].workerData.conditionVariable init failed\n");
		LOGF_NOW("%sconditionVariable init failed for client %d, exiting", LOG_FATAL_PREFIX, clientId);
		exit(0);
	}

    data->clients[clientId].tlsIsNegotiating = 0;
    data->clients[clientId].tlsIsEnabled = 0;
    data->clients[clientId].dataChannelIsTls = 0;
    data->clients[clientId].socketDescriptor = -1;
    data->clients[clientId].socketCommandReceived = 0;
    data->clients[clientId].socketIsConnected = 0;
    data->clients[clientId].socketEventReady = 0;
    data->clients[clientId].bufferIndex = 0;
    data->clients[clientId].commandIndex = 0;
    data->clients[clientId].telnetState = 0;
    data->clients[clientId].closeTheClient = 0;
    data->clients[clientId].closeReason = NULL;
    data->clients[clientId].accessLogged = 0;
    memset(data->clients[clientId].logUserName, 0, sizeof(data->clients[clientId].logUserName));
    data->clients[clientId].dataReplyPending = 0;
    data->clients[clientId].sockaddr_in_size = sizeof(struct sockaddr_in);
    data->clients[clientId].sockaddr_in_server_size = sizeof(struct sockaddr_in);
    data->clients[clientId].pbszIsSet = 0;
    data->clients[clientId].epsvAllUsed = 0;
    data->clients[clientId].controlChannelCleared = 0;
    data->clients[clientId].mlstFacts = MLST_FACTS_ALL;
    data->clients[clientId].recordStructure = 0;
    data->clients[clientId].cccShutdownPending = CCC_SHUTDOWN_DONE;
    
    memset(&data->clients[clientId].client_sockaddr_in, 0, data->clients[clientId].sockaddr_in_size);
    memset(&data->clients[clientId].server_sockaddr_in, 0, data->clients[clientId].sockaddr_in_server_size);
    memset(data->clients[clientId].clientIpAddress, 0, sizeof(data->clients[clientId].clientIpAddress));
    memset(data->clients[clientId].buffer, 0, CLIENT_BUFFER_STRING_SIZE+1);
    memset(data->clients[clientId].theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE+1);
    cleanLoginData(&data->clients[clientId].login, isInitialization, &data->clients[clientId].memoryTable);
    
    //Rename from and to data init
    cleanDynamicStringDataType(&data->clients[clientId].renameFromFile, isInitialization, &data->clients[clientId].memoryTable);
    cleanDynamicStringDataType(&data->clients[clientId].renameFromFileWd, isInitialization, &data->clients[clientId].memoryTable);
    cleanDynamicStringDataType(&data->clients[clientId].renameToFile, isInitialization, &data->clients[clientId].memoryTable);
    cleanDynamicStringDataType(&data->clients[clientId].fileToStor, isInitialization, &data->clients[clientId].memoryTable);
    cleanDynamicStringDataType(&data->clients[clientId].fileToRetr, isInitialization, &data->clients[clientId].memoryTable);
    cleanDynamicStringDataType(&data->clients[clientId].listPath, isInitialization, &data->clients[clientId].memoryTable);
    cleanDynamicStringDataType(&data->clients[clientId].listPath, isInitialization, &data->clients[clientId].memoryTable);
    cleanDynamicStringDataType(&data->clients[clientId].ftpCommand.commandArgs, isInitialization, &data->clients[clientId].memoryTable);
    cleanDynamicStringDataType(&data->clients[clientId].ftpCommand.commandOps, isInitialization, &data->clients[clientId].memoryTable);

    data->clients[clientId].connectionTimeStamp = 0;
    data->clients[clientId].loginTimerStart = 0;
    data->clients[clientId].tlsNegotiatingTimeStart = 0;
    data->clients[clientId].lastActivityTimeStamp = 0;

	#ifdef OPENSSL_ENABLED
	data->clients[clientId].ssl = SSL_new(data->serverCtx);
	#endif

	//my_printf("\nclient memory table :%lld", data->clients[clientId].memoryTable);
}

int compareStringCaseInsensitive(char * stringIn, char * stringRef, int stringLenght)
{
    int i = 0;
    char *alfaLowerCase = "qwertyuiopasdfghjklzxcvbnm .";
    char *alfaUpperCase = "QWERTYUIOPASDFGHJKLZXCVBNM .";

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
    for (int i = 0; i < stringLen; i++)
    {
        if (theString[i] == theChar)
        {
            return i;
        }
    }

    return -1;
}


