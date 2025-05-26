#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <semaphore.h>
#include <limits.h>
#include <sys/stat.h>
#include <ctype.h>
#include <dirent.h>

#include "log.h"
#include "../debugHelper.h"
#include "dynamicVectors.h"
#include "fileManagement.h"

#define LOG_LINE_SIZE  (1024 + PATH_MAX)
#define LOG_FILENAME_PREFIX "uftpLog_"
#define MAX_FILENAME_LENGTH 256

static void* logThread(void* arg);
static int deleteOldLogs(const char* folderPath, int daysToKeep);
static long long getDateNumeric(const char* str);

static DYNV_VectorString_DataType logQueue;
static DYNV_VectorString_DataType workerQueue;

static sem_t logSem;
static pthread_t logThreadId;
static pthread_mutex_t logMutex = PTHREAD_MUTEX_INITIALIZER;

static int maxLogFiles = 0;
static char logFolder[PATH_MAX] = {0};

// Convert YYYY-MM-DD to comparable numeric
static long long getDateNumeric(const char* str) {
    if (strlen(str) != 10 || str[4] != '-' || str[7] != '-') return 0;
    char year[5] = {0}, month[3] = {0}, day[3] = {0};

    strncpy(year, str, 4);
    strncpy(month, str + 5, 2);
    strncpy(day, str + 8, 2);

    return atoll(year) * 365 + (atoll(month) - 1) * 31 + atoll(day);
}

static int deleteOldLogs(const char* folderPath, int daysToKeep) {
    DIR* dir = opendir(folderPath);
    if (!dir) {
        perror("opendir");
        return -1;
    }

    time_t now = time(NULL);
    struct tm* today = localtime(&now);
    char todayStr[11];
    strftime(todayStr, sizeof(todayStr), "%Y-%m-%d", today);
    long long todayNumeric = getDateNumeric(todayStr);

    struct dirent* entry;
    char filePath[PATH_MAX];
    struct stat fileStat;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_REG) continue;
        if (strncmp(entry->d_name, LOG_FILENAME_PREFIX, strlen(LOG_FILENAME_PREFIX)) != 0) continue;

        snprintf(filePath, sizeof(filePath), "%s%s", folderPath, entry->d_name);
        if (stat(filePath, &fileStat) != 0) continue;

        long long fileDate = getDateNumeric(entry->d_name + strlen(LOG_FILENAME_PREFIX));
        if (fileDate > 0 && (fileDate + daysToKeep < todayNumeric)) {
            my_printf("\nRemoving old log file: %s", filePath);
            remove(filePath);
        }
    }

    closedir(dir);
    return 0;
}

static void* logThread(void* arg) {
    int lastDay = -1;

    while (1) {
        sem_wait(&logSem);

        time_t now = time(NULL);
        struct tm* tm_now = localtime(&now);

        char dateStr[11], logFilePath[PATH_MAX];
        strftime(dateStr, sizeof(dateStr), "%Y-%m-%d", tm_now);
        snprintf(logFilePath, sizeof(logFilePath), "%s%s%s", logFolder, LOG_FILENAME_PREFIX, dateStr);

        int currentDay = tm_now->tm_mday;
        if (currentDay != lastDay) {
            deleteOldLogs(logFolder, maxLogFiles);
            lastDay = currentDay;
        }

        pthread_mutex_lock(&logMutex);
        for (int i = 0; i < logQueue.Size; ++i) {
            workerQueue.PushBack(&workerQueue, logQueue.Data[i], strnlen(logQueue.Data[i], LOG_LINE_SIZE));
        }
        while (logQueue.Size > 0) logQueue.PopBack(&logQueue);
        pthread_mutex_unlock(&logMutex);

        for (int i = 0; i < workerQueue.Size; ++i) {
            FILE_AppendStringToFile(logFilePath, workerQueue.Data[i]);
        }
        while (workerQueue.Size > 0) workerQueue.PopBack(&workerQueue);
    }
}

int logInit(const char* folder, int numberOfLogFiles) {
    if (numberOfLogFiles <= 0 || !folder) return -1;

    maxLogFiles = numberOfLogFiles;
    snprintf(logFolder, sizeof(logFolder), "%s", folder);

    DYNV_VectorString_Init(&logQueue);
    DYNV_VectorString_Init(&workerQueue);

    sem_init(&logSem, 0, 0);

    if (pthread_create(&logThreadId, NULL, logThread, NULL) != 0) {
        addLog("Failed to create log thread", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
        return -1;
    }

    deleteOldLogs(logFolder, maxLogFiles);
    my_printf("\nLog system initialized in folder: %s", logFolder);

    return 1;
}

void addLog(const char* message, const char* file, int line, const char* function) {
    if (maxLogFiles <= 0 || !message) return;

    char logEntry[LOG_LINE_SIZE] = {0};
    time_t now = time(NULL);
    struct tm* tm_now = localtime(&now);

    strftime(logEntry, sizeof(logEntry), "%Y-%m-%d_%H:%M:%S: ", tm_now);
    strncat(logEntry, message, LOG_LINE_SIZE - strlen(logEntry) - 1);

    char metaInfo[256];
    snprintf(metaInfo, sizeof(metaInfo), " - File %s at line %d - fun %s()", file, line, function);
    strncat(logEntry, metaInfo, LOG_LINE_SIZE - strlen(logEntry) - 1);

    pthread_mutex_lock(&logMutex);
    logQueue.PushBack(&logQueue, logEntry, strlen(logEntry));
    pthread_mutex_unlock(&logMutex);
    sem_post(&logSem);
}
