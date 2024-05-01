#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <semaphore.h>
#include <limits.h>

#include "log.h"
#include "../debugHelper.h"
#include "dynamicVectors.h"
#include "fileManagement.h"



#define LOG_LINE_SIZE 1024 + PATH_MAX

static void logThread(void * arg);

static DYNV_VectorString_DataType logQueue;
static DYNV_VectorString_DataType workerQueue;
static sem_t logsem; // Semaphore for controlling log to write

static pthread_t pLogThread;
static pthread_mutex_t mutex;

static char logFolder[PATH_MAX]; // Semaphore for controlling log to write

// STATIC SECTION
static void logThread(void * arg)
{
    while(1)
    {
        if (sem_wait(&logsem) == 0) 
        {
            char theLogFilename[PATH_MAX];    
            
            // write the logs to the file
            time_t now = time(NULL);
            struct tm *info = localtime(&now);
            char logName[50]; 
            
            memset(theLogFilename, 0, PATH_MAX);

            if (strftime(logName, sizeof(logName), "uftpLog_%Y-%m-%d", info) == 0) 
            {
                my_printfError("strftime error");
                return;
            }

            strncpy(theLogFilename, logFolder, PATH_MAX);
            strncat(theLogFilename, logName, PATH_MAX);

            // Fill the worker queue
            pthread_mutex_lock(&mutex);
            for(int i = 0; i <logQueue.Size; i++)
            {
                workerQueue.PushBack(&workerQueue, logQueue.Data[i], strnlen(logQueue.Data[i], LOG_LINE_SIZE));
            }

            // empty the log vector
            while (logQueue.Size > 0)
            {
                logQueue.PopBack(&logQueue);
            }
            // Release the mutex to let the log queue be available
            pthread_mutex_unlock(&mutex);


            for(int i = 0; i <workerQueue.Size; i++)
            {
                FILE_AppendStringToFile(theLogFilename, workerQueue.Data[i]);
                my_printf("\n Log at %d : %s", i, workerQueue.Data[i]);
            }

            // empty the log vector
            while (workerQueue.Size > 0)
            {
                workerQueue.PopBack(&workerQueue);
            }
        }
    }
}

int logInit(char * folder)
{
    int returnCode;
    my_printf("\n Init logging system..");

    DYNV_VectorString_Init(&logQueue);
    DYNV_VectorString_Init(&workerQueue);

    sem_init(&logsem, 0, 0); // Initialize semaphore with number of printers

    // Initialize the mutex
    pthread_mutex_init(&mutex, NULL);

    returnCode = pthread_create(&pLogThread, NULL, &logThread, NULL);
    if (returnCode != 0)
    {
        my_printfError("Error while creating log thread.");
        return 0;
    }

    //addLog("Log init ", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);

    memset(logFolder, 0, PATH_MAX);
    strncpy(logFolder, folder, PATH_MAX);

    my_printf("\n Log init LogFolder: %s ", logFolder);

    return 1;
}

void addLog(char* logString, char * currFile, int currLine, char * currFunction)
{

    char theLogString[LOG_LINE_SIZE];
    char debugInfo[LOG_LINE_SIZE];
    memset(theLogString, 0, LOG_LINE_SIZE);
    memset(debugInfo, 0, LOG_LINE_SIZE);

    time_t now = time(NULL);
    struct tm *info = localtime(&now);

    if (strftime(theLogString, sizeof(theLogString), "%Y-%m-%d_%H:%M: ", info) == 0) 
    {
        my_printfError("strftime error");
        return;
    }

    snprintf(debugInfo, LOG_LINE_SIZE, " - File %s at line %d - fun %s() ", currFile, currLine, currFunction);
    strncat(theLogString, logString, LOG_LINE_SIZE);
    strncat(theLogString, debugInfo, LOG_LINE_SIZE);


    // Acquire the mutex lock before accessing count
    pthread_mutex_lock(&mutex);
    //Add a string to the log
    logQueue.PushBack(&logQueue, theLogString, strnlen(theLogString, LOG_LINE_SIZE));
    // Acquire the mutex lock before accessing count

    //Count log available
    sem_post(&logsem);
    pthread_mutex_unlock(&mutex);
}

