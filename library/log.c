#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <semaphore.h>
#include <limits.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <ctype.h>
#include <dirent.h>


#include "log.h"
#include "../debugHelper.h"
#include "dynamicVectors.h"
#include "fileManagement.h"

#define LOG_LINE_SIZE           1024 + PATH_MAX
#define LOG_FILENAME_PREFIX     "uftpLog_"

static void logThread(void * arg);

static DYNV_VectorString_DataType logQueue;
static DYNV_VectorString_DataType workerQueue;
static sem_t logsem; // Semaphore for controlling log to write

static pthread_t pLogThread;
static pthread_mutex_t mutex;

static int logFilesNumber;

static char logFolder[PATH_MAX];

#define MAX_FILENAME_LENGTH 256


static long long is_date_format(const char* str);
static int delete_old_logs(const char* folder_path, int days_to_keep);

static long long is_date_format(const char* str) 
{
  char year[5];
  char month[3];
  char day[3];

  memset(year, 0, 5);
  memset(month, 0, 3);
  memset(day, 0, 3);

  if (strlen(str) != 10 || str[4] != '-' || str[7] != '-') 
  {
    return 0;
  }

  // Check for valid digits in year, month, and day components
  for (int i = 0; i < 4; i++) 
  {
    if (!isdigit(str[i])) {
      return 0;
    }
    year[i] = str[i];
  }

  for (int i = 5; i < 7; i++) {
    if (!isdigit(str[i])) {
      return 0;
    }
  }
  for (int i = 8; i < 10; i++) {
    if (!isdigit(str[i])) {
      return 0;
    }
  }

    month[0] = str[5];
    month[1] = str[6];

    day[0] = str[8];
    day[1] = str[9];

    return atoll(year)*365+(atoll(month)-1)*31+atoll(day);
}

static int delete_old_logs(const char* folder_path, int days_to_keep) 
{
  unsigned long long n_of_day_file;
  unsigned long long n_of_day_today;

  struct stat statbuf;
  DIR* dir;
  struct dirent* entry;
  char full_path[PATH_MAX];

  dir = opendir(folder_path);
  if (dir == NULL) 
  {
    perror("opendir");
    return 1;
  }

  time_t now = time(NULL);
  struct tm *info = localtime(&now);
  char timeToday[11]; 
  if (strftime(timeToday, sizeof(timeToday), "%Y-%m-%d", info) == 0) 
  {
    my_printfError("strftime error");
    return;
  }

  n_of_day_today = is_date_format(timeToday);

  while ((entry = readdir(dir)) != NULL) 
  {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue; // Skip . and .. entries
    }

    snprintf(full_path, sizeof(full_path), "%s%s", folder_path, entry->d_name);

    if (stat(full_path, &statbuf) == -1) 
    {
      perror("stat");
      continue;
    }

    if (!S_ISREG(statbuf.st_mode)) 
    {
      continue; // Not a regular file
    }

    if (strncmp(entry->d_name, LOG_FILENAME_PREFIX, strlen(LOG_FILENAME_PREFIX)) != 0) 
    {
      continue; // Not a log file
    }

    n_of_day_file = is_date_format(entry->d_name + strlen(LOG_FILENAME_PREFIX));

    if (!n_of_day_file)
    {
      continue; // Invalid date format
    }

    if (n_of_day_file+days_to_keep < n_of_day_today) 
    {
      my_printf("\nRemoving old log file: %s", full_path);
      
      // File is older than specified days
      if (remove(full_path) == -1) 
      {
        perror("remove");
        continue;
      }
    }
  }

  closedir(dir);
  return 0;
}


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

            if (strftime(logName, sizeof(logName), LOG_FILENAME_PREFIX"%Y-%m-%d", info) == 0) 
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

int logInit(char * folder, int numberOfLogFiles)
{
    int returnCode;
    my_printf("\n Init logging system..");

    logFilesNumber = numberOfLogFiles;

    if (logFilesNumber <= 0)
        return;
  
    delete_old_logs(folder, numberOfLogFiles);

    DYNV_VectorString_Init(&logQueue);
    DYNV_VectorString_Init(&workerQueue);

    sem_init(&logsem, 0, 0); // Initialize semaphore with number of printers

    // Initialize the mutex
    pthread_mutex_init(&mutex, NULL);

    returnCode = pthread_create(&pLogThread, NULL, &logThread, NULL);
    if (returnCode != 0)
    {
        addLog("Pthead create error restarting the server", CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC);
        exit(0);    
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

    if (logFilesNumber <= 0)
        return;

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

