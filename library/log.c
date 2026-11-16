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
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>

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

/* Limits on what can be logged: many lines can be caused by anybody (one per refused
   connection, before any login), and both the file of the day and the queue in
   memory used to grow without limit.

   - The same message (same text from the same place in the code) is written at most
     once every LOG_REPEAT_INTERVAL seconds; the next time it is written, it says how
     many copies were left out.
   - At most LOG_MAX_LINES_PER_SECOND lines per second in total (an attacker with many
     addresses produces different messages), and at most LOG_MAX_QUEUED_LINES waiting
     to be written. The lines left out are counted and reported. */
#define LOG_REPEAT_INTERVAL        10
#define LOG_REPEAT_TABLE_SIZE      128
#define LOG_MAX_LINES_PER_SECOND   100
#define LOG_MAX_QUEUED_LINES       10000

struct logRepeatEntry
{
    unsigned long long hash;
    time_t lastWritten;
    unsigned long suppressed;
    /* the line as it was written (without time and pid), to report the copies left out
       once the interval is over even if the line never comes back */
    char text[200];
};

static struct logRepeatEntry logRepeatTable[LOG_REPEAT_TABLE_SIZE];
static time_t logCurrentSecond = 0;
static int logLinesThisSecond = 0;
static unsigned long logLinesDropped = 0;
static char logFolder[PATH_MAX] = {0};

/* Before logStartWriter() (and always in the supervisor process, which never starts
   it) lines are written at once by the calling thread: nothing is lost if the process
   stops right after, and a queue copied by fork() can not be written twice. */
static int logWriterStarted = 0;

/* File of the last line written, for the crash handler (it can not compute it) */
static char logCurrentPath[PATH_MAX] = {0};

/* Offset of local time from UTC when the log was configured, for timestamps written
   from a signal handler (localtime is not async-signal-safe) */
static long logUtcOffset = 0;

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

/* Path of the log file of the day of `when`; also remembered for the crash handler */
static int logFilePathFor(time_t when, char *path, size_t pathSize)
{
    struct tm tm_when;
    char dateStr[11];

    localtime_r(&when, &tm_when);
    strftime(dateStr, sizeof(dateStr), "%Y-%m-%d", &tm_when);

    int written = snprintf(path, pathSize, "%s%s%s", logFolder, LOG_FILENAME_PREFIX, dateStr);
    if (written < 0 || (size_t)written >= pathSize)
        return 0;

    if (strcmp(logCurrentPath, path) != 0)
        snprintf(logCurrentPath, sizeof(logCurrentPath), "%s", path);

    return 1;
}

/* Append one line. If the file can not be opened the line goes to stderr, which is
   kept by systemd and by the shell when the server does not run as a daemon. */
/* Mode of the log files. They used to be created 0666 (with the umask 0 of the daemon
   mode): anybody on the machine could change or delete the access records. Uploads are
   not affected. */
#define LOG_FILE_MODE 0640

/* Append one line. If the file can not be opened the line goes to stderr, which is
   kept by systemd and by the shell when the server does not run as a daemon. */
static void logAppendLine(const char *path, const char *line)
{
    static char checkedPath[PATH_MAX] = {0};
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT, LOG_FILE_MODE);
    FILE *fp = (fd >= 0) ? fdopen(fd, "a") : NULL;

    if (fp == NULL)
    {
        if (fd >= 0)
            close(fd);
        fprintf(stderr, "%s\n", line);
        return;
    }

    /* a file of the day created by an older version keeps its mode: fixed once */
    if (strcmp(checkedPath, path) != 0)
    {
        struct stat fileStat;

        if (fstat(fd, &fileStat) == 0 && (fileStat.st_mode & 07777) != LOG_FILE_MODE)
            (void)fchmod(fd, LOG_FILE_MODE);

        snprintf(checkedPath, sizeof(checkedPath), "%s", path);
    }

    fprintf(fp, "%s\n", line);
    fclose(fp);
}

static void* logThread(void* arg) {
    int lastDay = -1;
    (void)arg;

    while (1) {
        sem_wait(&logSem);

        time_t now = time(NULL);
        struct tm tm_now;
        localtime_r(&now, &tm_now);

        char logFilePath[PATH_MAX];
        if (logFilePathFor(now, logFilePath, sizeof(logFilePath)) == 0) {
            my_printfError("Log file path too long");
            continue;
        }

        if (tm_now.tm_mday != lastDay) {
            deleteOldLogs(logFolder, maxLogFiles);
            lastDay = tm_now.tm_mday;
        }

        pthread_mutex_lock(&logMutex);
        for (int i = 0; i < logQueue.Size; ++i) {
            workerQueue.PushBack(&workerQueue, logQueue.Data[i], strnlen(logQueue.Data[i], LOG_LINE_SIZE));
        }
        while (logQueue.Size > 0) logQueue.PopBack(&logQueue);
        pthread_mutex_unlock(&logMutex);

        for (int i = 0; i < workerQueue.Size; ++i) {
            logAppendLine(logFilePath, workerQueue.Data[i]);
        }
        while (workerQueue.Size > 0) workerQueue.PopBack(&workerQueue);
    }
    return NULL;
}

/* Where and how long to keep the log. Called right after the configuration is read,
   before anything that can fail: from here on lines are written at once. */
int logConfigure(const char* folder, int numberOfLogFiles) {
    if (numberOfLogFiles <= 0 || !folder) return -1;

    maxLogFiles = numberOfLogFiles;

    /* the folder and the file name are joined as they are: "/var/log" used to give
       "/var/loguftpLog_..." */
    size_t folderLen = strlen(folder);
    snprintf(logFolder, sizeof(logFolder), "%s%s", folder,
             (folderLen > 0 && folder[folderLen - 1] != '/') ? "/" : "");

    time_t now = time(NULL);
    struct tm tm_now;
    localtime_r(&now, &tm_now);
    logUtcOffset = tm_now.tm_gmtoff;

    char path[PATH_MAX];
    logFilePathFor(now, path, sizeof(path));

    DYNV_VectorString_Init(&logQueue);
    DYNV_VectorString_Init(&workerQueue);

    deleteOldLogs(logFolder, maxLogFiles);
    return 1;
}

/* Write the queued lines now. Registered with atexit(): the lines logged just before
   an exit() (fatal errors) used to be lost together with the writer thread. */
void logFlush(void)
{
    char path[PATH_MAX];

    if (maxLogFiles <= 0 || logWriterStarted == 0)
        return;

    /* exit() may be called while another thread holds the mutex: do not wait for it */
    if (pthread_mutex_trylock(&logMutex) != 0)
        return;

    if (logFilePathFor(time(NULL), path, sizeof(path)) == 1)
    {
        for (int i = 0; i < logQueue.Size; ++i)
            logAppendLine(path, logQueue.Data[i]);
    }
    while (logQueue.Size > 0) logQueue.PopBack(&logQueue);

    pthread_mutex_unlock(&logMutex);
}

/* Start the writer thread: in the process that serves the clients, after fork() */
int logStartWriter(void) {
    if (maxLogFiles <= 0) return -1;

    sem_init(&logSem, 0, 0);

    if (pthread_create(&logThreadId, NULL, logThread, NULL) != 0) {
        LOG_ERROR("Failed to create log thread, lines are written by the calling thread");
        return -1;
    }

    pthread_mutex_lock(&logMutex);
    logWriterStarted = 1;
    pthread_mutex_unlock(&logMutex);

    atexit(logFlush);
    return 1;
}

int logInit(const char* folder, int numberOfLogFiles) {
    if (logConfigure(folder, numberOfLogFiles) != 1)
        return -1;

    return logStartWriter();
}

static unsigned long long logMessageHash(const char *message, const char *file, int line)
{
    unsigned long long hash = 1469598103934665603ULL;      /* FNV-1a */
    const char *parts[2] = { message, file };

    for (int i = 0; i < 2; i++)
    {
        for (const unsigned char *c = (const unsigned char *)parts[i]; *c != '\0'; c++)
        {
            hash ^= *c;
            hash *= 1099511628211ULL;
        }
    }

    return hash ^ (unsigned long long)line;
}

/* Called with logMutex held. Returns 0 if the message must not be written now,
   otherwise 1 and *suppressed = copies left out since it was last written. */
static int logRepeatCheck(unsigned long long hash, time_t now, unsigned long *suppressed, const char *text)
{
    struct logRepeatEntry *oldest = &logRepeatTable[0];

    for (int i = 0; i < LOG_REPEAT_TABLE_SIZE; i++)
    {
        struct logRepeatEntry *entry = &logRepeatTable[i];

        if (entry->lastWritten != 0 && entry->hash == hash)
        {
            if (now - entry->lastWritten < LOG_REPEAT_INTERVAL)
            {
                entry->suppressed++;
                return 0;
            }

            *suppressed = entry->suppressed;
            entry->suppressed = 0;
            entry->lastWritten = now;
            return 1;
        }

        if (entry->lastWritten < oldest->lastWritten)
            oldest = entry;
    }

    /* not seen recently: it takes the place of the oldest message */
    oldest->hash = hash;
    oldest->lastWritten = now;
    oldest->suppressed = 0;
    snprintf(oldest->text, sizeof(oldest->text), "%s", text);
    *suppressed = 0;
    return 1;
}

/* Write one already formatted line: at once before the writer thread exists, else
   through its queue. Called with logMutex held. Returns 1 if the writer must be woken. */
static int logEmitLocked(const char *entry, time_t now)
{
    if (logWriterStarted == 0)
    {
        char path[PATH_MAX];

        if (logFilePathFor(now, path, sizeof(path)) == 1)
            logAppendLine(path, entry);
        return 0;
    }

    logQueue.PushBack(&logQueue, (char *)entry, strlen(entry));
    return 1;
}

/* Called once a second by the control thread. The copies of a repeated line left out
   used to be reported only when the same line came back after the interval: at the
   end of a burst the count was lost. Now it is written as soon as the interval is
   over. */
void logFlushRepeated(void)
{
    int wake = 0;
    time_t now = time(NULL);
    struct tm tm_now;

    if (maxLogFiles <= 0)
        return;

    localtime_r(&now, &tm_now);
    pthread_mutex_lock(&logMutex);

    for (int i = 0; i < LOG_REPEAT_TABLE_SIZE; i++)
    {
        struct logRepeatEntry *entry = &logRepeatTable[i];
        char line[512];

        if (entry->suppressed == 0 || now - entry->lastWritten < LOG_REPEAT_INTERVAL)
            continue;

        strftime(line, sizeof(line), "%Y-%m-%d_%H:%M:%S: ", &tm_now);
        /* a summary, not an event: "N more times", unlike the "(repeated N more times)"
           of a line written again, which is one event plus N copies */
        snprintf(line + strlen(line), sizeof(line) - strlen(line), "[pid %d] %s (%lu more times in the last %d s, grouped)",
                 (int)getpid(), entry->text, entry->suppressed, LOG_REPEAT_INTERVAL);
        wake |= logEmitLocked(line, now);

        entry->suppressed = 0;
        entry->lastWritten = now;
    }

    pthread_mutex_unlock(&logMutex);

    if (wake)
        sem_post(&logSem);
}

static void logMessageWrite(const char* message, const char* file, int line, const char* function, int synchronous, int isAccessRecord) {
    if (!message) return;

    if (maxLogFiles <= 0)
    {
        /* log disabled: only fatal lines are kept, on stderr */
        if (synchronous)
            fprintf(stderr, "[pid %d] %s - File %s at line %d - fun %s()\n", (int)getpid(), message, file, line, function);
        return;
    }

    char logEntry[LOG_LINE_SIZE] = {0};
    char droppedEntry[128] = {0};
    unsigned long suppressed = 0;
    time_t now = time(NULL);
    struct tm tm_now;
    localtime_r(&now, &tm_now);

    pthread_mutex_lock(&logMutex);

    if (now != logCurrentSecond)
    {
        logCurrentSecond = now;
        logLinesThisSecond = 0;
    }

    /* The access records of logged in users are the audit trail: they are not dropped
       to stay under LOG_MAX_LINES_PER_SECOND (they come at the pace of the commands of
       authenticated users), only if the queue is full. */
    if (!synchronous && ((!isAccessRecord && logLinesThisSecond >= LOG_MAX_LINES_PER_SECOND) || logQueue.Size >= LOG_MAX_QUEUED_LINES))
    {
        logLinesDropped++;
        pthread_mutex_unlock(&logMutex);
        return;
    }

    /* Identical lines are grouped, except the access records of logged in users: each
       login, transfer and file change is an event of its own, with its own time (it used
       to be grouped like the lines that an outsider can repeat at will). */
    if (!isAccessRecord && logRepeatCheck(logMessageHash(message, file, line), now, &suppressed, message) == 0)
    {
        pthread_mutex_unlock(&logMutex);
        return;
    }

    logLinesThisSecond++;

    /* the pid tells the supervisor from the server, and one run of the server from the next */
    strftime(logEntry, sizeof(logEntry), "%Y-%m-%d_%H:%M:%S: ", &tm_now);
    snprintf(logEntry + strlen(logEntry), sizeof(logEntry) - strlen(logEntry), "[pid %d] ", (int)getpid());

    if (logLinesDropped > 0)
    {
        char timeStamp[32];
        strftime(timeStamp, sizeof(timeStamp), "%Y-%m-%d_%H:%M:%S: ", &tm_now);
        snprintf(droppedEntry, sizeof(droppedEntry), "%s%s%lu log lines dropped (too many lines)",
                 timeStamp, LOG_ERROR_PREFIX, logLinesDropped);
        logLinesDropped = 0;
    }

    strncat(logEntry, message, LOG_LINE_SIZE - strlen(logEntry) - 1);

    char metaInfo[320];
    if (suppressed > 0)
        snprintf(metaInfo, sizeof(metaInfo), " (repeated %lu more times) - File %s at line %d - fun %s()", suppressed, file, line, function);
    else
        snprintf(metaInfo, sizeof(metaInfo), " - File %s at line %d - fun %s()", file, line, function);
    strncat(logEntry, metaInfo, LOG_LINE_SIZE - strlen(logEntry) - 1);

    if (synchronous || logWriterStarted == 0)
    {
        char path[PATH_MAX];

        if (logFilePathFor(now, path, sizeof(path)) == 1)
        {
            /* queued lines first, to keep the order */
            for (int i = 0; i < logQueue.Size; ++i)
                logAppendLine(path, logQueue.Data[i]);
            while (logQueue.Size > 0) logQueue.PopBack(&logQueue);

            if (droppedEntry[0] != '\0')
                logAppendLine(path, droppedEntry);
            logAppendLine(path, logEntry);
        }

        pthread_mutex_unlock(&logMutex);
        return;
    }

    if (droppedEntry[0] != '\0')
        logQueue.PushBack(&logQueue, droppedEntry, strlen(droppedEntry));
    logQueue.PushBack(&logQueue, logEntry, strlen(logEntry));
    pthread_mutex_unlock(&logMutex);
    sem_post(&logSem);
}

/* The data channel workers log too and can be cancelled (ABOR, a new PASV...). Writing
   a line at once uses stdio, whose calls are cancellation points: a worker cancelled
   there would leave logMutex locked and stop every later log call. */
static void logMessageInternal(const char* message, const char* file, int line, const char* function, int synchronous, int isAccessRecord) {
    int previousCancelState;

    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previousCancelState);
    logMessageWrite(message, file, line, function, synchronous, isAccessRecord);
    pthread_setcancelstate(previousCancelState, NULL);
}

void logMessage(const char* message, const char* file, int line, const char* function) {
    logMessageInternal(message, file, line, function, 0, 0);
}

// printf-style log function
void logMessagef(const char* file, int line, const char* function, const char* fmt, ...) {
    if (maxLogFiles <= 0 || !fmt) return;

    char messageBuffer[LOG_LINE_SIZE] = {0};
    va_list args;
    va_start(args, fmt);
    vsnprintf(messageBuffer, sizeof(messageBuffer), fmt, args);
    va_end(args);

    logMessageInternal(messageBuffer, file, line, function, 0, 0);
}

/* A line already formatted by the caller. isAccessRecord: see logMessageInternal() */
void logMessageRecord(const char* message, const char* file, int line, const char* function, int isAccessRecord) {
    logMessageInternal(message, file, line, function, 0, isAccessRecord);
}

/* Written before returning, with the queued lines: for events after which the process
   may stop at once (fatal errors, supervisor). With the log disabled it goes to stderr. */
void logMessageNowf(const char* file, int line, const char* function, const char* fmt, ...) {
    if (!fmt) return;

    char messageBuffer[LOG_LINE_SIZE] = {0};
    va_list args;
    va_start(args, fmt);
    vsnprintf(messageBuffer, sizeof(messageBuffer), fmt, args);
    va_end(args);

    logMessageInternal(messageBuffer, file, line, function, 1, 0);
}

/* ---- for signal handlers: only async-signal-safe calls below ---------------------- */

static size_t logSafeAppend(char *buffer, size_t used, size_t size, const char *text)
{
    while (*text != '\0' && used + 1 < size)
        buffer[used++] = *text++;
    buffer[used] = '\0';
    return used;
}

static size_t logSafeAppendNumber(char *buffer, size_t used, size_t size, unsigned long long number, int minDigits)
{
    char digits[24];
    int count = 0;

    do {
        digits[count++] = (char)('0' + (number % 10));
        number /= 10;
    } while (number > 0 && count < (int)sizeof(digits));

    while (count < minDigits && count < (int)sizeof(digits))
        digits[count++] = '0';

    while (count > 0 && used + 1 < size)
        buffer[used++] = digits[--count];
    buffer[used] = '\0';
    return used;
}

/* "YYYY-MM-DD_HH:MM:SS: [pid N] " in local time, without localtime() */
size_t logSignalSafePrefix(char *buffer, size_t size)
{
    long long seconds = (long long)time(NULL) + logUtcOffset;
    long long days = seconds / 86400, rest = seconds % 86400;
    size_t used = 0;

    if (rest < 0) { rest += 86400; days--; }

    /* days since 1970-01-01 to a civil date (H. Hinnant's algorithm) */
    days += 719468;
    long long era = (days >= 0 ? days : days - 146096) / 146097;
    long long dayOfEra = days - era * 146097;
    long long yearOfEra = (dayOfEra - dayOfEra / 1460 + dayOfEra / 36524 - dayOfEra / 146096) / 365;
    long long dayOfYear = dayOfEra - (365 * yearOfEra + yearOfEra / 4 - yearOfEra / 100);
    long long monthIndex = (5 * dayOfYear + 2) / 153;
    long long day = dayOfYear - (153 * monthIndex + 2) / 5 + 1;
    long long month = monthIndex < 10 ? monthIndex + 3 : monthIndex - 9;
    long long year = yearOfEra + era * 400 + (month <= 2);

    used = logSafeAppendNumber(buffer, used, size, (unsigned long long)year, 4);
    used = logSafeAppend(buffer, used, size, "-");
    used = logSafeAppendNumber(buffer, used, size, (unsigned long long)month, 2);
    used = logSafeAppend(buffer, used, size, "-");
    used = logSafeAppendNumber(buffer, used, size, (unsigned long long)day, 2);
    used = logSafeAppend(buffer, used, size, "_");
    used = logSafeAppendNumber(buffer, used, size, (unsigned long long)(rest / 3600), 2);
    used = logSafeAppend(buffer, used, size, ":");
    used = logSafeAppendNumber(buffer, used, size, (unsigned long long)((rest / 60) % 60), 2);
    used = logSafeAppend(buffer, used, size, ":");
    used = logSafeAppendNumber(buffer, used, size, (unsigned long long)(rest % 60), 2);
    used = logSafeAppend(buffer, used, size, ": [pid ");
    used = logSafeAppendNumber(buffer, used, size, (unsigned long long)getpid(), 1);
    used = logSafeAppend(buffer, used, size, "] ");
    return used;
}

size_t logSignalSafeAppend(char *buffer, size_t used, size_t size, const char *text)
{
    return logSafeAppend(buffer, used, size, text);
}

size_t logSignalSafeAppendNumber(char *buffer, size_t used, size_t size, unsigned long long number)
{
    return logSafeAppendNumber(buffer, used, size, number, 1);
}

/* Descriptor of the current log file, or -1 (log disabled, or it can not be opened) */
int logSignalSafeOpen(void)
{
    if (maxLogFiles <= 0 || logCurrentPath[0] == '\0')
        return -1;

    return open(logCurrentPath, O_WRONLY | O_APPEND | O_CREAT, LOG_FILE_MODE);
}
