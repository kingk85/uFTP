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


#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "fileManagement.h"
#include "../debugHelper.h"
/* syslog.h defines LOG_INFO and LOG_DEBUG as priorities; here they are the uFTP log
   macros (only LOG_ERR of syslog is used in this file) */
#undef LOG_INFO
#undef LOG_DEBUG
#include "log.h"

#define LOCKFILE "/var/run/uFTP.pid"
#define LOCKMODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)
#define MAXIMUM_IDLE_TIME			60

static int WatchDogTime = 0, WatchDogTimerTimeOut = MAXIMUM_IDLE_TIME;

int isProcessAlreadyRunning(void)
{
    int fd;
    int returnCode;
    char buf[101];
    memset(buf, 0,101);
    fd = open(LOCKFILE, O_RDWR|O_CREAT, LOCKMODE);
    if (fd < 0) 
    {
        syslog(LOG_ERR, "can’t open %s: %s", LOCKFILE, strerror(errno));
        exit(1);
    }
    //my_printf("\nFile pid opened.");
    
    if ((returnCode = FILE_LockFile(fd)) < 0) 
    {
        if (errno == EACCES || errno == EAGAIN) 
        {
        close(fd);
        return(1);
        }
        syslog(LOG_ERR, "can’t lock %s: %s", LOCKFILE, strerror(errno));
        exit(1);
    }
    
    //my_printf("\nFILE_LockFile returnCode = %d", returnCode);    
    ftruncate(fd, 0);
    returnCode = snprintf(buf, 100, "%ld", (long)getpid());
    returnCode = write(fd, buf, strnlen(buf, 100)+1);
    return 0;
}

void daemonize(const char *cmd)
	{
    int
    i;
    pid_t pid;
    struct rlimit rl;
    struct sigaction sa;
    
    /*
    * Clear file creation mask.
    */
    umask(0);
    
    /*
    * Get maximum number of file descriptors.
    */
    if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
    my_printf("%s: can’t get file limit", cmd);
    
    /*
    * Become a session leader to lose controlling TTY.
    */
    if ((pid = fork()) < 0)
        my_printf("%s: can’t fork", cmd);
    else if (pid != 0) /* parent */
        exit(0);
    
    setsid();
    
    /*
    * Ensure future opens won’t allocate controlling TTYs.
    */
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    
    sa.sa_flags = 0;
    if (sigaction(SIGHUP, &sa, NULL) < 0)
        my_printf("%s: can’t ignore SIGHUP", cmd);
    if ((pid = fork()) < 0)
        my_printf("%s: can’t fork", cmd);
    else if (pid != 0) /* parent */
    exit(0);
    /*
    * Change the current working directory to the root so
    * we won’t prevent file systems from being unmounted.
    */
    if (chdir("/") < 0)
        my_printf("%s: can’t change directory to /", cmd);
    /*
    * Close all open file descriptors.
    */
    if (rl.rlim_max == RLIM_INFINITY)
        rl.rlim_max = 1024;
    for (i = 0; i < rl.rlim_max; i++)
        close(i);
    /*
    * Attach file descriptors 0, 1, and 2 to /dev/null.
    */
    open("/dev/null", O_RDWR);
    dup(0);
    dup(0);
    }

void respawnProcess(void)
{
    pid_t spawnedProcess;

    /* SIGCHLD is ignored by the server: the supervisor needs it, otherwise the child is
       reaped by the system and waitpid() can not tell how it ended */
    signal(SIGCHLD, SIG_DFL);

    LOGF_NOW("%sSupervisor started, it restarts the server if it stops (RESPAWN_PROCESS)", LOG_INFO_PREFIX);

    while(1)
    {
        spawnedProcess = fork();

        if (spawnedProcess == 0)
        {
            //is child, exit from the loop
            signal(SIGCHLD, SIG_IGN);
            my_printf("\nRespawn mode is active");
            break;
        }

        if (spawnedProcess < 0)
        {
            LOGF_NOW("%sSupervisor: fork failed: %s, retrying in 1 second", LOG_ERROR_PREFIX, strerror(errno));
            sleep(1);
            continue;
        }

        int returnStatus = 0;
        pid_t waited;

        do {
            waited = waitpid(spawnedProcess, &returnStatus, 0);
        } while (waited < 0 && errno == EINTR);

        if (waited < 0)
        {
            LOGF_NOW("%sSupervisor: server process %d lost (waitpid: %s), restarting in 1 second", LOG_ERROR_PREFIX, (int)spawnedProcess, strerror(errno));
        }
        else if (WIFEXITED(returnStatus))
        {
            if (WEXITSTATUS(returnStatus) == 99)
            {
                LOGF_NOW("%sSupervisor: server process %d exited with code 99, not restarting it", LOG_INFO_PREFIX, (int)spawnedProcess);
                exit(3);
            }

            LOGF_NOW("%sSupervisor: server process %d exited with code %d%s, restarting in 1 second",
                     WEXITSTATUS(returnStatus) == 0 ? LOG_INFO_PREFIX : LOG_ERROR_PREFIX,
                     (int)spawnedProcess, WEXITSTATUS(returnStatus),
                     WEXITSTATUS(returnStatus) == 98 ? " (watchdog: control loop blocked)" : "");
        }
        else if (WIFSIGNALED(returnStatus))
        {
            LOGF_NOW("%sSupervisor: server process %d killed by signal %d (%s)%s, restarting in 1 second", LOG_ERROR_PREFIX,
                     (int)spawnedProcess, WTERMSIG(returnStatus), strsignal(WTERMSIG(returnStatus)),
                     WCOREDUMP(returnStatus) ? ", core dumped" : "");
        }

        sleep(1);
    }
    return;
}

void *watchDog(void * arg)
{
	WatchDogTime = (int)time(NULL);

	while(1)
	{
		//Check if the time is expired
		if ((int)time(NULL) - WatchDogTime > WatchDogTimerTimeOut)
		{
			my_printf("\nWatchDog Time Expired");
			LOGF_NOW("%sWatchdog: the control loop has been blocked for more than %d seconds, exiting with code 98", LOG_FATAL_PREFIX, WatchDogTimerTimeOut);
			exit(98);
		}

		//my_printf("\nWatchDog Time ok %d, %d", (int)time(NULL), WatchDogTime);

		sleep(5);
	}
}

void updateWatchDogTime(int theTime)
{
	WatchDogTime = theTime;
}
