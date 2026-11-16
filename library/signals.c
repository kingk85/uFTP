/*
 * The MIT License
 *
 * Copyright 2018 Ugo Cirmignani
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


#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* backtrace() is a glibc extension: with other C libraries (musl, used for the static
   and cross builds) the crash is logged without the stack */
#if defined(__GLIBC__)
#include <execinfo.h>
#define UFTP_HAVE_BACKTRACE 1
#endif
#include "../ftpServer.h"
#include "../debugHelper.h"
#include "log.h"

/* Catch Signal Handler functio */
void signal_callback_handler(int signum) 
{
    my_printf("Caught signal SIGPIPE %d\n",signum);
}

static const char *signalName(int sig)
{
    switch (sig)
    {
        case SIGSEGV: return "SIGSEGV";
        case SIGABRT: return "SIGABRT";
        case SIGBUS:  return "SIGBUS";
        case SIGFPE:  return "SIGFPE";
        case SIGILL:  return "SIGILL";
        case SIGTERM: return "SIGTERM";
        case SIGINT:  return "SIGINT";
        default:      return "signal";
    }
}

/* One line to the log file and to stderr, from a signal handler: only
   async-signal-safe calls (no stdio, no malloc, no localtime). */
static void writeSignalLine(const char *what, int sig, int withBacktrace)
{
    (void)withBacktrace;
    char line[256];
    size_t used = logSignalSafePrefix(line, sizeof(line));

    used = logSignalSafeAppend(line, used, sizeof(line), what);
    used = logSignalSafeAppend(line, used, sizeof(line), signalName(sig));
    used = logSignalSafeAppend(line, used, sizeof(line), " (");
    used = logSignalSafeAppendNumber(line, used, sizeof(line), (unsigned long long)sig);
    used = logSignalSafeAppend(line, used, sizeof(line), ")\n");

    int logFd = logSignalSafeOpen();
    int targets[2] = { logFd, STDERR_FILENO };

    for (int i = 0; i < 2; i++)
    {
        if (targets[i] < 0)
            continue;

        if (write(targets[i], line, used) < 0) { /* nothing else can be done */ }

#ifdef UFTP_HAVE_BACKTRACE
        if (withBacktrace)
        {
            void *frames[64];
            int count = backtrace(frames, 64);
            backtrace_symbols_fd(frames, count, targets[i]);
        }
#endif
    }

    if (logFd >= 0)
        close(logFd);
}

/* Crash: the reason and the stack go to the log, then the process ends with the
   same signal as before (exit status, core dump and supervisor restart unchanged). */
static void onUftpCrash(int sig)
{
    writeSignalLine(LOG_FATAL_PREFIX "uFTP crashed with ", sig, 1);
    signal(sig, SIG_DFL);
    raise(sig);
}

/* SIGTERM (systemd, kill): logged, then the default action as before */
static void onUftpTerminate(int sig)
{
    writeSignalLine(LOG_INFO_PREFIX "uFTP stopped by ", sig, 0);
    signal(sig, SIG_DFL);
    raise(sig);
}

void onUftpClose(int sig)
{
    writeSignalLine(LOG_INFO_PREFIX "uFTP stopped by ", sig, 0);
    my_printf("\nuFTP exit() sig %d\n", sig);
    deallocateMemory();
    exit(0);
}

void signalHandlerInstall(void)
{
    /* a stack of its own, so that a stack overflow can be reported too (main thread) */
    static char alternateStack[64 * 1024];
    stack_t stack;
    memset(&stack, 0, sizeof(stack));
    stack.ss_sp = alternateStack;
    stack.ss_size = sizeof(alternateStack);
    sigaltstack(&stack, NULL);

#ifdef UFTP_HAVE_BACKTRACE
    /* backtrace() loads libgcc the first time: do it now, not inside a crash */
    void *frames[4];
    backtrace(frames, 4);
#endif

    struct sigaction crashAction;
    memset(&crashAction, 0, sizeof(crashAction));
    crashAction.sa_handler = onUftpCrash;
    crashAction.sa_flags = SA_ONSTACK | SA_RESETHAND;
    sigemptyset(&crashAction.sa_mask);
    int crashSignals[] = { SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL };
    for (size_t i = 0; i < sizeof(crashSignals) / sizeof(crashSignals[0]); i++)
        sigaction(crashSignals[i], &crashAction, NULL);

    signal(SIGTERM,onUftpTerminate);
    signal(SIGINT,onUftpClose);	
    signal(SIGUSR2,SIG_IGN);	
    signal(SIGPIPE,SIG_IGN);
    signal(SIGALRM,SIG_IGN);
    signal(SIGTSTP,SIG_IGN);
    signal(SIGTTIN,SIG_IGN);
    signal(SIGTTOU,SIG_IGN);
    signal(SIGURG,SIG_IGN);
    signal(SIGXCPU,SIG_IGN);
    signal(SIGXFSZ,SIG_IGN);
    signal(SIGVTALRM,SIG_IGN);
    signal(SIGPROF,SIG_IGN);
    signal(SIGIO,SIG_IGN);
    signal(SIGCHLD,SIG_IGN);
}