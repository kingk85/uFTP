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

#include "../ftpServer.h"
#include "../debugHelper.h"
#include "log.h"

static void ignore_sigpipe(void);

/* Catch Signal Handler functio */
void signal_callback_handler(int signum) 
{
    my_printf("Caught signal SIGPIPE %d\n",signum);
}

static void ignore_sigpipe(void)
{
    // ignore SIGPIPE (or else it will bring our program down if the client
    // closes its socket).
    // NB: if running under gdb, you might need to issue this gdb command:
    //          handle SIGPIPE nostop noprint pass
    //     because, by default, gdb will stop our program execution (which we
    //     might not want).
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;

    if (sigemptyset(&sa.sa_mask) < 0 || sigaction(SIGPIPE, &sa, 0) < 0) 
    {
        perror("Could not ignore the SIGPIPE signal");
        my_printfError("Could not ignore the SIGPIPE signal");
        LOG_INFO("Could not ignore the SIGPIPE signal");
        exit(0);
    }
}

void onUftpClose(int sig)
{
    my_printf("\nuFTP exit() sig %d\n", sig);
    deallocateMemory();
    exit(0);
}

void signalHandlerInstall(void)
{
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