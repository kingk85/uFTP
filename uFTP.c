
#include <stdio.h>
#include <stdlib.h>
#include "ftpServer.h"
#include <signal.h>


int main(int argc, char** argv) 
{
    signal(SIGPIPE, signal_callback_handler);

    runFtpServer();
    return (EXIT_SUCCESS);
}

