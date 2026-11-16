


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <errno.h>

#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <pthread.h>
#include <limits.h>

#include "../ftpData.h"
#include "../ftpServer.h"
#include "library/fileManagement.h"
#include "library/configRead.h"
#include "library/openSsl.h"
#include "library/connection.h"
#include "library/dynamicMemory.h"
#include "library/auth.h"
#include "library/serverHelpers.h"
#include "dataChannel/dataChannel.h"
#include "ftpCommandsElaborate.h"

#include "debugHelper.h"
#include "library/log.h"

void handleThreadReuse(ftpDataType *data, int socketId)
{
    void *pReturn;
    int returnCode = 0;

    if (data->clients[socketId].workerData.threadHasBeenCreated == 1)
    {
        /* this thread waits in pthread_join below, and it serves every client: a worker
           that is closing its connection stops waiting for the peer */
        data->clients[socketId].workerData.stopRequested = 1;

        if (data->clients[socketId].workerData.threadIsAlive == 1)
        {
            cancelWorker(data, socketId);
        }

        returnCode = pthread_join(data->clients[socketId].workerData.workerThread, &pReturn);
        my_printf("\njoin thread status %d", returnCode);
        if (returnCode != 0) 
        {
            LOGF("%sJoining thread error: %d", LOG_ERROR_PREFIX, returnCode);
        }

        data->clients[socketId].workerData.threadHasBeenCreated = 0;
    }
}

void cancelWorker(ftpDataType *data, int clientId)
{
    LOG_DEBUG("Cancelling thread because it is busy");

    int returnCode = pthread_cancel(data->clients[clientId].workerData.workerThread);
    if (returnCode != 0) {
        LOGF("%sCancel thread error: %d", LOG_ERROR_PREFIX, returnCode);
    }
}

/* Start the data channel worker of a client (PASV, EPSV, PORT, EPRT).

   threadHasBeenCreated and threadIsAlive are set here, in the control thread,
   BEFORE pthread_create. They used to be set by the worker itself once running:
   when two data channel commands arrived in the same read (e.g. "PASV\r\nPASV\r\n")
   the second one found both flags still at 0, handleThreadReuse() neither cancelled
   nor joined the first worker, and two workers shared the same SSL objects and
   memory table: double free / use-after-free in resetWorkerData().

   Returns 1 on success, -1 if the arguments could not be allocated, 0 if
   pthread_create failed. */
int startDataWorker(ftpDataType *data, int socketId, char *label)
{
    int returnCode;
    cleanUpWorkerArgs *workerArgs = DYNMEM_malloc(sizeof(cleanUpWorkerArgs), &data->clients[socketId].workerData.memoryTable, label);

    if (!workerArgs)
    {
        LOG_ERROR("Failed to allocate memory for workerArgs");
        return -1;
    }

    workerArgs->ftpData = data;
    workerArgs->socketId = socketId;

    data->clients[socketId].workerData.threadHasBeenCreated = 1;
    data->clients[socketId].workerData.threadIsAlive = 1;
    data->clients[socketId].workerData.stopRequested = 0;
    data->clients[socketId].dataReplyPending = 1;

    returnCode = pthread_create(&data->clients[socketId].workerData.workerThread, NULL, (void *(*)(void *))connectionWorkerHandle, workerArgs);

    if (returnCode != 0)
    {
        data->clients[socketId].workerData.threadHasBeenCreated = 0;
        data->clients[socketId].workerData.threadIsAlive = 0;
        data->clients[socketId].dataReplyPending = 0;
        DYNMEM_free(workerArgs, &data->clients[socketId].workerData.memoryTable);
        my_printfError("\nError in pthread_create %d", returnCode);
        LOGF("%sPthead create error(code=%d): %s restarting the server", LOG_ERROR_PREFIX, returnCode, strerror(returnCode));
        return 0;
    }

    return 1;
}

/* Stop the current data channel worker before a new data channel command
   (PASV, EPSV, PORT, EPRT) or ABOR.

   Every FTP command must get exactly one reply (RFC 959). The reply to PASV,
   EPSV, PORT and EPRT is sent by the worker; when two of these commands arrive
   together, the second one can stop the first worker before it has replied.
   In that case the reply of the stopped command is sent here.

   Returns 0 on success, -1 if the reply could not be written. */
int replaceDataWorker(ftpDataType *data, int socketId)
{
    handleThreadReuse(data, socketId);

    /* after pthread_join, the value written by the worker is visible here */
    if (data->clients[socketId].dataReplyPending == 1)
    {
        data->clients[socketId].dataReplyPending = 0;

        if (socketPrintf(data, socketId, "s", "425 Data connection request superseded by a new command\r\n") <= 0)
        {
            return -1;
        }
    }

    return 0;
}
