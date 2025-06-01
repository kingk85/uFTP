


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
#include "library/logFunctions.h"
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

int handleThreadReuse(ftpDataType *data, int socketId)
{
    void *pReturn;
    int returnCode = 0;

    if (data->clients[socketId].workerData.threadHasBeenCreated == 1)
    {
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

    return returnCode;
}

void cancelWorker(ftpDataType *data, int clientId)
{
    LOG_DEBUG("Cancelling thread because it is busy");

    int returnCode = pthread_cancel(data->clients[clientId].workerData.workerThread);
    if (returnCode != 0) {
        LOGF("%sCancel thread error: %d", LOG_ERROR_PREFIX, returnCode);
    }
}