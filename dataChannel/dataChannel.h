#ifndef DATA_CHANNEL_H
#define DATA_CHANNEL_H

#include "ftpData.h"

typedef struct {
    ftpDataType *ftpData;
    int socketId;
} cleanUpWorkerArgs;

void workerCleanup(cleanUpWorkerArgs *args);
void *connectionWorkerHandle(cleanUpWorkerArgs *args);

#endif /* DATA_CHANNEL_H */

