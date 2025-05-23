#ifndef CTRL_CHANNEL_H
#define CTRL_CHANNEL_H

#include "ftpData.h"

typedef int (*CommandHandler)(struct FtpDataType*, int);

typedef struct {
    const char* command;
    CommandHandler handler;
} CommandMapEntry;

void evaluateControlChannel(ftpDataType *ftpData);

#endif /* DATA_CHANNEL_H */

