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

#ifndef CONFIGREAD_H
#define CONFIGREAD_H

#ifdef __cplusplus
extern "C" {
#endif

#include "dynamicVectors.h"
#include "dynamicMemory.h"
#include "../ftpData.h"

#define DEFAULT_CONFIGURATION_FILENAME      "/etc/uftpd.cfg"
#define LOCAL_CONFIGURATION_FILENAME        "./uftpd.cfg"
    

/*Public functions */
void initFtpData(ftpDataType *ftpData);
int searchUser(char *name, DYNV_VectorGenericDataType *usersVector);
void configurationRead(ftpParameters_DataType *ftpParameters, DYNMEM_MemoryTable_DataType **memoryTable);
void applyConfiguration(ftpParameters_DataType *ftpParameters);


#ifdef __cplusplus
}
#endif

#endif /* CONFIGREAD_H */

