/*
 * The MIT License
 *
 * Copyright 2018 ugo.
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

/* 
 * File:   configRead.h
 * Author: ugo
 *
 * Created on 24 gennaio 2018, 14.11
 */

#ifndef CONFIGREAD_H
#define CONFIGREAD_H

#ifdef __cplusplus
extern "C" {
#endif
    
#include "dynamicVectors.h"

struct parameter
{
    char* name;
    char* value;
} typedef parameter_DataType;

struct usersParameters
{
    char* name;
    char* password;
    char* homePath;    
} typedef usersParameters_DataType;

struct ftpParameters
{
    unsigned char ftpIpAddress[4];
    int port;
    int maxClients;
    DYNV_VectorGenericDataType usersVector;
} typedef ftpParameters_DataType;

int readConfigurationFile(char *path, DYNV_VectorGenericDataType *parametersVector);
int searchParameter(char *name, DYNV_VectorGenericDataType *parametersVector);
int searchUser(char *name, DYNV_VectorGenericDataType *usersVector);
int parseConfigurationFile(ftpParameters_DataType *ftpParameters, DYNV_VectorGenericDataType *parametersVector);

#ifdef __cplusplus
}
#endif

#endif /* CONFIGREAD_H */

