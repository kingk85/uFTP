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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "configRead.h"
#include "../ftpData.h"
#include "dynamicVectors.h"
#include "../debugHelper.h"

#ifdef OPENSSL_ENABLED
	#include "openSsl.h"
#endif

#include "fileManagement.h"
#include "daemon.h"
#include "dynamicMemory.h"

#define PARAMETER_SIZE_LIMIT        1024

/* Private Functions */
static int parseConfigurationFile(ftpParameters_DataType *ftpParameters, DYNV_VectorGenericDataType *parametersVector);
static int searchParameter(char *name, DYNV_VectorGenericDataType *parametersVector);
static int readConfigurationFile(char *path, DYNV_VectorGenericDataType *parametersVector, DYNMEM_MemoryTable_DataType ** memoryTable);

void destroyConfigurationVectorElement(DYNV_VectorGenericDataType *theVector)
{
    int i;
    for (i = 0; i < theVector->Size; i++)
    {
		//my_printf("\n(parameter_DataType *)theVector->Data[%d])->value = %ld", i, ((parameter_DataType *)theVector->Data)->value);
		DYNMEM_free(((parameter_DataType *)theVector->Data[i])->value, &theVector->memoryTable);
		//my_printf("\n(parameter_DataType *)theVector->Data[%d])->name = %ld", i, ((parameter_DataType *)theVector->Data)->name);
		DYNMEM_free(((parameter_DataType *)theVector->Data[i])->name, &theVector->memoryTable);
		DYNMEM_free(theVector->Data[i], &theVector->memoryTable);
    }
}

/* Public Functions */
int searchUser(char *name, DYNV_VectorGenericDataType *usersVector)
{
    int returnCode = -1;
    int i = 0;

    for (i = 0; i <usersVector->Size; i++)
    {
        if (strcmp(name, ((usersParameters_DataType *) usersVector->Data[i])->name) == 0)
        {
            return i;
        }
    }

    return returnCode;

}

void configurationRead(ftpParameters_DataType *ftpParameters, DYNMEM_MemoryTable_DataType **memoryTable)
{
    int returnCode = 0;
    DYNV_VectorGenericDataType configParameters;
    DYNV_VectorGeneric_Init(&configParameters);
    memset(ftpParameters, 0, sizeof(ftpParameters_DataType));

    if (FILE_IsFile(LOCAL_CONFIGURATION_FILENAME) == 1)
    {
        my_printf("\nReading configuration from \n -> %s \n", LOCAL_CONFIGURATION_FILENAME);
        returnCode = readConfigurationFile(LOCAL_CONFIGURATION_FILENAME, &configParameters, memoryTable);
    }
    else if (FILE_IsFile(DEFAULT_CONFIGURATION_FILENAME) == 1)
    {
        my_printf("\nReading configuration from \n -> %s\n", DEFAULT_CONFIGURATION_FILENAME);
        returnCode = readConfigurationFile(DEFAULT_CONFIGURATION_FILENAME, &configParameters, memoryTable);
    }

    if (returnCode == 1)
    {
        parseConfigurationFile(ftpParameters, &configParameters);
    }
    else
    {
        my_printf("\nError: could not read the configuration file located at: \n -> %s or at \n -> %s", DEFAULT_CONFIGURATION_FILENAME, LOCAL_CONFIGURATION_FILENAME);
        exit(1);
    }

    DYNV_VectorGeneric_Destroy(&configParameters, destroyConfigurationVectorElement);
    //my_printf("\n\nconfigParameters.memoryTable = %d ***", configParameters.memoryTable);

    return;
}

void applyConfiguration(ftpParameters_DataType *ftpParameters)
{
    /* Fork the process daemon mode */
    if (ftpParameters->daemonModeOn == 1)
    {
        daemonize("uFTP");
    }

    if (ftpParameters->singleInstanceModeOn == 1)
    {
        int returnCode = isProcessAlreadyRunning();

        if (returnCode == 1)
        {
            my_printf("\nThe process is already running..");
            exit(0);
        }
    }
}

void initFtpData(ftpDataType *ftpData)
{
    int i;
     /* Intializes random number generator */
    srand(time(NULL));    

    ftpData->generalDynamicMemoryTable = NULL;

	#ifdef OPENSSL_ENABLED
	initOpenssl();
	ftpData->serverCtx = createServerContext();
	ftpData->clientCtx = createClientContext();
	configureContext(ftpData->serverCtx, ftpData->ftpParameters.certificatePath, ftpData->ftpParameters.privateCertificatePath);
	configureClientContext(ftpData->clientCtx, ftpData->ftpParameters.certificatePath, ftpData->ftpParameters.privateCertificatePath);
	#endif

    ftpData->connectedClients = 0;
    ftpData->clients = (clientDataType *) DYNMEM_malloc((sizeof(clientDataType) * ftpData->ftpParameters.maxClients), &ftpData->generalDynamicMemoryTable, "ClientData");

	//my_printf("\nDYNMEM_malloc called");
	//my_printf("\nElement location: %ld", (long int) ftpData->generalDynamicMemoryTable);
	//my_printf("\nElement size: %ld", ftpData->generalDynamicMemoryTable->size);
	//my_printf("\nElement address: %ld", (long int) ftpData->generalDynamicMemoryTable->address);
	//my_printf("\nElement nextElement: %ld",(long int) ftpData->generalDynamicMemoryTable->nextElement);
	//my_printf("\nElement previousElement: %ld",(long int) ftpData->generalDynamicMemoryTable->previousElement);


    ftpData->serverIp.ip[0] = 127;
    ftpData->serverIp.ip[1] = 0;
    ftpData->serverIp.ip[2] = 0;
    ftpData->serverIp.ip[3] = 1;

    memset(ftpData->welcomeMessage, 0, 1024);
    strcpy(ftpData->welcomeMessage, "220 Hello\r\n");

    DYNV_VectorGeneric_InitWithSearchFunction(&ftpData->loginFailsVector, searchInLoginFailsVector);

    //Client data reset to zero
    for (i = 0; i < ftpData->ftpParameters.maxClients; i++)
    {
        resetWorkerData(ftpData, i, 1);
        resetClientData(ftpData, i, 1);
        ftpData->clients[i].clientProgressiveNumber = i;
    }

    return;
}

/*Private functions*/
static int readConfigurationFile(char *path, DYNV_VectorGenericDataType *parametersVector, DYNMEM_MemoryTable_DataType ** memoryTable)
{
    #define STATE_START              0
    #define STATE_NAME               1
    #define STATE_VALUE              2
    #define STATE_STORE              3
    #define STATE_TO_NEW_LINE        4

    int theFileSize = 0;
    int i, state, nameIndex, valueIndex, allowSpacesInValue;
    char * theFileContent;

    theFileSize = FILE_GetStringFromFile(path, &theFileContent, memoryTable);

    char name[PARAMETER_SIZE_LIMIT];
    char value[PARAMETER_SIZE_LIMIT];
    memset(name, 0, PARAMETER_SIZE_LIMIT);
    memset(value, 0, PARAMETER_SIZE_LIMIT);
    nameIndex = 0;
    valueIndex = 0;
    i = 0;
    state = STATE_START;

    allowSpacesInValue = 0;

    while (i < theFileSize)
    {

        switch (state)
         {
            case STATE_START:
            {
                /* Skip Special chars not allowed in the name */
                if (theFileContent[i] == ' ' ||
                    theFileContent[i] == '\r' ||
                    theFileContent[i] == '\n' ||
                    theFileContent[i] == '\t')
                {
                i++;
                }
                /* 1st char is a sharp comment case */
                else if (theFileContent[i] == '#')
                {
                    state = STATE_TO_NEW_LINE;
                    i++;
                }
                /* Name Start */
                else
                {
                    state = STATE_NAME;
                }
            }
            break;

            case STATE_NAME:
            {
                /* Not allowed chars in the name */
                if (theFileContent[i] == ' ' ||
                    theFileContent[i] == '\r' ||
                    theFileContent[i] == '\t')
                {
                    i++;
                }
                /* Unexpected end of line no parameter acquisition */
                else if (theFileContent[i] == '\n')
                {
                    i++;
                    nameIndex = 0;
                    memset(name, 0, PARAMETER_SIZE_LIMIT);
                    state = STATE_START;
                }
                /* Name ends and value starts */
                else if (theFileContent[i] == '=')
                {
                    i++;
                    /* Name stored proceed to value*/
                    if (nameIndex > 0)
                        state = STATE_VALUE;
                    else if (nameIndex == 0) /* No void name allowed*/
                        state = STATE_TO_NEW_LINE;
                }
                else
                {
                    if (nameIndex < PARAMETER_SIZE_LIMIT)
                        name[nameIndex++] = theFileContent[i];
                    i++;
                }
            }
            break;

            case STATE_VALUE:
            {
                /* Skip not allowed values */
                if ((theFileContent[i] == ' ' && allowSpacesInValue == 0) ||
                    theFileContent[i] == '\r' ||
                    theFileContent[i] == '\t')
                {
                    i++;
                }
                /* Toggle the allow spaces flag */
                else if (theFileContent[i] == '"')
                {
                    i++;

                    if (allowSpacesInValue == 0)
                        allowSpacesInValue = 1;
                    else
                        allowSpacesInValue = 0;
                }    
                else if (theFileContent[i] == '\n' ||
                         i == (theFileSize-1))
                {
                    /* Value stored proceed to save */
                    if (valueIndex > 0) 
                    {
                        state = STATE_STORE;
                    }
                    else if (valueIndex == 0) /* No void value allowed*/
                    {
                        memset(name, 0, PARAMETER_SIZE_LIMIT);
                        memset(value, 0, PARAMETER_SIZE_LIMIT);
                        nameIndex = 0;
                        valueIndex = 0;
                        state = STATE_START;
                    }
                    i++;
                }
                else
                {
                    if (valueIndex < PARAMETER_SIZE_LIMIT)
                        value[valueIndex++] = theFileContent[i];
                    i++;
                }
            }
            break;

            case STATE_TO_NEW_LINE:
            {
                /* Wait until a new line is found */
                if (theFileContent[i] == '\n')
                {
                    state = STATE_START;
                }
                i++;
            }
            break;
            
            case STATE_STORE:
            {
                parameter_DataType parameter;
                parameter.name = DYNMEM_malloc(nameIndex+1, &parametersVector->memoryTable, "readConfig");
                parameter.value = DYNMEM_malloc(valueIndex+1, &parametersVector->memoryTable, "readConfig");
                strcpy(parameter.name, name);
                strcpy(parameter.value, value);
                parameter.name[nameIndex]  = '\0';
                parameter.value[valueIndex] = '\0';
                memset(name, 0, PARAMETER_SIZE_LIMIT);
                memset(value, 0, PARAMETER_SIZE_LIMIT);
                nameIndex = 0;
                valueIndex = 0;
                state = STATE_START;
                //my_printf("\nParameter read: %s = %s", parameter.name, parameter.value);
                parametersVector->PushBack(parametersVector, &parameter, sizeof(parameter_DataType));
            }
            break;

            default:
            break;
         }
    }
    
    /* che if there is a value to store */
    if (state == STATE_STORE &&
        valueIndex > 0)
    {
        parameter_DataType parameter;
        parameter.name = DYNMEM_malloc(nameIndex+1, &parametersVector->memoryTable, "readConfig");
        parameter.value = DYNMEM_malloc(valueIndex+1, &parametersVector->memoryTable, "readConfig");
        strcpy(parameter.name, name);
        strcpy(parameter.value, value);
        parameter.name[nameIndex]  = '\0';
        parameter.value[valueIndex] = '\0';
        memset(name, 0, PARAMETER_SIZE_LIMIT);
        memset(value, 0, PARAMETER_SIZE_LIMIT);
        nameIndex = 0;
        valueIndex = 0;
        //my_printf("\nParameter read: %s = %s", parameter.name, parameter.value);
        parametersVector->PushBack(parametersVector, &parameter, sizeof(parameter_DataType));
    }

    if (theFileSize > 0)
    {
        DYNMEM_free(theFileContent, memoryTable);
    }

    return 1;
}

static int searchParameter(char *name, DYNV_VectorGenericDataType *parametersVector)
{
    int returnCode = -1;
    int i = 0;
    
    for (i = 0; i <parametersVector->Size; i++)
    {
        if (strcmp(name, ((parameter_DataType *) parametersVector->Data[i])->name) == 0)
        {
            return i;
        }
    }
    return returnCode;
}

static int parseConfigurationFile(ftpParameters_DataType *ftpParameters, DYNV_VectorGenericDataType *parametersVector)
{
    int searchIndex, userIndex;

    char    userX[PARAMETER_SIZE_LIMIT], 
            passwordX[PARAMETER_SIZE_LIMIT], 
            homeX[PARAMETER_SIZE_LIMIT], 
            userOwnerX[PARAMETER_SIZE_LIMIT], 
            groupOwnerX[PARAMETER_SIZE_LIMIT];
    
    my_printf("\nReading configuration settings..");
    
    searchIndex = searchParameter("MAXIMUM_ALLOWED_FTP_CONNECTION", parametersVector);
    if (searchIndex != -1)
    {
        ftpParameters->maxClients = atoi(((parameter_DataType *) parametersVector->Data[searchIndex])->value);
        //my_printf("\nMAXIMUM_ALLOWED_FTP_CONNECTION: %d", ftpParameters->maxClients);
    }
    else
    {
        ftpParameters->maxClients = 10;
        //my_printf("\nMAXIMUM_ALLOWED_FTP_CONNECTION parameter not found in the configuration file, using the default value: %d", ftpParameters->maxClients);
    }

    searchIndex = searchParameter("MAX_CONNECTION_NUMBER_PER_IP", parametersVector);
    if (searchIndex != -1)
    {
        ftpParameters->maximumConnectionsPerIp = atoi(((parameter_DataType *) parametersVector->Data[searchIndex])->value);
        //my_printf("\nMAX_CONNECTION_NUMBER_PER_IP: %d", ftpParameters->maximumConnectionsPerIp);
    }
    else
    {
        ftpParameters->maximumConnectionsPerIp = 4;
        //my_printf("\nMAX_CONNECTION_NUMBER_PER_IP parameter not found in the configuration file, using the default value: %d", ftpParameters->maximumConnectionsPerIp);
    }

    searchIndex = searchParameter("MAX_CONNECTION_TRY_PER_IP", parametersVector);
    if (searchIndex != -1)
    {
        ftpParameters->maximumUserAndPassowrdLoginTries = atoi(((parameter_DataType *) parametersVector->Data[searchIndex])->value);
        //my_printf("\nMAX_CONNECTION_TRY_PER_IP: %d", ftpParameters->maximumUserAndPassowrdLoginTries);
    }
    else
    {
        ftpParameters->maximumUserAndPassowrdLoginTries = 3;
        //my_printf("\nMAX_CONNECTION_TRY_PER_IP parameter not found in the configuration file, using the default value: %d", ftpParameters->maximumUserAndPassowrdLoginTries);
    }
    

    
    searchIndex = searchParameter("FTP_PORT", parametersVector);
    if (searchIndex != -1)
    {
        ftpParameters->port = atoi(((parameter_DataType *) parametersVector->Data[searchIndex])->value);
        //my_printf("\nFTP_PORT: %d", ftpParameters->port);
    }
    else
    {
        ftpParameters->port = 21;
        //my_printf("\nFTP_PORT parameter not found in the configuration file, using the default value: %d", ftpParameters->maxClients);
    }
    
    
    ftpParameters->daemonModeOn = 0;
    searchIndex = searchParameter("DAEMON_MODE", parametersVector);
    if (searchIndex != -1)
    {
        if(compareStringCaseInsensitive(((parameter_DataType *) parametersVector->Data[searchIndex])->value, "true", strlen("true")) == 1)
            ftpParameters->daemonModeOn = 1;
        
        //my_printf("\nDAEMON_MODE value: %d", ftpParameters->daemonModeOn);
    }
    else
    {
        //my_printf("\nDAEMON_MODE parameter not found in the configuration file, using the default value: %d", ftpParameters->daemonModeOn);
    }
    
    ftpParameters->singleInstanceModeOn = 0;
    searchIndex = searchParameter("SINGLE_INSTANCE", parametersVector);
    if (searchIndex != -1)
    {
        if(compareStringCaseInsensitive(((parameter_DataType *) parametersVector->Data[searchIndex])->value, "true", strlen("true")) == 1)
            ftpParameters->singleInstanceModeOn = 1;

    }
    else
    {
       // my_printf("\nSINGLE_INSTANCE parameter not found in the configuration file, using the default value: %d", ftpParameters->singleInstanceModeOn);
    }

    ftpParameters->pamAuthEnabled = 0;
    searchIndex = searchParameter("ENABLE_PAM_AUTH", parametersVector);
    if (searchIndex != -1)
    {
        if(compareStringCaseInsensitive(((parameter_DataType *) parametersVector->Data[searchIndex])->value, "true", strlen("true")) == 1)
        	ftpParameters->pamAuthEnabled = 1;
    }
    else
    {
       // my_printf("\nENABLE_PAM_AUTH parameter not found in the configuration file, using the default value: %d", ftpParameters->pamAuthEnabled);
    }


    ftpParameters->forceTLS = 0;
    searchIndex = searchParameter("FORCE_TLS", parametersVector);
    if (searchIndex != -1)
    {
        if(compareStringCaseInsensitive(((parameter_DataType *) parametersVector->Data[searchIndex])->value, "true", strlen("true")) == 1)
            ftpParameters->forceTLS = 1;
    }
    else
    {
        // my_printf("\FORCE_TLS parameter not found in the configuration file, using the default value: %d", ftpParameters->forceTLS);
    }

    searchIndex = searchParameter("SERVER_IP", parametersVector);
    if (searchIndex != -1)
    {
        strncpy(&ftpParameters->natIpAddress, ((parameter_DataType *) parametersVector->Data[searchIndex])->value, STRING_SZ_SMALL);
        my_printf("\n SERVER_IP parameter:%s", ftpParameters->natIpAddress);
    }
    else
    {
        my_printf("\n SERVER_IP parameter not found in the configuration file, using the server IP.");
    }


    ftpParameters->maximumIdleInactivity = 3600;
    searchIndex = searchParameter("IDLE_MAX_TIMEOUT", parametersVector);
    if (searchIndex != -1)
    {
        ftpParameters->maximumIdleInactivity = atoi(((parameter_DataType *) parametersVector->Data[searchIndex])->value);
        //my_printf("\nIDLE_MAX_TIMEOUT value: %d", ftpParameters->maximumIdleInactivity);
    }
    else
    {
        //my_printf("\nIDLE_MAX_TIMEOUT parameter not found in the configuration file, using the default value: %d", ftpParameters->maximumIdleInactivity);
    }

    searchIndex = searchParameter("FTP_SERVER_IP", parametersVector);
    if (searchIndex != -1)
    {
        sscanf (((parameter_DataType *) parametersVector->Data[searchIndex])->value,"%d.%d.%d.%d",  &ftpParameters->ftpIpAddress[0],
                                                                                                    &ftpParameters->ftpIpAddress[1],
                                                                                                    &ftpParameters->ftpIpAddress[2],
                                                                                                    &ftpParameters->ftpIpAddress[3]);
        //my_printf("\nFTP_SERVER_IP value: %d.%d.%d.%d",    ftpParameters->ftpIpAddress[0],
        //                                                ftpParameters->ftpIpAddress[1],
        //                                                ftpParameters->ftpIpAddress[2],
        //                                                ftpParameters->ftpIpAddress[3]);
    }
    else
    {
        ftpParameters->ftpIpAddress[0] = 127;
        ftpParameters->ftpIpAddress[1] = 0;
        ftpParameters->ftpIpAddress[2] = 0;
        ftpParameters->ftpIpAddress[3] = 1;       
        //my_printf("\nFTP_SERVER_IP parameter not found in the configuration file, listening on all available networks");
    }    
    

    searchIndex = searchParameter("CERTIFICATE_PATH", parametersVector);
    if (searchIndex != -1)
    {
        strcpy(ftpParameters->certificatePath, ((parameter_DataType *) parametersVector->Data[searchIndex])->value);
       // my_printf("\nCERTIFICATE_PATH: %s", ftpParameters->certificatePath);
    }
    else
    {
    	strcpy(ftpParameters->certificatePath, "cert.pem");
       // my_printf("\nCERTIFICATE_PATH parameter not found in the configuration file, using the default value: %s", ftpParameters->certificatePath);
    }

    searchIndex = searchParameter("PRIVATE_CERTIFICATE_PATH", parametersVector);
    if (searchIndex != -1)
    {
        strcpy(ftpParameters->privateCertificatePath, ((parameter_DataType *) parametersVector->Data[searchIndex])->value);
        //my_printf("\nPRIVATE_CERTIFICATE_PATH: %s", ftpParameters->certificatePath);
    }
    else
    {
    	strcpy(ftpParameters->privateCertificatePath, "key.pem");
        //my_printf("\nPRIVATE_CERTIFICATE_PATH parameter not found in the configuration file, using the default value: %s", ftpParameters->privateCertificatePath);
    }


    searchIndex = searchParameter("RANDOM_PORT_START", parametersVector);
    if (searchIndex != -1)
    {
        ftpParameters->connectionPortMin = atoi(((parameter_DataType *) parametersVector->Data[searchIndex])->value);
        my_printf("\n RANDOM_PORT_START: %d", ftpParameters->connectionPortMin);
    }
    else
    {
        ftpParameters->connectionPortMin = 10000;
        my_printf("\n RANDOM_PORT_START parameter not found in the configuration file, using the default value: %d", ftpParameters->connectionPortMin);
    }


    searchIndex = searchParameter("RANDOM_PORT_END", parametersVector);
    if (searchIndex != -1)
    {
        ftpParameters->connectionPortMax = atoi(((parameter_DataType *) parametersVector->Data[searchIndex])->value);
        my_printf("\n RANDOM_PORT_END: %d", ftpParameters->connectionPortMax);
    }
    else
    {
        ftpParameters->connectionPortMax = 50000;
        my_printf("\n RANDOM_PORT_END parameter not found in the configuration file, using the default value: %d", ftpParameters->connectionPortMax);
    }


    /* USER SETTINGS */
    userIndex = 0;
    memset(userX, 0, PARAMETER_SIZE_LIMIT);
    memset(passwordX, 0, PARAMETER_SIZE_LIMIT);
    memset(homeX, 0, PARAMETER_SIZE_LIMIT);
    memset(userOwnerX, 0, PARAMETER_SIZE_LIMIT);
    memset(groupOwnerX, 0, PARAMETER_SIZE_LIMIT);
    
    DYNV_VectorGeneric_Init(&ftpParameters->usersVector);
    while(1)
    {
        int searchUserIndex, searchPasswordIndex, searchHomeIndex, searchUserOwnerIndex, searchGroupOwnerIndex, returnCode;
        usersParameters_DataType userData;

        returnCode = snprintf(userX, PARAMETER_SIZE_LIMIT, "USER_%d", userIndex);
        returnCode = snprintf(passwordX, PARAMETER_SIZE_LIMIT, "PASSWORD_%d", userIndex);
        returnCode = snprintf(homeX, PARAMETER_SIZE_LIMIT, "HOME_%d", userIndex);
        returnCode = snprintf(groupOwnerX, PARAMETER_SIZE_LIMIT, "GROUP_NAME_OWNER_%d", userIndex);
        returnCode = snprintf(userOwnerX, PARAMETER_SIZE_LIMIT, "USER_NAME_OWNER_%d", userIndex);
        userIndex++;
        
        searchUserIndex = searchParameter(userX, parametersVector);
        searchPasswordIndex = searchParameter(passwordX, parametersVector);
        searchHomeIndex = searchParameter(homeX, parametersVector);
        searchUserOwnerIndex = searchParameter(userOwnerX, parametersVector);
        searchGroupOwnerIndex = searchParameter(groupOwnerX, parametersVector);        
        
        //my_printf("\ngroupOwnerX = %s", groupOwnerX);
        //my_printf("\nuserOwnerX = %s", userOwnerX);
        //my_printf("\nsearchUserOwnerIndex = %d", searchUserOwnerIndex);
        //my_printf("\nsearchGroupOwnerIndex = %d", searchGroupOwnerIndex);

        
        if (searchUserIndex == -1 ||
            searchPasswordIndex == -1 ||
            searchHomeIndex == -1)
        {
            //my_printf("\n BREAK ");
            break;
        }

        userData.ownerShip.groupOwnerString = NULL;
        userData.ownerShip.userOwnerString = NULL;

        userData.name = DYNMEM_malloc((strlen(((parameter_DataType *) parametersVector->Data[searchUserIndex])->value) + 1), &ftpParameters->usersVector.memoryTable, "userData");
        userData.password = DYNMEM_malloc((strlen(((parameter_DataType *) parametersVector->Data[searchPasswordIndex])->value) + 1), &ftpParameters->usersVector.memoryTable, "userData");
        userData.homePath = DYNMEM_malloc((strlen(((parameter_DataType *) parametersVector->Data[searchHomeIndex])->value) + 1), &ftpParameters->usersVector.memoryTable, "userData");

        strcpy(userData.name, ((parameter_DataType *) parametersVector->Data[searchUserIndex])->value);
        strcpy(userData.password, ((parameter_DataType *) parametersVector->Data[searchPasswordIndex])->value);
        strcpy(userData.homePath, ((parameter_DataType *) parametersVector->Data[searchHomeIndex])->value);

        userData.name[strlen(((parameter_DataType *) parametersVector->Data[searchUserIndex])->value)] = '\0';
        userData.password[strlen(((parameter_DataType *) parametersVector->Data[searchPasswordIndex])->value)] = '\0';
        userData.homePath[strlen(((parameter_DataType *) parametersVector->Data[searchHomeIndex])->value)] = '\0';
        
        if (searchUserOwnerIndex != -1 &&
            searchGroupOwnerIndex != -1)
        {
            userData.ownerShip.groupOwnerString = DYNMEM_malloc((strlen(((parameter_DataType *) parametersVector->Data[searchGroupOwnerIndex])->value) + 1), &ftpParameters->usersVector.memoryTable, "userOwnershipData");
            userData.ownerShip.userOwnerString  = DYNMEM_malloc((strlen(((parameter_DataType *) parametersVector->Data[searchUserOwnerIndex])->value) + 1), &ftpParameters->usersVector.memoryTable, "userOwnershipData");

            strcpy(userData.ownerShip.groupOwnerString, ((parameter_DataType *) parametersVector->Data[searchGroupOwnerIndex])->value);
            strcpy(userData.ownerShip.userOwnerString, ((parameter_DataType *) parametersVector->Data[searchUserOwnerIndex])->value);

            userData.ownerShip.groupOwnerString[strlen(((parameter_DataType *) parametersVector->Data[searchGroupOwnerIndex])->value)] = '\0';
            userData.ownerShip.userOwnerString[strlen(((parameter_DataType *) parametersVector->Data[searchUserOwnerIndex])->value)] = '\0';
            
            userData.ownerShip.gid = FILE_getGID(userData.ownerShip.groupOwnerString);
            userData.ownerShip.uid = FILE_getUID(userData.ownerShip.userOwnerString);


            if (userData.ownerShip.gid != -1 &&
            	userData.ownerShip.uid != -1)
            {
            	userData.ownerShip.ownerShipSet = 1;
            }
            else
            {
                userData.ownerShip.gid = 0;
                userData.ownerShip.uid = 0;
            	userData.ownerShip.ownerShipSet = 0;
            }
        }
        else
        {
            userData.ownerShip.ownerShipSet = 0;
            userData.ownerShip.gid = 0;
            userData.ownerShip.uid = 0;
            userData.ownerShip.groupOwnerString = NULL;
            userData.ownerShip.userOwnerString  = NULL;
        }
//
//        my_printf("\n\nUser parameter found");
//        my_printf("\nName: %s", userData.name);
//        my_printf("\nPassword: %s", userData.password);
//        my_printf("\nHomePath: %s", userData.homePath);
//        my_printf("\ngroupOwnerStr: %s", userData.ownerShip.groupOwnerString);
//        my_printf("\nuserOwnerStr: %s", userData.ownerShip.userOwnerString);
//        my_printf("\nuserData.gid = %d", userData.ownerShip.gid);
//        my_printf("\nuserData.uid = %d", userData.ownerShip.uid);
//        my_printf("\nuserData.ownerShipSet = %d", userData.ownerShip.ownerShipSet);
        ftpParameters->usersVector.PushBack(&ftpParameters->usersVector, &userData, sizeof(usersParameters_DataType));
    }

    // parse the blocked user list
    userIndex = 0;
    memset(userX, 0, PARAMETER_SIZE_LIMIT);
    DYNV_VectorString_Init(&ftpParameters->blockedUsersVector);
    while(1)
    {
        int searchUserIndex, returnCode;
        returnCode = snprintf(userX, PARAMETER_SIZE_LIMIT, "BLOCK_USER_%d", userIndex);
        userIndex++;

        searchUserIndex = searchParameter(userX, parametersVector);

        if (searchUserIndex == -1)
        {
            break;
        }

        my_printf("\nAdd blocked user = %s", ((parameter_DataType *) parametersVector->Data[searchUserIndex])->value);
        ftpParameters->blockedUsersVector.PushBack(&ftpParameters->blockedUsersVector, ((parameter_DataType *) parametersVector->Data[searchUserIndex])->value, strnlen(((parameter_DataType *) parametersVector->Data[searchUserIndex])->value, PARAMETER_SIZE_LIMIT));
    }

    for (int i = 0; i < ftpParameters->blockedUsersVector.Size; i++) 
    {
        my_printf("\n User %s is blocked", ftpParameters->blockedUsersVector.Data[i]);
    }

    return 1;
}
