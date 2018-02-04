#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "configRead.h"
#include "dynamicVectors.h"
#include "fileManagement.h"

#define PARAMETER_SIZE_LIMIT        1024

int readConfigurationFile(char *path, DYNV_VectorGenericDataType *parametersVector)
{

    #define STATE_START              0
    #define STATE_NAME               1
    #define STATE_VALUE              2
    #define STATE_STORE              3
    #define STATE_TO_NEW_LINE        4

    int theFileSize = 0;
    int i, state, nameIndex, valueIndex, allowSpacesInValue;
    char * theFileContent;
    theFileSize = FILE_GetStringFromFile(path, &theFileContent);

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
                else if (theFileContent[i] == '\n')
                {
                    /* Value stored proceed to save */
                    if (valueIndex > 0)
                        state = STATE_STORE;
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
            parameter.name = malloc(nameIndex+1);
            parameter.value = malloc(valueIndex+1);
            strcpy(parameter.name, name);
            strcpy(parameter.value, value);
            parameter.name[nameIndex]  = '\0';
            parameter.value[valueIndex] = '\0';
            memset(name, 0, PARAMETER_SIZE_LIMIT);
            memset(value, 0, PARAMETER_SIZE_LIMIT);
            nameIndex = 0;
            valueIndex = 0;
            state = STATE_START;
            printf("\nParameter read: %s = %s", parameter.name, parameter.value);
            parametersVector->PushBack(parametersVector, &parameter, sizeof(parameter_DataType));
            }
            break;

         }


    }
    
    return 1;

}

int searchParameter(char *name, DYNV_VectorGenericDataType *parametersVector)
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

int parseConfigurationFile(ftpParameters_DataType *ftpParameters, DYNV_VectorGenericDataType *parametersVector)
{
    int searchIndex;
    int userIndex;
    char userX[PARAMETER_SIZE_LIMIT], passwordX[PARAMETER_SIZE_LIMIT], homeX[PARAMETER_SIZE_LIMIT];
    
    searchIndex = searchParameter("MAXIMUM_ALLOWED_FTP_CONNECTION", parametersVector);
    if (searchIndex != -1)
    {
        ftpParameters->maxClients = atoi(((parameter_DataType *) parametersVector->Data[searchIndex])->value);
        printf("\nFtp maximum allowed clients: %d", ftpParameters->maxClients);
    }
    else
    {
        ftpParameters->maxClients = 10;
    }
    
    searchIndex = searchParameter("FTP_PORT", parametersVector);
    if (searchIndex != -1)
    {
        ftpParameters->port = atoi(((parameter_DataType *) parametersVector->Data[searchIndex])->value);
        printf("\nFtp port: %d", ftpParameters->port);
    }
    else
    {
        ftpParameters->port = 21;
    }
    
    
    searchIndex = searchParameter("FTP_SERVER_IP", parametersVector);
    if (searchIndex != -1)
    {
        sscanf (((parameter_DataType *) parametersVector->Data[searchIndex])->value,"%d.%d.%d.%d",  &ftpParameters->ftpIpAddress[0],
                                                                                                    &ftpParameters->ftpIpAddress[1],
                                                                                                    &ftpParameters->ftpIpAddress[2],
                                                                                                    &ftpParameters->ftpIpAddress[3]);
        printf("\nFtp ip address: %d.%d.%d.%d", ftpParameters->ftpIpAddress[0],
                                                ftpParameters->ftpIpAddress[1],
                                                ftpParameters->ftpIpAddress[2],
                                                ftpParameters->ftpIpAddress[3]);
    }
    else
    {
        ftpParameters->ftpIpAddress[0] = 127;
        ftpParameters->ftpIpAddress[1] = 0;
        ftpParameters->ftpIpAddress[2] = 0;
        ftpParameters->ftpIpAddress[3] = 1;
    }    
    
    printf("\nFtp port wait start: %d", ftpParameters->port);
    /* USER SETTINGS */
    userIndex = 0;
    
    memset(userX, 0, PARAMETER_SIZE_LIMIT);
    memset(passwordX, 0, PARAMETER_SIZE_LIMIT);
    memset(homeX, 0, PARAMETER_SIZE_LIMIT);

    DYNV_VectorGeneric_Init(&ftpParameters->usersVector);
    printf("\nFtp port xxx: %d", ftpParameters->port);
    while(1)
    {
        printf("\nFtp port start: %d", ftpParameters->port);
        int searchUserIndex, searchPasswordIndex, searchHomeIndex;
        usersParameters_DataType userData;

        sprintf(userX, "USER_%d", userIndex);
        sprintf(passwordX, "PASSWORD_%d", userIndex);
        sprintf(homeX, "HOME_%d", userIndex);
        userIndex++;
        
        searchUserIndex = searchParameter(userX, parametersVector);
        searchPasswordIndex = searchParameter(passwordX, parametersVector);
        searchHomeIndex = searchParameter(homeX, parametersVector);
        
        if (searchUserIndex == -1 ||
            searchPasswordIndex == -1 ||
            searchHomeIndex == -1)
        {
            printf("\n BREAK ");
            break;
        }
        
        userData.name = malloc(strlen(((parameter_DataType *) parametersVector->Data[searchUserIndex])->value) + 1);
        userData.password = malloc(strlen(((parameter_DataType *) parametersVector->Data[searchPasswordIndex])->value) + 1);
        userData.homePath = malloc(strlen(((parameter_DataType *) parametersVector->Data[searchHomeIndex])->value) + 1);

        strcpy(userData.name, ((parameter_DataType *) parametersVector->Data[searchUserIndex])->value);
        strcpy(userData.password, ((parameter_DataType *) parametersVector->Data[searchPasswordIndex])->value);
        strcpy(userData.homePath, ((parameter_DataType *) parametersVector->Data[searchHomeIndex])->value);

        userData.name[strlen(((parameter_DataType *) parametersVector->Data[searchUserIndex])->value)] = '\0';
        userData.password[strlen(((parameter_DataType *) parametersVector->Data[searchPasswordIndex])->value)] = '\0';
        userData.homePath[strlen(((parameter_DataType *) parametersVector->Data[searchHomeIndex])->value)] = '\0';

        printf("\n\nAdding user");
        printf("\nName: %s", userData.name);
        printf("\nPassword: %s", userData.password);
        printf("\nHomePath: %s", userData.homePath);
        
        ftpParameters->usersVector.PushBack(&ftpParameters->usersVector, &userData, sizeof(usersParameters_DataType));
        printf("\nFtp port end: %d", ftpParameters->port);
    }
    
    

    
    return 1;
}