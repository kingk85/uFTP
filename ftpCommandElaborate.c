/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include "ftpServer.h"
#include "ftpCommandsElaborate.h"
#include "ftpData.h"

/* Elaborate the User login command */
int parseCommandUser(clientDataType *theClientData)
{
    int i, theNameIndex;
    char theName[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
    memset(theName, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
    theNameIndex = 0;

    for (i = strlen("USER")+1; i < theClientData->commandIndex; i++)
    {
        if (theClientData->theCommandReceived[i] == '\r' ||
            theClientData->theCommandReceived[i] == '\n')
            {
            break;
            }
        
        if (theClientData->theCommandReceived[i] != ' ' &&
            theNameIndex < FTP_COMMAND_ELABORATE_CHAR_BUFFER)
        {
            theName[theNameIndex++] = theClientData->theCommandReceived[i];
        }
    }
    printf("\n The Name: %s", theName);
    
    if (theNameIndex > 1)
    {
        char *theResponse = "331 User ok, Waiting for the password.\r\n";
        setDynamicStringDataType(&theClientData->login.name, theName, theNameIndex);
        write(theClientData->socketDescriptor, theResponse, strlen(theResponse));
        printf("\nUSER COMMAND OK, USERNAME IS: %s", theClientData->login.name.text);
        return 1;
    }
    else
    {
        return 0;
    }
}

int parseCommandPass(clientDataType *theClientData)
{
    int i, thePassIndex;
    char thePass[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
    memset(thePass, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
    thePassIndex = 0;

    for (i = strlen("PASS")+1; i < theClientData->commandIndex; i++)
    {
        if (theClientData->theCommandReceived[i] == '\r' ||
            theClientData->theCommandReceived[i] == '\n')
            {
            break;
            }
        
        if (theClientData->theCommandReceived[i] != ' ' &&
            thePassIndex < FTP_COMMAND_ELABORATE_CHAR_BUFFER)
        {
            thePass[thePassIndex++] = theClientData->theCommandReceived[i];
        }
    }

    printf("\n The Pass is: %s", thePass);

    if (thePassIndex > 1)
    {
        //430	Invalid username or password.
        char *theResponse = "230 Login Ok.\r\n";
        setDynamicStringDataType(&theClientData->login.password, thePass, thePassIndex);
        
        setDynamicStringDataType(&theClientData->login.absolutePath, "/home/ugo", strlen("/home/ugo"));
        setDynamicStringDataType(&theClientData->login.homePath, "/home/ugo", strlen("/home/ugo"));
        setDynamicStringDataType(&theClientData->login.ftpPath, "/", strlen("/"));
        
        write(theClientData->socketDescriptor, theResponse, strlen(theResponse));
        printf("\nPASS COMMAND OK, PASSWORD IS: %s", theClientData->login.password.text);
        printf("\nheClientData->login.homePath: %s", theClientData->login.homePath.text);
        printf("\nheClientData->login.ftpPath: %s", theClientData->login.ftpPath.text);
        printf("\nheClientData->login.absolutePath: %s", theClientData->login.absolutePath.text);
        
       return 1;
    }
    else
    {
        return 0;
    }
}

int parseCommandAuth(clientDataType *theClientData)
{
    int i, theAuthIndex;
    char theAuth[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
    memset(theAuth, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
    theAuthIndex = 0;

    for (i = strlen("AUTH")+1; i < theClientData->commandIndex; i++)
    {
        if (theClientData->theCommandReceived[i] == '\r' ||
            theClientData->theCommandReceived[i] == '\n')
            {
            break;
            }
        
        if (theClientData->theCommandReceived[i] != ' ' &&
            theAuthIndex < FTP_COMMAND_ELABORATE_CHAR_BUFFER)
        {
            theAuth[theAuthIndex++] = theClientData->theCommandReceived[i];
        }
    }

    printf("\n The Auth is: %s", theAuth);

    char *theResponse = "502 Auth command is not supported.\r\n";
    write(theClientData->socketDescriptor, theResponse, strlen(theResponse));
    return 1;

}

int parseCommandPwd(clientDataType *theClientData)
{
    int i, thePwdIndex;
    char thePwdResponse[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
    memset(thePwdResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
    thePwdIndex = 0;
    sprintf(thePwdResponse, "257 \"%s\" is your current location\r\n", theClientData->login.ftpPath.text);
    write(theClientData->socketDescriptor, thePwdResponse, strlen(thePwdResponse));
    return 1;
}

int parseCommandSyst(clientDataType *theClientData)
{
    char *theResponse = "215 UNIX Type: L8\r\n";
    write(theClientData->socketDescriptor, theResponse, strlen(theResponse));
    return 1;
}

int parseCommandFeat(clientDataType *theClientData)
{
    
    /*
    211-Extensions supported:
     EPRT
     IDLE
     MDTM
     SIZE
     MFMT
     REST STREAM
     MLST type*;size*;sizd*;modify*;UNIX.mode*;UNIX.uid*;UNIX.gid*;unique*;
     MLSD
     AUTH TLS
     PBSZ
     PROT
     UTF8
     TVFS
     ESTA
     PASV
     EPSV
     SPSV
     ESTP
    211 End.

     */
    char *theResponse = "211-Extensions supported:\r\n PASV\r\n211 End.\r\n";
    write(theClientData->socketDescriptor, theResponse, strlen(theResponse));
    return 1;
}

int parseCommandTypeI(clientDataType *theClientData)
{
    char *theResponse = "200 TYPE is now 8-bit binary\r\n";
    write(theClientData->socketDescriptor, theResponse, strlen(theResponse));
    return 1;
}

int parseCommandPasv(ftpDataType * data, int socketId)
{
    char theResponse[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
    memset(theResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
    
    sprintf(theResponse, "227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)\r\n",data->serverIp.ip[0], data->serverIp.ip[1], data->serverIp.ip[2], data->serverIp.ip[3], (data->clients[socketId].pasvData.passivePort / 256), (data->clients[socketId].pasvData.passivePort % 256));

    /* Create worker thread */
     if (data->clients[socketId].pasvData.passiveSocketIsConnected == 0)
        pthread_create(&data->clients[socketId].pasvData.pasvThread, NULL, pasvThreadHandler, (void *) &socketId);
    
    //pthread_join(data->clients[socketId].pasvThread, NULL);
   
    write(data->clients[socketId].socketDescriptor, theResponse, strlen(theResponse));

    return 1;
}

int parseCommandList(ftpDataType * data, int socketId)
{
    char theResponse[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
    memset(theResponse, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);

    /* Create worker thread */
    memset(data->clients[socketId].pasvData.theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);
    strcpy(data->clients[socketId].pasvData.theCommandReceived, data->clients[socketId].theCommandReceived);
    data->clients[socketId].pasvData.commandReceived = 1;
    
    //strcpy(theResponse, "150 Accepted data connection\r\n");
    //strcat(theResponse, "226 List processed\r\n");
   
    //226-Options: -a -l 
    //226 31 matches total 
   //write(data->clients[socketId].socketDescriptor, theResponse, strlen(theResponse));
   return 1;
}

int parseCommandRetr(ftpDataType * data, int socketId)
{
    memset(data->clients[socketId].pasvData.theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);
    strcpy(data->clients[socketId].pasvData.theCommandReceived, data->clients[socketId].theCommandReceived);
    data->clients[socketId].pasvData.commandReceived = 1;
    return 1;
}

int parseCommandCwd(clientDataType *theClientData)
{
    int i, thePathIndex;
    char thePath[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
    memset(thePath, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
    thePathIndex = 0;
    
    for (i = strlen("CWD")+1; i < theClientData->commandIndex; i++)
    {
        if (theClientData->theCommandReceived[i] == '\r' ||
            theClientData->theCommandReceived[i] == '\n')
            {
            break;
            }
        
        if (thePathIndex < FTP_COMMAND_ELABORATE_CHAR_BUFFER)
        {
            thePath[thePathIndex++] = theClientData->theCommandReceived[i];
        }
    }
    printf("\n The Path requested for CWD IS: %s", thePath);
    fflush(0);
    if (thePathIndex > 0)
    {
        char *theResponse;
        theResponse = (char *) malloc (strlen("250 OK. Current directory is ")+1);
        strcpy(theResponse, "250 OK. Current directory is ");
        
        if (thePath[0] != '/')
        {
                FILE_AppendToString(&theResponse, "/");

                if (theClientData->login.absolutePath.text[theClientData->login.absolutePath.textLen-1] != '/')
                    FILE_AppendToString(&theClientData->login.absolutePath.text, "/");
                
                if (theClientData->login.ftpPath.text[theClientData->login.ftpPath.textLen-1] != '/')
                    FILE_AppendToString(&theClientData->login.ftpPath.text, "/");
                
                FILE_AppendToString(&theClientData->login.absolutePath.text, thePath);
                FILE_AppendToString(&theClientData->login.ftpPath.text, thePath);
        }
        else if (thePath[0] == '/')
        {
            if (theClientData->login.absolutePath.text[theClientData->login.absolutePath.textLen-1] != '/')
                FILE_AppendToString(&theClientData->login.absolutePath.text, thePath);
            else
                FILE_AppendToString(&theClientData->login.absolutePath.text, thePath+1);
            
            if (theClientData->login.ftpPath.text[theClientData->login.ftpPath.textLen-1] != '/')
                FILE_AppendToString(&theClientData->login.ftpPath.text, thePath);
            else
                FILE_AppendToString(&theClientData->login.ftpPath.text, thePath+1);
        }
        
        FILE_AppendToString(&theResponse, thePath);
        FILE_AppendToString(&theResponse, " \r\n");
        
   

        
        theClientData->login.absolutePath.textLen = strlen(theClientData->login.absolutePath.text);
        theClientData->login.ftpPath.textLen = strlen(theClientData->login.ftpPath.text);
        
        write(theClientData->socketDescriptor, theResponse, strlen(theResponse));
        printf("\nUSER COMMAND OK, NEW PATH IS: %s", theClientData->login.absolutePath.text);
        printf("\nUSER COMMAND OK, NEW LOCAL PATH IS: %s", theClientData->login.ftpPath.text);
        
        fflush(0);
        free(theResponse);
        return 1;
        
    }
    else
    {
        return 0;
    }    
    
}

int parseCommandRest(clientDataType *theClientData)
{
    int i, theSizeIndex;
    char theSize[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
    memset(theSize, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
    theSizeIndex = 0;
    
    char *theResponse;
    theResponse = (char *) malloc (strlen("350 Restarting at ")+1);
    strcpy(theResponse, "350 Restarting at ");
    
    for (i = strlen("REST")+1; i < theClientData->commandIndex; i++)
    {
        if (theClientData->theCommandReceived[i] == '\r' ||
            theClientData->theCommandReceived[i] == '\n')
            {
            break;
            }
        
        if (theSizeIndex < FTP_COMMAND_ELABORATE_CHAR_BUFFER &&
            (theClientData->theCommandReceived[i] == '0' ||
            theClientData->theCommandReceived[i] == '1' ||
            theClientData->theCommandReceived[i] == '2' ||
            theClientData->theCommandReceived[i] == '3' ||
            theClientData->theCommandReceived[i] == '4' ||
            theClientData->theCommandReceived[i] == '5' ||
            theClientData->theCommandReceived[i] == '6' ||
            theClientData->theCommandReceived[i] == '7' ||
            theClientData->theCommandReceived[i] == '8' ||
            theClientData->theCommandReceived[i] == '9' ))
        {
            theSize[theSizeIndex++] = theClientData->theCommandReceived[i];
        }
    }
    
    printf("\n REST set to: %s", theSize);
    fflush(0);
    
    FILE_AppendToString(&theResponse, theSize);
    FILE_AppendToString(&theResponse, " \r\n");
    theClientData->pasvData.retrRestartAtByte = atoll(theSize);
    write(theClientData->socketDescriptor, theResponse, strlen(theResponse));    
    free(theResponse);
    
    return 1;
}

int parseCommandCdup(clientDataType *theClientData)
{
        int i;

        char *theResponse;
        theResponse = (char *) malloc (strlen("250 OK. Current directory is ")+1);
        strcpy(theResponse, "250 OK. Current directory is ");
        
        FILE_DirectoryToParent(&theClientData->login.absolutePath.text);
        FILE_DirectoryToParent(&theClientData->login.ftpPath.text);
        theClientData->login.absolutePath.textLen = strlen(theClientData->login.absolutePath.text);
        theClientData->login.ftpPath.textLen = strlen(theClientData->login.ftpPath.text);
        
        if(strncmp(theClientData->login.absolutePath.text, theClientData->login.homePath.text, theClientData->login.homePath.textLen) != 0)
        {
            setDynamicStringDataType(&theClientData->login.absolutePath, theClientData->login.homePath.text, theClientData->login.homePath.textLen);
        }
        
        FILE_AppendToString(&theResponse, theClientData->login.ftpPath.text);
        FILE_AppendToString(&theResponse, " \r\n");

        write(theClientData->socketDescriptor, theResponse, strlen(theResponse));
        printf("\nUSER COMMAND OK, NEW PATH IS: %s", theClientData->login.absolutePath.text);
        printf("\nUSER COMMAND OK, NEW LOCAL PATH IS: %s", theClientData->login.ftpPath.text);
        
        free(theResponse);
        return 1;
    
}