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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include "ftpData.h"
#include "ftpServer.h"
#include "library/logFunctions.h"
#include "library/fileManagement.h"
#include "library/configRead.h"
#include "library/openSsl.h"
#include "library/connection.h"
#include "library/dynamicMemory.h"
#include "library/auth.h"
#include "ftpCommandsElaborate.h"


/* Elaborate the User login command */
int parseCommandUser(ftpDataType * data, int socketId)
{
    int returnCode;
    char *theUserName;
    theUserName = getFtpCommandArg("USER", data->clients[socketId].theCommandReceived, 0);

    if (strlen(theUserName) >= 1)
    {
        setDynamicStringDataType(&data->clients[socketId].login.name, theUserName, strlen(theUserName), &data->clients[socketId].memoryTable);
        returnCode = socketPrintf(data, socketId, "s", "331 User ok, Waiting for the password.\r\n");

        if (returnCode <= 0) 
            return FTP_COMMAND_PROCESSED_WRITE_ERROR;

        return FTP_COMMAND_PROCESSED;
    }
    else
    {
        returnCode = socketPrintf(data, socketId, "s", "430 Invalid username.\r\n");

        if (returnCode <= 0)
            return FTP_COMMAND_PROCESSED_WRITE_ERROR;

        return FTP_COMMAND_PROCESSED;
    }
}

/* Elaborate the User login command */
int parseCommandSite(ftpDataType * data, int socketId)
{
    int returnCode, setPermissionsReturnCode;
    char *theCommand;
    theCommand = getFtpCommandArg("SITE", data->clients[socketId].theCommandReceived, 0);

    if(compareStringCaseInsensitive(theCommand, "CHMOD", strlen("CHMOD")) == 1)
    {
        setPermissionsReturnCode = setPermissions(theCommand, data->clients[socketId].login.absolutePath.text, data->clients[socketId].login.ownerShip);

        switch (setPermissionsReturnCode)
        {
            case FTP_CHMODE_COMMAND_RETURN_CODE_OK:
            {
            	returnCode = socketPrintf(data, socketId, "s", "200 Permissions changed\r\n");
            }
            break;

            case FTP_CHMODE_COMMAND_RETURN_CODE_NO_FILE:
            {
            	returnCode = socketPrintf(data, socketId, "s", "550 chmod no such file\r\n");
            }
            break;

            case FTP_CHMODE_COMMAND_RETURN_CODE_NO_PERMISSIONS:
            {
            	returnCode = socketPrintf(data, socketId, "s", "550 Some errors occurred while changing file permissions.\r\n");
            }
            break;            

            case FTP_CHMODE_COMMAND_RETURN_NAME_TOO_LONG:
            default: 
            {
                return FTP_COMMAND_PROCESSED_WRITE_ERROR;
            }
            break;
        }
    }
    else
    {
    	returnCode = socketPrintf(data, socketId, "s", "500 unknown extension\r\n");

        if (returnCode <= 0) 
            return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }
 
    return FTP_COMMAND_PROCESSED;
}

int parseCommandPass(ftpDataType * data, int socketId)
{
    int returnCode;
    char *thePass;
    loginFailsDataType element;
    int searchPosition = -1;

    thePass = getFtpCommandArg("PASS", data->clients[socketId].theCommandReceived, 0);

    strcpy(element.ipAddress, data->clients[socketId].clientIpAddress);
    element.failTimeStamp = time(NULL);
    element.failureNumbers = 1;

    searchPosition = data->loginFailsVector.SearchElement(&data->loginFailsVector, &element);

    if (searchPosition != -1)
    {
        if (element.failTimeStamp - ((loginFailsDataType *) data->loginFailsVector.Data[searchPosition])->failTimeStamp < WRONG_PASSWORD_ALLOWED_RETRY_TIME)
        {
            if (((loginFailsDataType *) data->loginFailsVector.Data[searchPosition])->failureNumbers >= data->ftpParameters.maximumUserAndPassowrdLoginTries)
            {
                //printf("\n TOO MANY LOGIN FAILS! \n");
                data->clients[socketId].closeTheClient = 1;
                returnCode = socketPrintf(data, socketId, "s", "430 Too many login failure detected, your ip will be blacklisted for 5 minutes\r\n");
                if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
                return FTP_COMMAND_PROCESSED;
            }
        }
    }

    if (strlen(thePass) >= 1)
    {

    	//printf("\nLogin try with user %s, password %s", data->clients[socketId].login.name.text, thePass);

    	//PAM AUTH METHOD IF ENABLED
#ifdef PAM_SUPPORT_ENABLED
    	if (data->ftpParameters.pamAuthEnabled == 1)
    	{
			loginCheck( data->clients[socketId].login.name.text, thePass, &data->clients[socketId].login, &data->clients[socketId].memoryTable);
			if (data->clients[socketId].login.userLoggedIn == 1)
			{
				//printf("\n User logged with PAM ok!");
				returnCode = socketPrintf(data, socketId, "s", "230 Login Ok.\r\n");
				if (returnCode <= 0)
					return FTP_COMMAND_PROCESSED_WRITE_ERROR;

				return 1;
			}
    	}
#endif


        int searchUserNameIndex;
        searchUserNameIndex = searchUser(data->clients[socketId].login.name.text, &data->ftpParameters.usersVector);

        if (searchUserNameIndex < 0 ||
            (strcmp(((usersParameters_DataType *) data->ftpParameters.usersVector.Data[searchUserNameIndex])->password, thePass) != 0))
        {
            
            //Record the login fail!
            if (searchPosition == -1)
            {
                if (data->ftpParameters.maximumUserAndPassowrdLoginTries != 0)
                    data->loginFailsVector.PushBack(&data->loginFailsVector, &element, sizeof(loginFailsDataType));
            }
            else
            {
                ((loginFailsDataType *) data->loginFailsVector.Data[searchPosition])->failureNumbers++;
                ((loginFailsDataType *) data->loginFailsVector.Data[searchPosition])->failTimeStamp = time(NULL);
            }
            returnCode = socketPrintf(data, socketId, "s", "430 Invalid username or password\r\n");
            if (returnCode <= 0)
            	return FTP_COMMAND_PROCESSED_WRITE_ERROR;
        }
        else
        {
            setDynamicStringDataType(&data->clients[socketId].login.password, thePass, strlen(thePass), &data->clients[socketId].memoryTable);
            setDynamicStringDataType(&data->clients[socketId].login.absolutePath, ((usersParameters_DataType *) data->ftpParameters.usersVector.Data[searchUserNameIndex])->homePath, strlen(((usersParameters_DataType *) data->ftpParameters.usersVector.Data[searchUserNameIndex])->homePath), &data->clients[socketId].memoryTable);
            setDynamicStringDataType(&data->clients[socketId].login.homePath, ((usersParameters_DataType *) data->ftpParameters.usersVector.Data[searchUserNameIndex])->homePath, strlen(((usersParameters_DataType *) data->ftpParameters.usersVector.Data[searchUserNameIndex])->homePath), &data->clients[socketId].memoryTable);
            setDynamicStringDataType(&data->clients[socketId].login.ftpPath, "/", strlen("/"), &data->clients[socketId].memoryTable);

            data->clients[socketId].login.ownerShip.ownerShipSet = ((usersParameters_DataType *) data->ftpParameters.usersVector.Data[searchUserNameIndex])->ownerShip.ownerShipSet;
            data->clients[socketId].login.ownerShip.gid = ((usersParameters_DataType *) data->ftpParameters.usersVector.Data[searchUserNameIndex])->ownerShip.gid;
            data->clients[socketId].login.ownerShip.uid = ((usersParameters_DataType *) data->ftpParameters.usersVector.Data[searchUserNameIndex])->ownerShip.uid;
            data->clients[socketId].login.userLoggedIn = 1;


            printf("\ndata->clients[socketId].login.ownerShip.ownerShipSet = %d", data->clients[socketId].login.ownerShip.ownerShipSet);
            printf("\ndata->clients[socketId].login.ownerShip.gid = %d", data->clients[socketId].login.ownerShip.gid);
            printf("\ndata->clients[socketId].login.ownerShip.uid = %d", data->clients[socketId].login.ownerShip.uid);

            returnCode = socketPrintf(data, socketId, "s", "230 Login Ok.\r\n");
            if (returnCode <= 0)
            	return FTP_COMMAND_PROCESSED_WRITE_ERROR;
        }

       return FTP_COMMAND_PROCESSED;
    }
    else
    {

        //Record the login fail!
        if (searchPosition == -1)
        {
            if (data->ftpParameters.maximumUserAndPassowrdLoginTries != 0)
                data->loginFailsVector.PushBack(&data->loginFailsVector, &element, sizeof(loginFailsDataType));
        }
        else
        {
            ((loginFailsDataType *) data->loginFailsVector.Data[searchPosition])->failureNumbers++;
            ((loginFailsDataType *) data->loginFailsVector.Data[searchPosition])->failTimeStamp = time(NULL);
        }

        returnCode = socketPrintf(data, socketId, "s", "430 Invalid username or password\r\n");
        if (returnCode <= 0)
        	return FTP_COMMAND_PROCESSED_WRITE_ERROR;
        return 1;
    }
}

int parseCommandAuth(ftpDataType * data, int socketId)
{
    int returnCode, returnCodeTls;

	#ifndef OPENSSL_ENABLED
    	returnCode = socketPrintf(data, socketId, "s", "502 Security extensions not implemented.\r\n");
		if (returnCode <= 0)
			return FTP_COMMAND_PROCESSED_WRITE_ERROR;
	#endif

	#ifdef OPENSSL_ENABLED

		returnCode = socketPrintf(data, socketId, "s", "234 AUTH TLS OK..\r\n");
		if (returnCode <= 0)
			return FTP_COMMAND_PROCESSED_WRITE_ERROR;

		returnCode = SSL_set_fd(data->clients[socketId].ssl, data->clients[socketId].socketDescriptor);

		if (returnCode == 0)
		{
			return FTP_COMMAND_PROCESSED_WRITE_ERROR;
		}

		returnCodeTls = SSL_accept(data->clients[socketId].ssl);
		data->clients[socketId].tlsNegotiatingTimeStart = (int)time(NULL);

		if (returnCodeTls <= 0)
		{
			//printf("\nSSL NOT YET ACCEPTED: %d", returnCodeTls);
			data->clients[socketId].tlsIsEnabled = 0;
			data->clients[socketId].tlsIsNegotiating = 1;
		}
		else
		{
			//printf("\nSSL ACCEPTED");
			data->clients[socketId].tlsIsEnabled = 1;
			data->clients[socketId].tlsIsNegotiating = 0;
		}
	#endif



    return FTP_COMMAND_PROCESSED;
}

int parseCommandPwd(ftpDataType * data, int socketId)
{
	//printf("\n pwd is %s", data->clients[socketId].login.ftpPath.text);
    int returnCode;
    returnCode = socketPrintf(data, socketId, "sss", "257 \"", data->clients[socketId].login.ftpPath.text ,"\" is your current location\r\n");


    if (returnCode <= 0) 
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;

    return FTP_COMMAND_PROCESSED;
}

int parseCommandSyst(ftpDataType * data, int socketId)
{
    int returnCode;
    returnCode = socketPrintf(data, socketId, "s", "215 UNIX Type: L8\r\n");
    if (returnCode <= 0) 
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;

    return FTP_COMMAND_PROCESSED;
}

int parseCommandFeat(ftpDataType * data, int socketId)
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

    int returnCode;
	#ifdef OPENSSL_ENABLED
    returnCode = socketPrintf(data, socketId, "s", "211-Extensions supported:\r\nPASV\r\nUTF8\r\nAUTH TLS\r\nPBSZ\r\nPROT\r\n211 End.\r\n");
	#endif
	#ifndef OPENSSL_ENABLED
	returnCode = socketPrintf(data, socketId, "s", "211-Extensions supported:\r\nPASV\r\nUTF8\r\n211 End.\r\n");
	#endif
    if (returnCode <= 0)
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;

    return FTP_COMMAND_PROCESSED;
}

int parseCommandProt(ftpDataType * data, int socketId)
{
    int returnCode;
    char *theProtArg;
    theProtArg = getFtpCommandArg("PROT", data->clients[socketId].theCommandReceived, 0);

    if (theProtArg[0] == 'C' || theProtArg[0] == 'c')
    {
    	//Clear
    	//printf("\nSet data channel to clear");
    	data->clients[socketId].dataChannelIsTls = 0;
    	returnCode = socketPrintf(data, socketId, "scs", "200 PROT set to ", theProtArg[0], "\r\n");

    }
    else if (theProtArg[0] == 'P' || theProtArg[0] == 'p')
    {
    	//Private
    	//printf("\nSet data channel to private");
    	data->clients[socketId].dataChannelIsTls = 1;
    	returnCode = socketPrintf(data, socketId, "scs", "200 PROT set to ", theProtArg[0], "\r\n");
    }
    else
    {
    	returnCode = socketPrintf(data, socketId, "scs", "502 Mode ", theProtArg[0]," is not implemented\r\n");
    }

    if (returnCode <= 0)
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;

    return FTP_COMMAND_PROCESSED;
}

int parseCommandCcc(ftpDataType * data, int socketId)
{
	    int returnCode;

	#ifdef OPENSSL_ENABLED

    returnCode = socketPrintf(data, socketId, "s", "200 TLS connection aborted\r\n");
    SSL_set_shutdown(data->clients[socketId].ssl, SSL_SENT_SHUTDOWN);
    data->clients[socketId].tlsIsEnabled = 0;

    if (returnCode <= 0)
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;
	#endif

	#ifndef OPENSSL_ENABLED
    returnCode = socketPrintf(data, socketId, "s", "500 command not supported\r\n");

    if (returnCode <= 0)
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;
	#endif

    return FTP_COMMAND_PROCESSED;
}

int parseCommandPbsz(ftpDataType * data, int socketId)
{
    int returnCode;
    char *thePbszSize;
    thePbszSize = getFtpCommandArg("PBSZ", data->clients[socketId].theCommandReceived, 0);

    returnCode = socketPrintf(data, socketId, "sss", "200 PBSZ set to ", thePbszSize, "\r\n");
    if (returnCode <= 0) 
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;

    return FTP_COMMAND_PROCESSED;
}

int parseCommandTypeA(ftpDataType * data, int socketId)
{
    int returnCode;
    returnCode = socketPrintf(data, socketId, "s", "200 TYPE is now 8-bit binary\r\n");

    if (returnCode <= 0) 
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;

    return FTP_COMMAND_PROCESSED;
}

int parseCommandTypeI(ftpDataType * data, int socketId)
{
    int returnCode;
    returnCode = socketPrintf(data, socketId, "s", "200 TYPE is now 8-bit binary\r\n");
    
    if (returnCode <= 0) 
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;

    return FTP_COMMAND_PROCESSED;
}

int parseCommandStruF(ftpDataType * data, int socketId)
{
    int returnCode;
    returnCode = socketPrintf(data, socketId, "s", "200 TYPE is now 8-bit binary\r\n");
    if (returnCode <= 0) 
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;

    return FTP_COMMAND_PROCESSED;
}

int parseCommandModeS(ftpDataType * data, int socketId)
{
    int returnCode;
    returnCode = socketPrintf(data, socketId, "s", "200 TYPE is now 8-bit binary\r\n");

    if (returnCode <= 0) 
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;

    return FTP_COMMAND_PROCESSED;
}

int parseCommandPasv(ftpDataType * data, int socketId)
{
    /* Create worker thread */
    void *pReturn;
    int returnCode;
    //printf("\n data->clients[%d].workerData.workerThread = %d",socketId,  (int)data->clients[socketId].workerData.workerThread);

    //printf("\n data->clients[%d].workerData.threadHasBeenCreated = %d", socketId,  data->clients[socketId].workerData.threadHasBeenCreated);
    if (data->clients[socketId].workerData.threadIsAlive == 1)
    {
    	returnCode = pthread_cancel(data->clients[socketId].workerData.workerThread);
    	//printf("\npasv pthread_cancel = %d", returnCode);
    }

    if (data->clients[socketId].workerData.threadHasBeenCreated == 1)
    {
    	returnCode = pthread_join(data->clients[socketId].workerData.workerThread, &pReturn);
    	//printf("\nPasv join ok %d", returnCode);
    }

    data->clients[socketId].workerData.passiveModeOn = 1;
    data->clients[socketId].workerData.activeModeOn = 0;    
    returnCode = pthread_create(&data->clients[socketId].workerData.workerThread, NULL, connectionWorkerHandle, (void *) &data->clients[socketId].clientProgressiveNumber);

    if (returnCode != 0)
    {
    	//printf("\nError in pthread_create %d", returnCode);
    	return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }

    return FTP_COMMAND_PROCESSED;
}

int parseCommandPort(ftpDataType * data, int socketId)
{
	int returnCode;
    char *theIpAndPort;
    int ipAddressBytes[4];
    int portBytes[2];
    theIpAndPort = getFtpCommandArg("PORT", data->clients[socketId].theCommandReceived, 0);    
    sscanf(theIpAndPort, "%d,%d,%d,%d,%d,%d", &ipAddressBytes[0], &ipAddressBytes[1], &ipAddressBytes[2], &ipAddressBytes[3], &portBytes[0], &portBytes[1]);
    data->clients[socketId].workerData.connectionPort = (portBytes[0]*256)+portBytes[1];
    returnCode = snprintf(data->clients[socketId].workerData.activeIpAddress, CLIENT_BUFFER_STRING_SIZE, "%d.%d.%d.%d", ipAddressBytes[0],ipAddressBytes[1],ipAddressBytes[2],ipAddressBytes[3]);

    void *pReturn;
    if (data->clients[socketId].workerData.threadIsAlive == 1)
    {
    	returnCode = pthread_cancel(data->clients[socketId].workerData.workerThread);
    }
    if (data->clients[socketId].workerData.threadHasBeenCreated == 1)
    {
    	returnCode = pthread_join(data->clients[socketId].workerData.workerThread, &pReturn);
    }
    data->clients[socketId].workerData.passiveModeOn = 0;
    data->clients[socketId].workerData.activeModeOn = 1;    
    returnCode = pthread_create(&data->clients[socketId].workerData.workerThread, NULL, connectionWorkerHandle, (void *) &data->clients[socketId].clientProgressiveNumber);

    if (returnCode != 0)
    {
    	//printf("\nError in pthread_create %d", returnCode);
    	return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }


    return FTP_COMMAND_PROCESSED;
}

int parseCommandAbor(ftpDataType * data, int socketId)
{
    /*
     426 ABORT
    226-Transfer aborted
    226 3.406 seconds (measured here), 1.58 Mbytes per second
    226 Since you see this ABOR must've succeeded
    */
    int returnCode;
    if (data->clients[socketId].workerData.threadIsAlive == 1)
    {
        if (data->clients[socketId].workerData.threadIsAlive == 1)
        {
            pthread_cancel(data->clients[socketId].workerData.workerThread);
        }

        returnCode = socketPrintf(data, socketId, "s", "426 ABORT\r\n");
        if (returnCode <= 0) 
            return FTP_COMMAND_PROCESSED_WRITE_ERROR;

        returnCode = socketPrintf(data, socketId, "s", "226 Transfer aborted\r\n");
        if (returnCode <= 0) 
            return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }
    else
    {
    	returnCode = socketPrintf(data, socketId, "s", "226 Since you see this ABOR must've succeeded\r\n");
        if (returnCode <= 0) 
            return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }

    return FTP_COMMAND_PROCESSED;
}

int parseCommandList(ftpDataType * data, int socketId)
{
    /*
      -1 List one file per line
      -A List all files except "." and ".."
      -a List all files including those whose names start with "."
      -C List entries by columns
      -d List directory entries instead of directory contents
      -F Append file type indicator (one of "*", "/", "=", "@" or "|") to names
      -h Print file sizes in human-readable format (e.g. 1K, 234M, 2G)
      -L List files pointed to by symlinks
      -l Use a long listing format
      -n List numeric UIDs/GIDs instead of user/group names
      -R List subdirectories recursively
      -r Sort filenames in reverse order
      -S Sort by file size
      -t Sort by modification time 
     */
    
    int isSafePath = 0;
    char *theNameToList;
    
    theNameToList = getFtpCommandArg("LIST", data->clients[socketId].theCommandReceived, 1);
    getFtpCommandArgWithOptions("LIST", data->clients[socketId].theCommandReceived, &data->clients[socketId].workerData.ftpCommand, &data->clients[socketId].workerData.memoryTable);
 
   // if (data->clients[socketId].workerData.ftpCommand.commandArgs.text != NULL)
    //	printf("\nLIST COMMAND ARG: %s", data->clients[socketId].workerData.ftpCommand.commandArgs.text);
    //if (data->clients[socketId].workerData.ftpCommand.commandOps.text != NULL)
    //	printf("\nLIST COMMAND OPS: %s", data->clients[socketId].workerData.ftpCommand.commandOps.text);
   // printf("\ntheNameToList: %s", theNameToList);
    
    cleanDynamicStringDataType(&data->clients[socketId].workerData.ftpCommand.commandArgs, 0, &data->clients[socketId].workerData.memoryTable);
    cleanDynamicStringDataType(&data->clients[socketId].workerData.ftpCommand.commandOps, 0, &data->clients[socketId].workerData.memoryTable);
    cleanDynamicStringDataType(&data->clients[socketId].listPath, 0, &data->clients[socketId].memoryTable);

    if (strlen(theNameToList) > 0)
    {
        isSafePath = getSafePath(&data->clients[socketId].listPath, theNameToList, &data->clients[socketId].login, &data->clients[socketId].memoryTable);
    }

    if (isSafePath == 0)
    {
        cleanDynamicStringDataType(&data->clients[socketId].listPath, 0, &data->clients[socketId].memoryTable);
        setDynamicStringDataType(&data->clients[socketId].listPath, data->clients[socketId].login.absolutePath.text, data->clients[socketId].login.absolutePath.textLen, &data->clients[socketId].memoryTable);
    }

    pthread_mutex_lock(&data->clients[socketId].conditionMutex);
    memset(data->clients[socketId].workerData.theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);
    strcpy(data->clients[socketId].workerData.theCommandReceived, data->clients[socketId].theCommandReceived);
    data->clients[socketId].workerData.commandReceived = 1;
    pthread_cond_signal(&data->clients[socketId].conditionVariable);
    pthread_mutex_unlock(&data->clients[socketId].conditionMutex);

    return FTP_COMMAND_PROCESSED;
}

int parseCommandNlst(ftpDataType * data, int socketId)
{
    int isSafePath = 0;
    char *theNameToNlist;
    theNameToNlist = getFtpCommandArg("NLIST", data->clients[socketId].theCommandReceived, 1);
    cleanDynamicStringDataType(&data->clients[socketId].nlistPath, 0, &data->clients[socketId].memoryTable);

   // printf("\nNLIST COMMAND ARG: %s", data->clients[socketId].workerData.ftpCommand.commandArgs.text);
    //printf("\nNLIST COMMAND OPS: %s", data->clients[socketId].workerData.ftpCommand.commandOps.text);
   // printf("\ntheNameToNlist: %s", theNameToNlist);
    
    if (strlen(theNameToNlist) > 0)
    {
        isSafePath = getSafePath(&data->clients[socketId].nlistPath, theNameToNlist, &data->clients[socketId].login, &data->clients[socketId].memoryTable);
    }

    if (isSafePath == 0)
    {
        cleanDynamicStringDataType(&data->clients[socketId].nlistPath, 0, &data->clients[socketId].memoryTable);
        setDynamicStringDataType(&data->clients[socketId].nlistPath, data->clients[socketId].login.absolutePath.text, data->clients[socketId].login.absolutePath.textLen, &data->clients[socketId].memoryTable);
    }
    
    pthread_mutex_lock(&data->clients[socketId].conditionMutex);

    memset(data->clients[socketId].workerData.theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);
    strcpy(data->clients[socketId].workerData.theCommandReceived, data->clients[socketId].theCommandReceived);
    data->clients[socketId].workerData.commandReceived = 1;
    pthread_cond_signal(&data->clients[socketId].conditionVariable);
    pthread_mutex_unlock(&data->clients[socketId].conditionMutex);

    return FTP_COMMAND_PROCESSED;
}

int parseCommandRetr(ftpDataType * data, int socketId)
{
    int isSafePath = 0;
    char *theNameToRetr;

    theNameToRetr = getFtpCommandArg("RETR", data->clients[socketId].theCommandReceived, 0);
    cleanDynamicStringDataType(&data->clients[socketId].fileToRetr, 0, &data->clients[socketId].memoryTable);

    if (strlen(theNameToRetr) > 0)
    {
        isSafePath = getSafePath(&data->clients[socketId].fileToRetr, theNameToRetr, &data->clients[socketId].login, &data->clients[socketId].memoryTable);
    }

    if (isSafePath == 1 &&
        FILE_IsFile(data->clients[socketId].fileToRetr.text) == 1)
    {
        pthread_mutex_lock(&data->clients[socketId].conditionMutex);

        memset(data->clients[socketId].workerData.theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);
        strcpy(data->clients[socketId].workerData.theCommandReceived, data->clients[socketId].theCommandReceived);
        data->clients[socketId].workerData.commandReceived = 1;
        pthread_cond_signal(&data->clients[socketId].conditionVariable);
        pthread_mutex_unlock(&data->clients[socketId].conditionMutex);

        return FTP_COMMAND_PROCESSED;
    }
    else
    {
        return FTP_COMMAND_NOT_RECONIZED;
    }

    return FTP_COMMAND_PROCESSED;
}

int parseCommandStor(ftpDataType * data, int socketId)
{
    int isSafePath = 0;
    char *theNameToStor;
    theNameToStor = getFtpCommandArg("STOR", data->clients[socketId].theCommandReceived, 0);
    cleanDynamicStringDataType(&data->clients[socketId].fileToStor, 0, &data->clients[socketId].memoryTable);

    if (strlen(theNameToStor) > 0)
    {
        isSafePath = getSafePath(&data->clients[socketId].fileToStor, theNameToStor, &data->clients[socketId].login, &data->clients[socketId].memoryTable);
    }

    if (isSafePath == 1)
    {
        pthread_mutex_lock(&data->clients[socketId].conditionMutex);
        memset(data->clients[socketId].workerData.theCommandReceived, 0, CLIENT_COMMAND_STRING_SIZE);
        strcpy(data->clients[socketId].workerData.theCommandReceived, data->clients[socketId].theCommandReceived);
        data->clients[socketId].workerData.commandReceived = 1;
        pthread_cond_signal(&data->clients[socketId].conditionVariable);
        pthread_mutex_unlock(&data->clients[socketId].conditionMutex);

    }
    else
    {
        return FTP_COMMAND_NOT_RECONIZED;
    }

    return FTP_COMMAND_PROCESSED;
}

int parseCommandCwd(ftpDataType * data, int socketId)
{
    dynamicStringDataType absolutePathPrevious, ftpPathPrevious, theSafePath;
    int isSafePath;
    int returnCode;
    char *thePath;

    cleanDynamicStringDataType(&absolutePathPrevious, 1, &data->clients[socketId].memoryTable);
    cleanDynamicStringDataType(&ftpPathPrevious, 1, &data->clients[socketId].memoryTable);
    cleanDynamicStringDataType(&theSafePath, 1, &data->clients[socketId].memoryTable);

    thePath = getFtpCommandArg("CWD", data->clients[socketId].theCommandReceived, 0);

    //printf("\ncdw requested path: %s", thePath);

    if (strlen(thePath) > 0)
    {
    	//printf("Memory data address 1st call : %lld", &data->clients[socketId].memoryTable);
        isSafePath = getSafePath(&theSafePath, thePath, &data->clients[socketId].login, &data->clients[socketId].memoryTable);
        //printf("\ncdw safe path: %s", theSafePath.text);
    }

    if (isSafePath == 1)
    {
        //printf("\n The Path requested for CWD IS:%s", theSafePath.text);
        setDynamicStringDataType(&absolutePathPrevious, data->clients[socketId].login.absolutePath.text, data->clients[socketId].login.absolutePath.textLen, &data->clients[socketId].memoryTable);
        setDynamicStringDataType(&ftpPathPrevious, data->clients[socketId].login.ftpPath.text, data->clients[socketId].login.ftpPath.textLen, &data->clients[socketId].memoryTable);

        cleanDynamicStringDataType(&data->clients[socketId].login.ftpPath, 0, &data->clients[socketId].memoryTable);
        cleanDynamicStringDataType(&data->clients[socketId].login.absolutePath, 0, &data->clients[socketId].memoryTable);
		setDynamicStringDataType(&data->clients[socketId].login.absolutePath, theSafePath.text, theSafePath.textLen, &data->clients[socketId].memoryTable);

		if (data->clients[socketId].login.absolutePath.textLen == data->clients[socketId].login.homePath.textLen)
		{
	        setDynamicStringDataType(&data->clients[socketId].login.ftpPath, "/", 1, &data->clients[socketId].memoryTable);
		}
		else if (data->clients[socketId].login.absolutePath.textLen > data->clients[socketId].login.homePath.textLen)
		{
			char *theFtpPathPointer = data->clients[socketId].login.absolutePath.text;
			theFtpPathPointer += data->clients[socketId].login.homePath.textLen;
			if (theFtpPathPointer[0] != '/')
			{
				setDynamicStringDataType(&data->clients[socketId].login.ftpPath, "/", 1, &data->clients[socketId].memoryTable);
				appendToDynamicStringDataType(&data->clients[socketId].login.ftpPath, theFtpPathPointer, strlen(theFtpPathPointer), &data->clients[socketId].memoryTable);
			}
			else
			{
				setDynamicStringDataType(&data->clients[socketId].login.ftpPath, theFtpPathPointer, strlen(theFtpPathPointer), &data->clients[socketId].memoryTable);
			}
		}


//		printf("\ndata->clients[socketId].login.absolutePath = %s", data->clients[socketId].login.absolutePath.text);
//		printf("\ndata->clients[socketId].login.ftpPath = %s", data->clients[socketId].login.ftpPath.text);
//        printf("\nChecking the directory: %s", data->clients[socketId].login.absolutePath.text);



        if (FILE_IsDirectory(data->clients[socketId].login.absolutePath.text) == 1 )
        {
        	if((checkUserFilePermissions(data->clients[socketId].login.absolutePath.text, data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid) & FILE_PERMISSION_R ) == FILE_PERMISSION_R)
        	{
        		returnCode = socketPrintf(data, socketId, "sss", "250 OK. Current directory is  ", data->clients[socketId].login.ftpPath.text, "\r\n");
        	}
        	else
        	{
                returnCode = socketPrintf(data, socketId, "sss", "530 Can't change directory to ", data->clients[socketId].login.absolutePath.text, ": no permissions\r\n");
                setDynamicStringDataType(&data->clients[socketId].login.absolutePath, absolutePathPrevious.text, absolutePathPrevious.textLen, &data->clients[socketId].memoryTable);
                setDynamicStringDataType(&data->clients[socketId].login.ftpPath, ftpPathPrevious.text, ftpPathPrevious.textLen, &data->clients[socketId].memoryTable);
        	}
        }
        else
        {
            returnCode = socketPrintf(data, socketId, "sss", "530 Can't change directory to ", data->clients[socketId].login.absolutePath.text, ": No such file or directory\r\n");
            setDynamicStringDataType(&data->clients[socketId].login.absolutePath, absolutePathPrevious.text, absolutePathPrevious.textLen, &data->clients[socketId].memoryTable);
            setDynamicStringDataType(&data->clients[socketId].login.ftpPath, ftpPathPrevious.text, ftpPathPrevious.textLen, &data->clients[socketId].memoryTable);
        }
        
        cleanDynamicStringDataType(&absolutePathPrevious, 0, &data->clients[socketId].memoryTable);
        cleanDynamicStringDataType(&ftpPathPrevious, 0, &data->clients[socketId].memoryTable);
        cleanDynamicStringDataType(&theSafePath, 0, &data->clients[socketId].memoryTable);
        
        if (returnCode <= 0) 
            return FTP_COMMAND_PROCESSED_WRITE_ERROR;


        return FTP_COMMAND_PROCESSED;
    }
    else
    {
        cleanDynamicStringDataType(&absolutePathPrevious, 0, &data->clients[socketId].memoryTable);
        cleanDynamicStringDataType(&ftpPathPrevious, 0, &data->clients[socketId].memoryTable);
        cleanDynamicStringDataType(&theSafePath, 0, &data->clients[socketId].memoryTable);
        return FTP_COMMAND_NOT_RECONIZED;
    }
}

int parseCommandRest(ftpDataType * data, int socketId)
{
    int returnCode;
    int i, theSizeIndex;
    char theSize[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
    memset(theSize, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
    theSizeIndex = 0;

    for (i = strlen("REST")+1; i < data->clients[socketId].commandIndex; i++)
    {
        if (data->clients[socketId].theCommandReceived[i] == '\r' ||
        	data->clients[socketId].theCommandReceived[i] == '\0' ||
			data->clients[socketId].theCommandReceived[i] == '\n')
            {
            break;
            }
        
        if (theSizeIndex < FTP_COMMAND_ELABORATE_CHAR_BUFFER &&
            (data->clients[socketId].theCommandReceived[i] == '0' ||
			 data->clients[socketId].theCommandReceived[i] == '1' ||
			 data->clients[socketId].theCommandReceived[i] == '2' ||
			 data->clients[socketId].theCommandReceived[i] == '3' ||
			 data->clients[socketId].theCommandReceived[i] == '4' ||
			 data->clients[socketId].theCommandReceived[i] == '5' ||
			 data->clients[socketId].theCommandReceived[i] == '6' ||
			 data->clients[socketId].theCommandReceived[i] == '7' ||
			 data->clients[socketId].theCommandReceived[i] == '8' ||
			 data->clients[socketId].theCommandReceived[i] == '9' ))
        {
            theSize[theSizeIndex++] = data->clients[socketId].theCommandReceived[i];
        }
    }

    data->clients[socketId].workerData.retrRestartAtByte = atoll(theSize);
	returnCode = socketPrintf(data, socketId, "sss", "350 Restarting at ", theSize, "\r\n");

    if (returnCode <= 0) 
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;

    return FTP_COMMAND_PROCESSED;
}

int parseCommandMkd(ftpDataType * data, int socketId)
{
    int returnCode;
    int functionReturnCode = FTP_COMMAND_NOT_RECONIZED;
    int isSafePath;
    char *theDirectoryFilename;
    dynamicStringDataType mkdFileName;

    theDirectoryFilename = getFtpCommandArg("MKD", data->clients[socketId].theCommandReceived, 0);
    
    cleanDynamicStringDataType(&mkdFileName, 1, &data->clients[socketId].memoryTable);
    isSafePath = getSafePath(&mkdFileName, theDirectoryFilename, &data->clients[socketId].login, &data->clients[socketId].memoryTable);
    
    if (isSafePath == 1)
    {
    	if ((checkParentDirectoryPermissions(mkdFileName.text, data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid) & FILE_PERMISSION_W) == FILE_PERMISSION_W)
    	{
            int returnStatus;
            returnStatus = mkdir(mkdFileName.text, S_IRWXU | S_IRWXG | S_IRWXO);

            if (returnStatus == -1)
            {
            	returnCode = socketPrintf(data, socketId, "sss", "550 error while creating directory ", theDirectoryFilename, "\r\n");
                if (returnCode <= 0)
                {
                    functionReturnCode = FTP_COMMAND_PROCESSED_WRITE_ERROR;
                }
                else
                {
                    functionReturnCode = FTP_COMMAND_PROCESSED;
                }
            }
            else
            {
                if (data->clients[socketId].login.ownerShip.ownerShipSet == 1)
                {
                    returnStatus = FILE_doChownFromUidGid(mkdFileName.text, data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid);
                }

                returnCode = socketPrintf(data, socketId, "sss", "257 \"", theDirectoryFilename, "\" : The directory was successfully created\r\n");

                if (returnCode <= 0)
                {
                    functionReturnCode = FTP_COMMAND_PROCESSED_WRITE_ERROR;
                }
                else
                {
                    functionReturnCode = FTP_COMMAND_PROCESSED;
                }
            }
    	}
    	else
    	{
        	returnCode = socketPrintf(data, socketId, "sss", "550 no permition to create directory ", theDirectoryFilename, "\r\n");
            if (returnCode <= 0) 
            {
                functionReturnCode = FTP_COMMAND_PROCESSED_WRITE_ERROR;
            }
            else
            {
                functionReturnCode = FTP_COMMAND_PROCESSED;
            }
    	}

    }
    else
    {
        cleanDynamicStringDataType(&mkdFileName, 0, &data->clients[socketId].memoryTable);
        functionReturnCode = FTP_COMMAND_NOT_RECONIZED;
    }

    cleanDynamicStringDataType(&mkdFileName, 0, &data->clients[socketId].memoryTable);
    return functionReturnCode;
}

int parseCommandOpts(ftpDataType * data, int socketId)
{
    int returnCode;
    returnCode = socketPrintf(data, socketId, "s", "200 OK\r\n");

    if (returnCode <= 0) 
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;

    return FTP_COMMAND_PROCESSED;
}

int parseCommandDele(ftpDataType * data, int socketId)
{
    int functionReturnCode = 0;
    int returnCode;
    int isSafePath;
    int returnStatus = 0;
    char *theFileToDelete;
    dynamicStringDataType deleFileName;

    theFileToDelete = getFtpCommandArg("DELE", data->clients[socketId].theCommandReceived, 0);

    cleanDynamicStringDataType(&deleFileName, 1, &data->clients[socketId].memoryTable);
    isSafePath = getSafePath(&deleFileName, theFileToDelete, &data->clients[socketId].login, &data->clients[socketId].memoryTable);
    
    if (isSafePath == 1)
    {
        //printf("\nThe file to delete is: %s", deleFileName.text);
        if (FILE_IsFile(deleFileName.text) == 1)
        {

        	if ((checkUserFilePermissions(deleFileName.text, data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid) & FILE_PERMISSION_W) == FILE_PERMISSION_W)
        	{
                returnStatus = remove(deleFileName.text);

                if (returnStatus == -1)
                {
                    returnCode = socketPrintf(data, socketId, "sss", "550 Could not delete the file: ", theFileToDelete, " some errors occurred\r\n");
                }
                else
                {
                	returnCode = socketPrintf(data, socketId, "sss", "250 Deleted ", theFileToDelete, "\r\n");
                }

                functionReturnCode = FTP_COMMAND_PROCESSED;

                if (returnCode <= 0)
                    functionReturnCode = FTP_COMMAND_PROCESSED_WRITE_ERROR;

        	}
        	else
        	{
                returnCode = socketPrintf(data, socketId, "sss", "550 Could not delete the file: ", theFileToDelete, " no permissions\r\n");

                functionReturnCode = FTP_COMMAND_PROCESSED;

                if (returnCode <= 0)
                    functionReturnCode = FTP_COMMAND_PROCESSED_WRITE_ERROR;
        	}
        }
        else
        {
            returnCode = socketPrintf(data, socketId, "s", "550 Could not delete the file: No such file or file is a directory\r\n");
            functionReturnCode = FTP_COMMAND_PROCESSED;

            if (returnCode <= 0) 
                functionReturnCode = FTP_COMMAND_PROCESSED_WRITE_ERROR;
        }
    }
    else
    {
        functionReturnCode = FTP_COMMAND_NOT_RECONIZED;
    }
    
    cleanDynamicStringDataType(&deleFileName, 0, &data->clients[socketId].memoryTable);
    return functionReturnCode;
}

int parseCommandMdtm(ftpDataType * data, int socketId)
{
    int functionReturnCode = 0;
    int returnCode;
    int isSafePath;
    char *theFileToGetModificationDate;

    dynamicStringDataType mdtmFileName;
    char theResponse[LIST_DATA_TYPE_MODIFIED_DATA_STR_SIZE];
    memset(theResponse, 0, LIST_DATA_TYPE_MODIFIED_DATA_STR_SIZE);

    theFileToGetModificationDate = getFtpCommandArg("MDTM", data->clients[socketId].theCommandReceived, 0);

    cleanDynamicStringDataType(&mdtmFileName, 1, &data->clients[socketId].memoryTable);
    isSafePath = getSafePath(&mdtmFileName, theFileToGetModificationDate, &data->clients[socketId].login, &data->clients[socketId].memoryTable);


    printf("\ntheFileToGetModificationDate = %s", theFileToGetModificationDate);
    printf("\nmdtmFileName.text = %s", mdtmFileName.text);
    printf("\nisSafePath = %d", isSafePath);
    printf("\n Safe ok is file: %d, is directory: %d", FILE_IsFile(mdtmFileName.text), FILE_IsDirectory(mdtmFileName.text));
    if (isSafePath == 1)
    {
    	printf("\n Safe ok is file: %d, is directory: %d", FILE_IsFile(mdtmFileName.text), FILE_IsDirectory(mdtmFileName.text));

        if (FILE_IsFile(mdtmFileName.text) == 1 ||
			FILE_IsDirectory(mdtmFileName.text) == 1)
        {
        	time_t theTime = FILE_GetLastModifiedData(mdtmFileName.text);
        	strftime(theResponse, LIST_DATA_TYPE_MODIFIED_DATA_STR_SIZE, "213 %Y%m%d%H%M%S\r\n", localtime(&theTime));
        	returnCode = socketPrintf(data, socketId, "s", theResponse);
        	functionReturnCode = FTP_COMMAND_PROCESSED;

            if (returnCode <= 0)
                functionReturnCode = FTP_COMMAND_PROCESSED_WRITE_ERROR;

        }
        else
        {
            returnCode = socketPrintf(data, socketId, "s", "550 Can't check for file existence\r\n");
            functionReturnCode = FTP_COMMAND_PROCESSED;

            if (returnCode <= 0)
                functionReturnCode = FTP_COMMAND_PROCESSED_WRITE_ERROR;
        }
    }
    else
    {
        functionReturnCode = FTP_COMMAND_NOT_RECONIZED;
    }

    cleanDynamicStringDataType(&mdtmFileName, 0, &data->clients[socketId].memoryTable);
    return functionReturnCode;
}

int parseCommandNoop(ftpDataType * data, int socketId)
{
    int returnCode;

    returnCode = socketPrintf(data, socketId, "s", "200 Zzz...\r\n");
    if (returnCode <= 0) {
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }

    return FTP_COMMAND_PROCESSED;
}

int notLoggedInMessage(ftpDataType * data, int socketId)
{
    int returnCode;
    returnCode = socketPrintf(data, socketId, "s", "530 You aren't logged in\r\n");

    if (returnCode <= 0) 
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;

    return FTP_COMMAND_PROCESSED;
}

int parseCommandQuit(ftpDataType * data, int socketId)
{
    int returnCode;
    returnCode = socketPrintf(data, socketId, "s", "221 Logout.\r\n");

    if (returnCode <= 0) 
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;

    data->clients[socketId].closeTheClient = 1;
    //printf("\n Closing the client quit received");
    return FTP_COMMAND_PROCESSED;
}

int parseCommandRmd(ftpDataType * data, int socketId)
{
    int functionReturnCode = 0;
    int returnCode;
    int isSafePath;
    int returnStatus = 0;
    char *theDirectoryFilename;
    dynamicStringDataType rmdFileName;

    theDirectoryFilename = getFtpCommandArg("RMD", data->clients[socketId].theCommandReceived, 0);
    cleanDynamicStringDataType(&rmdFileName, 1, &data->clients[socketId].memoryTable);
    isSafePath = getSafePath(&rmdFileName, theDirectoryFilename, &data->clients[socketId].login, &data->clients[socketId].memoryTable);
    
    if (isSafePath == 1)
    {
        if (FILE_IsDirectory(rmdFileName.text) == 1) 
        {
        	if ((checkUserFilePermissions(rmdFileName.text, data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid) & FILE_PERMISSION_W) == FILE_PERMISSION_W)
        	{
				returnStatus = rmdir(rmdFileName.text);

				if (returnStatus == -1)
				{
					returnCode = socketPrintf(data, socketId, "s", "550 Could not remove the directory, some errors occurred.\r\n");
				}
				else
				{
					returnCode = socketPrintf(data, socketId, "s", "250 The directory was successfully removed\r\n");
				}

				functionReturnCode = FTP_COMMAND_PROCESSED;

				if (returnCode <= 0)
					functionReturnCode = FTP_COMMAND_PROCESSED_WRITE_ERROR;
        	}
        	else
        	{
            	returnCode = socketPrintf(data, socketId, "s", "550 Could not delete the directory: No permissions\r\n");
                functionReturnCode = FTP_COMMAND_PROCESSED;

                if (returnCode <= 0)
                    functionReturnCode = FTP_COMMAND_PROCESSED_WRITE_ERROR;
        	}
        }
        else
        {
        	returnCode = socketPrintf(data, socketId, "s", "550 Could not delete the directory:No such directory\r\n");
            functionReturnCode = FTP_COMMAND_PROCESSED;

            if (returnCode <= 0) 
                functionReturnCode = FTP_COMMAND_PROCESSED_WRITE_ERROR;
        }
    }
    else
    {
        functionReturnCode = FTP_COMMAND_NOT_RECONIZED;
    }

    cleanDynamicStringDataType(&rmdFileName, 0, &data->clients[socketId].memoryTable);

    return functionReturnCode;
}

int parseCommandSize(ftpDataType * data, int socketId)
{
    int returnCode;
    int isSafePath;
    long long int theSize;
    char *theFileName;
    dynamicStringDataType getSizeFromFileName;

    theFileName = getFtpCommandArg("SIZE", data->clients[socketId].theCommandReceived, 0);

    cleanDynamicStringDataType(&getSizeFromFileName, 1, &data->clients[socketId].memoryTable);
    
    isSafePath = getSafePath(&getSizeFromFileName, theFileName, &data->clients[socketId].login, &data->clients[socketId].memoryTable);

    if (isSafePath == 1)
    {

        if (FILE_IsFile(getSizeFromFileName.text)== 1)
        {
            theSize = FILE_GetFileSizeFromPath(getSizeFromFileName.text);
            returnCode = socketPrintf(data, socketId, "sls", "213 ", theSize, "\r\n");
        }
        else
        {
        	returnCode = socketPrintf(data, socketId, "s", "550 Can't check for file existence\r\n");
        }
    }
    else
    {
    	returnCode = socketPrintf(data, socketId, "s", "550 Can't check for file existence\r\n");
    }
    cleanDynamicStringDataType(&getSizeFromFileName, 0, &data->clients[socketId].memoryTable);

    if (returnCode <= 0) 
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    
    return FTP_COMMAND_PROCESSED;
}

int parseCommandRnfr(ftpDataType * data, int socketId)
{
    int returnCode;
    int isSafePath;
    char *theRnfrFileName;

    theRnfrFileName = getFtpCommandArg("RNFR", data->clients[socketId].theCommandReceived, 0);
    cleanDynamicStringDataType(&data->clients[socketId].renameFromFile, 0, &data->clients[socketId].memoryTable);
    
    isSafePath = getSafePath(&data->clients[socketId].renameFromFile, theRnfrFileName, &data->clients[socketId].login, &data->clients[socketId].memoryTable);
    
    if (isSafePath == 1&&
        (FILE_IsFile(data->clients[socketId].renameFromFile.text) == 1 ||
         FILE_IsDirectory(data->clients[socketId].renameFromFile.text) == 1))
    {
        if (FILE_IsFile(data->clients[socketId].renameFromFile.text) == 1 ||
            FILE_IsDirectory(data->clients[socketId].renameFromFile.text) == 1)
        {
        	returnCode = socketPrintf(data, socketId, "s", "350 RNFR accepted - file exists, ready for destination\r\n");
        }
        else
        {
        	returnCode = socketPrintf(data, socketId, "s", "550 Sorry, but that file doesn't exist\r\n");
        }
    }
    else
    {
    	returnCode = socketPrintf(data, socketId, "s", "550 Sorry, but that file doesn't exist\r\n");
    }
    

    if (returnCode <= 0) return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    return FTP_COMMAND_PROCESSED;
}

int parseCommandRnto(ftpDataType * data, int socketId)
{
    int returnCode = 0;
    int isSafePath;
    char *theRntoFileName;

    theRntoFileName = getFtpCommandArg("RNTO", data->clients[socketId].theCommandReceived, 0);
    cleanDynamicStringDataType(&data->clients[socketId].renameToFile, 0, &data->clients[socketId].memoryTable);
    
    isSafePath = getSafePath(&data->clients[socketId].renameToFile, theRntoFileName, &data->clients[socketId].login, &data->clients[socketId].memoryTable);

    if (isSafePath == 1 &&
    		data->clients[socketId].renameFromFile.textLen > 0)
    {

        if (FILE_IsFile(data->clients[socketId].renameFromFile.text) == 1 ||
            FILE_IsDirectory(data->clients[socketId].renameFromFile.text) == 1)
        {

        	if ((checkUserFilePermissions(data->clients[socketId].renameFromFile.text, data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid) & FILE_PERMISSION_W) == FILE_PERMISSION_W &&
        		(checkParentDirectoryPermissions(data->clients[socketId].renameToFile.text, data->clients[socketId].login.ownerShip.uid, data->clients[socketId].login.ownerShip.gid) & FILE_PERMISSION_W) == FILE_PERMISSION_W)
        	{
                returnCode = rename (data->clients[socketId].renameFromFile.text, data->clients[socketId].renameToFile.text);
                if (returnCode == 0)
                {
                	returnCode = socketPrintf(data, socketId, "s",  "250 File successfully renamed or moved\r\n");
                }
                else
                {
                	returnCode = socketPrintf(data, socketId, "s",  "503 Error Renaming the file\r\n");
                }
        	}
        	else
        	{
            	returnCode = socketPrintf(data, socketId, "s", "550 No permissions to rename the file\r\n");
        	}
        }
        else
        {
        	returnCode = socketPrintf(data, socketId, "s", "503 Need RNFR before RNTO\r\n");
        }
    }
    else
    {
    	returnCode = socketPrintf(data, socketId, "s", "503 Error Renaming the file\r\n");
    }

    if (returnCode <= 0)
    {
    	return FTP_COMMAND_PROCESSED_WRITE_ERROR;
    }
    else
	{
    	return FTP_COMMAND_PROCESSED;
    }

}

int parseCommandCdup(ftpDataType * data, int socketId)
{
    int returnCode;

    FILE_DirectoryToParent(&data->clients[socketId].login.absolutePath.text, &data->clients[socketId].memoryTable);
    FILE_DirectoryToParent(&data->clients[socketId].login.ftpPath.text, &data->clients[socketId].memoryTable);
    data->clients[socketId].login.absolutePath.textLen = strlen(data->clients[socketId].login.absolutePath.text);
    data->clients[socketId].login.ftpPath.textLen = strlen(data->clients[socketId].login.ftpPath.text);

    if(strncmp(data->clients[socketId].login.absolutePath.text, data->clients[socketId].login.homePath.text, data->clients[socketId].login.homePath.textLen) != 0)
    {
        setDynamicStringDataType(&data->clients[socketId].login.absolutePath, data->clients[socketId].login.homePath.text, data->clients[socketId].login.homePath.textLen, &data->clients[socketId].memoryTable);
    }

    returnCode = socketPrintf(data, socketId, "sss", "250 OK. Current directory is ", data->clients[socketId].login.ftpPath.text, "\r\n");

    if (returnCode <= 0) 
        return FTP_COMMAND_PROCESSED_WRITE_ERROR;

    return FTP_COMMAND_PROCESSED;
}

long long int writeRetrFile(ftpDataType * data, int theSocketId, long long int startFrom, FILE *retrFP)
{
    long long int readen = 0;
    long long int toReturn = 0, writtenSize = 0;
    long long int currentPosition = 0;
    long long int theFileSize;
    char buffer[FTP_COMMAND_ELABORATE_CHAR_BUFFER];

    #ifdef LARGE_FILE_SUPPORT_ENABLED
		//#warning LARGE FILE SUPPORT IS ENABLED!
        retrFP = fopen64(data->clients[theSocketId].fileToRetr.text, "rb");
    #endif

    #ifndef LARGE_FILE_SUPPORT_ENABLED
		#warning LARGE FILE SUPPORT IS NOT ENABLED!
        retrFP = fopen(data->clients[theSocketId].fileToRetr.text, "rb");
    #endif

    if (retrFP == NULL)
    {
        return -1;
    }

    theFileSize = FILE_GetFileSize(retrFP);

    if (startFrom > 0)
    {
        #ifdef LARGE_FILE_SUPPORT_ENABLED
			//#warning LARGE FILE SUPPORT IS ENABLED!
            currentPosition = (long long int) lseek64(fileno(retrFP), startFrom, SEEK_SET);
        #endif

        #ifndef LARGE_FILE_SUPPORT_ENABLED
			#warning LARGE FILE SUPPORT IS NOT ENABLED!
            currentPosition = (long long int) lseek(fileno(retrFP), startFrom, SEEK_SET);
        #endif

        if (currentPosition == -1)
        {
            fclose(retrFP);
            retrFP = NULL;
            return toReturn;
        }
    }

    while ((readen = (long long int) fread(buffer, sizeof(char), FTP_COMMAND_ELABORATE_CHAR_BUFFER, retrFP)) > 0)
    {

    	if (data->clients[theSocketId].dataChannelIsTls != 1)
    	{
    		writtenSize = write(data->clients[theSocketId].workerData.socketConnection, buffer, readen);
    	}
    	else
    	{

		#ifdef OPENSSL_ENABLED
		if (data->clients[theSocketId].workerData.passiveModeOn == 1)
			writtenSize = SSL_write(data->clients[theSocketId].workerData.serverSsl, buffer, readen);
		else if (data->clients[theSocketId].workerData.activeModeOn == 1)
			writtenSize = SSL_write(data->clients[theSocketId].workerData.clientSsl, buffer, readen);
		#endif
    	}

      if (writtenSize <= 0)
      {

    	  printf("\nError %d while writing retr file.", writtenSize);
          fclose(retrFP);
          retrFP = NULL;
          return -1;
      }
      else
      {
            toReturn = toReturn + writtenSize;
      }
    }
    fclose(retrFP);
    retrFP = NULL;
    return toReturn;
}

char *getFtpCommandArg(char * theCommand, char *theCommandString, int skipArgs)
{
    char *toReturn = theCommandString + strlen(theCommand);

   /* Pass spaces */ 
    while (toReturn[0] == ' ')
    {
        toReturn += 1;
    }

    /* Skip eventual secondary arguments */
    if(skipArgs == 1)
    {
        if (toReturn[0] == '-')
        {
            while (toReturn[0] != ' ' &&
                   toReturn[0] != '\r' &&
                   toReturn[0] != '\n' &&
                   toReturn[0] != 0)
                {
                    toReturn += 1;
                }
        }

        /* Pass spaces */ 
        while (toReturn[0] == ' ')
        {
            toReturn += 1;
        }
    }

    return toReturn;
}

int getFtpCommandArgWithOptions(char * theCommand, char *theCommandString, ftpCommandDataType *ftpCommand, DYNMEM_MemoryTable_DataType **memoryTable)
{
    #define CASE_ARG_MAIN   0
    #define CASE_ARG_SECONDARY   1

    int i = 0;
    int isSecondArg = 0;
    char argMain[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
    char argSecondary[FTP_COMMAND_ELABORATE_CHAR_BUFFER];
    memset (argMain, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);
    memset (argSecondary, 0, FTP_COMMAND_ELABORATE_CHAR_BUFFER);

    int argMainIndex = 0;
    int argSecondaryIndex = 0;

    char *theCommandPointer = theCommandString;
    theCommandPointer += strlen(theCommand);
    
    /*Remove spaces*/
    while (theCommandPointer[0] == ' ')
    {
        theCommandPointer += 1;
    }
    
    if (theCommandPointer[i] == '-') 
    {
        isSecondArg = 1;
        theCommandPointer++;
    }
    
    while (theCommandPointer[i] != '\r' &&
           theCommandPointer[i] != '\n' &&
           theCommandPointer[i] != 0)
    {
        switch(isSecondArg)
        {
            case CASE_ARG_MAIN:
            {
                if (argMainIndex < FTP_COMMAND_ELABORATE_CHAR_BUFFER)
                    argMain[argMainIndex++] = theCommandPointer[i];
                i++;
            }
            break;
                
            case CASE_ARG_SECONDARY:
            {
                if (theCommandPointer[i] != ' ')
                {
                    if (argSecondaryIndex < FTP_COMMAND_ELABORATE_CHAR_BUFFER)
                        argSecondary[argSecondaryIndex++] = theCommandPointer[i];
                    i++;
                }
                else 
                {
                    isSecondArg = 0;
                    while (theCommandPointer[0] == ' ')
                    {
                        theCommandPointer += 1;
                    }
                }
            }
            break;
        }
    }
    
    if (argMainIndex > 0)
        setDynamicStringDataType(&ftpCommand->commandArgs, argMain, argMainIndex, &*memoryTable);

    if (argSecondaryIndex > 0)
        setDynamicStringDataType(&ftpCommand->commandOps, argSecondary, argSecondaryIndex, &*memoryTable);
        
    return 1;
}

int setPermissions(char * permissionsCommand, char * basePath, ownerShip_DataType ownerShip)
{
	#define MAXIMUM_FILENAME_LEN			4096
    #define STATUS_INCREASE 0
    #define STATUS_PERMISSIONS 1
    #define STATUS_LOCAL_PATH 2

    int permissionsCommandCursor = 0;
    int returnCode = 0;

    int status = STATUS_INCREASE;
    char thePermissionString[MAXIMUM_FILENAME_LEN];
    char theLocalPath[MAXIMUM_FILENAME_LEN];
    char theFinalFilename[MAXIMUM_FILENAME_LEN];
    int returnCodeSetPermissions, returnCodeSetOwnership;

    memset(theLocalPath, 0, MAXIMUM_FILENAME_LEN);
    memset(thePermissionString, 0, MAXIMUM_FILENAME_LEN);
    memset(theFinalFilename, 0, MAXIMUM_FILENAME_LEN);
    int thePermissionStringCursor = 0, theLocalPathCursor = 0;

    while (permissionsCommand[permissionsCommandCursor] != '\r' &&
           permissionsCommand[permissionsCommandCursor] != '\n' &&
           permissionsCommand[permissionsCommandCursor] != '\0')
    {
        switch (status)
        {
            case STATUS_INCREASE:
                if (permissionsCommandCursor == strlen("chmod"))
                {
                    status = STATUS_PERMISSIONS;
                }
            break;
            
            case STATUS_PERMISSIONS:
                if (permissionsCommand[permissionsCommandCursor] == ' ')
                {
                    status = STATUS_LOCAL_PATH;
                    break;
                }
                if (thePermissionStringCursor < MAXIMUM_FILENAME_LEN )
                    thePermissionString[thePermissionStringCursor++] = permissionsCommand[permissionsCommandCursor];
                else
                    return FTP_CHMODE_COMMAND_RETURN_NAME_TOO_LONG;
            break;
            
            case STATUS_LOCAL_PATH:
                    if (theLocalPathCursor < MAXIMUM_FILENAME_LEN)
                        theLocalPath[theLocalPathCursor++] = permissionsCommand[permissionsCommandCursor];
                    else
                        return FTP_CHMODE_COMMAND_RETURN_NAME_TOO_LONG;
            break;
        }

        permissionsCommandCursor++;
    }

    if ((strlen(basePath) + strlen(theLocalPath) + 2) >= MAXIMUM_FILENAME_LEN)
    {
        return FTP_CHMODE_COMMAND_RETURN_NAME_TOO_LONG;
    }

    if (basePath[strlen(basePath)-1] != '/') 
    {
    	returnCode = snprintf(theFinalFilename, MAXIMUM_FILENAME_LEN, "%s/%s", basePath, theLocalPath);

    	if (returnCode >= MAXIMUM_FILENAME_LEN)
    		return FTP_CHMODE_COMMAND_RETURN_NAME_TOO_LONG;
    }
    else 
    {
    	returnCode = snprintf(theFinalFilename, MAXIMUM_FILENAME_LEN, "%s%s", basePath, theLocalPath);

    	if (returnCode >= MAXIMUM_FILENAME_LEN)
    		return FTP_CHMODE_COMMAND_RETURN_NAME_TOO_LONG;
    }
    
    if (FILE_IsFile(theFinalFilename) != 1 && 
        FILE_IsDirectory(theFinalFilename) != 1)
    {
        return FTP_CHMODE_COMMAND_RETURN_CODE_NO_FILE;
    }

    if (ownerShip.ownerShipSet == 1)
    {
        returnCodeSetOwnership = FILE_doChownFromUidGid(theFinalFilename, ownerShip.uid, ownerShip.gid);
    }

    returnCode = strtol(thePermissionString, 0, 8);
    if ((returnCodeSetPermissions = chmod (theFinalFilename, returnCode)) < 0)
    {
        //printf("\n---> ERROR WHILE SETTING FILE PERMISSION");
    }

    if (returnCodeSetOwnership != 1 || returnCodeSetPermissions == -1)
    {
        return FTP_CHMODE_COMMAND_RETURN_CODE_NO_PERMISSIONS;
    }

    return FTP_CHMODE_COMMAND_RETURN_CODE_OK;
}
