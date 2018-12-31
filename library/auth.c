/*
 * auth.c
 *
 *  Created on: 30 dic 2018
 *      Author: ugo
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <security/pam_appl.h>

#include "auth.h"
#include "ftpData.h"

struct pam_response *reply;

// //function used to get user input
int function_conversation(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
    *resp = reply;
        return PAM_SUCCESS;
}

int authenticateSystem(const char *username, const char *password)
{
    const struct pam_conv local_conversation = { function_conversation, NULL };
    pam_handle_t *local_auth_handle = NULL; // this gets set by pam_start

    int retval;
    retval = pam_start("su", username, &local_conversation, &local_auth_handle);

    if (retval != PAM_SUCCESS)
    {
		printf("pam_start returned: %d\n ", retval);
		return 0;
    }

    reply = (struct pam_response *)malloc(sizeof(struct pam_response));
    reply[0].resp = strdup(password);
    reply[0].resp_retcode = 0;
    retval = pam_authenticate(local_auth_handle, 0);

    if (retval != PAM_SUCCESS)
    {
		if (retval == PAM_AUTH_ERR)
		{
			printf("Authentication failure.\n");
		}
		else
		{
			printf("pam_authenticate returned %d\n", retval);
		}
		return 0;
    }

    retval = pam_end(local_auth_handle, retval);

    if (retval != PAM_SUCCESS)
    {
		printf("pam_end returned\n");
		return 0;
    }

    return 1;
}


void loginCheck(char *name, char *password, loginDataType *login, DYNMEM_MemoryTable_DataType **memoryTable)
{
    if (authenticateSystem(name, password) == 1)
    {
    	struct passwd *pass;
    	pass = getpwnam(name);

    	if (pass == NULL)
    	{
    		login->userLoggedIn = 0;
    		return;
    	}
    	else
    	{
			//printf("Authenticate with %s - %s through system\n", login, password);
			setDynamicStringDataType(&login->name, name, strlen(name), &*memoryTable);
			setDynamicStringDataType(&login->homePath, pass->pw_dir, strlen(pass->pw_dir), &*memoryTable);
			//setDynamicStringDataType(&login->homePath, "/", 1, &*memoryTable);
			setDynamicStringDataType(&login->absolutePath, pass->pw_dir, strlen(pass->pw_dir), &*memoryTable);
            setDynamicStringDataType(&login->ftpPath, "/", strlen("/"), &*memoryTable);

			if (login->homePath.text[login->homePath.textLen-1] != '/')
			{
				appendToDynamicStringDataType(&login->homePath, "/", 1, &*memoryTable);
			}

			if (login->absolutePath.text[login->absolutePath.textLen-1] != '/')
			{
				appendToDynamicStringDataType(&login->absolutePath, "/", 1, &*memoryTable);
			}

			//setDynamicStringDataType(&login->ftpPath, "/", strlen("/"), &*memoryTable);

			login->ownerShip.uid = pass->pw_gid;
			login->ownerShip.gid = pass->pw_uid;
			login->ownerShip.ownerShipSet = 1;
			login->userLoggedIn = 1;

			printf("\nLogin as: %s", pass->pw_name);
			printf("\nPasswd: %s", pass->pw_passwd);
			printf("\nDir: %s", pass->pw_dir);
			printf("\nGid: %d", pass->pw_gid);
			printf("\nUid: %d", pass->pw_uid);
			printf("\nlogin->homePath.text: %s", login->homePath.text);
			printf("\nlogin->absolutePath.text: %s", login->absolutePath.text);
    	}
    }
    else
    {
		cleanLoginData(login, 0, &*memoryTable);
    }
}






