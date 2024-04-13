/*
 * auth.c
 *
 *  Created on: 30 dic 2018
 *      Author: ugo
 */

#ifdef PAM_SUPPORT_ENABLED

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <pwd.h>
#include <security/pam_appl.h>

#include "auth.h"
#include "ftpData.h"
#include "../debugHelper.h"

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
    retval = pam_start("sudo", username, &local_conversation, &local_auth_handle);

    if (retval != PAM_SUCCESS)
    {
		my_printf("pam_start returned: %d\n ", retval);
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
			my_printf("Authentication failure.\n");
		}
		else
		{
			my_printf("pam_authenticate returned %d\n", retval);
		}
		return 0;
    }

    retval = pam_end(local_auth_handle, retval);

    if (retval != PAM_SUCCESS)
    {
		my_printf("pam_end returned\n");
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
			//my_printf("Authenticate with %s - %s through system\n", login, password);
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

//			my_printf("\nLogin as: %s", pass->pw_name);
//			my_printf("\nPasswd: %s", pass->pw_passwd);
//			my_printf("\nDir: %s", pass->pw_dir);
//			my_printf("\nGid: %d", pass->pw_gid);
//			my_printf("\nUid: %d", pass->pw_uid);
//			my_printf("\nlogin->homePath.text: %s", login->homePath.text);
//			my_printf("\nlogin->absolutePath.text: %s", login->absolutePath.text);
    	}
    }

}


#endif



