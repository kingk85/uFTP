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

/* The answer to every question of PAM is the password. It is allocated for each call and handed to PAM, which frees it (a
   global shared by all the logins, one element for any number of messages, was read past its end when PAM sent an
   information message with the question, and leaked when PAM did not ask anything). */
static int function_conversation(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
    const char *password = (const char *)appdata_ptr;
    struct pam_response *replies;
    int i;

    if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG || password == NULL)
        return PAM_CONV_ERR;

    replies = (struct pam_response *)calloc((size_t)num_msg, sizeof(struct pam_response));
    if (replies == NULL)
        return PAM_BUF_ERR;

    for (i = 0; i < num_msg; i++)
    {
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF || msg[i]->msg_style == PAM_PROMPT_ECHO_ON)
        {
            replies[i].resp = strdup(password);
            if (replies[i].resp == NULL)
            {
                while (i-- > 0)
                    free(replies[i].resp);
                free(replies);
                return PAM_BUF_ERR;
            }
        }
    }

    *resp = replies;
    return PAM_SUCCESS;
}

int authenticateSystem(const char *username, const char *password)
{
    const struct pam_conv local_conversation = { function_conversation, (void *)password };
    pam_handle_t *local_auth_handle = NULL; // this gets set by pam_start
    int retval, accepted = 0;

    retval = pam_start("sudo", username, &local_conversation, &local_auth_handle);

    if (retval != PAM_SUCCESS)
    {
		my_printf("pam_start returned: %d\n ", retval);
		return 0;
    }

    retval = pam_authenticate(local_auth_handle, 0);

    if (retval == PAM_SUCCESS)
    {
        /* the password is right, but the account may be expired or not allowed to log in now */
        retval = pam_acct_mgmt(local_auth_handle, 0);
        accepted = (retval == PAM_SUCCESS);
    }

    if (accepted == 0)
    {
        my_printf("pam returned %d\n", retval);
    }

    /* always: a failed login used to leave the handle (and what PAM loaded for it) behind */
    pam_end(local_auth_handle, retval);

    return accepted;
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

			login->ownerShip.uid = pass->pw_uid;
			login->ownerShip.gid = pass->pw_gid;
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



