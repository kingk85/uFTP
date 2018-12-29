#include <stdio.h>
#include <security/pam_appl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
//gcc -o pamTest pamTest.c -lpam

struct pam_response *reply;

// //function used to get user input
int function_conversation(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
    *resp = reply;
        return PAM_SUCCESS;
}

int authenticate_system(const char *username, const char *password)
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

    printf("Authenticated.\n");
    retval = pam_end(local_auth_handle, retval);

    if (retval != PAM_SUCCESS)
    {
            printf("pam_end returned\n");
            return 0;
    }

    return 1;
}

int main(int argc, char** argv)
{
    char* login;
    char* password;

    printf("Authentication module\n");

    if (argc != 3)
    {
        printf("Invalid count of arguments %d.\n", argc);
        printf("./authModule <username> <password>");
        return 1;
    }

    login = argv[1];
    password = argv[2];

    if (authenticate_system(login, password) == 1)
    {
        printf("Authenticate with %s - %s through system\n", login, password);
        return 0;
    }

    printf("Authentication failed!\n");
    return 1;
}
