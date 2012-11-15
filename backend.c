#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <pppd/pppd.h>
#include <pppd/chap-new.h>
#include <pppd/fsm.h>
#include <pppd/ipcp.h>

char pppd_version[] = VERSION;

char *backend = NULL;

static option_t options[] = {
    { "backend_command", o_string, &backend, "Execute this backend command to retrieve secret for a user." },
    { NULL }
};

static int backend_check(void)
{
    return 1;
}

static int backend_verify(char *name, char *ourname, int id, struct chap_digest_type *digest, unsigned char *challenge, unsigned char *response, char *message, int message_space)
{
    int ok = 0;
    char command[512];
    FILE *fp;
    unsigned char secret[MAXSECRETLEN + 1];
    int secret_len = 0;

    //
    // Need to have a backend specified.
    //

    if (backend == NULL)
    {
        return 0;
    }
    
    //
    // Construct the command to be issued.
    //

    if (snprintf(command, sizeof(command), backend, name) <= 0)
    {
        return 0;
    }
    info("BACKEND executing: %s", command);
    
    fp = popen(command, "r");
    if (fp == NULL)
    {
        return 0;
    }

    if (fgets(secret, sizeof(secret), fp) != NULL)
    {
        secret_len = strlen(secret);
        while (secret_len > 0 && secret[secret_len - 1] == '\n')
        {
            secret_len--;
        }

        if (secret_len > 0)
        {
            ok = digest->verify_response(id, name, secret, secret_len, challenge, response, message, message_space);
        }
    }

    memset(secret, 0, sizeof(secret));

    pclose(fp);

    return ok;
}

static int backend_allowed_address(u_int32_t addr)
{
	ipcp_options *options = &ipcp_wantoptions[0];
	if (options->hisaddr != 0 && options->hisaddr == addr)
	{
		return 1;
	}
	return -1;
}

void plugin_init(void)
{
    add_options(options);

    chap_check_hook = backend_check;
	chap_verify_hook = backend_verify;
	
    allowed_address_hook = backend_allowed_address;

    //
    // Only support one type of auth for now.
    //	
	chap_mdtype_all &= MDTYPE_MICROSOFT_V2;

	info("BACKEND plugin initialized.");
}

