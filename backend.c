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
    if (backend)
    {
        return 1;
    }
    return 0;
}

static int backend_exec(const char *cmd, char *argv[], pid_t *ppid, FILE **pfp_read, FILE **pfp_write)
{
    int fd_read[2];
    int fd_write[2];
    pid_t pid = 0;
    FILE *fp_read = NULL;
    FILE *fp_write = NULL;

    *ppid = 0;
    *pfp_read = NULL;
    *pfp_write = NULL;

    //
    // Create the pipes.
    //

    if (pipe(fd_read) < 0)
    {
        return 0;
    }

    if (pipe(fd_write) < 0)
    {
        close(fd_read[0]);
        close(fd_read[1]);
        return 0;
    }

    //
    // Fork.
    //

    pid = fork();
    if (pid < 0)
    {
        close(fd_read[0]);
        close(fd_read[1]);
        close(fd_write[0]);
        close(fd_write[1]);
        return 0;
    }

    //
    // If we are child process.
    //

    if (pid == 0)
    {
        //
        // Redirect pipes.
        //

        if (fd_read[1] != STDOUT_FILENO)
        {
            dup2(fd_read[1], STDOUT_FILENO);
            close(fd_read[1]);
        }
        close(fd_read[0]);

        if (fd_write[0] != STDIN_FILENO)
        {
            dup2(fd_write[0], STDIN_FILENO);
            close(fd_write[0]);
        }
        close(fd_write[1]);

        //
        // Execute the backend with name as the argument.
        //

        execv(backend, argv);
        _exit(127);
        return 0;
    }

    //
    // We are the parent process.
    //

    close(fd_read[1]);
    close(fd_write[0]);

    //
    // Connect up read and write pipe to child process.
    //

    fp_read = fdopen(fd_read[0], "r");
    if (fp_read == NULL)
    {
        close(fd_read[0]);
        close(fd_write[1]);
        return 0;
    }

    fp_write = fdopen(fd_write[1], "w");
    if (fp_write == NULL)
    {
        fclose(fp_read);
        close(fd_write[1]);
        return 0;
    }

    //
    // No failure.
    //

    *ppid = pid;
    *pfp_read = fp_read;
    *pfp_write = fp_write;

    return 1;
}

static int backend_close(pid_t pid, FILE *fp_read, FILE *fp_write)
{
    int result_read = 0;
    int result_write = 0;

    //
    // Close and wait till child process exits.
    //

    result_read = fclose(fp_read);
    result_write = fclose(fp_write);

    if (result_read == EOF || result_write == EOF)
    {
        return 0;
    }

    while (waitpid(pid, NULL, 0) < 0)
    {
        if (errno != EINTR)
        {
            return 0;
        }
    }

    return 1;
}

static int backend_verify(char *name, char *ourname, int id, struct chap_digest_type *digest, unsigned char *challenge, unsigned char *response, char *message, int message_space)
{
    int ok = 0;
    unsigned char secret[MAXSECRETLEN + 1];
    FILE *fp_read = NULL;
    FILE *fp_write = NULL;
    pid_t pid = 0;
    int secret_len = 0;
    char *argv[3] = {backend, name, NULL};

    //
    // Need to have a backend specified.
    //

    if (backend == NULL)
    {
        return 0;
    }
    
    //
    // Execute backend.
    //

    if (!backend_exec(backend, argv, &pid, &fp_read, &fp_write))
    {
        return 0;
    }

    info("BACKEND plugin executing: %s", backend);

    //
    // Read backend output.
    //

    if (fgets(secret, sizeof(secret), fp_read) != NULL)
    {
        //
        // Strip trailing return character.
        //

        secret_len = strlen(secret);
        if (secret_len > 0 && secret[secret_len - 1] == '\n')
        {
            secret_len--;
        }

        //
        // Verify challenge response.
        //

        if (secret_len > 0)
        {
            ok = digest->verify_response(id, name, secret, secret_len, challenge, response, message, message_space);
        }
    }

    //
    // Clean up.
    //

    memset(secret, 0, sizeof(secret));

    backend_close(pid, fp_read, fp_write);

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

