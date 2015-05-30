#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <pppd/pppd.h>
#include <pppd/chap-new.h>
#include <pppd/fsm.h>
#include <pppd/ipcp.h>

typedef struct _backend
{
    int fd_read[2];
    int fd_write[2];
    pid_t pid;
    FILE *fp_read;
    FILE *fp_write;
} backend_t;

static void backend_zero(backend_t *backend)
{
    memset(backend, 0, sizeof(*backend));
    backend->fd_read[0] = -1;
    backend->fd_read[1] = -1;
    backend->fd_write[0] = -1;
    backend->fd_write[1] = -1;
}

static int backend_wait(backend_t *backend)
{
    int status = 0;

    if (backend->fp_write != NULL)
    {
        fclose(backend->fp_write);
        backend->fp_write = NULL;
    }

    if (backend->fp_read != NULL)
    {
        fclose(backend->fp_read);
        backend->fp_read = NULL;
    }

    if (backend->pid == 0)
    {
        return 0;
    }

    if (waitpid(backend->pid, &status, 0) != backend->pid)
    {
        return 0;
    }

    if (status != 0)
    {
        return 0;
    }

    return 1;
}

static void backend_close(backend_t *backend)
{
    backend_wait(backend);

    if (backend->fd_read[0] >= 0)
    {
        close(backend->fd_read[0]);
    }

    if (backend->fd_read[1] >= 0)
    {
        close(backend->fd_read[1]);
    }

    if (backend->fd_write[0] >= 0)
    {
        close(backend->fd_write[0]);
    }

    if (backend->fd_write[1] >= 0)
    {
        close(backend->fd_write[1]);
    }

    backend_zero(backend);
}

static int backend_open(const char *cmd, char *argv[], backend_t *backend_out)
{
    backend_t backend;

    backend_zero(&backend);
    backend_zero(backend_out);

    //
    // Create the pipes.
    //

    if (pipe(backend.fd_read) < 0)
    {
        backend_close(&backend);
        return 0;
    }

    if (pipe(backend.fd_write) < 0)
    {
        backend_close(&backend);
        return 0;
    }

    //
    // Fork.
    //

    backend.pid = fork();
    if (backend.pid < 0)
    {
        backend_close(&backend);
        return 0;
    }

    //
    // If we are child process.
    //

    if (backend.pid == 0)
    {
        //
        // Redirect pipes.
        //

        if (backend.fd_read[1] != STDOUT_FILENO)
        {
            dup2(backend.fd_read[1], STDOUT_FILENO);
            close(backend.fd_read[1]);
            backend.fd_read[1] = -1;
        }
        close(backend.fd_read[0]);
        backend.fd_read[0] = -1;

        if (backend.fd_write[0] != STDIN_FILENO)
        {
            dup2(backend.fd_write[0], STDIN_FILENO);
            close(backend.fd_write[0]);
            backend.fd_write[0] = -1;
        }
        close(backend.fd_write[1]);
        backend.fd_write[1] = -1;

        //
        // Execute the backend with name as the argument.
        //

        execv(cmd, argv);

        //
        // Should never reach here.
        //

        _exit(127);
        return 0;
    }

    //
    // We are the parent process.
    //

    close(backend.fd_read[1]);
    backend.fd_read[1] = -1;
    close(backend.fd_write[0]);
    backend.fd_write[0] = -1;

    //
    // Connect up read and write pipe to child process.
    //

    backend.fp_read = fdopen(backend.fd_read[0], "r");
    if (backend.fp_read == NULL)
    {
        backend_close(&backend);
        return 0;
    }

    backend.fp_write = fdopen(backend.fd_write[1], "w");
    if (backend.fp_write == NULL)
    {
        backend_close(&backend);
        return 0;
    }

    //
    // No failure.
    //

    *backend_out = backend;
    backend_close(&backend);
    return 1;
}

static char *backend_command = NULL;

static option_t backend_options[] = {
    { "backend_command", o_string, &backend_command, "Execute this backend command to retrieve secret for a user." },
    { NULL }
};

static int backend_verify(char *name, char *ourname, int id, struct chap_digest_type *digest, unsigned char *challenge, unsigned char *response, char *message, int message_space)
{
    char *argv[3] = {backend_command, name, NULL};
    backend_t backend;
    char secret[MAXSECRETLEN + 1];
    int secret_len = 0;

    //
    // Need to have a backend specified.
    //

    if (backend_command == NULL)
    {
        return 0;
    }

    //
    // Execute backend.
    //

    info("backend plugin executing: %s", backend_command);
    if (!backend_open(backend_command, argv, &backend))
    {
        return 0;
    }

    //
    // Read backend output.
    //

    if (fgets(secret, sizeof(secret), backend.fp_read) != NULL)
    {
        //
        // Strip trailing return character.
        //

        secret_len = strlen(secret);
        if (secret_len > 0 && secret[secret_len - 1] == '\n')
        {
            secret_len--;
        }
    }

    //
    // Verify challenge response.
    //

    if (secret_len <= 0)
    {
        backend_close(&backend);
        return 0;
    }

    if (!digest->verify_response(id, name, (unsigned char *)secret, secret_len, challenge, response, message, message_space))
    {
        backend_close(&backend);
        return 0;
    }

    //
    // If backend process exited abnormally, consider that as a failed auth.
    //

    if (!backend_wait(&backend))
    {
        backend_close(&backend);
        return 0;
    }

    //
    // No failure.
    //

    backend_close(&backend);
    return 1;
}

void plugin_init(void)
{
    add_options(backend_options);

    //
    // Only support one type of auth for now.
    //

    chap_mdtype_all &= MDTYPE_MICROSOFT_V2;
    chap_verify_hook = backend_verify;

    info("backend plugin initialized.");
}

