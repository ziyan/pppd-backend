#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <pppd/pppd.h>
#include <pppd/chap-new.h>
#include <pppd/fsm.h>
#include <pppd/ipcp.h>

#include <python2.7/Python.h>

//
// Specifying pppd version compiled against.
//

char pppd_version[] = VERSION;

static PyObject *pybackend_module = NULL;
static char *pybackend_module_name = NULL;

static option_t pybackend_options[] = {
    { "pybackend_module_name", o_string, &pybackend_module_name, "Name of python module that implements pppd hook." },
    { NULL }
};

static void pybackend_load_module()
{
    if (pybackend_module != NULL)
    {
        return;
    }

    if (pybackend_module_name == NULL)
    {
        return;
    }

    pybackend_module = PyImport_ImportModule(pybackend_module_name);
    if (pybackend_module == NULL)
    {
        warn("pybackend plugin: failed import module: %s", pybackend_module_name);
        pybackend_module_name = NULL;
        return;
    }

    info("pybackend plugin: loaded module: %s", pybackend_module_name);
}

static PyObject *pybackend_get_function(const char *name)
{
    PyObject *attr = NULL;

    if (pybackend_module == NULL)
    {
        return NULL;
    }

    attr = PyObject_GetAttrString(pybackend_module, name);
    if (attr == NULL)
    {
        return NULL;
    }

    if (!PyCallable_Check(attr))
    {
        return NULL;
    }

    return attr;
}

static int pybackend_has_function(const char *name)
{
    if (pybackend_get_function(name) == NULL)
    {
        return 0;
    }

    return 1;
}

static int pybackend_chap_check(void)
{
    dbglog("pybackend plugin: chap_check_hook()");
    pybackend_load_module();
    return 1;
}

static int pybackend_chap_verify(char *name, char *ourname, int id, struct chap_digest_type *digest, unsigned char *challenge, unsigned char *response, char *message, int message_space)
{
    dbglog("pybackend plugin: chap_verify_hook(name = %s, ourname = %s, id = %d, ipparm = %s)", name, ourname, id, ipparam);
    pybackend_load_module();
    return 1;
}

static void pybackend_ip_choose(u_int32_t *addr)
{
    dbglog("pybackend plugin: ip_choose_hook()");
    pybackend_load_module();
}

static int pybackend_allowed_address(u_int32_t addr)
{
    ipcp_options *options = &ipcp_wantoptions[0];

    dbglog("pybackend plugin: allowed_address_hook(addr = %d)", addr);
    pybackend_load_module();

    if (options->hisaddr != 0 && options->hisaddr == addr)
    {
        return 1;
    }
    return 0;
}

static void pybackend_notifier(void *hook, int arg)
{
    const char *func = (const char *)hook;

    dbglog("pybackend plugin: %s(arg = %d)", func, arg);
    pybackend_load_module();
}

void plugin_init(void)
{
    dbglog("pybackend plugin: plugin_init()");

    Py_Initialize();

    add_options(pybackend_options);

    //
    // Only support one type of auth for now.
    //

    chap_mdtype_all &= MDTYPE_MICROSOFT_V2;

    chap_check_hook = pybackend_chap_check;
    // chap_verify_hook = pybackend_chap_verify;
    ip_choose_hook = pybackend_ip_choose;
    allowed_address_hook = pybackend_allowed_address;

    add_notifier(&ip_up_notifier, pybackend_notifier, "ip_up_notifier");
    add_notifier(&ip_down_notifier, pybackend_notifier, "ip_down_notifier");
    add_notifier(&auth_up_notifier, pybackend_notifier, "auth_up_notifier");
    add_notifier(&link_down_notifier, pybackend_notifier, "link_down_notifier");

    info("pybackend plugin: initialized");
}

