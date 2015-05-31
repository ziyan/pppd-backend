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

static PyObject *pybackend_load_module()
{
    PyObject *result = NULL;

    if (pybackend_module != NULL)
    {
        result = pybackend_module;
        goto Exit;
    }

    if (pybackend_module_name == NULL)
    {
        warn("pybackend plugin: no python module specified");
        goto Exit;
    }

    pybackend_module = PyImport_ImportModule(pybackend_module_name);
    if (pybackend_module == NULL)
    {
        warn("pybackend plugin: failed import module: %s", pybackend_module_name);
        goto Exit;
    }

    info("pybackend plugin: loaded module: %s", pybackend_module_name);
    result = pybackend_module;

Exit:

    Py_XINCREF(result);
    return result;
}

static PyObject *pybackend_get_function(const char *name)
{
    PyObject *result = NULL;
    PyObject *module = NULL;
    PyObject *attr = NULL;

    module = pybackend_load_module();
    if (module == NULL)
    {
        goto Exit;
    }

    attr = PyObject_GetAttrString(module, name);
    if (attr == NULL)
    {
        warn("pybackend plugin: function %s not found in python module", name);
        goto Exit;
    }

    if (!PyCallable_Check(attr))
    {
        warn("pybackend plugin: function %s is not a callable in python module", name);
        goto Exit;
    }

    //
    // No failure.
    //

    result = attr;
    attr = NULL;

Exit:

    Py_CLEAR(attr);
    Py_CLEAR(module);
    return result;
}

static PyObject *pybackend_call_function(const char *name, int nargs, ...)
{
    PyObject *result = NULL;
    PyObject *func = NULL;
    PyObject *arg = NULL;
    PyObject *args = NULL;
    PyObject *ret = NULL;
    va_list argp;
    int i = 0;

    args = PyTuple_New(nargs);
    va_start(argp, nargs);
    for (i = 0; i < nargs; i++)
    {
        arg = va_arg(argp, PyObject *);
        Py_XINCREF(arg);
        PyTuple_SetItem(args, i, arg);
        arg = NULL;
    }
    va_end(argp);

    func = pybackend_get_function(name);
    if (func == NULL)
    {
        goto Exit;
    }

    dbglog("pybackend plugin: calling %s() with %d arguments", name, nargs);
    ret = PyObject_CallObject(func, args);
    if (ret == NULL)
    {
        warn("pybackend plugin: call to %s() failed", name);
        PyErr_Print();
        goto Exit;
    }

    //
    // No failure.
    //

    result = ret;
    ret = NULL;

Exit:

    Py_CLEAR(ret);
    Py_CLEAR(args);
    Py_CLEAR(func);
    return result;
}


static int pybackend_chap_check(void)
{
    int result = 0;
    PyObject *ret = NULL;

    dbglog("pybackend plugin: chap_check_hook()");

    ret = pybackend_call_function("chap_check_hook", 0);
    if (ret == NULL || ret == Py_None)
    {
        goto Exit;
    }

    if (!PyBool_Check(ret))
    {
        warn("pybackend plugin: chap_check_hook() did not return a boolean value");
        goto Exit;
    }

    if (ret == Py_True)
    {
        result = 1;
    }

Exit:

    Py_CLEAR(ret);

    dbglog("pybackend plugin: chap_check_hook: %d", result);
    return result;
}

static int pybackend_chap_verify(char *name, char *ourname, int id, struct chap_digest_type *digest, unsigned char *challenge, unsigned char *response, char *message, int message_space)
{
    int result = 0;
    PyObject *ret = NULL;
    PyObject *arg0 = NULL;
    PyObject *arg1 = NULL;
    PyObject *arg2 = NULL;
    char *secret = NULL;
    size_t secret_len = 0;

    dbglog("pybackend plugin: chap_verify_hook(name = %s, ourname = %s, id = %d, ipparm = %s)", name, ourname, id, ipparam);

    arg0 = PyString_FromString(name);
    arg1 = PyString_FromString(ourname);
    arg2 = PyString_FromString(ipparam);
    ret = pybackend_call_function("chap_verify_hook", 3, arg0, arg1, arg2);
    if (ret == NULL || ret == Py_None)
    {
        goto Exit;
    }

    if (!PyString_Check(ret))
    {
        warn("pybackend plugin: return value of chap_verify_hook() is not a string");
        goto Exit;
    }

    secret = PyString_AsString(ret);
    secret_len = strlen(secret);
    dbglog("pybackend plugin: chap_verify_hook: %s, %d", secret, secret_len);

    if (!digest->verify_response(id, name, (unsigned char *)secret, secret_len, challenge, response, message, message_space))
    {
        goto Exit;
    }

    //
    // No failure.
    //

    result = 1;

Exit:

    Py_CLEAR(arg0);
    Py_CLEAR(arg1);
    Py_CLEAR(arg2);
    Py_CLEAR(ret);

    dbglog("pybackend plugin: chap_verify_hook: %d", result);
    return result;
}

static void pybackend_ip_choose(u_int32_t *addr)
{
    PyObject *ret = NULL;
    PyObject *arg0 = NULL;

    dbglog("pybackend plugin: ip_choose_hook(addr = %d)", *addr);

    arg0 = PyInt_FromSize_t(*addr);
    ret = pybackend_call_function("ip_choose_hook", 1, arg0);
    if (ret == NULL || ret == Py_None)
    {
        goto Exit;
    }

    if (!PyInt_Check(ret))
    {
        warn("pybackend plugin: return value of ip_choose_hook() is not an int");
        goto Exit;
    }

    //
    // No failure.
    //

    *addr = PyInt_AsUnsignedLongMask(ret);

Exit:

    Py_CLEAR(arg0);
    Py_CLEAR(ret);

    dbglog("pybackend plugin: ip_choose_hook: %d", *addr);
    return;
}

static int pybackend_allowed_address(u_int32_t addr)
{
    int result = 0;
    PyObject *ret = NULL;
    PyObject *arg0 = NULL;

    dbglog("pybackend plugin: allowed_address_hook(addr = %d)", addr);

    arg0 = PyInt_FromSize_t(addr);
    ret = pybackend_call_function("allowed_address_hook", 1, arg0);
    if (ret == NULL || ret == Py_None)
    {
        goto Exit;
    }

    if (!PyBool_Check(ret))
    {
        warn("pybackend plugin: allowed_address_hook() did not return a boolean value");
        goto Exit;
    }

    if (ret == Py_True)
    {
        result = 1;
    }

Exit:

    Py_CLEAR(arg0);
    Py_CLEAR(ret);

    dbglog("pybackend plugin: allowed_address_hook: %d", result);
    return result;
}

static void pybackend_notifier(void *hook, int arg)
{
    const char *name = (const char *)hook;
    PyObject *ret = NULL;
    PyObject *arg0 = NULL;

    dbglog("pybackend plugin: %s(arg = %d)", name, arg);

    arg0 = PyInt_FromSize_t(arg);
    ret = pybackend_call_function(name, 1, arg0);
    if (ret == NULL || ret == Py_None)
    {
        goto Exit;
    }

Exit:

    Py_CLEAR(arg0);
    Py_CLEAR(ret);

    dbglog("pybackend plugin: %s: void", name);
    return;
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
    chap_verify_hook = pybackend_chap_verify;
    ip_choose_hook = pybackend_ip_choose;
    allowed_address_hook = pybackend_allowed_address;

    add_notifier(&ip_up_notifier, pybackend_notifier, "ip_up_notifier");
    add_notifier(&ip_down_notifier, pybackend_notifier, "ip_down_notifier");
    add_notifier(&auth_up_notifier, pybackend_notifier, "auth_up_notifier");
    add_notifier(&link_down_notifier, pybackend_notifier, "link_down_notifier");

    info("pybackend plugin: initialized");
}

