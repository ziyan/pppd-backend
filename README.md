pppd-backend
============

Executes a program to check username/password pair for pppd.

Usage
=====

```shell
make
sudo make install
```

In /etc/ppp/pptp-options and /etc/ppp/options.xl2tp, add:

    debug
    plugin backend.so
    backend_command "/etc/ppp/auth.sh"

Replace the command with what you want to execute.
The first argument to your executable will be the username.
Your executable should output with the secret associated with the user in one line if the user is valid.

Example auth.sh would be:

```shell
#!/bin/sh
[ "$1" == "test" ] && echo "password"
```

Example python module:

```python
def chap_check_hook():
    return True

def chap_verify_hook(name, ourname, ipparam):
    return "pass"

def ip_choose_hook(ip):
    return ip

def allowed_address_hook(ip):
    return True

def ip_up_notifier(arg):
    pass

def ip_down_notifier(arg):
    pass

def auth_up_notifier(arg):
    pass

def link_down_notifier(arg):
    pass
```

