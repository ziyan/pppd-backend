pppd-backend
============

Executes a program to check username/password pair for pppd.

Usage
=====

Create a symlink or copy backend.so to /usr/lib/pppd/VERSION/

In /etc/ppp/pptp-options and /etc/ppp/options.xl2tp, add:

    debug
    plugin backend.so
    backend_command "/etc/ppp/auth.sh"

Replace the command with what you want to execute.
The first argument to your executable will be the username.
Your executable should output with the secret associated with the user in one line if the user is valid.

Example auth.sh would be:

    #!/bin/sh
    USER=$1
    [ "$USER" == "test" ] && echo "password"

