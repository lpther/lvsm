#!/usr/bin/env python
# Khosrow Ebrahimpour - Sep 2012

"""
lvsm - LVS Manager
LVS Manager is a shell that eases the management of a linux virtual server.

Using it without arguments will enter an interactive shell. Supplying one or
more command-line arguments will run lvsm for a "single-shot" use.

Usage: lvsm [-h] [-c <conffile>][commands]

Options:
  -h, --help            Show this help message and exit

  -c <conffile>         Specify which configuration file to use.
  -config=<connfile>    The default is /etc/lvsm.conf

  -v, --version         Display lvsm version

Commands:
  configure
  status
  help

Use 'lvsm help <command>' for information on a specific command.
"""

import getopt
import sys
import signal
import subprocess
import __init__ as appinfo
import lvsm
import utils


def usage(code, msg=''):
    if code:
        fd = sys.stderr
    else:
        fd = sys.stdout
    print >> fd, __doc__
    if msg:
        print >> fd, msg
    sys.exit(code)


def main():
    CONFFILE = "/etc/lvsm.conf"

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hvc:d",
                                   ["help", "version", "config=", "debug"])
    except getopt.error, msg:
        usage(2, msg)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage(0)
        elif opt in ("-v", "--version"):
            print "lvsm " + appinfo.__version__
            sys.exit(0)
        elif opt in ("-c", "--config"):
            CONFFILE = arg
        elif opt in ("-d", "--debug"):
            utils.DEBUG = True

    # open config file and read it
    config = utils.parse_config(CONFFILE)
    utils.log("Parsed config file")
    utils.log(str(config))

    # get the rows, cols from stty to be used by utils.pager
    utils.update_rows_cols()
    signal.signal(signal.SIGWINCH, utils.sigwinch_handler)

    try:
        shell = lvsm.MainPrompt(config)
        if args:
            shell.onecmd(' '.join(args[:]))
        else:
            shell.cmdloop()
    except KeyboardInterrupt:
        print "\nleaving abruptly!"
        sys.exit(1)

if __name__ == "__main__":
    main()
