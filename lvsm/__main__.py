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

Commands:
  configure
  status
  help

Use 'lvsm help <command>' for information on a specific command.
"""

import getopt
import lvsm
import sys


def usage(code, msg=''):
    if code:
        fd = sys.stderr
    else:
        fd = sys.stdout
    print >> fd, __doc__
    if msg:
        print >> fd, msg
    sys.exit(code)


def parse_config(filename):
    #open config file and read it
    try:
        file = open(filename)
        lines = file.readlines()
        file.close()
    except IOError as e:
        print "[ERROR] Unable to read configuration file:"
        print "[ERROR] " + e.strerror + " '" + filename + "'"
        sys.exit(1)
    # list of valid config keys
    config_items = {'director_config': '',
                    'firewall_config': '',
                    'dsh_group': '',
                    'director': '',
                    'maintenance_dir': ''
                    }
    linenum = 0
    for line in lines:
        linenum += 1
        if line[0] == '#':
            continue
        k, sep, v = line.rstrip().partition('=')
        key = k.lstrip().rstrip()
        value = v.lstrip().rstrip()
        if config_items.get(key) is None:
            print "[ERROR] configuration file line " + str(linenum) +\
                  ": invalid variable '" + key + "'"
            sys.exit(1)
        else:
            config_items[key] = value
            # if the item is a config file, verify that the file exists
            if key.endswith('_config'):
                try:
                    file = open(value)
                    file.close()
                except IOError as e:
                    print "[ERROR] in lvsm configuration file line " +\
                          str(linenum)
                    print "[ERROR] " + e.strerror + ": '" + e.filename +\
                          "'"
                    sys.exit(1)
    return config_items


def main():
    CONFFILE = "/etc/lvsm.conf"

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hc:d",
                                   ["help", "config=", "debug"])
    except getopt.error, msg:
        usage(2, msg)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage(0)
        elif opt in ("-c", "--config"):
            CONFFILE = arg
        elif opt in ("-d", "--debug"):
            lvsm.DEBUG = True

    #open config file and read it
    config = parse_config(CONFFILE)
    lvsm.log("Parsed config file")
    lvsm.log(str(config))

    shell = lvsm.MainPrompt(config)
    if args:
        shell.onecmd(' '.join(args[:]))
    else:
        shell.cmdloop()

if __name__ == "__main__":
    main()
