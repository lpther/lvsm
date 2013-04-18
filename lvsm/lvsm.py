"""Various levels of command line shells for accessing ipvs and iptables
functionality form one location."""

import cmd
import getpass
import subprocess
import sys
import socket
import shutil
import tempfile
import lvsdirector
import firewall
import utils
import termcolor
import time
import os

DEBUG = False


class CommandPrompt(cmd.Cmd):
    settings = {'numeric': False,
                'color': True}
    variables = ['numeric', 'color']
    rawprompt = ''

    def __init__(self, config, stdin=sys.stdin, stdout=sys.stdout):
        # super(CommandPrompt, self).__init__()
        cmd.Cmd.__init__(self)
        self.config = config
        self.director = lvsdirector.Director(self.config['director'],
                                             self.config['maintenance_dir'],
                                             self.config['ipvsadm'],
                                             configfile      = self.config['director_config'],
                                             finalconfigfile = self.config['director_finalconfig'],
                                             restart_cmd     = self.config['director_cmd'],
                                             nodes           = self.config['nodes'])
        # disable color if the terminal doesn't support it
        if not sys.stdout.isatty():
            self.settings['color'] = False

    def help_help(self):
        print
        print "show help"

    def do_exit(self, line):
        """Exit from lvsm shell."""
        modified = list()
        if self.config['version_control'] == 'svn':
            # check to see if any config files are modified using "svn status"
            # the command will return 'M  filename' if a file is modified
            args = ["svn", "status"]

            if self.config['director_config']:
                args.append(self.config['director_config'])
                try:
                    result = utils.check_output(args)
                except OSError as e:
                    print"[ERROR] " + e.strerror
                except subprocess.CalledProcessError as e:
                    print"[ERROR] " + e.output
                if result and result[0] == "M":
                    modified.append(self.config['director_config'])

            if self.config['firewall_config']:
                args.append(self.config['firewall_config'])
                try:
                    try:
                        result = subprocess.check_output(args)
                    except AttributeError as e:
                        result, stderr = subprocess.Popen(args, stdout=subprocess.PIPE).communicate()
                except OSError as e:
                    print("[ERROR] " + e.strerror)
                if result and result[0] == "M":
                    modified.append(self.config['firewall_config'])

            if modified:
                print "The following config file(s) were not comitted to svn:"
                for filename in modified:
                    print filename
                print
                while True:
                    answer = raw_input("Do you want to quit? (y/n) ")
                    if answer.lower() == "y":
                        print "goodbye."
                        sys.exit(0)
                    elif answer.lower() == "n":
                        break

        if not modified:
            print "goodbye."
            sys.exit(0)

    def do_quit(self, line):
        """Exit from lvsm shell."""
        self.do_exit(line)

    def do_end(self, line):
        """Return to previous context."""
        return True

    def help_set(self):
        print "Set or display different variables."
        print ""
        print "syntax: set [<variable>] [<value>]"
        print ""
        print "<variable> can be one of:"
        print "\tnumeric on|off          Toggle numeric ipvsadm display ON/OFF"
        print "\tcolor on|off            Toggle color display ON/OFF"
        print ""

    def do_set(self, line):
        """Set or display different variables."""
        if not line:
            print
            print "Shell Settings"
            print "=============="
            for key, value in self.settings.items():
                print str(key) + " : " + str(value)
            print
        else:
            tokens = line.split()
            if len(tokens) == 2:
                if tokens[0] == "numeric":
                    if tokens[1] == "on":
                        self.settings['numeric'] = True
                    elif tokens[1] == "off":
                        self.settings['numeric'] = False
                    else:
                        print "syntax: set numeric on|off"
                elif tokens[0] == "color":
                    if tokens[1] == "on":
                        self.settings['color'] = True
                        self.prompt = termcolor.colored(self.rawprompt,
                                                        attrs=["bold"])
                    elif tokens[1] == "off":
                        self.settings['color'] = False
                        self.prompt = self.rawprompt
                    else:
                        print "syntax: set color on|off"
                else:
                    self.help_set()
            else:
                self.help_set()

    def complete_set(self, text, line, begidx, endidx):
        """Tab completion for the set command."""
        if len(line) < 12:
            if not text:
                    completions = self.variables[:]
            else:
                completions = [m for m in self.variables if m.startswith(text)]
        else:
            completions = []
        return completions

    def emptyline(self):
        """Override the default emptyline and return a blank line."""
        pass

    def postcmd(self, stop, line):
        """Hook method executed just after a command dispatch is finished."""
        # check to see if the prompt should be colorized
        if self.settings['color']:
            self.prompt = termcolor.colored(self.rawprompt, attrs=None)
                                            # attrs=["bold"])
        else:
            self.prompt = self.rawprompt
        return stop


class MainPrompt(CommandPrompt):
    """Class to handle the top level prompt in lvsm."""
    def __init__(self, config, stdin=sys.stdin, stdout=sys.stdout):
        CommandPrompt.__init__(self, config)
        self.modules = ['director', 'firewall']
        self.rawprompt = "lvsm# "
        if self.settings['color']:
            # c = "red"
            c = None
            # a = ["bold"]
            a = None
        else:
            c = None
            a = None
        self.prompt = termcolor.colored("lvsm# ", color=c, attrs=a)

    def help_configure(self):
        print "The configuration level."
        print ""
        print "Items related to configuration of IPVS and iptables are available here."

    def do_configure(self, line):
        """Enter configuration level."""
        commands = line.split()
        configshell = ConfigurePrompt(self.config)
        if not line:
            configshell.cmdloop()
        else:
            configshell.onecmd(' '.join(commands[0:]))

    def help_status(self):
        print "The status level."
        print ""
        print "Running status of IPVS and iptables are available here."

    def do_status(self, line):
        """Enter status level."""

        # Running status of IPVS and iptables are available here.
        # """
        commands = line.split()
        statshell = StatusPrompt(self.config)
        if not line:
            statshell.cmdloop()
        else:
            statshell.onecmd(' '.join(commands[0:]))

    def help_restart(self):
        print "Restart the given module."
        print ""
        print "Module must be one of director or firewall."
        print ""
        print "syntax: restart director|firewall"

    def do_restart(self, line):
        """Restart the direcotr or firewall module."""
        if line == "director":
            if self.config['director_cmd']:
                print "restaring director"
                try:
                    result = subprocess.call(self.config['director_cmd'],
                                             shell=True)
                except OSError as e:
                    print "[ERROR] problem restaring director - " + e.strerror
            else:
                print "[ERROR] 'director_cmd' not defined in config!"
        elif line == "firewall":
            if self.config['firewall_cmd']:
                print "restarting firewall"
                try:
                    result = subprocess.call(self.config['firewall_cmd'],
                                             shell=True)
                except OSError as e:
                    print "[ERROR] problem restaring firewall - " + e.strerror
            else:
                print "[ERROR] 'firewall_cmd' not defined in config!"
        else:
            print "syntax: restart firewall|director"

    def complete_restart(self, text, line, begix, endidx):
        """Tab completion for restart command."""
        if len(line) < 17:
            if not text:
                completions = self.modules[:]
            else:
                completions = [m for m in self.modules if m.startswith(text)]
        else:
            completions = []
        return completions


class ConfigurePrompt(CommandPrompt):
    def __init__(self, config, stdin=sys.stdin, stdout=sys.stdout):
        CommandPrompt.__init__(self, config)
        # List of moduels used in autocomplete function
        self.modules = ['director', 'firewall']
        self.rawprompt = "lvsm(configure)# "
        # Setup color related things here
        if self.settings['color']:
            # c = "red"
            c = None
            # a = ["bold"]
            a = None
        else:
            c = None
            a = None
        self.prompt = termcolor.colored("lvsm(configure)# ", color=c,
                                        attrs=a)

    def svn_sync(self, filename, username, password):
        """Commit changed configs to svn and do update on remote node."""
        # commit config locally
        args = ['svn',
                'commit',
                '--username',
                username,
                '--password',
                password,
                filename]
        svn_cmd = ('svn commit --username ' + username +
                   ' --password ' + password + ' ' + filename)
        try:
            result = subprocess.call(svn_cmd, shell=True)
        except OSError as e:
            print "[ERROR] problem with configuration sync - " + e.strerror

        # update config on all nodes
        n = self.config['nodes']
        if n != '':
            nodes = n.replace(' ', '').split(',')
        else:
            nodes = None

        try:
            hostname = utils.check_output(['hostname', '-s'])
        except (OSError, subprocess.CalledProcessError):
            hostname = ''
        if nodes is not None:
            svn_cmd = ('svn update --username ' + username +
                       ' --password ' + password + ' ' + filename)
            for node in nodes:
                if node != hostname:
                    args = 'ssh ' + node + ' ' + svn_cmd
                    try:
                        result = subprocess.call(args, shell=True)
                    except OSError as e:
                        print "[ERROR] problem with configuration sync - " + e.strerror

    def complete_show(self, text, line, begidx, endidx):
        """Tab completion for the show command."""
        if len(line) < 14:
            if not text:
                completions = self.modules[:]
            else:
                completions = [m for m in self.modules if m.startswith(text)]
        else:
            completions = []
        return completions

    def help_show(self):
        print "Show configuration for an item. The configuration files are defined in lvsm.conf"
        print ""
        
        print ""
        print "<module> can be one of the following"
        print "\tdirector                the IPVS director config file"
        print "\tfirewall                the iptables firewall config file"

    def do_show(self, line):
        """Show director or firewall configuration."""
        if line == "director" or line == "firewall":
            configkey = line + "_config"
            if not self.config[configkey]:
                print("[ERROR] '" + configkey + "' not defined in " +
                      "configuration file!")
            else:
                lines = utils.print_file(self.config[configkey])
                utils.pager(lines)
        else:
            print "syntax: show <module>"

    def complete_edit(self, text, line, begidx, endidx):
        """Tab completion for the show command"""
        if len(line) < 14:
            if not text:
                completions = self.modules[:]
            else:
                completions = [m for m in self.modules if m.startswith(text)]
        else:
            completions = []
        return completions

    def help_edit(self):
        print "Edit the configuration of an item. The configuration files are defined in lvsm.conf"
        print ""
        print "syntax: edit <module>"
        print ""
        print "<module> can be one of the follwoing"
        print "\tdirector                the IPVS director config file"
        print "\tfirewall                the iptables firewall config file"

    def do_edit(self, line):
        """Edit the configuration of an item."""
        if line == "director":
            key = line + "_config"
            filename = self.config[key]
            if not filename:
                print "[ERROR] '" + key + "' not defined in config file!"
            else:
                # make a temp copy of the config
                try:
                    temp = tempfile.NamedTemporaryFile()
                    shutil.copyfile(filename, temp.name)
                except IOError as e:
                    print "[ERROR] " + e.strerror

                while True:
                    args = "vi " + temp.name
                    result = subprocess.call(args, shell=True)
                    if result != 0:
                        print "[ERROR] something happened during the edit of " +\
                              config[line]
                    # Parse the config file and verify the changes
                    # If successful, copy changes back to original file
                    if self.director.parse_config(temp.name):
                        shutil.copyfile(temp.name, filename)
                        temp.close()
                        break
                    else:
                        answer = raw_input("You had a syntax error in your config file, edit again? (y/n) ")
                        if answer.lower() == 'y':
                            pass
                        elif answer.lower() == 'n':
                            print "[WARN] Changes were not saved due to syntax errors."
                            break

        elif line == "firewall":
            key = line + "_config"
            filename = self.config[key]
            if not filename:
                print "[ERROR] '" + key + "' not defined in config file!"
            else:
                args = "vi " + filename
                utils.log(str(args))
                result = subprocess.call(args, shell=True)
                if result != 0:
                    print "[ERROR] something happened during the edit of " +\
                          config[line]
        else:
            print "syntax: edit <module>"

    def help_sync(self):
        print "Sync all configuration files across the cluster."
        print ""
        print "syntax: sync"

    def do_sync(self, line):
        """Sync all configuration files across the cluster."""
        if line:
            print "syntax: sync"
        elif self.config['version_control'] == 'svn':
            # ask for username and passwd so user isn't bugged on each server
            username = raw_input("Enter SVN username: ")
            password = getpass.getpass("Enter SVN password: ")
            # update director config
            if self.config['director_config']:
                print "Syncing " + self.config['director_config'] + " ..."
                self.svn_sync(self.config['director_config'],
                              username, password)
            # update firewall config
            if self.config['firewall_config']:
                print "Syncing " + self.config['firewall_config'] + " ..."
                self.svn_sync(self.config['firewall_config'],
                              username, password)
        elif self.config['version_control'] == 'rsync':
            # Backup self.configfile into the self.configdir's archive
            # and rsync pull the content of self.configdir from all nodes
            archivedir = "%s/.archive" % self.director.getmaintenancedir()
            comment_file = "%s/comment.log" % self.director.getmaintenancedir()
            now = time.gmtime()


            # Configdir archive is mandatory
            try:
                os.makedirs(archivedir)
            except OSError as e:
                # Ignore if dir already exists
                if e.errno != 17:
                    raise e

            # Get modification comment
            comment = time.strftime("%c", now) + "\n______________\n"
            lastcomment = ""
            print "Please, indicate the reason why you made a change."
            print "When you're done, enter . on a new line."

            while True:
                lastcomment = raw_input(">> ")

                if lastcomment == ".":
                    break
                else:
                    comment += (lastcomment + "\n")

            comment = comment.replace("\\","").replace('"','\\"')
    
            utils.check_output(""" echo "%s" >> %s """ % (comment,comment_file), shell=True)

            # Copy config file to archive
            current_time_file_str = time.strftime("%Y-%m-%d_%H:%M:%S", now)
            shutil.copy(self.director.getconfigfile(),"%s/%s_%s" % (archivedir,self.director.getconfigfilename(),current_time_file_str))

            # Rsync directories to other nodes
            rename_cmd = """ cp {maintenancedir}/{configfilename}_{node} {finalconfigfile} """
            rename_args = {"maintenancedir" : self.director.getmaintenancedir(),
                           "configfilename" : self.director.getconfigfilename(), "finalconfigfile" : self.director.getfinalconfigfile() }
            rsync_cmd = """ mkdir -p {maintenancedir} ; rsync -qavrp --delete {pull-from-node}:{maintenancedir} {maintenancedir} ; {rename_cmd}  """

            rsync_args = dict( rename_args.items() )
            rsync_args["rename_cmd"] = rename_cmd

            print
            print "Starting synchronization across nodes"
            print "-------------------------------------"

            for node in self.director.getnodes():
                rename_args["node"] = node
                if node == self.director.hostname:
                    print "%s is local node, copying file only" % node
                    print
                    utils.check_output(rename_cmd.format(**rename_args), shell=True)
                else:
                    rsync_args["pull-from-node"] = self.director.hostname
                    print "Pulling config from %s" % node
                    print 
                    utils.check_output("ssh %s \"%s\" " % (node,rsync_cmd.format(**rsync_args).format(**rename_args)), shell=True)

        else:
            print "You need to define version_control in lvsm.conf"


class StatusPrompt(CommandPrompt):
    def __init__(self, config, stdin=sys.stdin, stdout=sys.stdout):
        # super(CommandPrompt, self).__init__()
        CommandPrompt.__init__(self, config)
        self.modules = ['director', 'firewall', 'nat', 'virtual', 'real']
        self.protocols = ['tcp', 'udp', 'fwm']
        self.firewall = firewall.Firewall(self.config['iptables'])
        self.rawprompt = "lvsm(status)# "
        if self.settings['color']:
            # c = "red"
            c = None
            # a = ["bold"]
            a = None
        else:
            c = None
            a = None
        self.prompt = termcolor.colored("lvsm(status)# ", color=c,
                                        attrs=a)

    def complete_show(self, text, line, begidx, endidx):
        """Tab completion for the show command"""
        if line.startswith("show virtual "):
            if line == "show virtual ":
                completions = self.protocols[:]
            elif len(line) < 16:
                completions = [p for p in self.protocols if p.startswith(text)]
            else:
                completions = []
        elif (line.startswith("show director") or
              line.startswith("show firewall") or
              line.startswith("show nat") or
              line.startswith("show real")):
            completions = []
        elif not text:
            completions = self.modules[:]
        else:
            completions = [m for m in self.modules if m.startswith(text)]
        return completions

    def help_show(self):
        print "Show information about a specific item."
        print ""
        print "syntax: show <module>"
        print ""
        print "<module> can be one of the following"
        print "\tdirector                the running ipvs status"
        print "\tfirewall                the iptables firewall status"
        print "\tnat                     the NAT done by iptables"
        print "\treal <server> <port>    the status of a realserver"
        print "\tvirtual tcp|udp|fwm <vip> <port>    the status of a specific VIP"

    def do_show(self, line):
        """Show information about a specific item."""
        commands = line.split()
        numeric = self.settings['numeric']
        color = self.settings['color']
        if line == "director":
            utils.pager(self.director.show(numeric, color))
        elif line == "firewall":
            utils.pager(self.firewall.show(numeric, color))
        elif line == "nat":
            utils.pager(self.firewall.show_nat(numeric))
        elif line.startswith("virtual"):
            if len(commands) == 4:
                protocol = commands[1]
                vip = commands[2]
                port = commands[3]
                if protocol in self.protocols:
                    d = self.director.show_virtual(vip, port, protocol, numeric, color)
                    if d:
                        f = self.firewall.show_virtual(vip, port, protocol, numeric, color)
                        utils.pager(d + f)
                else:
                    print "syntax: virtual tcp|udp|fwm <vip> <port>"
            else:
                print "syntax: virtual tcp|udp|fwm <vip> <port>"
        elif line.startswith("real"):
            if len(commands) == 3:
                host = commands[1]
                port = commands[2]
                utils.pager(self.director.show_real(host, port, numeric, color))
            else:
                print "syntax: real <server> <port>"
        else:
            print "syntax: show <module>"

    def complete_disable(self, text, line, begidx, endidx):
        """Tab completion for disable command."""
        servers = ['real', 'virtual']
        if  (line.startswith("disable real") or
             line.startswith("disable virtual")):
            completions = []
        elif not text:
            completions = servers[:]
        else:
            completions = [s for s in servers if s.startswith(text)]
        return completions

    def help_disable(self):
        print "Disable a real or virtual server."
        print ""
        print "syntax: disable real|virtual <host> [<port>]"

    def do_disable(self, line):
        """Disable a real or virtual server."""
        commands = line.split()
        if len(commands) < 2 or len(commands) > 3:
            print "syntax: disable real|virtual <host> [<port>]"
        elif line.startswith("virtual"):
            host = commands[1]
            print "Not implemented yet!"
        elif line.startswith("real"):
            host = commands[1]
            if len(commands) == 2:
                port = ''
            elif len(commands) == 3:
                port = commands[2]
            else:
                print "syntax: disable real <host> [<port>]"
                return
            # ask for an optional reason for disabling
            reason = raw_input("Reason for disabling [default = None]: ")
            if not self.director.disable(host, port, reason):
                print "[ERROR] could not disable " + host
        else:
            print "syntax: disable real|virtual <host> [<port>]"

    def complete_enable(self, text, line, begidx, endidx):
        """Tab completion for enable command."""
        servers = ['real', 'virtual']
        if  (line.startswith("enable real") or
             line.startswith("enable virtual")):
            completions = []
        elif not text:
            completions = servers[:]
        else:
            completions = [s for s in servers if s.startswith(text)]
        return completions

    def help_enable(self):
        print "Enable a real or virtual server."
        print ""
        print "syntax: enable real|virtual <host> [<port>]"

    def do_enable(self, line):
        """Enable a real or virtual server."""
        commands = line.split()
        if len(commands) < 2 or len(commands) > 3:
            print "syntax: enable real|virtual <host> [<port>]"
        elif line.startswith("virtual"):
            host = commands[1]
            print "Not implemented yet!"
        elif line.startswith("real"):
            host = commands[1]
            if len(commands) == 2:
                port = ''
            elif len(commands) == 3:
                port = commands[2]
            else:
                print "syntax: enable real <host> [<port>]"
                return
            if not self.director.enable(host, port):
                print "[ERROR] could not enable " + host
        else:
            print "syntax: enable real|virtual <host> [<port>]"
