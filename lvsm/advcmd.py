import cmd
import time
import readline

class AdvCommandPrompt(cmd.Cmd):
    def __init__(self):
        cmd.Cmd.__init__(self,completekey="tab")

        self.registeredcmd = CommandLevel()
        self.labeldict = {}
   
        # Global help is removed from Cmd class
        del cmd.Cmd.do_help
        del cmd.Cmd.complete_help

        print "use_rawinput=%s" % self.use_rawinput
        print "readline completer delims='%s'" % readline.get_completer_delims()

        readline.parse_and_bind(" ? : complete")

    def default(self, line):
        """
        """
        print "default: line='%s'" % (line)

    def completedefault(self, text, line, begidx, endidx):
        """
        """
        print "completedefault: text='%s' line='%s' begidx=%s endidx=%s" % (text, line, begidx, endidx)
        return None

    def complete(self, text, state):
        """
        """
        print "complete: text='%s' state=%s" % (text,state)
        print "completiontype=%s" % (readline.get_completion_type())

    def registercmd(self, command):
        """
        command     Command object
        """
        self.__registercmd_recursively(command.getfieldlist(), command, self.registeredcmd)
        self.__refreshlabeldict()

    def printregisteredcmd(self):
        """
        For debugging
        """
        labelkeys = self.labeldict.keys()
        labelkeys.sort()

        print "Registered commands:"
        print

        for key in labelkeys:
            prefix = key.split()[:-1]
            cmd = key.split()[-1]

            print "%s%s (%s)" % (len(" ".join(prefix)) * " ",cmd,",".join(self.labeldict[key]))

    def __refreshlabeldict(self):
        """
        """
        self.labeldict = {}
        self.__labeldictregisteredcmd_recursively(self.registeredcmd,self.labeldict)

    def __labeldictregisteredcmd_recursively(self,cmdlevel,labeldict,cmdstack=[]):
        """
        For debugging

        Will populate labeldict with command names and associated modules
        """

        for field in cmdlevel.getfields():
            label = field[0]
            module = field[1]

            cmdstack += [label]

            if " ".join(cmdstack) not in labeldict:
                labeldict[" ".join(cmdstack)] = []

            if module not in labeldict[" ".join(cmdstack)]:
                labeldict[" ".join(cmdstack)] += [module]

            subcmd = cmdlevel.getsubcmd(field)
            if subcmd != None:
                subdict = self.__labeldictregisteredcmd_recursively(subcmd,labeldict,cmdstack)

            cmdstack.pop()

    def __registercmd_recursively(self, fields, command, cmdlevel):
        """
        fields      list    list of fields to register to current level
        command     Command
        cmddict     dict
        """
        cmdlevelfield = (fields[0],command.getmodulename())

        # Add field to this cmd level
        cmdlevel.addfield(cmdlevelfield[0],cmdlevelfield[1])

        # If there are subcommands
        if len(fields) >= 2:
      
            if cmdlevel.getsubcmd(cmdlevelfield) == None:
                newsublevel = CommandLevel(level=cmdlevel.getlevel() + 1)
                cmdlevel.addcmdlevel(cmdlevelfield,newsublevel)

            self.__registercmd_recursively(fields[1:], command, cmdlevel.getsubcmd(cmdlevelfield))

class Command(object):
    def __init__(self,fieldlist,module):
        """
        fieldlist   [str|method]    method must return a list of permitted strings
        modulename  str             name of module creating the command
        """
        self.fieldlist     = fieldlist
        self.modulename    = modulename

    def getfieldlist(self):
        """
        """
        return self.fieldlist

    def getmodulename(self):
        """
        """
        return self.modulename

class Module(object):
    """
    """
    def __init__():
        pass

########### Utilitary classes ###########

class CommandLevel(object):
    """
    Placeholder for commands

    Do not directly instanciate this class
    """
    def __init__(self, level=0):
        """
        """
        self.fields = {}
        self.level = level
        self.modules = []

    def addcmdlevel(self,field,cmdlevel):
        """
        """
        self.fields[field[0]][field[1]] = cmdlevel

    def getsubcmd(self,field):
        """
        """
        return self.fields[field[0]][field[1]]

    def isleafcmd(self):
        """
        """
        for field in self.getfields():
            if self.getsubcmd(field) != None:
                return False
            
        return True

    def getfields(self):
        """
        """
        fields = self.fields.keys()
        fields.sort()

        keys = []

        for field in fields:
            module_keys = self.fields[field].keys()
            module_keys.sort()

            for module in module_keys:
                keys += [(field,module)]

        return keys

    def getfieldslabels(self):
        """
        """
        fields = self.fields.keys()
        fields.sort()
        return fields
    
    def getlabelmodules(self,label):
        """
        """
        modules = []

        modules = self.fields[label].keys()
        modules.sort()
        return modules

    def getfieldsmodules(self):
        """
        """
        fields = self.fields.keys()
        fields.sort()

        modules = []

        for field in fields:
            module_keys = self.fields[field].keys()
            module_keys.sort()

            for module in module_keys:
                if module not in modules:
                    modules += [module]

        modules.sort()
        return modules



    def addfield(self,field,modulename):
        """
        """
        if modulename not in self.modules:
            self.modules += [modulename]

        if field not in self.fields:
            self.fields[field] = {}

        if modulename not in self.fields[field]:
            self.fields[field][modulename] = None

    def findfield(self,field):
        """
        """
        return field in self.getfields()

    def getlevel(self):
        """
        """
        return self.level


class Field(object):
    def __init__(self, label):
        """
        """
        self.label = label

    def printfield(self):
        """
        For debugging
        """
        print self.label

class Command(object):
    def __init__(self,fieldlist,modulename=None):
        """
        fieldlist   [str|method]    method must return a list of permitted strings
        modulename  str             name of module creating the command
        """
        self.fieldlist     = fieldlist
        self.modulename    = modulename

    def getfieldlist(self):
        """
        """
        return self.fieldlist

    def getmodulename(self):
        """
        """
        return self.modulename

def main():
    cmd = AdvCommandPrompt()

    cmd_show            = Command(["show"], modulename="generic")
    cmd.registercmd(cmd_show)

    cmd_show_helloworld = Command(["show","helloworld"], modulename="generic")
    cmd.registercmd(cmd_show_helloworld)

    cmd_show_helloworld_multiverse = Command(["show","helloworld"], modulename="multiverse")
    cmd.registercmd(cmd_show_helloworld_multiverse)

    cmd_show_helloworld_hemi_north = Command(["show","helloworld","hemisphere","north"], modulename="generic")
    cmd.registercmd(cmd_show_helloworld_hemi_north)

    cmd_show_helloworld_hemi_south = Command(["show","helloworld","hemisphere","south"], modulename="generic")
    cmd.registercmd(cmd_show_helloworld_hemi_south)

    cmd.printregisteredcmd()
#    cmd_show_time       = Command(["show","time"], modulename="time")

    cmd.cmdloop()

if __name__ == "__main__":
    main()
