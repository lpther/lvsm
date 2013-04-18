from genericdirector import GenericDirector
import os
import utils

class Keepalived(GenericDirector):
    """
    Implements Keepalived specific functions.
    """
    def __init__(self, maintenance_dir, ipvsadm,
                 configfile='', restart_cmd='', nodes='', 
                 finalconfigfile=None):
        super(Keepalived, self).__init__(maintenance_dir, ipvsadm,
                                         configfile=configfile, restart_cmd=restart_cmd,
                                         nodes=nodes,finalconfigfile=finalconfigfile)

        # maintenancedir is mandatory
        try:
            os.makedirs(self.getmaintenancedir())
        except OSError as e:
            # Ignore if dir already exists
            if e.errno != 17:
                raise e

    def parse_config(self, configfile):
        """
        Parses all configuration files derived from the master


        configfile      str     "/path/to/keepalive-master-file"
        """
        parse_is_ok = True

        self.__generate_config(configfile, self.getmaintenancedir(), self.getnodes())

        for node in self.getnodes():
            node_configfile = "%s/%s_%s" % (self.getmaintenancedir(),self.getconfigfilename(),node)

            parse_result = self.__parse_single_config(node_configfile)

            if parse_result["return_code"] != "0":
                print "Parse of %s is incorrect : %s" % (node_configfile,parse_result["message"])
                parse_is_ok = False

        return parse_is_ok

    def getfinalconfigfile(self):
        return self.finalconfigfile

    def __parse_single_config(self, configfile):
        """
        Parse a single configuration file

        configfile      str     "/path/to/keepalive-file"
        """
        ret = utils.check_output("/etc/keepalived/keepalived-check.rb %s; echo -n $?" % configfile, shell=True)

        return_code = ret.splitlines()[-1]
        message = "\n".join(ret.splitlines()[:-1])

        return {"return_code":return_code , "message":message}

    def __generate_config(self, configfile, configdir, nodes):
        """
        Generate node configuration files from a master configuration file
    
        configfile      str     "keepalive-master-file"
        configdir       str     "/path/to/dir/"
        nodes           list    ["node1","node2"]
        """
        for node in nodes:
            node_configfile = "%s/%s_%s" % (configdir,self.configfilename,node)

            utils.check_output("""sed 's/lvsm_slb_hostname/%s/' %s > %s""" % (node,configfile,node_configfile), shell=True)
            utils.check_output("""sed -i 's/lvsm_master %s/priority 150/' %s""" % (node,node_configfile), shell=True)
            utils.check_output("""sed -i 's/lvsm_backup %s/priority 100/' %s""" % (node,node_configfile), shell=True)
            utils.check_output("""sed -i 's/lvsm_support_failback/priority 50/' %s""" % (node_configfile), shell=True)
            utils.check_output("""sed -i '/lvsm_/d' %s""" % (node_configfile), shell=True)
