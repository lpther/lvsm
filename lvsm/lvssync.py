"""
ipvs sync library
"""
import fcntl
import select
import socket
import struct
import string
import sys
import time

# lvs sync constants
LVSSYNC_MIN_SLEEP = 0.25    # In debugging mode, how much time to sleep before checking the buffer
FQDN_NR = False              # Set to True for fully qualified name resolution

# ipvs sync constants
MCAST_GRP = '224.0.0.81'
MCAST_PORT = 8848

IP_VS_CONN_HDRLEN       = 8
IP_VS_CONN_CONNHDRLEN   = 8

IP_VS_CONN_F_MASQ       = {'flag': 0x0000 , 'flagname': "MASQ" }
IP_VS_CONN_F_LOCALNODE  = {'flag': 0x0001 , 'flagname': "LOCALNODE" }
IP_VS_CONN_F_TUNNEL     = {'flag': 0x0002 , 'flagname': "TUNNEL" }
IP_VS_CONN_F_DROUTE     = {'flag': 0x0003 , 'flagname': "DROUTE" }
IP_VS_CONN_F_BYPASS     = {'flag': 0x0004 , 'flagname': "BYPASS" }
IP_VS_CONN_F_SYNC       = {'flag': 0x0020 , 'flagname': "SYNC" }
IP_VS_CONN_F_HASHED     = {'flag': 0x0040 , 'flagname': "HASHED" }
IP_VS_CONN_F_NOOUTPUT   = {'flag': 0x0080 , 'flagname': "NOOUTPUT" }
IP_VS_CONN_F_INACTIVE   = {'flag': 0x0100 , 'flagname': "INACTIVE" }
IP_VS_CONN_F_OUT_SEQ    = {'flag': 0x0200 , 'flagname': "F_OUT_SEQ" }
IP_VS_CONN_F_IN_SEQ     = {'flag': 0x0400 , 'flagname': "F_IN_SEQ" }
IP_VS_CONN_F_NO_CPORT   = {'flag': 0x0800 , 'flagname': "NO_CPORT" }
IP_VS_CONN_F_TEMPLATE   = {'flag': 0x1000 , 'flagname': "TEMPLATE" }
IP_VS_CONN_F_ONE_PACKET = {'flag': 0x2000 , 'flagname': "ONE_PACKET" }

IP_VS_TCP_S_CONNECTION_STATES = ["NONE","ESTABLISHED","SYN_SENT","SYN_RECV", "FIN_WAIT", \
                                "TIME_WAIT","CLOSE","CLOSE_WAIT","LAST_ACK","LISTEN","SYNACK","LAST"]

IP_VS_F_FWD_METHOD = ["MASQ","LOCALNODE","TUNNEL","DROUTE","BYPASS"]

IP_VS_F_BOOL = [IP_VS_CONN_F_SYNC,IP_VS_CONN_F_HASHED,IP_VS_CONN_F_NOOUTPUT,IP_VS_CONN_F_INACTIVE,IP_VS_CONN_F_OUT_SEQ,IP_VS_CONN_F_IN_SEQ,IP_VS_CONN_F_NO_CPORT,IP_VS_CONN_F_TEMPLATE,IP_VS_CONN_F_ONE_PACKET]

# other constants
SIOCGIFADDR = 0x8915

class ipvssync(object):
    """
    Main class to receive or send ipvs sync connections
    Supports only Version 1 ip_vs_sync connections    

    interface   str     interface to bind the mcast socket
                        defaults to socket.INADDR_ANY
    syncid      int     syncid instance identifier
    """
    def __init__(self, syncid, interface=None):
        self.interface = interface
        self.interfaceaddress = None
        self.syncid = syncid
        self.socket = None
        self.socketisblocking = None
        self.recvbuffer = ""
        self.sendbuffer = ""

    def debug(self, duration, fd=sys.stdout, printdate=False, nameresolution=False):
        """
        Binds to the ipvs sync multicast address and dumps received packets
        to the fd during the specified time.

        duration    int      seconds
        """
        if self.socket == None:
            self.__initsocket(blocking=False)

        self.__print_debug(fd, ["Bound to %s:%s, joined group %s on interface %s (%s)" % \
            (self.socket.getsockname()[0], MCAST_PORT, MCAST_GRP, self.interface, self.interfaceaddress)],printdate)

        self.__print_conns_col(fd, printdate)

        starttime = time.time()
        numpackets = 0 
        numconnections = 0
        try:
            while True:
                while True:
                    try:
                        newbuffer = self.socket.recv(9999)
                    except socket.error as e:
                        if e.errno == 11:
                            newbuffer = ""
                        else:
                            raise
       
                    if len(newbuffer) > 0:
                        self.recvbuffer += newbuffer
                    else:
                        break
    
                while True:
                    if len(self.recvbuffer) >= IP_VS_CONN_HDRLEN:
                        reserved , syncid , rawsize , nr_conns, version, spare = struct.unpack("BBHBbH",self.recvbuffer[0:IP_VS_CONN_HDRLEN])
    
                        # Network to host conversions
                        size = socket.ntohs(rawsize)

                        header = {}
                        header["reserved"] = rawsize
                        header["syncid"] = syncid
                        header["size"] = size
                        header["nr_conns"] = nr_conns
                        header["version"] = version
                        header["spare"] = spare
    
                        if len(self.recvbuffer) >= size:
                            conns = self.__decode_conns(self.recvbuffer[IP_VS_CONN_HDRLEN:header["size"]])
    
                            numpackets += 1
                            numconnections += len(conns)

                            self.__print_conns(fd,header,conns,nameresolution=nameresolution)
    
                            self.recvbuffer = self.recvbuffer[header["size"]:]
                        else:
                            break
                    else:
                        break

                if duration == 0 or time.time() - starttime < duration:
                    time.sleep(LVSSYNC_MIN_SLEEP)
                else:
                    break
        except KeyboardInterrupt:
            duration = time.time() - starttime
            pass
    
        print self.recvbuffer

        print >>fd, "Received %s packets (%s total connections) during %.2f seconds" % (numpackets, numconnections, duration)
   
    def __getipaddr(self, interface):
        """
        Return the associated ip address from interface

        interface   str     "eth0"
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa( \
            fcntl.ioctl( s.fileno(), SIOCGIFADDR, struct.pack('256s', interface[:15])) \
            [20:24])
        s.shutdown()


    def __initsocket(self, blocking=True):
        """
        Initialize the multicast socket
        """
        # Determine which interface to use
        if self.interface == None:
            self.interfaceaddress = "0.0.0.0"
        else:
            self.interfaceaddress = self.__getipaddr(self.interface)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.socketisblocking = blocking

        # Set options
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.socket.bind(("", MCAST_PORT))

        mreq = struct.pack("4s4s", socket.inet_aton(MCAST_GRP), socket.inet_aton(self.interfaceaddress))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        if not blocking:
            self.socket.setblocking(0)

    def __decode_conns(self, rawconns):
        """
        Decode the binary encoded connection list, and return a list
        of dict
        """
        conns = []
        while True:
            if len(rawconns) <= 0:
                break
            else:
                conn_type, protocol, ver_size, flags, state, cport, vport, dport, fwmark, timeout, caddr, vaddr, daddr \
                    = struct.unpack("BBHIHHHHIIIII",rawconns[:36])
                conn_size = socket.ntohs(ver_size) & 0b0000111111111111
                conn_ver = socket.ntohs(ver_size) >> 12 

                this_conn = {}
                this_conn["type"] = conn_type
                this_conn["protocol"] = protocol
                this_conn["version"] = conn_ver
                this_conn["size"] = conn_size
                this_conn["flags"] = self.__decode_flags(socket.ntohl(flags))
                this_conn["state"] = IP_VS_TCP_S_CONNECTION_STATES[socket.ntohs(state)]
                this_conn["timeout"] = int(socket.ntohl(timeout))
                this_conn["cport"] = socket.ntohs(cport)
                this_conn["vport"] = socket.ntohs(vport)
                this_conn["dport"] = socket.ntohs(dport)
                this_conn["caddr"] = self.__unsigned_int_to_ip(socket.ntohl(caddr))
                this_conn["vaddr"] = self.__unsigned_int_to_ip(socket.ntohl(vaddr))
                this_conn["daddr"] = self.__unsigned_int_to_ip(socket.ntohl(daddr))

                conns.append(this_conn)

                # Shift the buffer
                rawconns = rawconns[conn_size:]

        return conns

    def __decode_flags(self, rawflags):
        """
        """
        flags = []

        flags += [ IP_VS_F_FWD_METHOD[rawflags & 0x0007] ]

        for f in IP_VS_F_BOOL:
            if rawflags & f['flag']:
                flags.append(f['flagname'])

        return flags

    def __unsigned_int_to_ip(self, unsigned_int):
        """
        """
        a = (unsigned_int & 0xff000000) >> 24
        b = (unsigned_int & 0x00ff0000) >> 16
        c = (unsigned_int & 0x0000ff00) >> 8
        d = unsigned_int & 0x000000ff
        return "%s.%s.%s.%s" % (a,b,c,d)
        
    def __print_conns(self, fd, header, conns, printdate=False, nameresolution=False):
        """
        """
        stringlist = []

        for c in conns:
            # Get protocol name
            if c["protocol"] == socket.SOL_TCP:
                protocol_str = "TCP"
            elif c["protocol"] == socket.SOL_UDP:
                protocol_str = "UDP"
            else:
                protocol_str = str(c["protocol"])

            # Get expiration format
            expire = "%3d:%2s" % (c["timeout"] / 60, str(c["timeout"] % 60).zfill(2))

            # Get s/v/d client:protocol pair
            caddr, vaddr , daddr = (c["caddr"] , c["vaddr"] , c["daddr"])
            addrspacer = ""

            if nameresolution:
                addrspacer = " "
                try:
                    caddr = socket.gethostbyaddr(caddr)[0]
                    
                    if not FQDN_NR:
                        caddr = caddr.split(".")[0]
                except:
                    pass

                try:
                    vaddr = socket.gethostbyaddr(vaddr)[0]
                    
                    if not FQDN_NR:
                        vaddr = vaddr.split(".")[0]
                except:
                    pass

                try:
                    daddr = socket.gethostbyaddr(daddr)[0]
                    
                    if not FQDN_NR:
                        daddr = daddr.split(".")[0]
                except:
                    pass

            
            source = "%s:%s" % (caddr,c["cport"]) + addrspacer
            virtual = "%s:%s" % (vaddr,c["vport"]) + addrspacer
            destination = "%s:%s" % (daddr,c["dport"]) + addrspacer

            strformat = "%s%s%s%s%s%s%s%s" % (string.ljust(str(header["syncid"]),7),string.center(protocol_str,4),string.center(expire,7), \
                                                    string.center(c["state"],13),string.center(source,22), \
                                                    string.center(virtual,22),string.center(destination,22)," ".join(c["flags"]))

            stringlist += [strformat]

        self.__print_debug(fd, stringlist, printdate)
        
    def __print_conns_col(self, fd, printdate=False):
        """
        """
        strformat = "%s%s%s%s%s%s%s%s" % (string.ljust("syncid",7),string.center("pro",4),string.center("expire",7), \
                                                string.center("state",13),string.center("source",22), \
                                                string.center("virtual",22),string.center("destination",22),"flags")
        sep = (len(strformat) + 20) * "="

        self.__print_debug(fd,[strformat,sep],printdate)

    def __print_debug(self, fd, stringlist, printdate=False):
        """
        """
        if printdate:
            pass
        else:
            datestring = ""

        for s in stringlist:
            print >>fd, "%s%s" % (datestring,s)


if __name__ == "__main__":
    import lvssync
    import os

    if "LVSSYNCNR" in os.environ:
        nameresolution = os.environ["LVSSYNCNR"]
    else:
        nameresolution = False

    if "LVSSYNCINT" in os.environ:
        sync = lvssync.ipvssync(0,os.environ["LVSSYNCINT"])
    else:
        sync = lvssync.ipvssync(0)
		
    sync.debug(0,nameresolution=nameresolution)
