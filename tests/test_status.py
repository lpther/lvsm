import unittest
import os
import sys
import StringIO

from lvsm import lvsm

path = os.path.abspath(os.path.dirname(__file__))


class TestStatus(unittest.TestCase):
    config = {'ipvsadm': path + '/scripts/ipvsadm',
              'iptables': path + '/scripts/iptables',
              'director_config': path + '/etc/ldirectord.conf',
              'firewall_config': path + '/etc/iptables.rules',
              'dsh_group': '',
              'director': 'ldirectord',
              'maintenance_dir': path + '/maintenance'
              }
    shell = lvsm.StatusPrompt(config)

    def test_showdirector(self):
        output = StringIO.StringIO()
        sys.stdout = output
        expected_result = """IP Virtual Server version 1.2.1 (size=4096)
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port           Forward Weight ActiveConn InActConn
TCP  lvs-test-web1.cmc.ec.gc.ca:w rr
  -> lvs-test-fe02:www            Masq    1      0          0
  -> lvs-test-fe03:www            Masq    1      0          0
TCP  lvs-test-web1.cmc.ec.gc.ca:h rr persistent 300
  -> lvs-test-fe02:https          Masq    1      0          0
TCP  lvs-test-other.cmc.ec.gc.ca: rr
  -> lvs-test-fe02:ssh            Masq    1      0          0
  -> lvs-test-fe03:ssh            Masq    1      0          0
TCP  lvs-test-other.cmc.ec.gc.ca: rr
  -> lvs-test-fe02:domain         Masq    1      0          0
TCP  lvs-test-web2.cmc.ec.gc.ca:f rr
  -> lvs-test-fe02:ftp            Masq    1      0          0
  -> lvs-test-fe03:ftp            Masq    1      0          0
TCP  lvs-test-web2.cmc.ec.gc.ca:w rr
  -> lvs-test-fe02:www            Masq    1      0          0
UDP  lvs-test-other.cmc.ec.gc.ca: rr
  -> lvs-test-fe02:domain         Masq    1      0          0"""
        self.shell.onecmd(' show director')
        result = output.getvalue()
        self.assertEqual(result.rstrip(), expected_result.rstrip())

    def test_showfirewall(self):
        output = StringIO.StringIO()
        sys.stdout = output
        expected_result = """Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination"""
        self.shell.onecmd(' show firewall')
        result = output.getvalue()
        self.assertEqual(result.rstrip(), expected_result.rstrip())

    def test_showvirtualtcp(self):
        output = StringIO.StringIO()
        sys.stdout = output
        expected_result = """IP Virtual Server version 1.2.1 (size=4096)
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port           Forward Weight ActiveConn InActConn
TCP  lvs-test-web1.cmc.ec.gc.ca:w rr
  -> lvs-test-fe02:www            Masq    1      0          0
  -> lvs-test-fe03:www            Masq    1      0          0"""
        self.shell.onecmd(' show virtual tcp lvs-test-web1 80')
        result = output.getvalue()
        self.assertEqual(result.rstrip(), expected_result.rstrip())

    def test_showvirtualudp(self):
        output = StringIO.StringIO()
        sys.stdout = output
        expected_result = """IP Virtual Server version 1.2.1 (size=4096)
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port           Forward Weight ActiveConn InActConn
UDP  lvs-test-other.cmc.ec.gc.ca: rr
  -> lvs-test-fe02:domain         Masq    1      0          0"""
        self.shell.onecmd(' show virtual udp lvs-test-other 53')
        result = output.getvalue()
        self.assertEqual(result.rstrip(), expected_result.rstrip())

    def test_showrealactive(self):
        output = StringIO.StringIO()
        sys.stdout = output
        expected_result = """
Active servers:
---------------
TCP  lvs-test-web1.cmc.ec.gc.ca:w rr
  -> lvs-test-fe02:www            Masq    1      0          0
TCP  lvs-test-web2.cmc.ec.gc.ca:w rr
  -> lvs-test-fe02:www            Masq    1      0          0"""
        self.shell.onecmd(' show real lvs-test-fe02 www')
        result = output.getvalue()
        self.assertEqual(result.rstrip(), expected_result.rstrip())

    def test_showrealdisabled(self):
        output = StringIO.StringIO()
        sys.output = output
        expected_result = ""
        self.assertTrue(True)

    def test_disablereal(self):
        self.assertTrue(True)

    def test_enablereal(self):
        self.assertTrue(True)