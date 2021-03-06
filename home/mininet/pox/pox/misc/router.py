"""
[555 Comments]
Your router code and any other helper functions related to router should be written in this file
"""
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import *
from pox.lib.addresses import *
from pox.lib.packet.icmp import *
from pox.lib.packet.ipv4 import *

log = core.getLogger()

"""
[555 Comments]
  Function : router_handler
  Input Parameters:
      rt_object : The router object. This will be initialized in the controller file corresponding to the scenario in __init__
                  function of tutorial class. Any data structures you would like to use for a router should be initialized
                  in the contoller file corresponding to the scenario.
      packet    : The packet that is received from the packet forwarding switch.
      packet_in : The packet_in object that is received from the packet forwarding switch
"""
class router:
    def __init__ (self):
        self.port_ip = {}
        self.ip_port = {}
        self.port_mac = {}
        self.host_ip = {}
        self.arp_pending = {}
        self.host_ip_mac = {}
        self.next_hop = {}

    def add_port(self, mac, ip, port):
        self.port_ip[port] = IPAddr(ip)
        self.ip_port[IPAddr(ip)] = port
        self.port_mac[port] = EthAddr(mac)

    def add_host(self, ip, port):
        self.host_ip[IPAddr(ip)] = port
    def add_router(self, mac, dpid):
        self.next_hop[dpid] = mac


