# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
[555 Comments]
This is the controller file corresponding to scenario 2.
"""
# This part of router logical is referenced from https://github.com/suzhou1898/Switch-Router-with-OpenFlow-
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import *
from pox.lib.addresses import *
from pox.lib.packet.icmp import *
from pox.lib.packet.ipv4 import *
import pox.lib.packet as pcket

log = core.getLogger()

class Tutorial (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """

  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection
    self.valid_ip = set([IPAddr("10.0.0.1"), IPAddr("20.0.0.1"), IPAddr("30.0.0.1"),IPAddr("10.0.0.2"),IPAddr("20.0.0.2"), IPAddr("30.0.0.2")])

    # This binds our PacketIn event listener
    connection.addListeners(self)

    self.port_ip = [IPAddr("10.0.0.1"), IPAddr("20.0.0.1"), IPAddr("30.0.0.1")]
    self.port_mac = [EthAddr("02:00:DE:AD:BE:11"),
                     EthAddr("02:00:DE:AD:BE:12"),
                     EthAddr("02:00:DE:AD:BE:13")]
    self.host_ip = {}
    self.host_ip[IPAddr("10.0.0.2")] = 1
    self.host_ip[IPAddr("20.0.0.2")] = 2
    self.host_ip[IPAddr("30.0.0.2")] = 3

    self.arp_pending = {}
    self.host_ip_mac = {}

    """
    [555 Comments]
    In scenario 2, there is only one router. So, classify it as a router and initialize all the data structures you need for
    the router here.
    For the details of port info table, routing table, look into the project description document provided.
    Initialize all the data structures you wish to for the router in this function

    A word of caution:
    Your router and switch code should be the same for all scenarios. So, be careful to design your data structures for router
    and switches in such a way that your single piece of switch code and router code along with your data structure design
    should work for all the scenarios
    """

  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)
    
  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    port_in = event.port
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    packet_info = packet.next
    if isinstance(packet_info, arp):
      self.host_ip[packet_info.protosrc] = port_in
      msg = of.ofp_flow_mod()
      msg.match.dl_type = 0x0800
      msg.match.nw_dst = packet_info.protosrc
      msg.actions.append(of.ofp_action_dl_addr.set_src(self.port_mac[port_in - 1]))
      msg.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
      msg.actions.append(of.ofp_action_output(port=port_in))
      self.connection.send(msg)
      self.handle_arp(packet, packet_info, port_in)

    if isinstance(packet_info, ipv4):
      self.host_ip[packet_info.srcip] = port_in
      if packet_info.dstip not in self.valid_ip:
        p = self.icmp_unreach_packet(packet.payload, port_in)
        self.send_frame(p, ethernet.IP_TYPE, self.port_mac[port_in - 1], packet.src, port_in)
      else:
        self.handle_IP(packet, packet.payload, port_in)

  def handle_arp(self, packet, packet_info, port_in):
    srcip = packet_info.protosrc
    if packet_info.protodst in self.port_ip:
      index = port_in - 1
      if packet_info.opcode == packet_info.REQUEST:
        self.host_ip_mac[srcip] = packet_info.hwsrc
        reply_packet = self.arp_packet(arp.REPLY, packet_info.hwsrc, packet_info.protosrc, port_in)
        self.send_frame(reply_packet, ethernet.ARP_TYPE, self.port_mac[index], packet_info.hwsrc, port_in)
      elif packet_info.opcode == packet_info.REPLY:
        self.host_ip_mac[srcip] = packet.src
        pending = self.arp_pending[packet_info.protosrc]
        self.arp_pending.pop(packet_info.protosrc)
        for packet in pending:
          self.send_frame(packet, ethernet.IP_TYPE,self.port_mac[index], packet_info.hwsrc, port_in)
    return 0

  def send_frame(self, packet, frame_type, src, dst, outport):
    ether = ethernet()
    ether.type = frame_type
    ether.src = src
    ether.dst = dst
    ether.payload = packet
    msg = of.ofp_packet_out()
    msg.data = ether.pack()
    msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
    msg.in_port = outport
    self.connection.send(msg)

  def arp_packet(self, opcode, dst_mac, dst_ip, outport):
    p = arp()
    p.opcode = opcode
    p.hwsrc = self.port_mac[outport - 1]
    p.hwdst = dst_mac
    p.protosrc = self.port_ip[outport - 1]
    p.protodst = dst_ip
    return p

  def icmp_unreach_packet(self, ip_packet, inport):
    p = icmp()
    p.type = pcket.TYPE_DEST_UNREACH
    data = ip_packet.pack()
    data = data[:ip_packet.hl * 4 + 8]
    data = struct.pack("!HH", 0, 0) + data
    p.payload = data

    p_ip = ipv4()
    p_ip.protocol = p_ip.ICMP_PROTOCOL
    p_ip.srcip = self.port_ip[inport - 1]
    p_ip.dstip = ip_packet.srcip

    p_ip.payload = p
    return p_ip

  def handle_IP(self, packet, IP_packet, port_in):
    if isinstance(IP_packet.payload, icmp):
      self.handle_ICMP(IP_packet, port_in, packet)
    else:
      outport = self.host_ip[IP_packet.dstip]
      if IP_packet.dstip in self.host_ip_mac:
        self.send_frame(packet.payload, ethernet.IP_TYPE, self.port_mac[outport - 1], self.host_ip_mac[IP_packet.dstip], outport)
      else:
        if IP_packet.dstip in self.arp_pending:
          pending = self.arp_pending[IP_packet.dstip]
          pending.append(packet.payload)
          self.arp_pending[IP_packet.dstip] = pending
        else:
          pending = []
          pending.append(packet.payload)
          self.arp_pending[IP_packet.dstip] = pending
        arp_rq = self.arp_packet(arp.REQUEST, EthAddr("ff:ff:ff:ff:ff:ff"), IP_packet.dstip, outport)
        self.send_frame(arp_rq, ethernet.ARP_TYPE, self.port_mac[outport - 1], EthAddr("ff:ff:ff:ff:ff:ff"), outport)

  def handle_ICMP(self,IP_packet, port_in, packet):
    if IP_packet.payload.type == pcket.TYPE_ECHO_REQUEST:
      dstip = IP_packet.dstip
      if dstip in self.port_ip:
        p = icmp()
        p.type = pcket.TYPE_ECHO_REPLY
        p.payload = IP_packet.payload.payload
        IP_packet.srcip, IP_packet.dstip = IP_packet.dstip, IP_packet.srcip
        IP_packet.payload = p
        self.send_frame(IP_packet, ethernet.IP_TYPE, self.port_mac[port_in - 1], packet.src, port_in)
      else:
        outport = self.host_ip[IP_packet.dstip]
        if IP_packet.dstip in self.host_ip_mac:
          self.send_frame(packet.payload, ethernet.IP_TYPE, self.port_mac[outport - 1],
                          self.host_ip_mac[IP_packet.dstip], outport)
        else:
          if IP_packet.dstip in self.arp_pending:
            pending = self.arp_pending[IP_packet.dstip]
            pending.append(packet.payload)
            self.arp_pending[IP_packet.dstip] = pending
          else:
            pending = []
            pending.append(packet.payload)
            self.arp_pending[IP_packet.dstip] = pending
          arp_rq = self.arp_packet(arp.REQUEST, EthAddr("ff:ff:ff:ff:ff:ff"), IP_packet.dstip, outport)
          self.send_frame(arp_rq, ethernet.ARP_TYPE, self.port_mac[outport - 1], EthAddr("ff:ff:ff:ff:ff:ff"), outport)
    elif IP_packet.payload.type == pcket.TYPE_ECHO_REPLY:
      out_port = self.host_ip[IP_packet.dstip]
      dst_mac = self.host_ip_mac[IP_packet.dstip]
      self.send_frame(IP_packet, ethernet.IP_TYPE, self.port_mac[out_port - 1], dst_mac, out_port)




def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    #log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)