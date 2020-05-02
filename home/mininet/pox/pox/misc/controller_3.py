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
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's roughly similar to the one Brandon Heller did for NOX.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import *
from pox.lib.addresses import *
from pox.lib.packet.icmp import *
from pox.lib.packet.ipv4 import *
import pox.lib.packet as pcket
from switch import *
from router import *

log = core.getLogger()



class Tutorial (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self,connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connections = {}
    # This binds our PacketIn event listener
    connection.addListeners(self)

    self.device = {}
    self.subnet = {}
    for i in range(1, 4):
      ro = router()
      self.device[i] = ro

    for i in range(4, 9):
      sw = switch()
      self.device[i] = sw

    self.init_device()



    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).


  def resend_packet (self, packet_in, out_port, dpid):
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
    self.connections[dpid].send(msg)

  def _handle_PacketIn(self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed  # This is the parsed packet data.
    port_in = event.port
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return
    dpid = event.connection.dpid
    self.connections[dpid] = event.connection
    packet_in = event.ofp  # The actual ofp_packet_in message.
    packet_info = packet.next
    if dpid > 3:
      self.act_like_switch(packet, packet_in, dpid)
    else:
      if isinstance(packet_info, arp):
        self.device[dpid].host_ip[packet_info.protosrc] = port_in
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x0800
        msg.match.nw_dst = packet_info.protosrc
        msg.actions.append(of.ofp_action_dl_addr.set_src(self.device[dpid].port_mac[port_in]))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
        msg.actions.append(of.ofp_action_output(port=port_in))
        self.connections[dpid].send(msg)
        self.handle_arp(packet, packet_info, port_in, dpid)

      if isinstance(packet_info, ipv4):
        self.device[dpid].host_ip[packet_info.srcip] = port_in
        if packet_info.dstip not in self.subnet:
          p = self.icmp_unreach_packet(packet.payload, port_in, dpid)
          self.send_frame(p, ethernet.IP_TYPE, self.device[dpid].port_mac[port_in], packet.src, port_in, dpid)
        else:
          self.handle_IP(packet, packet.payload, port_in, dpid, packet_in)



  def act_like_switch (self, packet, packet_in, dpid):
    if packet.src not in self.device[dpid].mac_to_port:
      self.device[dpid].mac_to_port[packet.src] = packet_in.in_port

    if packet.dst in self.device[dpid].mac_to_port:
      self.resend_packet(packet_in,  self.device[dpid].mac_to_port[packet.dst], dpid)
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match()
      msg.match.dl_dst = packet.dst
      msg.match.dl_src = packet.src

      msg.actions.append(of.ofp_action_output(port = self.device[dpid].mac_to_port[packet.dst]))
      
      self.connections[dpid].send(msg)
    else:
      self.resend_packet(packet_in, of.OFPP_ALL, dpid)

  def handle_arp(self, packet, packet_info, port_in, dpid):
    srcip = packet_info.protosrc
    if packet_info.protodst in self.device[dpid].ip_port:
      index = port_in
      if packet_info.opcode == packet_info.REQUEST:
        self.device[dpid].host_ip_mac[srcip] = packet_info.hwsrc
        reply_packet = self.arp_packet(arp.REPLY, packet_info.hwsrc, packet_info.protosrc, port_in, dpid)
        self.send_frame(reply_packet, ethernet.ARP_TYPE, self.device[dpid].port_mac[index], packet_info.hwsrc, port_in, dpid)
      elif packet_info.opcode == packet_info.REPLY:
        self.device[dpid].host_ip_mac[srcip] = packet.src
        pending = self.device[dpid].arp_pending[packet_info.protosrc]
        self.device[dpid].arp_pending.pop(packet_info.protosrc)
        for packet in pending:
          self.send_frame(packet, ethernet.IP_TYPE, self.device[dpid].port_mac[index], packet_info.hwsrc, port_in, dpid)
    return 0

  def handle_IP(self, packet, IP_packet, port_in, dpid, packet_in):
    payload = packet.payload
    if isinstance(IP_packet.payload, icmp):
      self.handle_ICMP(IP_packet, port_in, packet, dpid)
    else:
      outport = self.device[dpid].host_ip[IP_packet.dstip]
      traget_dpid = self.subnet[IP_packet.dstip]
      self.device[dpid].host_ip_mac[IP_packet.srcip] = packet.src
      if traget_dpid != dpid:
        dstmac = self.device[dpid].next_hop[traget_dpid]
        self.device[dpid].host_ip_mac[IP_packet.srcip] = packet.src
        self.device[dpid].host_ip_mac[IP_packet.dstip] = dstmac


        msg = of.ofp_packet_out(buffer_id=packet_in.buffer_id, in_port=port_in)
        msg.actions.append(of.ofp_action_dl_addr.set_dst(dstmac))
        msg.actions.append(of.ofp_action_output(port=outport))# FIXED router to router port
        self.connections[dpid].send(msg)

        # install flow
        fm = of.ofp_flow_mod()
        fm.match.dl_type = 0x800
        fm.match.nw_dst = payload.dstip
        fm.actions.append(of.ofp_action_dl_addr.set_dst(dstmac))
        fm.actions.append(of.ofp_action_output(port=outport))
        self.connections[dpid].send(fm)
      elif IP_packet.dstip in self.device[dpid].host_ip_mac:

        msg = of.ofp_packet_out(buffer_id=packet_in.buffer_id, in_port=port_in)
        msg.actions.append(of.ofp_action_dl_addr.set_dst(self.device[dpid].host_ip_mac[IP_packet.dstip]))
        msg.actions.append(of.ofp_action_output(port=self.device[dpid].host_ip[IP_packet.dstip]))
        self.connections[dpid].send(msg)
        # install flow
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x800
        msg.match.nw_dst = payload.dstip
        msg.actions.append(of.ofp_action_dl_addr.set_dst(self.device[dpid].host_ip_mac[IP_packet.dstip]))
        msg.actions.append(of.ofp_action_output(port=self.device[dpid].host_ip[IP_packet.dstip]))
        self.connections[dpid].send(msg)
      else:
        if IP_packet.dstip in self.device[dpid].arp_pending:
          pending = self.device[dpid].arp_pending[IP_packet.dstip]
          pending.append(packet.payload)
          self.device[dpid].arp_pending[IP_packet.dstip] = pending
        else:
          pending = []
          pending.append(packet.payload)
          self.device[dpid].arp_pending[IP_packet.dstip] = pending
          arp_rq = self.arp_packet(arp.REQUEST, EthAddr("ff:ff:ff:ff:ff:ff"), IP_packet.dstip, outport, dpid)
          self.send_frame(arp_rq, ethernet.ARP_TYPE, self.device[dpid].port_mac[outport], EthAddr("ff:ff:ff:ff:ff:ff"), outport, dpid)

  def handle_ICMP(self,IP_packet, port_in, packet, dpid):
    if IP_packet.payload.type == pcket.TYPE_ECHO_REQUEST:
      dstip = IP_packet.dstip
      traget_dpid = self.subnet[IP_packet.dstip]
      #log.debug("ICMP port_in %s" % (port_in,))
      #log.debug("record mac srcip %s srcmac %s" % (IP_packet.srcip, packet.src,))
      self.device[dpid].host_ip_mac[IP_packet.srcip] = packet.src
      if traget_dpid != dpid:
        dstmac = self.device[dpid].next_hop[traget_dpid]
        outport = self.device[dpid].host_ip[IP_packet.dstip]
        #log.debug("Interrouter dstmac %s  output  %s  srcmac %s" % (dstmac, outport, self.device[dpid].port_mac[outport],))
        #log.debug("Interrouter dstip %s" % (dstip,))
        self.device[dpid].host_ip_mac[dstip] = dstmac
        self.send_frame(packet.payload, ethernet.IP_TYPE, self.device[dpid].port_mac[outport],
                        dstmac, outport, dpid)
      elif dstip in self.device[dpid].ip_port:
        p = icmp()
        p.type = pcket.TYPE_ECHO_REPLY
        p.payload = IP_packet.payload.payload
        IP_packet.srcip, IP_packet.dstip = IP_packet.dstip, IP_packet.srcip
        IP_packet.payload = p
        self.send_frame(IP_packet, ethernet.IP_TYPE, self.device[dpid].port_mac[port_in], packet.src, port_in, dpid)
      else:
        outport = self.device[dpid].host_ip[IP_packet.dstip]
        if IP_packet.dstip in self.device[dpid].host_ip_mac:
          self.send_frame(packet.payload, ethernet.IP_TYPE, self.device[dpid].port_mac[outport],
                          self.device[dpid].host_ip_mac[IP_packet.dstip], outport, dpid)
        else:
          if IP_packet.dstip in self.device[dpid].arp_pending:
            pending = self.device[dpid].arp_pending[IP_packet.dstip]
            pending.append(packet.payload)
            self.device[dpid].arp_pending[IP_packet.dstip] = pending
          else:
            pending = []
            pending.append(packet.payload)
            self.device[dpid].arp_pending[IP_packet.dstip] = pending
            arp_rq = self.arp_packet(arp.REQUEST, EthAddr("ff:ff:ff:ff:ff:ff"), IP_packet.dstip, outport, dpid)
            self.send_frame(arp_rq, ethernet.ARP_TYPE, self.device[dpid].port_mac[outport], EthAddr("ff:ff:ff:ff:ff:ff"), outport, dpid)
    elif IP_packet.payload.type == pcket.TYPE_ECHO_REPLY:
      out_port = self.device[dpid].host_ip[IP_packet.dstip]
      traget_dpid = self.subnet[IP_packet.dstip]
      if traget_dpid != dpid:
        self.device[dpid].host_ip_mac[IP_packet.dstip] = self.device[dpid].next_hop[traget_dpid]
      dst_mac = self.device[dpid].host_ip_mac[IP_packet.dstip]
      self.send_frame(IP_packet, ethernet.IP_TYPE, self.device[dpid].port_mac[out_port], dst_mac, out_port, dpid)


  def send_frame(self, packet, frame_type, src, dst, outport, dpid):
    ether = ethernet()
    ether.type = frame_type
    ether.src = src
    ether.dst = dst
    ether.payload = packet
    msg = of.ofp_packet_out()
    msg.data = ether.pack()
    msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
    msg.in_port = outport
    self.connections[dpid].send(msg)

  def arp_packet(self, opcode, dst_mac, dst_ip, outport, dpid):
    p = arp()
    p.opcode = opcode
    p.hwsrc = self.device[dpid].port_mac[outport]
    p.hwdst = dst_mac
    p.protosrc = self.device[dpid].port_ip[outport]
    p.protodst = dst_ip
    return p

  def icmp_unreach_packet(self, ip_packet, inport, dpid):
    p = icmp()
    p.type = pcket.TYPE_DEST_UNREACH
    data = ip_packet.pack()
    data = data[:ip_packet.hl * 4 + 8]
    data = struct.pack("!HH", 0, 0) + data
    p.payload = data

    p_ip = ipv4()
    p_ip.protocol = p_ip.ICMP_PROTOCOL
    p_ip.srcip = self.device[dpid].port_ip[inport]
    p_ip.dstip = ip_packet.srcip

    p_ip.payload = p
    return p_ip

  def init_device(self):
    self.device[1].add_port("02:00:DE:AD:BE:11", "172.17.16.1", 1)
    self.device[1].add_port("02:00:DE:AD:BE:12", "192.168.0.1", 2)
    self.device[1].add_port("02:00:DE:AD:BE:13", "192.168.0.5", 3)

    self.device[2].add_port("02:00:DE:AD:BE:21", "10.0.0.1", 1)
    self.device[2].add_port("02:00:DE:AD:BE:22", "10.0.0.129", 2)
    self.device[2].add_port("02:00:DE:AD:BE:23", "192.168.0.2", 3)

    self.device[3].add_port("02:00:DE:AD:BE:31", "20.0.0.1", 1)
    self.device[3].add_port("02:00:DE:AD:BE:32", "20.0.0.129", 2)
    self.device[3].add_port("02:00:DE:AD:BE:33", "192.168.0.6", 3)

    self.device[1].add_host("172.17.16.2", 1)
    self.device[1].add_host("172.17.16.3", 1)
    self.device[1].add_host("172.17.16.4", 1)
    self.device[1].add_host("10.0.0.1", 2)
    self.device[1].add_host("10.0.0.2", 2)
    self.device[1].add_host("10.0.0.3", 2)
    self.device[1].add_host("10.0.0.4", 2)
    self.device[1].add_host("10.0.0.129", 2)
    self.device[1].add_host("10.0.0.130", 2)
    self.device[1].add_host("10.0.0.131", 2)
    self.device[1].add_host("10.0.0.132", 2)
    self.device[1].add_host("192.168.0.2", 2)
    self.device[1].add_host("20.0.0.1", 3)
    self.device[1].add_host("20.0.0.2", 3)
    self.device[1].add_host("20.0.0.3", 3)
    self.device[1].add_host("20.0.0.4", 3)
    self.device[1].add_host("20.0.0.129", 3)
    self.device[1].add_host("20.0.0.130", 3)
    self.device[1].add_host("20.0.0.131", 3)
    self.device[1].add_host("20.0.0.132", 3)
    self.device[1].add_host("192.168.0.6", 3)

    self.device[2].add_host("172.17.16.1", 3)
    self.device[2].add_host("172.17.16.2", 3)
    self.device[2].add_host("172.17.16.3", 3)
    self.device[2].add_host("172.17.16.4", 3)
    self.device[2].add_host("192.168.0.1", 3)
    self.device[2].add_host("192.168.0.5", 3)
    self.device[2].add_host("10.0.0.2", 1)
    self.device[2].add_host("10.0.0.3", 1)
    self.device[2].add_host("10.0.0.4", 1)
    self.device[2].add_host("10.0.0.130", 2)
    self.device[2].add_host("10.0.0.131", 2)
    self.device[2].add_host("10.0.0.132", 2)
    self.device[2].add_host("20.0.0.1", 3)
    self.device[2].add_host("20.0.0.2", 3)
    self.device[2].add_host("20.0.0.3", 3)
    self.device[2].add_host("20.0.0.4", 3)
    self.device[2].add_host("20.0.0.130", 3)
    self.device[2].add_host("20.0.0.129", 3)
    self.device[2].add_host("20.0.0.131", 3)
    self.device[2].add_host("20.0.0.132", 3)
    self.device[2].add_host("192.168.0.6", 3)

    self.device[2].add_host("172.17.16.1", 3)
    self.device[3].add_host("172.17.16.2", 3)
    self.device[3].add_host("172.17.16.3", 3)
    self.device[3].add_host("172.17.16.4", 3)
    self.device[3].add_host("192.168.0.1", 3)
    self.device[3].add_host("192.168.0.5", 3)
    self.device[3].add_host("192.168.0.2", 3)
    self.device[3].add_host("10.0.0.1", 3)
    self.device[3].add_host("10.0.0.2", 3)
    self.device[3].add_host("10.0.0.3", 3)
    self.device[3].add_host("10.0.0.4", 3)
    self.device[3].add_host("10.0.0.129", 3)
    self.device[3].add_host("10.0.0.130", 3)
    self.device[3].add_host("10.0.0.131", 3)
    self.device[3].add_host("10.0.0.132", 3)
    self.device[3].add_host("20.0.0.2", 1)
    self.device[3].add_host("20.0.0.3", 1)
    self.device[3].add_host("20.0.0.4", 1)
    self.device[3].add_host("20.0.0.130", 2)
    self.device[3].add_host("20.0.0.131", 2)
    self.device[3].add_host("20.0.0.132", 2)

    self.device[1].add_router("02:00:DE:AD:BE:23", 2)
    self.device[1].add_router("02:00:DE:AD:BE:33", 3)
    self.device[2].add_router("02:00:DE:AD:BE:13", 1)
    self.device[2].add_router("02:00:DE:AD:BE:33", 3)
    self.device[3].add_router("02:00:DE:AD:BE:13", 1)
    self.device[3].add_router("02:00:DE:AD:BE:23", 2)

    self.subnet[IPAddr("172.17.16.1")] = 1
    self.subnet[IPAddr("172.17.16.2")] = 1
    self.subnet[IPAddr("172.17.16.3")] = 1
    self.subnet[IPAddr("172.17.16.4")] = 1
    self.subnet[IPAddr("192.168.0.1")] = 1
    self.subnet[IPAddr("192.168.0.5")] = 1
    self.subnet[IPAddr("10.0.0.1")] = 2
    self.subnet[IPAddr("10.0.0.2")] = 2
    self.subnet[IPAddr("10.0.0.3")] = 2
    self.subnet[IPAddr("10.0.0.4")] = 2
    self.subnet[IPAddr("10.0.0.129")] = 2
    self.subnet[IPAddr("10.0.0.130")] = 2
    self.subnet[IPAddr("10.0.0.131")] = 2
    self.subnet[IPAddr("10.0.0.132")] = 2
    self.subnet[IPAddr("192.168.0.2")] = 2
    self.subnet[IPAddr("20.0.0.1")] = 3
    self.subnet[IPAddr("20.0.0.2")] = 3
    self.subnet[IPAddr("20.0.0.3")] = 3
    self.subnet[IPAddr("20.0.0.4")] = 3
    self.subnet[IPAddr("20.0.0.129")] = 3
    self.subnet[IPAddr("20.0.0.130")] = 3
    self.subnet[IPAddr("20.0.0.131")] = 3
    self.subnet[IPAddr("20.0.0.132")] = 3
    self.subnet[IPAddr("192.168.0.6")] = 3




def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)