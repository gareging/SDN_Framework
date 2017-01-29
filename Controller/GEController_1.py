# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Controller framework
"""

import logging
import struct
import re
import sqlite3
import os
import sys
from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ether
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import tcp
from ryu.controller import dpset
from ryu.lib.packet import stream_parser
from ryu.lib.packet import packet_base
from netaddr import *
from utils import *
from ryu.lib.mac import haddr_to_bin
#from PropFair import *

'''
This file is edited from Ryu example which is located at  ryu/ryu/app/simple_switch.py.
According to its licecse(please don't trust my reading and read it), we can modify and use it as long as we keep the old license and state we've change the code. --Joe
'''

FLOW_HARD_TIMEOUT = 30
FLOW_IDLE_TIMEOUT = 10
CONTROLLER_IP = "10.10.10.10"
CONTROLLER_MAC = "00:00:00:00:00:01"


class SimpleSwitch(app_manager.RyuApp):
    global printComments

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.ip_mac_port = {}  #collection of all interfaces connected to OVS
	printComments = 1
	self.configuration = {}  #table for the configuration: DEFAULT/IP_addess;{PARAM*WEIGHT};TIMEOUT
	self.number_of_servers = {}
        self.servers_to_dpid = {}
        self.dpid_to_datapath = {}
	self.servers = {}
        self.serverLoad = {}
	self.switchNeighborInfo = {}
	#read the configuration file
	__location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__))) 
	with open(os.path.join(__location__, 'config')) as f:
           for line in f:
             if line.startswith( '#' ):
	       continue
	     split_line = re.split(';',line[:-1])
             server = split_line[0]
             parameters_weights = re.split(',',split_line[1])
             parameter_list = []
             for pw in parameters_weights:
               parameter = re.split('\*',pw)
               if len(parameter)==1:
                  #in case if we don't specify the weight
                  parameter.append(100/len(parameters_weights))
               parameter_list.append(tuple(parameter))
	     timeout = split_line[2]
	     self.configuration.setdefault(server, {})
             self.configuration[server] = (parameter_list, timeout)
	print self.configuration

        if "DEFAULT" not in self.configuration:
           print "WRONG CONFIGURATION"
	   exit()

        print "Configuration validated"
    
    def add_flow(self, datapath, match, act, priority=0, idle_timeout=0, flags=0, cookie=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, actions=act, flags=flags, idle_timeout=idle_timeout, cookie=cookie)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):      
        print "Packet in"
        #parse the message from the event
        msg = ev.msg
	in_port = msg.in_port 
        #switch id
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        #set default key in a dictionary
        self.ip_mac_port.setdefault(dpid, {})
       
        #read the packet
        pkt = packet.Packet(msg.data) 
	eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
          # self.logger.info("arp %s", arp_pkt)
           src_ip = arp_pkt.src_ip
           dst_ip = arp_pkt.dst_ip

           #save ip to mac and port correspondance
           self.ip_mac_port[dpid][src_ip] = (src, in_port)
           print self.ip_mac_port[dpid][src_ip]                  
                           
           self.send_arp_reply(dpid, datapath, eth, arp_pkt, src_ip, dst_ip, in_port, msg)


        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
           self.logger.info("ipv4_packet %s", ipv4_pkt)
           self.ip_packet_handler(dpid, datapath, eth, msg, pkt, in_port, ipv4_pkt)

    def ip_packet_handler (self, dpid, datapath, eth, msg, pkt, in_port, ipv4_pkt):
	print "Got IP packet"
        udp_segment = pkt.get_protocol(udp.udp)
        tcp_segment = pkt.get_protocol(tcp.tcp)
        parser = datapath.ofproto_parser
	ofproto = datapath.ofproto
        if udp_segment and ipv4_pkt.dst == CONTROLLER_IP:
           #This packet is for controller
           self.server_controller_communication(dpid, datapath, eth, msg, in_port, ipv4_pkt, udp_segment)
        elif tcp_segment:
	   dl_type_ipv4 = 0x0800
           timeout = 60
           #start calling SCHEDULER
           serverID = 1
           #end calling SCHEDULER
           serverIP = self.servers[serverID][0]
           serverDPID = self.servers_to_dpid[serverID]
           serverDP = self.dpid_to_datapath[serverDPID]
           serverIP_int = ipv4_to_int(serverIP)
           serverPORT = self.ip_mac_port[serverDPID][serverIP][1]
           serverMAC = self.ip_mac_port[serverDPID][serverIP][0]
           self.serverLoad[serverID] += 1
           print self.serverLoad

           clientIP_int = ipv4_to_int(ipv4_pkt.src)
           clientPORT = in_port

	   print "Adding FORWARD Flow"
           match = parser.OFPMatch (dl_type = dl_type_ipv4, nw_src=clientIP_int, 
                                                            tp_src=tcp_segment.src_port, nw_proto = 6) #TCP proto 6   
           actions = [parser.OFPActionSetNwDst(serverIP_int),
                    parser.OFPActionSetDlDst(haddr_to_bin(serverMAC)), parser.OFPActionOutput(serverPORT)]
           self.add_flow(datapath=datapath, match=match, act=actions, priority=1, idle_timeout=timeout, 
                        flags=ofproto.OFPFF_SEND_FLOW_REM, cookie=serverID)

	   print "Adding REVERSE Flow"
	   match = parser.OFPMatch (dl_type = dl_type_ipv4, nw_src=serverIP_int,
                                    nw_dst=clientIP_int, tp_dst=tcp_segment.src_port)
           actions = [ parser.OFPActionSetNwSrc (ipv4_to_int(ipv4_pkt.dst)), #REWRITE IP HEADER FOR TCP_HANDSHAKE
                    parser.OFPActionOutput(clientPORT)]
           self.add_flow(datapath=datapath, match=match, act=actions, priority=1, idle_timeout=timeout)

           #sending this packet
           print "Sending the packet out"
           actions = []
	   actions.append( createOFAction(datapath, ofproto.OFPAT_OUTPUT, serverPORT) )
           sendPacketOut(msg=msg, actions=actions, buffer_id=msg.buffer_id) 
   
    def server_controller_communication(self, dpid, datapath, eth, msg, in_port, ipv4_pkt, udp_segment):
	self.logger.info("udp %s", udp_segment)
        print "Got UDP packet for controller"	
        #parsing udp segment
        udp_pointer = len(msg.data) - udp_segment.total_length + 8 
        message = msg.data[udp_pointer:]
        if udp_segment.dst_port == 7777 and message == "Hello":
          print "Server initialization"
          #send UDP reply with the list of parameters and timeout
          self.ip_mac_port[dpid][ipv4_pkt.src] = (eth.src, in_port)
	  if ipv4_pkt.src in self.configuration:
            conf_src = ipv4_pkt.src
          else:
            conf_src = "DEFAULT"
                    
          serverID = findIPInServerList(self.servers, ipv4_pkt.src)
          if serverID==-1:
            print "Add new server"
            serverID = len(self.servers) 
            self.number_of_servers[dpid] = self.number_of_servers[dpid] + 1
            self.servers[serverID] = [0]*(len(self.configuration[conf_src][0]) + 1)
            self.servers[serverID][0] = ipv4_pkt.src
            #self.servers[serverID].append[1]=[0.0]*len(self.configuration[conf_src][0])
            self.servers_to_dpid[serverID] = dpid
            self.serverLoad[serverID] = 0
       
          message = ','.join(p[0] for p in self.configuration[conf_src][0]) + ";" + self.configuration[conf_src][1] + ";" + str(serverID)
	  self.send_udp_reply(dpid, datapath, eth.src, CONTROLLER_MAC, 
                  ipv4_pkt.src, ipv4_pkt.dst, udp_segment.src_port, udp_segment.dst_port, in_port, message)

          print self.servers
	  
        elif udp_segment.dst_port == 7778:
          print message
          recieved_data = re.split(';', message)
	  serverID = int(recieved_data[1])
          if serverID not in self.servers:
            print "Server not registered"
          else:
	    values = re.split(',', recieved_data[0])
            i = 1
            for value in values:
              self.servers[serverID][i] = float(value)
              i += 1         
            print self.servers
        #switch discover UDP segment. 7779 - recieved packet; 7780 - response so the flooder-switch will register the
        #port too
        elif udp_segment.dst_port == 7779:
          self.switchNeighborInfo[dpid][int(message)] = in_port
          self.send_udp_reply(dpid, datapath, CONTROLLER_MAC, CONTROLLER_MAC, 
                           CONTROLLER_IP, CONTROLLER_IP, 7780, 7780, in_port, str(dpid))

        elif udp_segment.dst_port == 7780:
          self.switchNeighborInfo[dpid][int(message)] = in_port

       # print self.ip_mac_port 
        print self.switchNeighborInfo

    def send_udp_reply(self, dpid, datapath, eth_dst, eth_src, ipv4_dst, ipv4_src, udp_dst, udp_src, out_port, message): 
	ofproto = datapath.ofproto
        e = ethernet.ethernet(dst=eth_dst, src=eth_src, ethertype=ether.ETH_TYPE_IP)
        i = ipv4.ipv4(dst=ipv4_dst, src=ipv4_src, proto=17, total_length=0)
        u = udp.udp(src_port=udp_src, dst_port=udp_dst, total_length=0, csum=0)
        udp_h = u.serialize(message, i)
        ip_h = i.serialize(udp_h + message, e)
        eth_h = e.serialize(ip_h + udp_h + message, None)

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        data = eth_h + ip_h + udp_h + message
 
	out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions, data=data)
	datapath.send_msg(out)

    def send_arp_reply(self, dpid, datapath, eth, arp_pkt, src_ip, dst_ip, in_port, msg):
	ofproto = datapath.ofproto
        out_port = None

        if dst_ip in self.ip_mac_port[dpid]:
           out_port = self.ip_mac_port[dpid][dst_ip][1]
	else:
	   print "Controller or unknown ARP request"
           e = ethernet.ethernet(dst=eth.src, src=CONTROLLER_MAC, ethertype=ether.ETH_TYPE_ARP)
           a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2, src_mac=CONTROLLER_MAC, 
                src_ip=dst_ip, dst_mac=eth.src, dst_ip=src_ip)  
         
        if (out_port != None):
           actions = [datapath.ofproto_parser.OFPActionOutput(out_port)] 
           data = msg.data

	else:
	   p = packet.Packet()
           p.add_protocol(e)
           p.add_protocol(a)
           p.serialize()
           actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
           data = p.data
           
	out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions, data=data)
	datapath.send_msg(out)


    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removal_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        dpid = dp.id
        serverID = msg.cookie
        self.logger.info("Client released serverID = %d", msg.cookie)
        if self.serverLoad[serverID] > 0:
	   self.serverLoad[serverID] -= 1
           print self.serverLoad
   
    def remove_table_flows(self, datapath, table_id, match):
        """Create OFP flow mod message to remove flows from table."""
        ofproto = datapath.ofproto
        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, match=match, command=ofproto.OFPFC_DELETE, 
                             cookie=0, idle_timeout=0,out_port=65535, buffer_id=4294967295, flags=0, hard_timeout=0,priority=0, actions=[])
        return flow_mod

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def _event_switch_enter_handler(self, ev):
       #definitions
       actions = []
       dl_type_ipv4 = 0x0800
       dl_type_arp = 0x0806
       dp = ev.dp
       dpid = dp.id

       self.dpid_to_datapath[dpid] = dp

       ofproto = dp.ofproto
       parser = dp.ofproto_parser
       empty_match = parser.OFPMatch()
       instructions = []

       self.number_of_servers.setdefault(dpid, {})
 #      self.servers.setdefault(dpid, {})
       self.switchNeighborInfo.setdefault(dpid, {})
       self.number_of_servers[dpid] = 0
#       self.servers[dpid][0] = ('0')
       
       #empty the flow table
       flow_mod = self.remove_table_flows(dp, 0,empty_match)
       dp.send_msg(flow_mod)

       #process arp packets normally
       actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]    
       match = parser.OFPMatch(dl_type = dl_type_arp)
       #self.add_flow(dp, match, actions, priority=100)

       #add miss flow
       match = parser.OFPMatch ()
       actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
       self.add_flow(dp, match, actions, priority=0)
 
       #send switch discover packet
       self.send_udp_reply(dpid, dp, CONTROLLER_MAC, CONTROLLER_MAC, 
                           CONTROLLER_IP, CONTROLLER_IP, 7779, 7779, ofproto.OFPP_FLOOD, str(dpid))
