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
import datetime
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
from collections import OrderedDict
#from PropFair import *

'''
This file is edited from Ryu example which is located at  ryu/ryu/app/simple_switch.py.
According to its licecse(please don't trust my reading and read it), we can modify and use it as long as we keep the old license and state we've change the code. --Joe
'''

FLOW_HARD_TIMEOUT = 30
FLOW_IDLE_TIMEOUT = 10
CONTROLLER_IP = "10.10.10.10"
CONTROLLER_MAC = "00:00:00:00:00:01"


class SDNFramework(app_manager.RyuApp):
    global printComments

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNFramework, self).__init__(*args, **kwargs)
        self.ip_mac_port = {}  #collection of all interfaces connected to OVS
	printComments = 1
        self.maxID = -1
	self.configuration = {}  #table for the configuration: DEFAULT/IP_addess;{PARAM*WEIGHT};TIMEOUT
	self.number_of_servers = {}
	self.server_info = []
        self.server_ip = []
        self.servers_on_switch = {}
        self.server_load = []
	self.switch_neighbor_info = {}
        self.dpid_to_datapath = {}
        
        self.todayis = datetime.datetime(2001, 1, 1, 00, 00)
        self.server_to_switch = []
        self.counter = 0

        self.T = {}
	#read the configuration file
	__location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__))) 
	with open(os.path.join(__location__, 'config')) as f:
           for line in f:
             if line.startswith( '#' ):
	       continue
	     split_line = re.split(';',line[:-1])
             server = split_line[0]
             self.configuration[server] = OrderedDict()
             parameters_and_weights = re.split(',',split_line[1])
             parameter_list = []
             for pw in parameters_and_weights:
               parsed = re.split('\*',pw)
               parameter = parsed[0] 
               parameter_weight = 0
               if len(parsed)==1:
                  #in case if we don't specify the weight
                  parameter_weight = 100/len(parameters_and_weights)
               else:
                  parameter_weight = parsed[1]
               self.configuration[server][parameter] = int(parameter_weight)
	     timeout = split_line[2]
             self.configuration[server]["t"] = timeout
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
        #print "Packet in"
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

        #save arp values

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
          # self.logger.info("arp %s", arp_pkt)
           src_ip = arp_pkt.src_ip
           dst_ip = arp_pkt.dst_ip
           self.ip_mac_port[dpid][src_ip] = (src, in_port)
#           print self.ip_mac_port                  

           #save ip to mac and port correspondance
                           
           self.send_arp_reply(dpid, datapath, eth, arp_pkt, src_ip, dst_ip, in_port, msg)
       
          

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
          # self.logger.info("ipv4_packet %s", ipv4_pkt)
           self.ip_mac_port[dpid][ipv4_pkt.src] = (src, in_port)
           self.ip_packet_handler(dpid, datapath, eth, msg, pkt, in_port, ipv4_pkt)
           

    def ip_packet_handler (self, dpid, datapath, eth, msg, pkt, in_port, ipv4_pkt):
	#print "Got IP packet for dpid", dpid
        udp_segment = pkt.get_protocol(udp.udp)
        tcp_segment = pkt.get_protocol(tcp.tcp)
        parser = datapath.ofproto_parser
	ofproto = datapath.ofproto
        if udp_segment and ipv4_pkt.dst == CONTROLLER_IP:
           #This packet is for controller
           self.server_controller_communication(dpid, datapath, eth, msg, in_port, ipv4_pkt, udp_segment)
        elif tcp_segment:
           print "CLIENT FROM ", dpid
	   dl_type_ipv4 = 0x0800
           timeout = 60

           conf_src = ""
           if ipv4_pkt.src in self.configuration:
             conf_src = ipv4_pkt.src
           else:
             conf_src = "DEFAULT"

           #start calling SCHEDULER
           newDPID, serverID = self.PropFair(dpid, conf_src)
           #print "newDPID", newDPID
           #print "serverID", serverID
           #end calling SCHEDULER

           serverIP = self.server_ip[serverID]
           serverIP_int = ipv4_to_int(serverIP)
           serverPORT = self.ip_mac_port[newDPID][serverIP][1]
           serverMAC = self.ip_mac_port[newDPID][serverIP][0]
           #print "serverIP", serverIP
           #print "serverPORT", serverPORT
           #print "serverMAC", serverMAC

           #print self.server_load

           clientIP_int = ipv4_to_int(ipv4_pkt.src)
           clientPORT = in_port
           #matcher
           match = parser.OFPMatch (dl_type = dl_type_ipv4, nw_src=clientIP_int, 
                                                              tp_src=tcp_segment.src_port, nw_proto = 6) #TCP proto 6   
           #rewrite header and transfer it to the port
           if dpid == newDPID:
             actions = [parser.OFPActionSetNwDst(serverIP_int), 
                      parser.OFPActionSetDlDst(haddr_to_bin(serverMAC)), parser.OFPActionOutput(serverPORT)]

             self.add_flow(datapath=datapath, match=match, act=actions, priority=1, idle_timeout=timeout, 
                          flags=ofproto.OFPFF_SEND_FLOW_REM, cookie=serverID)


           else:
             actions = [parser.OFPActionSetNwDst(serverIP_int),
                                  parser.OFPActionSetDlDst(haddr_to_bin(serverMAC)), 
                                  parser.OFPActionOutput( self.switch_neighbor_info[dpid][newDPID] )]
 
             self.add_flow(datapath=datapath, match=match, act=actions, priority=1, idle_timeout=timeout, 
                          flags=ofproto.OFPFF_SEND_FLOW_REM, cookie=serverID)

             actions =  [parser.OFPActionOutput(serverPORT)]

             self.add_flow(datapath=self.dpid_to_datapath[newDPID], match=match, 
                                  act=actions, priority=1, idle_timeout=timeout)

           match = parser.OFPMatch (dl_type = dl_type_ipv4, nw_src=serverIP_int,
                                nw_dst=clientIP_int, tp_dst=tcp_segment.src_port)
            
           #rewrite reverse packet's header
           actions = [ parser.OFPActionSetNwSrc (ipv4_to_int(ipv4_pkt.dst)), #REWRITE IP HEADER FOR TCP_HANDSHAKE
                  parser.OFPActionOutput(clientPORT)]
           self.add_flow(datapath=datapath, match=match, act=actions, priority=1, idle_timeout=timeout)

           if dpid != newDPID:
               print "Install the reverse flow into transition switch"
               actions = [ parser.OFPActionOutput(self.switch_neighbor_info[newDPID][dpid])]
               self.add_flow(datapath=self.dpid_to_datapath[newDPID], match=match, 
                                  act=actions, priority=1, idle_timeout=timeout)
                 
           if dpid==newDPID:
           #sending this packet
             #print "Sending the packet out"
             actions = []
       	     actions.append( createOFAction(datapath, ofproto.OFPAT_OUTPUT, serverPORT) )
             sendPacketOut(msg=msg, actions=actions, buffer_id=msg.buffer_id) 

           else:
             actions = []
       	     actions.append( createOFAction(datapath, ofproto.OFPAT_OUTPUT, self.switch_neighbor_info[dpid][newDPID]) )
             sendPacketOut(msg=msg, actions=actions, buffer_id=msg.buffer_id) 

           self.server_load[serverID] += 1
           print self.server_load     
           sys.stdout.write("CURRENT SERVER LOAD:\t" + str(self.todayis) + "\t") 
           for i in range (0, self.maxID):
              sys.stdout.write(str(self.server_load[i]) + "\t")
           print " "

    def server_controller_communication(self, dpid, datapath, eth, msg, in_port, ipv4_pkt, udp_segment):
	#self.logger.info("udp %s", udp_segment)
        #print "Got UDP packet for controller"	
        #parsing udp segment
        udp_pointer = len(msg.data) - udp_segment.total_length + 8 
        message = msg.data[udp_pointer:]
        if udp_segment.dst_port == 7777 and message == "Hello":
          #print "Server initialization"
          #send UDP reply with the list of parameters and timeout
          self.ip_mac_port[dpid][ipv4_pkt.src] = (eth.src, in_port)
	  if ipv4_pkt.src in self.configuration:
            conf_src = ipv4_pkt.src
          else:
            conf_src = "DEFAULT"
         
          try:   
            serverID = self.server_ip.index(ipv4_pkt.src)
            #print "serverID found", serverID
          except:
            serverID = -1
            #print "serverID not found"


          message = ""
          if serverID==-1:
            #print "Add new server"
            serverID = self.maxID = self.maxID + 1
            #print serverID
            self.logger.info("Server: dpid:%d, serverID:%d, serverIP: %s", dpid, serverID, ipv4_pkt.src)
            self.number_of_servers[dpid] += 1
            self.server_ip.append(ipv4_pkt.src)
            
            #for test run
            self.server_to_switch.append(dpid)
            
            self.server_info.append([])
            for parameter in self.configuration[conf_src]:
              if parameter!='t':
                self.server_info[serverID].append(0.0)
                message += parameter + ","
            self.server_load.append(0)
            self.servers_on_switch[dpid].append(serverID)
            self.T[dpid].append(1)

            #print self.server_info
        #    print self.T 
       
          if (message == ""):
            for parameter in self.configuration[conf_src]:
              if parameter!='t':
                message += parameter + ","

     
          message = message[:-1] + ";" + self.configuration[conf_src]["t"] + ";" + str(serverID)
 #         message = ','.join(p[0] for p in self.configuration[conf_src][0]) + ";" + self.configuration[conf_src][1] + ";" + str(serverID)
	  self.send_udp_reply(dpid, datapath, eth.src, CONTROLLER_MAC, 
                  ipv4_pkt.src, ipv4_pkt.dst, udp_segment.src_port, udp_segment.dst_port, in_port, message)

         # print self.servers
	  
        elif udp_segment.dst_port == 7778:
          #print message
          recieved_data = re.split(';', message)
	  serverID = int(recieved_data[1])
          if (serverID not in self.servers_on_switch[dpid]):
            print "Server not registered"
            self.send_udp_reply(dpid, datapath, eth.src, CONTROLLER_MAC, 
                           ipv4_pkt.src, CONTROLLER_IP, udp_segment.src_port, udp_segment.dst_port, in_port, "404")

          else:
	    values = re.split(',', recieved_data[0])
            i = 0
            for value in values:
              self.server_info[serverID][i] = float(value)
              i += 1         
            self.counter += 1
    
            if (self.counter % 9 == 0):
              sys.stdout.write("CURRENT ENERGY VALUES:\t" + str(self.todayis) + "\t") 
              for i in range (0, self.maxID + 1):
                 sys.stdout.write(str(self.server_info[i][0]) + "\t")
              #print "Value received: SYNCHRONIZED RESPONSE TO EVERY SERVER"
              for i in range (0, self.maxID + 1):
                 serverIP = self.server_ip[i]
                 serverDPID = self.server_to_switch[i]
                 serverPORT = self.ip_mac_port[serverDPID][serverIP][1]
                 serverMAC = self.ip_mac_port[serverDPID][serverIP][0]
                 serverDATAPATH = self.dpid_to_datapath[serverDPID]
                 self.send_udp_reply(serverDPID, serverDATAPATH, serverMAC, CONTROLLER_MAC, 
                             serverIP, CONTROLLER_IP, udp_segment.src_port, udp_segment.dst_port, serverPORT, "OK")

              print " "
              self.todayis += datetime.timedelta(hours=1)

        #switch discover UDP segment. 7779 - recieved packet; 7780 - response so the flooder-switch will register the
        #port too
        elif udp_segment.dst_port == 7779:
          self.switch_neighbor_info[dpid][int(message)] = in_port
          self.send_udp_reply(dpid, datapath, CONTROLLER_MAC, CONTROLLER_MAC, 
                           CONTROLLER_IP, CONTROLLER_IP, 7780, 7780, in_port, str(dpid))

        elif udp_segment.dst_port == 7780:
          self.switch_neighbor_info[dpid][int(message)] = in_port

       # print self.ip_mac_port 
       # print "Switch", dpid, "neighbors"
       # print self.switchNeighborInfo[dpid].keys()


        #print self.switchNeighborInfo

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
        mac_found = ""
        
        for dp, values in self.ip_mac_port.items():
#          print values
          if dst_ip in values:
            mac_found = values[dst_ip][0]
            out_port = in_port
            e = ethernet.ethernet(dst=eth.src, src=CONTROLLER_MAC, ethertype=ether.ETH_TYPE_ARP)
            a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2, src_mac=mac_found, 
                src_ip=dst_ip, dst_mac=eth.src, dst_ip=src_ip)  
            break
	
        if out_port == None:
	   #print "Controller or unknown ARP request"
           e = ethernet.ethernet(dst=eth.src, src=CONTROLLER_MAC, ethertype=ether.ETH_TYPE_ARP)
           a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2, src_mac=CONTROLLER_MAC, 
                src_ip=dst_ip, dst_mac=eth.src, dst_ip=src_ip) 
           out_port = in_port


    	p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        data = p.data
      
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)] 

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
        #self.logger.info("Client released serverID = %d", msg.cookie)
        if serverID in self.server_load:
          if self.server_load[serverID] > 0:
	    self.server_load[serverID] -= 1
            #print self.server_load
   
    def remove_table_flows(self, datapath, table_id, match):
        """Create OFP flow mod message to remove flows from table."""
        ofproto = datapath.ofproto
        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, match=match, command=ofproto.OFPFC_DELETE, 
                             cookie=0, idle_timeout=0,out_port=65535, buffer_id=4294967295, flags=0, hard_timeout=0,priority=0, actions=[])
        return flow_mod

    def PropFair(self, dpid, conf_src):
    	#getting Sid of the switch that particular user is connected to
    	#Server_Per_Switch=self.number_of_servers[dpid]
    	#Number_Switches_in_neighbourhood=len(self.switchNeighborInfo[dpid].keys())+1
    	Neighborhood=self.switch_neighbor_info[dpid].keys()
    	Neighborhood.append(dpid) # adding the switch that user is connected to to the neighborhood. 
    	tc=50
    	V={}
    	Metrics={}
    	Max={}
        W1 = self.configuration[conf_src]['GE'] #GE weight
        W2 = self.configuration[conf_src]['DL']

        GE_index = 0 #self.configuration[conf_src].keys().index('GE') #GE position read from the configuration
        DL_index = 1 #self.configuration[conf_src].keys().index('DL')

        #print "GE index", GE_index
        Maxdelay=30  
        MaxGreen=1000
        Valuedelay = 0
       # print "NUMBER OF SERVERS"
       # print self.number_of_servers
       # print "SEE NEIGHBORHOOD"
       # print Neighborhood
       # print "DPID", dpid
    	for s in Neighborhood:
          if s==dpid:
            delay=1 #delay between switch that users are connected to the servers in that switch is negligable 
          else:
            delay=20 #we assume the delay to next hop is almost the same for switches in a neighbourhood        
    	  V.setdefault(s,[0]*self.number_of_servers[s])
    	  Metrics.setdefault(s,[0]*self.number_of_servers[s])
          for i in range(0,self.number_of_servers[s]):
            if (delay >= Maxdelay):
              Valuedelay=0
            else:  
              Valuedelay=(1.0/delay)*(100)*(W2)
            serverID = self.servers_on_switch[s][i]  
            V[s][i]=(self.server_info[serverID][GE_index])*(W1)*((1.0/MaxGreen)*100)+ Valuedelay  # remember to calculate the proper N1 and N2 and devide by T
            Metrics[s][i]=V[s][i]/self.T[s][i]
        
        #print "SEE METRICS"
        #print Metrics

        maxvalue=0
    	Maxserver=0
        Maxsid=0        


     
	for z in Metrics: #z is the switch id
          if Metrics[z] and max(Metrics[z])>maxvalue:
            maxvalue=max(Metrics[z])
            Maxserver=Metrics[z].index(max(Metrics[z]))
            Maxsid=z        
        
        for s in Neighborhood:
       	  for i in range(0,self.number_of_servers[s]):
            if s==Maxsid and i==Maxserver:
              self.T[s][i]=(1.0-(1.0/tc))*self.T[s][i]+((1.0/tc))*V[s][i]
            else:
              self.T[s][i]=(1.0-(1.0/tc))*self.T[s][i]

        #print "Scheduler chooses", Maxserver 
        #print "Switch", Maxsid
        MaxserverID = self.servers_on_switch[Maxsid][Maxserver]         
	return Maxsid,MaxserverID


    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def _event_switch_enter_handler(self, ev):
       #definitions
       actions = []
       dl_type_ipv4 = 0x0800
       dl_type_arp = 0x0806
       dp = ev.dp
       dpid = dp.id

       ofproto = dp.ofproto
       parser = dp.ofproto_parser
       empty_match = parser.OFPMatch()
       instructions = []

       self.number_of_servers[dpid] = 0
       self.servers_on_switch[dpid] = []
       self.switch_neighbor_info[dpid] = {}
       self.dpid_to_datapath[dpid] = dp
       self.T[dpid] = []
       
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



