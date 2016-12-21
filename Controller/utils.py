import ConfigParser
import os
import sys
from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp
from ryu.lib.packet import arp
from ryu.lib.packet import vlan
from ryu.lib import mac

def readConfigFile(filename) :
    config = None
    filename = os.path.expanduser(filename)
    if not os.path.exists(filename):
    	sys.exit(-1)

    confparser = ConfigParser.RawConfigParser()
    try:
    	confparser.read(filename)
    except ConfigParser.Error as exc:
        print("Config file %s could not be parsed: %s" % (filename, str(exc)))
  # Create a dictionary from the configuration
  # - each section is a key in the dictionary that it's value
  # is a dictionary with (key, value) pairs of configuration
  # parameters
    config = {}
    for sec in confparser.sections():
    	config[sec] = {}
        for (key,val) in confparser.items(sec):
        	config[sec][key] = val

    return config

def packetIsIP(message) :
    pkt = packet.Packet(message.data)

    ip = pkt.get_protocol(ipv4.ipv4)
    if ip is not None :
        return True
    return False

def packetIsARP(message) :
    pkt = packet.Packet(message.data)

    a = pkt.get_protocol(arp.arp)
    if a is not None :
        return True
    return False

def packetIsRequestARP(message) :
    pkt = packet.Packet(message.data)

    a = pkt.get_protocol(arp.arp)
    if a.opcode == arp.ARP_REQUEST :
        return True
    return False

def packetIsReplyARP(message) :
    pkt = packet.Packet(message.data)

    a = pkt.get_protocol(arp.arp)
    if a.opcode == arp.ARP_REPLY :
	return True
    return False

def packetIsTCP(message) :
    pkt = packet.Packet(message.data)

    ip = pkt.get_protocol(ipv4.ipv4)
    if ip is not None and ip.proto == 6 :
	return True
    return False

def packetDstIp(message, ipaddr) :
    if packetIsIP(message):
	pkt = packet.Packet(message.data)
	ip = pkt.get_protocol(ipv4.ipv4)
    	if not cmp(ip.dst, ipaddr):
		return True
    return False

def packetSrcIp(message, ipaddr) :
    if packetIsIP(message):
        pkt = packet.Packet(message.data)
        ip = pkt.get_protocol(ipv4.ipv4)
        if not cmp(ip.src, ipaddr):
                return True
    return False

def packetDstTCPPort(message, tcpport) :
    if packetIsTCP(message) :
	pkt = packet.Packet(message.data)
        dsttcp = pkt.get_protocol(tcp.tcp)
	if dsttcp.dst_port == tcpport :
		return True
    return False

def packetSrcTCPPort(message, tcpport) :
    if packetIsTCP(message) :
        pkt = packet.Packet(message.data)
        srctcp = pkt.get_protocol(tcp.tcp)
	if srctcp.src_port == tcpport :
                return True
    return False

def packetArpDstIp(message, ipaddr) :
    if packetIsARP(message):
        pkt = packet.Packet(message.data)
        a = pkt.get_protocol(arp.arp)
        if not cmp(a.dst_ip, ipaddr):
                return True
    return False

def packetArpSrcIp(message, ipaddr) :
    if packetIsARP(message):
        pkt = packet.Packet(message.data)
        a = pkt.get_protocol(arp.arp)
        if not cmp(a.src_ip, ipaddr):
                return True
    return False

def createArpRequest(message, ip):
    if not packetIsARP(message):
    	print("Packet is not ARP")
    	return
    pkt = packet.Packet(message.data)
    origarp = pkt.get_protocol(arp.arp)
    a = arp.arp(
    	hwtype=origarp.hwtype,
    	proto=origarp.proto,
	src_mac=origarp.src_mac,
    	dst_mac=origarp.dst_mac,
	hlen=origarp.hlen,
    	opcode=arp.ARP_REQUEST,
    	plen=origarp.plen,
	src_ip=origarp.src_ip,
	dst_ip=ip
	)
    e = ethernet.ethernet(
	dst=mac.BROADCAST_STR,
	src=origarp.src_mac,
	ethertype=ether.ETH_TYPE_ARP)    
    p = packet.Packet()
    p.add_protocol(e)
    p.add_protocol(a)
    p.serialize()
    return p

def createArpReply(message, ip):
    if not packetIsARP(message):
        print("Packet is not ARP")
        return
    pkt = packet.Packet(message.data)
    origarp = pkt.get_protocol(arp.arp)
    a = arp.arp(
        hwtype=origarp.hwtype,
        proto=origarp.proto,
        src_mac=origarp.src_mac,
        dst_mac=origarp.dst_mac,
        hlen=origarp.hlen,
        opcode=arp.ARP_REPLY,
        plen=origarp.plen,
        src_ip=ip,
        dst_ip=origarp.dst_ip
        )
    e = ethernet.ethernet(
        dst=origarp.dst_mac,
        src=origarp.src_mac,
        ethertype=ether.ETH_TYPE_ARP)
    p = packet.Packet()
    p.add_protocol(e)
    p.add_protocol(a)
    p.serialize()
    return p

def ipv4_to_int(string):
	ip = string.split('.')
       	assert len(ip) == 4
       	i = 0
       	for b in ip:
    		b = int(b)
        	i = (i << 8) | b
        return i

def sendPacketOut( msg, actions, buffer_id=0xffffffff, data=None ):
    datapath = msg.datapath
    parser = datapath.ofproto_parser

    if buffer_id == 0xffffffff :
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)
    else :
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id, in_port=msg.in_port,
            actions=actions)
        datapath.send_msg(out)

def getFullMatch( msg ):
    datapath = msg.datapath
    parser = datapath.ofproto_parser
    
    in_port=None
    dl_src=None
    dl_dst=None
    dl_vlan=None
    dl_vlan_pcp=None
    dl_type=None
    nw_tos=None
    nw_proto=None
    nw_src=None
    nw_dst=None
    tp_src=None
    tp_dst=None
    
    in_port = msg.in_port

    pkt = packet.Packet(msg.data)
    eth = pkt.get_protocol(ethernet.ethernet)

    dl_src = eth.src
    dl_dst = eth.dst
    dl_type = eth.ethertype

    vl = pkt.get_protocol(vlan.vlan)
    if vl is not None :
        dl_vlan = vl.vid
        dl_vlan_pcp = vl.pcp
        dl_type = vl.ethertype
    
    ip = pkt.get_protocol(ipv4.ipv4)
    if ip is not None :
        nw_src = ip.src
        nw_dst = ip.dst
        nw_proto = ip.proto
        nw_tos = ip.tos

        t = pkt.get_protocol(tcp.tcp)
        if t is not None :
            tp_src = t.src_port
            tp_dst = t.dst_port

        u = pkt.get_protocol(udp.udp)   
        if u is not None :
            tp_src = u.src_port
            tp_dst = u.dst_port
    
        ic = pkt.get_protocol(icmp.icmp)
        if ic is not None :
            tp_src = ic.type
            tp_dst = ic.code
    
    a = pkt.get_protocol(arp.arp)
    if a is not None :
        nw_src = a.src_ip
        nw_dst = a.dst_ip
        nw_proto = a.opcode

    match = parser.OFPMatch( 
        dl_src=mac.haddr_to_bin(dl_src), 
        dl_dst=mac.haddr_to_bin(dl_dst), 
        dl_vlan=dl_vlan, 
        dl_vlan_pcp=dl_vlan_pcp, 
        dl_type=dl_type, 
        nw_tos=nw_tos, 
        nw_proto=nw_proto, 
        nw_src=ipv4_to_int(nw_src), 
        nw_dst=ipv4_to_int(nw_dst), 
        tp_src=tp_src, 
        tp_dst=tp_dst,
        in_port=in_port )
    return match

def createOFAction(datapath, action_type, arg) :
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser 

    if action_type == ofproto.OFPAT_OUTPUT : 
        return parser.OFPActionOutput(arg)
    if action_type == ofproto.OFPAT_SET_DL_SRC : 
        return parser.OFPActionSetDlSrc(mac.haddr_to_bin(arg))
    if action_type == ofproto.OFPAT_SET_DL_DST : 
        return parser.OFPActionSetDlDst(mac.haddr_to_bin(arg))
    if action_type == ofproto.OFPAT_SET_NW_SRC : 
        return parser.OFPActionSetNwSrc(ipv4_to_int(arg))
    if action_type == ofproto.OFPAT_SET_NW_DST : 
        return parser.OFPActionSetNwDst(ipv4_to_int(arg))
    if action_type == ofproto.OFPAT_SET_TP_SRC : 
        return parser.OFPActionSetTpSrc(arg)
    if action_type == ofproto.OFPAT_SET_TP_DST : 
        return parser.OFPActionSetTpDst(arg)
    return None
    
def sendFlowMod(msg, match, actions, hard_timeout, idle_timeout, buffer_id=None):
    datapath = msg.datapath
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    mod = parser.OFPFlowMod(
        datapath=datapath, match=match, cookie=0,
        command=ofproto.OFPFC_ADD, idle_timeout=idle_timeout, hard_timeout=hard_timeout,
        priority=ofproto.OFP_DEFAULT_PRIORITY,
        flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions, buffer_id=buffer_id)
    datapath.send_msg(mod)


