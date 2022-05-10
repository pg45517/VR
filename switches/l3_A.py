from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.ofproto import inet
from asyncio.log import logger
from ipaddress import ip_network

# To match ip address with subnet
import ipaddress

interface_mac_to_port = {'10:00:00:00:00:01' : 1, '10:00:00:00:00:02' : 2, '10:00:00:00:00:03' : 3}
interface_ip_to_mac = {'192.168.1.254': '10:00:00:00:00:01', '192.168.2.254': '10:00:00:00:00:02', '192.168.3.254': '10:00:00:00:00:03'}
NET_PORT = {'192.168.1.0/24': 1, '192.168.2.0/24': 2, '192.168.3.0/24': 3}


class L3Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(L3Switch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {}

    # This part is needed to initialize the switch features
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #print(ev.msg.datapath.address)

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            # ignore ipv6
            return

        dst_mac = eth.dst
        src_mac = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.ip_to_mac.setdefault(dpid, {})

        self.logger.info(self.mac_to_port)
        self.logger.info(self.ip_to_mac)

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.handle_arp(datapath, pkt, in_port, src_mac)
        else:
            self.handle_ip(datapath, pkt, in_port)


    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def handle_ip(self, datapath, pkt, in_port):
        dpid = datapath.id
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        self.logger.info('Packet received form %s to %s', src_ip, dst_ip)
    
        if dst_ip in self.ip_to_mac[dpid]:
            self.inject_flow(datapath, src_ip, in_port, dst_ip, self.mac_to_port[dpid][self.ip_to_mac[dpid][dst_ip]], 1)
            self.logger.info('Flow installed! Subsequent packets will be sent direclty.')

        else:
            for net in NET_PORT:
                if ipaddress.ip_address(dst_ip) in ipaddress.ip_network(net):
                    size = len(net)
                    for router_ip in interface_ip_to_mac:
                        if ipaddress.ip_address(router_ip) in ipaddress.ip_network(net):
                            self.logger.info('FLOOD EXECUTED TO FIND MAC ADDR!')
                            self.send_arp(datapath, 1, router_ip, interface_ip_to_mac[router_ip], dst_ip, 'FF:FF:FF:FF:FF:FF', interface_mac_to_port[interface_ip_to_mac[router_ip]])

    
    def inject_flow(self, datapath, src_ip, in_port, dst_ip, out_port, priority):
        dpid = datapath.id
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port = in_port, eth_type = 0x0800, ipv4_src= src_ip, ipv4_dst = dst_ip) 
        #self.logger.info(interface_ip_to_mac[dst_ip])
        for net in NET_PORT:
            if ipaddress.ip_address(dst_ip) in ipaddress.ip_network(net):
                size = len(net)
                for router_ip in interface_ip_to_mac:
                    if ipaddress.ip_address(router_ip) in ipaddress.ip_network(net):
                        mac = interface_ip_to_mac[router_ip]
        actions = [parser.OFPActionSetField(eth_src = mac), parser.OFPActionSetField(eth_dst = self.ip_to_mac[dpid][dst_ip]), parser.OFPActionOutput(out_port)]
        self.add_flow(datapath, priority, match, actions)


    def handle_arp(self, datapath, pkt, in_port, source):
        dpid = datapath.id
        arp_pkt = pkt.get_protocol(arp.arp)
        src_ip = arp_pkt.src_ip
        dst_ip = arp_pkt.dst_ip
           
        self.mac_to_port.setdefault(dpid, {})
        self.ip_to_mac.setdefault(dpid, {})

        self.update_mac_table(dpid, source, in_port)
        self.update_ip_table(dpid, src_ip, source)

        self.logger.info('Learning %s at port %d with mac %s.', src_ip, in_port, source)

        self.logger.info(self.mac_to_port)
        self.logger.info(self.ip_to_mac)

        if arp_pkt.opcode == 1:
            self.logger.info('Replying ARP REQ from %s', src_ip)
            self.send_arp(datapath, 2, dst_ip, interface_ip_to_mac[dst_ip], src_ip, source, in_port)
        #if arp_pkt.opcode == 2: # If ARP REPLY
        #    self.logger.info('Flow installed from ARP REPLY! Subsequent packets will be sent direclty.')
        #    self.inject_flow(datapath, src_ip, in_port, dst_ip, self.mac_to_port[dpid][self.ip_to_mac[dpid][dst_ip]], 1)


    def send_arp(self,datapath, opcode, srcIP, srcMAC, dstIP, dstMAC, out_port):
        e = ethernet.ethernet(dstMAC, srcMAC, ether_types.ETH_TYPE_ARP)
        a = arp.arp(1, 0x0800, 6, 4, opcode, srcMAC, srcIP, dstMAC, dstIP)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)

        datapath.send_msg(out)
        return

    def update_ip_table(self, dpid, ip, mac):
        #dpid = datapath.id
        self.ip_to_mac[dpid][ip] = mac
        
    def update_mac_table(self, dpid, mac, port):
        #dpid = datapath.id
        self.mac_to_port[dpid][mac] = port