
from pickle import FALSE, TRUE
from socket import IPPROTO_ICMP
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import in_proto
from ryu.lib.packet import icmp 
from ryu.lib.packet import arp
from ryu.ofproto import inet
from asyncio.log import logger
from ipaddress import ip_network

# To match ip address with subnet
import ipaddress
# To use a memory-efficient queue
from collections import deque

interface_mac_to_port = {'10:00:00:00:00:01' : 1, '10:00:00:00:00:02' : 2, '10:00:00:00:00:03' : 3}
interface_ip_to_mac = {'192.168.1.254': '10:00:00:00:00:01', '192.168.2.254': '10:00:00:00:00:02', '192.168.3.254': '10:00:00:00:00:03'}
NET_PORT = {'192.168.1.0/24': 1, '192.168.2.0/24': 2, '192.168.3.0/24': 3}

class L3Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L3Switch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {}
        self.fifo = deque()

    def in_fifo(self, packet):
        return self.fifo.appendleft(packet)
    
    def out_fifo(self):
        return self.fifo.pop()

    def isEmpty(self):
        return len(self.fifo) == 0

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
    

    def send_icmp(self, datapath, opcode, echo, srcIP, srcMAC, dstIP, dstMAC, out_port):
        e = ethernet.ethernet(dstMAC, srcMAC, ether_types.ETH_TYPE_IP)
        ip = ipv4.ipv4(version=4, header_length=5, tos=0, total_length=84,
                       identification=0, flags=0, offset=0, ttl=64,
                       proto=inet.IPPROTO_ICMP, csum=0,
                       src=srcIP, dst=dstIP)
        ping = icmp.icmp(opcode, data = echo)

        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(ip)
        p.add_protocol(ping)
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

    def sameNetwork(self,IP1, IP2):
        a = ip_network(IP1, strict = False).network_address
        b = ip_network(IP2, strict = False).network_address
  
        if(a == b) :
            return TRUE 
        else :
            return FALSE


    def update_ip_table(self, datapath, ip, mac):
        dpid = datapath.id
        self.ip_to_mac[dpid][ip] = mac
        
    def update_mac_table(self, datapath, mac, port):
        dpid = datapath.id
        self.mac_to_port[dpid][mac] = port


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
        
        self.logger.info("packet in %s %s %s %s", dpid, src_mac, dst_mac, in_port)

        if eth.ethertype == ether_types.ETH_TYPE_ARP: # ARP packet received...
            arp_pkt = pkt.get_protocol(arp.arp)
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip

            self.update_mac_table(datapath, src_mac, in_port)
            self.update_ip_table(datapath, src_ip, src_mac)

            self.logger.info(self.ip_to_mac)
            self.logger.info(self.mac_to_port)

            if arp_pkt.opcode == 1:  # If ARP request
                #self.logger.info("ARP  REQ to interface %s with address %s", interface_mac_to_port[interface_ip_to_mac[dst_ip]],dst_ip)
                if dst_ip in interface_ip_to_mac:   # It to routers interface
                    self.logger.info('ARP REQ REPLIED!')
                    self.send_arp(datapath, 2, dst_ip, interface_ip_to_mac[dst_ip], src_ip, src_mac, in_port)
                    return

                
            if arp_pkt.opcode == 2: # If ARP Reply
                if self.isEmpty():
                    self.logger.info('Warning! Not requested ARP reply!')
                    # If L3 did not send request, ignore
                    return

                ev_fifo = self.out_fifo()
                msg_fifo = ev_fifo.msg
                pkt_fifo = packet.Packet(msg_fifo.data)
                eth_fifo = pkt_fifo.get_protocol(ethernet.ethernet)
                arp_fifo = pkt_fifo.get_protocol(arp.arp)
                src_mac_fifo = eth_fifo.src
                dst_mac_fifo = eth_fifo.dst
                #dst_ip_fifo = arp_fifo.dst_ip


                if dst_ip in interface_ip_to_mac:
                    if dst_mac_fifo == src_mac:
                        self.logger.info('ADDED TO THE MAC TABLE: %s -> %s', dst_mac_fifo, in_port)
                        self.update_mac_table(dst_mac_fifo, in_port)
                        self.logger.info('ADDED TO THE IP TABLE: %s -> %s', dst_ip, dst_mac_fifo)
                        self.update_ip_table(dst_ip, dst_mac)
                        return

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            protocol = ip_pkt.proto

            if protocol == in_proto.IPPROTO_ICMP:
                icmp_pkt = pkt.get_protocol(icmp.icmp)
                echo = icmp_pkt.data

                if icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                    if dst_ip in interface_ip_to_mac:   # Its a router interface
                        self.logger.info('ARP REQ received and REPLIED!')
                        self.send_icmp(datapath, icmp.ICMP_ECHO_REPLY, echo, dst_ip, interface_ip_to_mac[dst_ip], src_ip, src_mac, in_port)
                        return

                    elif dst_ip not in self.ip_to_mac[dpid]: # If router does not knows
                        self.logger.info(dst_ip)
                        self.logger.info(self.ip_to_mac)
                        #ADICIONAR A FILA
                        self.in_fifo(ev)
                        for net in NET_PORT:
                            if ipaddress.ip_address(dst_ip) in ipaddress.ip_network(net):
                                size = len(net)
                                for router_ip in interface_ip_to_mac:
                                    if ipaddress.ip_address(router_ip) in ipaddress.ip_network(net):
                                        self.logger.info('FLOOD EXECUTED TO FIND MAC ADDR!')
                                        self.send_arp(datapath, 1, router_ip, interface_ip_to_mac[router_ip], dst_ip, 'FF:FF:FF:FF:FF:FF', interface_mac_to_port[interface_ip_to_mac[router_ip]])
                                        #return


                    else:   #If route know...
                        for net in NET_PORT:
                            if ipaddress.ip_address(dst_ip) in ipaddress.ip_network(net):
                                for net in NET_PORT:
                                    if ipaddress.ip_interface(dst_ip) in ipaddress.ip_network(net):
                                        self.logger.info(dst_ip)
                                        self.logger.info(net)
                                        for router_ip in interface_ip_to_mac:
                                            if ipaddress.ip_interface(router_ip) in ipaddress.ip_network(net):
                                                self.logger.info('ARP REQ FORWARDED!')
                                                self.send_icmp(datapath, icmp.ICMP_ECHO_REQUEST, echo, src_ip, interface_ip_to_mac[router_ip], dst_ip, self.ip_to_mac[dpid][dst_ip], self.mac_to_port[dpid][self.ip_to_mac[dpid][dst_ip]])
                                                return


                
                elif icmp_pkt.type == icmp.ICMP_ECHO_REPLY:
                    if dst_ip in interface_ip_to_mac:
                        # Ignore ICMP REPLY to routers interfaces
                        return

                    self.logger.info(src_ip)
                    self.logger.info(src_mac)
                    self.logger.info(dst_ip)
                    self.logger.info(dst_mac)
                    self.update_ip_table(datapath,src_ip, src_mac)
                    self.update_mac_table(datapath, src_mac, in_port)

                    for net in NET_PORT:
                        if ipaddress.ip_address(dst_ip) in ipaddress.ip_network(net):
                            for net in NET_PORT:
                                if ipaddress.ip_interface(dst_ip) in ipaddress.ip_network(net):
                                    self.logger.info(dst_ip)
                                    self.logger.info(net)
                                    for router_ip in interface_ip_to_mac:
                                        if ipaddress.ip_interface(router_ip) in ipaddress.ip_network(net):
                                            self.logger.info('ARP REQ FORWARDED!')
                                            self.send_icmp(datapath, icmp.ICMP_ECHO_REPLY, echo, src_ip, interface_ip_to_mac[router_ip], dst_ip, self.ip_to_mac[dpid][dst_ip], self.mac_to_port[dpid][self.ip_to_mac[dpid][dst_ip]])
                                            return                    

                            

