from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls 
from ryu.ofproto import ofproto_v1_3, inet
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, in_proto, icmp, arp
from asyncio.log import logger
from ipaddress import ip_network, ip_interface

# To work with IP easily
import ipaddress

# Define IPv4 addresses to each port of each switch
# {DPID:{PORT: IP}}
interface_port_to_ip = {1: {1: '192.168.1.254', 2: '192.168.2.254', 3: '192.168.3.254'}}

class L3Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L3Switch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {}
        self.L3_mac_to_port = {}
        self.L3_ip_to_mac = {}
        self.queue = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info(ev.msg.datapath.address)
        #address = ev.switch.dp.address
        #dpid = ev.switch.dp.id
        #self.logger.info(address)
        #self.logger.info(dpid)

        
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

        match = parser.OFPMatch(eth_type = ether_types.ETH_TYPE_IPV6)
        actions = []
        self.add_flow(datapath, 1, match, actions)
        self.send_port_desc_stats_request(datapath)

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

    def send_port_desc_stats_request(self, datapath):
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)
    
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id

        self.L3_mac_to_port.setdefault(dpid, {})
        self.L3_ip_to_mac.setdefault(dpid, {})

        for p in ev.msg.body:
            self.L3_mac_to_port[dpid][p.hw_addr] = p.port_no
            if not p.port_no == 4294967294:
                self.L3_ip_to_mac[dpid][interface_port_to_ip[dpid][p.port_no]] = p.hw_addr

        self.logger.info('%d MAC TABLE: %s', dpid, self.L3_mac_to_port[dpid])
        self.logger.info('%d ARP TABLE: %s', dpid, self.L3_ip_to_mac[dpid])

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
            # ignore ipv6 (redundance)
            return

        dst_mac = eth.dst
        src_mac = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.ip_to_mac.setdefault(dpid, {})
        
        self.logger.info("packet in %s %s %s %s", dpid, src_mac, dst_mac, in_port)

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.handle_arp(datapath, pkt, in_port, src_mac)
        
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            protocol = ip_pkt.proto

            if dst_ip in self.ip_to_mac[dpid]:
                self.logger.info('NEW FLOW ADDED, PLS CHECK FLOW TABLE')
                self.inject_flow(datapath, src_ip, in_port, dst_ip, self.mac_to_port[dpid][self.ip_to_mac[dpid][dst_ip]], 1)
            elif dst_ip in self.L3_ip_to_mac[dpid]:
                if protocol == in_proto.IPPROTO_ICMP:
                    icmp_pkt = pkt.get_protocol(icmp.icmp)
                    echo = icmp_pkt.data
                    if icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                        self.logger.info('ICMP REPLY to %s in port %d', dst_ip, in_port)
                        # Could be good add a flow to avoid use the controller
                        self.send_icmp(datapath, icmp.ICMP_ECHO_REPLY, echo, dst_ip, self.L3_ip_to_mac[dpid][dst_ip], src_ip, src_mac, in_port)
                        return
            else:
                # Should enqueue the arrived packet here while switch search for the MAC....
                self.flood_arp(datapath, dst_ip)
                return
                    
    def flood_arp(self, datapath, dst_ip):
        dpid = datapath.id 
        self.logger.info('flood')
        
        for router_ip in self.L3_ip_to_mac[dpid]:
            if self.same_network(dst_ip, router_ip, '/24'):
                self.logger.info('FLOOD executed to find %s', dst_ip)
                self.send_arp(datapath, 1, router_ip, self.L3_ip_to_mac[dpid][router_ip], dst_ip, 'FF:FF:FF:FF:FF:FF', self.L3_mac_to_port[dpid][self.L3_ip_to_mac[dpid][router_ip]])
                return

        # for net in NET_PORT:
        #     if ipaddress.ip_address(dst_ip) in ipaddress.ip_network(net):
        #         for router_ip in self.L3_ip_to_mac[dpid]:
        #             if ipaddress.ip_address(router_ip) in ipaddress.ip_network(net):
        #                 self.logger.info('FLOOD executed to find %s', dst_ip)
        #                 self.send_arp(datapath, 1, router_ip, self.L3_ip_to_mac[dpid][router_ip], dst_ip, 'FF:FF:FF:FF:FF:FF', self.L3_mac_to_port[dpid][self.L3_ip_to_mac[dpid][router_ip]])

    def handle_arp(self, datapath, pkt, in_port, src_mac):
        dpid = datapath.id
        arp_pkt = pkt.get_protocol(arp.arp)
        src_ip = arp_pkt.src_ip
        dst_ip = arp_pkt.dst_ip

        if arp_pkt.opcode == 1: #ARP REQ
            self.update_mac_table(datapath, src_mac, in_port)
            self.update_ip_table(datapath, src_ip, src_mac)
            self.logger.info(self.mac_to_port[dpid])
            self.logger.info(self.ip_to_mac[dpid])

            if dst_ip in self.L3_ip_to_mac[dpid]:
                self.logger.info('ARP REPLY to %s in port %d', src_ip, in_port)
                # Could be good add a flow to avoid use the controller
                self.send_arp(datapath, 2, dst_ip, self.L3_ip_to_mac[dpid][dst_ip], src_ip, src_mac, in_port)
                return

        else:   # ARP REPLY
            # TO DO
            # Added queue in this process...
            self.logger.info('Added to the table: %s -> %s -> %s -> %d', dpid, src_ip, src_mac, in_port)
            self.update_mac_table(datapath, src_mac, in_port)
            self.update_ip_table(datapath, src_ip, src_mac)
            return

    def inject_flow(self, datapath, src_ip, in_port, dst_ip, out_port, priority):
        dpid = datapath.id
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port = in_port, eth_type = 0x0800, ipv4_src= src_ip, ipv4_dst = dst_ip) 
        #self.logger.info(interface_ip_to_mac[dst_ip])
        for key, value in self.L3_mac_to_port[dpid].items():
            if value == out_port:
                mac = key
        actions = [parser.OFPActionSetField(eth_src = mac), parser.OFPActionSetField(eth_dst = self.ip_to_mac[dpid][dst_ip]), parser.OFPActionOutput(out_port)]
        self.add_flow(datapath, priority, match, actions)

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

    def update_ip_table(self, datapath, ip, mac):
        dpid = datapath.id
        self.ip_to_mac[dpid][ip] = mac
        
    def update_mac_table(self, datapath, mac, port):
        dpid = datapath.id
        self.mac_to_port[dpid][mac] = port

    def same_network(self, src_ip, dst_ip, mask):
        a = ip_interface(src_ip+mask);
        b = ip_interface(dst_ip+mask);
        if b.network.overlaps(a.network):
            self.logger.info('%s and %s overlaps!', src_ip, dst_ip)
            return True
        else:
            return False
