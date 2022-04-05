# Modified to implement switch L3
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
from ryu.lib.packet import tcp  
from ryu.lib.packet import udp
from asyncio.log import logger


class L3Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L3Switch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}   # MAC address and port association
        self.mac_to_ip = {}     # MAC address and IP address

    # This part is needed to initialize the switch features
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

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
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:

            #Original L2 match statement
            #match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            
            # Check if frame header protocol type indicates IPv4 i.e. 0x800
            # If so, extract the source and destination IP address as a new
            # match and send as a flow to the switch....
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                src_ip = ip.src
                dst_ip = ip.dst
                protocol = ip.proto # L4 protocol

                self.logger.info("DPID: %s | SRC_MAC: %s | SRC_IP: %s | DST_MAC: %s | DST_IP: %s | IN_PORT: %s", dpid, src, src_ip, dst, dst_ip, in_port)

                self.mac_to_ip.setdefault(dpid, {})
                self.mac_to_ip[dpid].setdefault(src,src_ip)
                
                self.logger.info(self.mac_to_ip)    

                # Handle ICMP Protocol
                if protocol == in_proto.IPPROTO_ICMP:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=src_ip,
                                            ipv4_dst=dst_ip,
                                            ip_proto = protocol)
                                            #RESPONDER ICMP

                # Handle TCP protocol
                if protocol == in_proto.IPPROTO_TCP:
                    _tcp = pkt.get_protocol(tcp.tcp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=src_ip,
                                            ipv4_dst=dst_ip,
                                            ip_proto = protocol,
                                            tcp_src = _tcp.src_port,
                                            tcp_dst = _tcp.dst_port)

                # Handle UDP protocol
                if protocol == in_proto.IPPROTO_UDP:
                    _udp = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=src_ip,
                                            ipv4_dst=dst_ip,
                                            ip_proto = protocol,
                                            udp_src = _udp.src_port,
                                            udp_dst = _udp.dst_port)
            
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        

    def add_sw_table_entry(self, port, host_addr):
        self.switch_table[int(port)] = host_addr


    def inside_sw_table(self, host_addr):
        for sw_port in self.switch_table:
            if host_addr == self.switch_table[sw_port]:
                return True
        return False


    def get_sw_port(self, host_addr):
        for sw_port in self.switch_table:
            if host_addr == self.switch_table[sw_port]:
                return sw_port


    def print_sw_table(self):
        logger.info("##################")
        logger.info("PORT \t MAC")
        for port, mac in self.switch_table.items():
            logger.info("%s \t %s", port, mac)
        logger.info("##################")
