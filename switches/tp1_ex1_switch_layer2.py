from asyncio.log import logger
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.switch_table = {}

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
    
    # switch replying to controller request about its features, is needed for switch reset counters and or create the instance of the flow table
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

    
    # PacketIN event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
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

        # add source mac address to the switch mac table
        self.add_sw_table_entry(in_port, eth.src)

        # print switch mac table
        self.print_sw_table()

        # if destination mac address is inside switch mac table, forward packet to that mac address
        if self.inside_sw_table(eth.dst):
            self.logger.info("DST_MAC found in SW table, packet will be forward to respective DST port")
            out_port = self.get_sw_port(eth.dst)
        else: # if not, flood the packet to all switch ports (hub behaviour, needed to learn macs on ports)
            self.logger.info("DST_MAC (%s) not found, packet will be flooded", eth.dst)
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
             data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.match['in_port'],
            actions=actions, data = data)
        datapath.send_msg(out)
