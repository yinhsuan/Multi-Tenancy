# from ryu.app import simple_switch_13


from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.ofproto import ofproto_v1_3
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import vlan
from ryu.lib.packet import icmp
from vlan_config import VlansConfig

class MultiTenancy(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        super(MultiTenancy, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        vlans = VlansConfig().vlans
        self.vlan_hosts = vlans['hosts']
        self.datapath_trunks = vlans['trunks']


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath 
        ofproto = datapath.ofproto 
        parser = datapath.ofproto_parser 
        match = parser.OFPMatch() 
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)] 

        # set table miss flow entry
        self.add_flow(datapath, 0, match, actions) 


    def add_flow(self, datapath, priority, match, actions, in_port=None, data=None, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

        


    def packet_out(self, datapath, buffer_id, in_port, actions, data):
        parser = datapath.ofproto_parser
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev): 
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dst = eth.dst
        src = eth.src
        dpid = format(datapath.id, "d").zfill(16) 
        vlan_id = pkt.get_protocols(vlan.vlan)
        self.mac_to_port.setdefault(dpid, {}) 

        self.logger.info("datapath.id %s", datapath.id)
        self.logger.info("in_port %s", in_port)
        if (datapath.id in self.datapath_trunks):
            self.logger.info("self.datapath_trunks[datapath.id] %s", self.datapath_trunks[datapath.id])
        self.logger.info("src %s", src)
        self.logger.info("dst %s", dst)


        if (datapath.id not in self.datapath_trunks):
            if not pkt.get_protocols(vlan.vlan):
                # icmp => broadcast
                out_port = ofproto.OFPP_FLOOD
                actions = [parser.OFPActionOutput(out_port)]
                self.packet_out(datapath, msg.buffer_id, in_port, actions, msg.data)
                self.logger.info("Enter icmp (datapath.id)")
                self.logger.info("")
                return

        if (datapath.id in self.datapath_trunks and in_port in self.datapath_trunks[datapath.id]):
            if not pkt.get_protocols(vlan.vlan):
                # icmp => broadcast
                out_port = ofproto.OFPP_FLOOD
                actions = [parser.OFPActionOutput(in_port)]
                self.packet_out(datapath, msg.buffer_id, in_port, actions, msg.data)
                self.logger.info("Enter icmp (in_port)")
                self.logger.info("")
                return

        if (dst not in self.vlan_hosts):
            if not pkt.get_protocols(vlan.vlan):
                # icmp => broadcast
                out_port = ofproto.OFPP_FLOOD
                actions = [parser.OFPActionOutput(out_port)]
                self.packet_out(datapath, msg.buffer_id, in_port, actions, msg.data)
                self.logger.info("Enter icmp (dst)")
                self.logger.info("")
                return

        # -------------------- STEP 1: do the mac learning -------------------- #
        self.mac_to_port[dpid][src] = in_port 
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # -------------------- LOGIC -------------------- #
        if self.vlan_hosts[src] is not self.vlan_hosts[dst]:
            # out_port = []
            actions = []
            self.logger.info("0. not in the same VLAN")
            self.logger.info("")

        elif out_port != ofproto.OFPP_FLOOD:
            # -------------------- STEP 2: check if vlan tag is present & check if edge switch -------------------- #
            # edge switch
            if datapath.id in self.datapath_trunks:
                # remove the vlan tag & forward
                trunk_port = self.datapath_trunks[datapath.id]
                if in_port in trunk_port:
                    self.logger.info("3. edge switch, remove tag")
                    self.logger.info("")
                    # if src & dst in the same vlan
                    vlan_id = self.vlan_hosts[dst]
                    match = parser.OFPMatch(vlan_vid=(0x1000 | vlan_id), eth_dst=dst)
                    actions = [parser.OFPActionPopVlan(),
                            parser.OFPActionOutput(out_port)]

                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match, actions)

                # add vlan tag it & forward
                else:
                    # if src in self.vlan_hosts:
                    vlan_id = self.vlan_hosts[src]
                    # self.logger.info("vlan_id: %s", vlan_id)
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                    self.logger.info("1. no vlan tag, add vlan tag")
                    self.logger.info("")
                    actions = [parser.OFPActionPushVlan(ether_types.ETH_TYPE_8021Q),
                            parser.OFPActionSetField(vlan_vid=(0x1000 | vlan_id)),
                            parser.OFPActionOutput(out_port)]
                    
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match, actions)

            # normal switch => forward
            else:
                self.logger.info("2. normal switch, just forward")
                self.logger.info("")
                # normal switch => forward
                vlan_id = self.vlan_hosts[dst]
                match = parser.OFPMatch(eth_dst=dst, vlan_vid=(0x1000 | vlan_id))
                actions = [parser.OFPActionOutput(out_port)]

                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)

        # -------------------- FLOOD -------------------- #
        else:
            # edge switch
            if datapath.id in self.datapath_trunks:
                trunk_port = self.datapath_trunks[datapath.id]
                # pop vlan
                if in_port in trunk_port:
                    self.logger.info("6. Flood, remove tag")
                    self.logger.info("")
                    vlan_id = self.vlan_hosts[dst]
                    match = parser.OFPMatch(vlan_vid=(0x1000 | vlan_id), eth_dst=dst)
                    actions = [parser.OFPActionPopVlan(),
                            parser.OFPActionOutput(out_port)]
                # push vlan
                else:
                    vlan_id = self.vlan_hosts[src]
                    # self.logger.info("vlan_id: %s", vlan_id)
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                    self.logger.info("4. Flood, add vlan tag")
                    self.logger.info("")
                    actions = [parser.OFPActionPushVlan(ether_types.ETH_TYPE_8021Q),
                            parser.OFPActionSetField(vlan_vid=(0x1000 | vlan_id)),
                            parser.OFPActionOutput(out_port)]
            # normal switch
            else:
                self.logger.info("5. Just Flood")
                self.logger.info("")
                actions = [parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        