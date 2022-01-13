from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types
from ryu.lib import mac, ip
from ryu.topology import event
from collections import defaultdict


class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.datapath_list = {}
        self.switches = []
        self.adjacency = defaultdict(dict)
        self.hosts = {
            '10.0.0.1': (1, 1),
            '10.0.0.2': (1, 2),
            '10.0.0.3': (2, 1),
            '10.0.0.4': (2, 2),
            '10.0.0.5': (3, 1),
            '10.0.0.6': (3, 2),
            '10.0.0.7': (4, 1),
            '10.0.0.8': (4, 2),
            '10.0.0.9': (5, 1),
            '10.0.0.10': (5, 2),
            '10.0.0.11': (6, 1),
            '10.0.0.12': (6, 2),
            '10.0.0.13': (7, 1),
            '10.0.0.14': (7, 2),
            '10.0.0.15': (8, 1),
            '10.0.0.16': (8, 2)
        }
        # students fill in
        self.table = {}
        self.load = [[0] * 21] * 21
        self.saved_path = []

    def get_port(self, dpid: int, dst_ip: str):
        s, port = self.hosts[dst_ip]
        assert (s in range(1, 9))
        s1 = (s + 1) // 2 * 2 + 7
        s2 = s1 + 1
        if dpid in range(1, 9):
            if dpid == s:
                return port
            d1 = (dpid + 1) // 2 * 2 + 7
            d2 = d1 + 1
            r1 = max(self.load[dpid][d1], self.load[s1][s], min(max(self.load[d1][17], self.load[17][s1]), max(self.load[d1][18], self.load[18][s1])))
            r2 = max(self.load[dpid][d2], self.load[s2][s], min(max(self.load[d2][19], self.load[19][s2]), max(self.load[d2][20], self.load[20][s2])))
            dest = d1 if r1 <= r2 else d2

        elif dpid in range(9, 17):
            if dpid in range((s + 1) // 2 * 2 + 7, (s + 1) // 2 * 2 + 9):
                dest = s
            elif dpid % 2 == 0:
                r1 = max(self.load[dpid][19], self.load[19][s2])
                r2 = max(self.load[dpid][20], self.load[20][s2])
                dest = 19 if r1 <= r2 else 20
            else:
                r1 = max(self.load[dpid][17], self.load[17][s1])
                r2 = max(self.load[dpid][18], self.load[18][s1])
                dest = 17 if r1 <= r2 else 18
        elif dpid in range(17, 19):
            dest = (s + 1) // 2 * 2 + 7
        elif dpid in range(19, 21):
            dest = (s + 1) // 2 * 2 + 8
        else:
            assert (0)
        self.load[dpid][dest] += 1
        self.load[dest][dpid] += 1
        return self.adjacency[dpid][dest]

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        print("switch_features_handler is called")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # students fill in
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        # print("match: ",msg.match)
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            _ipv4 = pkt.get_protocol(ipv4.ipv4)
            src_ip = _ipv4.src
            dst_ip = _ipv4.dst
        elif eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
        elif eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        else:
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.table.setdefault(dpid, {})

        self.logger.info("packet in %d %s %s %s", dpid, src, dst, in_port)
        info = (eth.ethertype, in_port, src_ip, dst_ip)

        if info in self.table[dpid]:
            out_port = self.table[dpid][info]
        else:
            out_port = self.get_port(dpid, dst_ip)
            self.table[dpid][info] = out_port
            if len(self.saved_path) <= 10:
                key = (src_ip, dst_ip)
                if key not in self.saved_path:
                    if len(self.saved_path) < 10:
                        self.saved_path.append(key)
                        print(eth.ethertype, src_ip, '->', dst_ip, ': ', dpid, in_port, '->', out_port)
                else:
                    print(eth.ethertype, src_ip, '->', dst_ip, ': ', dpid, in_port, '->', out_port)
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            match = parser.OFPMatch(eth_type=eth.ethertype, in_port=in_port, ipv4_src=src_ip, ipv4_dst=dst_ip)
        elif eth.ethertype == ether_types.ETH_TYPE_ARP:
            match = parser.OFPMatch(eth_type=eth.ethertype, in_port=in_port, arp_spa=src_ip, arp_tpa=dst_ip)
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

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        print(ev)
        switch = ev.switch.dp
        if switch.id not in self.switches:
            self.switches.append(switch.id)
            self.datapath_list[switch.id] = switch

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, ev):
        print(ev)
        switch = ev.switch.dp.id
        if switch in self.switches:
            self.switches.remove(switch)
            del self.datapath_list[switch]
            del self.adjacency[switch]

    # get adjacency matrix of fattree
    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        self.adjacency[s1.dpid][s2.dpid] = s1.port_no
        self.adjacency[s2.dpid][s1.dpid] = s2.port_no

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev):
        # s1 = ev.link.src
        # s2 = ev.link.dst
        # # Exception handling if switch already deleted
        # try:
        #     del self.adjacency[s1.dpid][s2.dpid]
        #     del self.adjacency[s2.dpid][s1.dpid]
        # except KeyError:
        #     pass
        pass
