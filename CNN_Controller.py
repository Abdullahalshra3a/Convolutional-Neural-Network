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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_5
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from math import log
import pandas as pd
from scipy.stats import entropy
window = []
counter = 0
class SimpleSwitch15(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_5.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch15, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

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

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def calculat_entropy(self):
           self.counter = 0
           src_list = [self.window[sub]['src'] for sub in range(len(self.window))]
           dst_list= [self.window[sub]['dst'] for sub in range(len(self.window))]
           src = pd.Series(src_list)
           dst = pd.Series(dst_list)  
           src = src.value_counts()
           dst = dst.value_counts()
           src_ent = 1 - (entropy(src,base = 2) / log(len(self.window),2))
           dst_ent = 1 - (entropy(dst,base = 2) / log(len(self.window),2))


           if src_ent > 0.5:#block src
              src_result = self.cnn_model()
              if src_result:
                 self.entropy_src(self.window)
                 return
                 
           elif dst_ent > 0.5:#block inport
              dst_result = self.cnn_model()
              if dst_result :
                 self.entropy_dst(self.window) 
                 return
           else:
             self.update_threshold()
             delete file.csv
           window.clear()

    def entropy_src(self, window):
                 max_src = max(set(src_list), key=src_list.count)
                 inport = [self.window[sub]['in_port'] for sub in range(len(self.window)) if self.window[sub]['src'] == max_src]
                 #block src
                 self.window = [self.window[sub] for sub in range(len(window)) if self.window[sub]['src'] != max_src]
                 src_list = [self.window[sub]['src'] for sub in range(len(self.window))]
                 src = pd.Series(src_list)
                 src = src.value_counts()
                 src_ent = 1 - (entropy(src,base = 2) / log(len(self.window),2))
                 if src_ent > 0.5:
                    self.entropy_src(self.window)

    def entropy_dst(self, window):
                 max_dst = max(set(dst_list), key=dst_list.count)
                 inport = [self.window[sub]['in_port'] for sub in range(len(self.window)) if self.window[sub]['dst'] == dst]
                 #block inport
                 self.window = [self.window[sub] for sub in range(len(window)) if self.window[sub]['dst'] != max_dst]
                 dst_list = [self.window[sub]['dst'] for sub in range(len(self.window))]
                 dst = pd.Series(dst_list)
                 dst = dst.value_counts()
                 dst_ent = 1 - (entropy(dst,base = 2) / log(len(self.window),2))
                 if dst_ent > 0.5:
                    self.entropy_dst(self.window)
 
        

       
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
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        
        #adding packet fatures to the window in order to calculate entropy
        self.counter = +1
        self.window[self.counter] = {'src': src, 'dst':dst, 'in_port':in_port}
        if self.counter >= 50:
           self.calculat_entropy()

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        match = parser.OFPMatch(in_port=in_port)

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  match=match, actions=actions, data=data)
        datapath.send_msg(out)
