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
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib import pcaplib
from shutil import copyfile
import os
from math import log
import pandas as pd
from scipy.stats import entropy


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    window_size = 90
    counter = 0
    src_threshold = 1
    dst_thrshold = 1
    pktcounter = 0
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.window = [0] * self.window_size
        #os.system("sudo cicflowmeter -i lo -c flows.csv")
        self.pcap_writer = pcaplib.Writer(open('mypcap.pcap', 'wb'))

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

        # Dump the packet data into PCAP file
        #self.pcap_writer.write_pkt(ev.msg.data)
        if pkt.get_protocol(ipv4.ipv4):
           self.pcap_writer.write_pkt(ev.msg.data)

        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        # Dump the packet data into PCAP file
        
        self.pktcounter =self.pktcounter+1
        print ("lf.counter =", self.pktcounter)
        #if self.pktcounter == 10:
         # copyfile('mypcap.pcap', 'mypcap1.pcap')
         # os.remove("mypcap.pcap")
         # self.pcap_writer = pcaplib.Writer(open('mypcap.pcap', 'wb'))
        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        #adding packet fatures to the window in order to calculate entropy

        self.window[self.counter] = {'src': src, 'dst':dst, 'in_port':in_port}#src and dst are sensitive fields of the entropy
        self.counter = +1
        if self.counter >= self.window_size:
           self.calculat_entropy()

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
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

    def calculat_entropy(self):
           window_copy = self.window
           self.counter = 0
           src_list = [window_copy[sub]['src'] for sub in range(len(window_copy))]
           dst_list= [window_copy[sub]['dst'] for sub in range(len(window_copy))]
           src = pd.Series(src_list)
           dst = pd.Series(dst_list)  
           src = src.value_counts()
           dst = dst.value_counts()
           src_ent = 1 - (entropy(src,base = 2) / log(len(window_copy),2))
           dst_ent = 1 - (entropy(dst,base = 2) / log(len(window_copy),2))


           if src_ent > self.src_threshold:#block src
              src_result = self.cnn_model()
              if src_result:
                 self.entropy_src(window_copy, src_list)
                 return
                 
           elif dst_ent > self.dst_threshold:#block inport
              dst_result = self.cnn_model()
              if dst_result :
                 self.entropy_dst(window_copy, dst_list) 
                 return
           else:
             self.src_threshold = (log(len(self.window),2) + src_ent ) * 0.5
             self.dst_threshold = (log(len(self.window),2) + dst_ent ) * 0.5
             os.remove('flows.csv')
             self.window = [0] * self.window_size

    def entropy_src(self, window_copy, src_list):
                 max_src = max(set(src_list), key=src_list.count)
                 inport = [window_copy[sub]['in_port'] for sub in range(len(window_copy)) if window_copy[sub]['src'] == max_src]
                 #block src
                 window_copy = [window_copy[sub] for sub in range(len(window_copy)) if window_copy[sub]['src'] != max_src]
                 src_list = [window_copy[sub]['src'] for sub in range(len(window_copy))]
                 src = pd.Series(src_list)
                 src = src.value_counts()
                 src_ent = 1 - (entropy(src,base = 2) / log(len(window_copy),2))
                 if src_ent > self.src_threshold:
                    self.entropy_src(window_copy, src_list)
                 self.window = [0] * self.window_size

    def entropy_dst(self, window_copy, dst_list):
                 max_dst = max(set(dst_list), key=dst_list.count)
                 inport = [window_copy[sub]['in_port'] for sub in range(len(window_copy)) if window_copy[sub]['dst'] == dst]
                 #block inport
                 window_copy = [window_copy[sub] for sub in range(len(window_copy)) if window_copy[sub]['dst'] != max_dst]
                 dst_list = [window_copy[sub]['dst'] for sub in range(len(window_copy))]
                 dst = pd.Series(dst_list)
                 dst = dst.value_counts()
                 dst_ent = 1 - (entropy(dst,base = 2) / log(len(window_copy),2))
                 if dst_ent > self.dst_threshold:
                    self.entropy_dst(window_copy, dst_list)
                 self.window = [0] * self.window_size
