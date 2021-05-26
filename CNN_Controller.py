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
from shutil import copyfile, move
from scapy.all import wrpcap, rdpcap
import os,sys, signal
from math import log
import pandas as pd
from scipy.stats import entropy
from subprocess import Popen, call, check_output
import time, psutil
from tensorflow.keras.models import  load_model
import threading 


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    Data_Path = {}
    Flowcounter = {}
    Memory = []
    CPU = []
    Entropy_src = []
    Entropy_dst = []
    Entropy_thresholdsrc = []
    Entropy_thresholddst = []
    window_size = 50
    counter = 0
    src_threshold = log(50,2)
    dst_threshold = log(50,2)
    n = 0
    src_ent = 0
    dst_ent = 0
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.window = [0] * self.window_size
        self.r1 = Popen('printf "0777743843\n" | sudo -S  ./CICFlowMeter/try_me.sh &', shell=True, preexec_fn=os.setsid)
        
        

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self.Data_Path[dpid]= datapath
        self.Flowcounter.setdefault(dpid, 1)
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
        self.Flowcounter[datapath.id] += 1

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
  

        dpid = datapath.id #format(datapath.id, "d").zfill(16)

        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        #adding packet fatures to the window in order to calculate entropy
        if dpid == 101 and in_port > 1 :
           self.window[self.counter] = {'src': src, 'dst':dst, 'in_port':in_port}#src and dst are sensitive fields of the entropy
           self.counter += 1
           if self.counter >= self.window_size:
              exit = self.calculat_entropy(dpid)
              if exit:
                 return

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
        self.Flowcounter.setdefault(datapath.id, 1)
        self.Flowcounter[datapath.id] += 1
        
    def calculat_entropy(self, dpid):
           window_copy = self.window
           self.counter = 0
           src_list = [window_copy[sub]['src'] for sub in range(len(window_copy))]
           dst_list= [window_copy[sub]['dst'] for sub in range(len(window_copy))]
           src = pd.Series(src_list)
           dst = pd.Series(dst_list)  
           src = src.value_counts()
           dst = dst.value_counts()
           self.src_ent = entropy(src,base = 2) 
           self.dst_ent = entropy(dst,base = 2)
                     
           if self.src_ent > self.src_threshold:#block src
              src_result = self.cnn_model()
              if src_result:
                 self.entropy_src(dpid, window_copy, src_list)
                 return True
                 
           elif self.dst_ent > self.dst_threshold:#block inport
              dst_result = self.cnn_model()
              if dst_result :
                 self.entropy_dst(dpid, window_copy, dst_list) 
                 return True
           else:
             self.src_threshold = (log(self.window_size,2) + self.src_ent ) * 0.5
             self.dst_threshold = (log(self.window_size,2) + self.dst_ent ) * 0.5            
             self.window = [0] * self.window_size
             return False
    
    def entropy_src(self, dpid, window_copy, src_list):
                 max_src = max(set(src_list), key=src_list.count)
                 in_port = [window_copy[sub]['in_port'] for sub in range(len(window_copy)) if window_copy[sub]['src'] == max_src]
                 datapath = self.Data_Path[dpid]
                 parser = datapath.ofproto_parser
                 actions = []#block src or inport
                 print("inport = ", in_port)
                 match = parser.OFPMatch(in_port=in_port[0])
                 self.add_flow(datapath, 10, match, actions)
                 print ("blocked info", dpid, in_port)
                 window_copy = [window_copy[sub] for sub in range(len(window_copy)) if window_copy[sub]['src'] != max_src]
                 src_list = [window_copy[sub]['src'] for sub in range(len(window_copy))]
                 src = pd.Series(src_list)
                 src = src.value_counts()
                 self.src_ent = 1 - (entropy(src,base = 2) / log(len(window_copy),2))
                 if self.src_ent > self.src_threshold:
                    self.entropy_src(window_copy, src_list)
                 self.window = [0] * self.window_size
                 self.r1 = Popen('printf "0777743843\n" | sudo -S  ./CICFlowMeter/try_me.sh &', shell=True, preexec_fn=os.setsid)
    def cnn_model(self):
         result = False
         os.killpg(os.getpgid(self.r1.pid), signal.SIGTERM)  # Send the signal to all the process groups
         result = subprocess.check_output([sys.executable, "cnn1.py"])
         return result
         
    def entropy_dst(self, dpid, window_copy, dst_list):
                 max_dst = max(set(dst_list), key=dst_list.count)
                 in_port = [window_copy[sub]['in_port'] for sub in range(len(window_copy)) if window_copy[sub]['dst'] == dst]
                 datapath = self.Data_Path[dpid]
                 parser = datapath.ofproto_parser
                 actions = []#block src or inport
                 print("inport = ", in_port)
                 match = parser.OFPMatch(in_port=in_port[0])
                 self.add_flow(datapath, 10, match, actions)
                 window_copy = [window_copy[sub] for sub in range(len(window_copy)) if window_copy[sub]['dst'] != max_dst]
                 dst_list = [window_copy[sub]['dst'] for sub in range(len(window_copy))]
                 dst = pd.Series(dst_list)
                 dst = dst.value_counts()
                 self.dst_ent = 1 - (entropy(dst,base = 2) / log(len(window_copy),2))
                 if self.dst_ent > self.dst_threshold:
                    self.entropy_dst(window_copy, dst_list)
                 self.window = [0] * self.window_size
class ThreadingExample(SimpleSwitch13): 
    def __init__(self):
        t = threading.Thread(target= self.get_CpuMemory_usage, args=())
        t.setDaemon(True)
        t.start() 
                      
    def get_CpuMemory_usage(self):
        point = 0
        while True:
          pid = os.getpid()
          #print("PID =", pid)
          ps = psutil.Process(pid)
          cpuUse = ps.cpu_percent(interval=1)
          memoryUse = ps.memory_percent()
          point = point + 1
          self.CPU.append(cpuUse)
          self.Memory.append(memoryUse)
          Cpufile = open ('CpuUsage.txt', 'w')
          Cpufile.write(str(self.CPU))
          Cpufile.close
          Memoryfile = open ('memoryUsage.txt', 'w')
          Memoryfile.write(str(self.Memory))
          Memoryfile.close
          Entryfile = open ('Flowcounter.txt', 'w')
          Entryfile.write(str(self.Flowcounter))
          Entryfile.close
          
          Entsrcfile = open ('Entropy_src.txt', 'w')
          Entsrcfile.writelines(str(self.Entropy_src))
          Entsrcfile.close
          Thsrcfile = open ('Entropy_thresholdsrc.txt', 'w')
          Thsrcfile.writelines(str(self.Entropy_thresholdsrc))
          Thsrcfile.close
          
          Entdstfile = open ('Entropy_dst.txt', 'w')
          Entdstfile.writelines(str(self.Entropy_dst ))
          Entdstfile.close
          Thdstfile = open ('Entropy_thresholddst.txt', 'w')
          Thdstfile.writelines(str(self.Entropy_thresholddst))
          Thdstfile.close
          
          self.Entropy_src.append(self.src_ent)
          self.Entropy_dst.append(self.dst_ent)
          self.Entropy_thresholdsrc.append(self.src_threshold)
          self.Entropy_thresholddst.append(self.dst_threshold)
          time.sleep(3)
example = ThreadingExample()
