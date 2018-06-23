# Python code for Mirai Bot Detection Algorithm
# Author: Ayush Kumar
# Organization: National University of Singapore

import socket, sys
import numpy as np
from struct import *

# create an INET, STREAMing socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error as msg:
    print ('Socket could not be created. Error Code : %s', msg)
    sys.exit()

s_addr_list = [None] * 100
# Create sampling matrix
samp_mat = np.array([[1,0,0,0],
            [0,1,0,0],
            [0,0,1,0]]) 
dev_buf = [[None] * 100 for i in range(100)]

def get_tcp_syn_flag(tcp_header):
    syn = tcp_header & 0x002
    syn >>=1
    return syn

# receive a packet
while True:
    packet = s.recvfrom(65565)

    # packet string from tuple
    packet = packet[0]

    # take first 20 characters for the ip header
    ip_header = packet[0:20]

    # now unpack them :)
    iph = unpack('!BBHHHBBH4s4s', ip_header)

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF

    iph_length = ihl * 4

    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])

    if s_addr not in s_addr_list:
        s_addr_list.append(s_addr)  # s_addr shouldn't be duplicated

    ## add packet to device buffer
    dev_buf[s_addr_list.index(s_addr)].append(packet)

t=0
bot_detected=[False]*len(s_addr_list)

while True:
    sel_dev_set = np.nonzero(samp_mat[:,t]==1)[0] # correct this if necessary
    for i in range(len(sel_dev_set)):
        sampled_pkts = dev_buf[sel_dev_set[i]]
        for j in range(len(sampled_pkts)):
            tcp_header = sampled_pkts[j][iph_length:iph_length + 20]

            # now unpack them :)
            tcph = unpack('!HHLLBBHHH', tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]
            tcp_flag = get_tcp_syn_flag(tcph[5])

            if (tcp_flag == SYN) and (dest_port == 23 or dest_port == 2323):
                bot_detected[sel_dev_set[i]] = True
    t=t+1