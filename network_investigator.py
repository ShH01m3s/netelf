import sys
from scapy.all import *
from pcapy import open_offline, open_live
from impacket.ImpactDecoder import EthDecoder
import argparse
import re

src_ip = ""
dst_ip = ""
src_port = 0
dst_port = 0
src_ips = []
dst_ips = []
ips = set()

def find_str_in_pkt(data, search_string):
    data = r"\x17\x03\x03\x00\x1d\xc6?\xb3\xa0\xd6\x41\x12\x04\xdbL\ta\"[\xdd\xf5\xc16?\xa3^\x85\xbb\x85}\x93\x1fn\xed\x82".split("\\")
    result = ""

    for char in data:
        match = re.findall(r"x[a-f0-9]{2}", char)
        if not match or len(char) != 3:
            result += char
            continue
        else:
            try:
                result += bytes.fromhex(char.strip("x")).decode()
            except UnicodeDecodeError:
                result += char

    if search_string in result:
        return True

def check_if_port_open():
    sock= socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    result = sock.connect_ex((dst_ip,dst_port))

    if result==0:
        print("Port {} is open:".format(dst_port))
    else:
        print("Port {} is closed".format(dst_port))
    sock.close()

# send a packet to the specified IP, using the specified IP, port numbers, ack and seq numbers and flags.
def send_packet(dip, sip, sprt, dprt, a, s, fs):
    send(IP(dst=dip, src=sip)/TCP(dport=dprt, sport=sprt, ack=a, seq=s, flags=fs))

def find_all_ips(self, pcap_file):
        pcap = rdpcap(pcap_file)
        for pkt in pcap:
            try:
                ips.add(pkt[IP].src)
                ips.add(pkt[IP].dst)
            except IndexError:
                pass
        return ips

def find_packets_with_ip(self, pcap_file):
        pcap = rdpcap(pcap_file)
        for pkt in pcap:
            try:
                if pkt[IP].src == src_ip or pkt[IP].dst == dst_ip:
                    if pkt[]
                    print(pkt)
            except IndexError:
                pass

def read_packet_impacket(hdr, data):
        return EthDecoder()

def i_find_all_http_traffic():
    pcap = open_offline(pcap_file)
    pcap.loop(0, read_packet)



# find all http traffic from ip 192.168.1.65
def filter_http_traffic_offline():


