from scapy.all import *
import os

# find interface name

# https://scapy.readthedocs.io/en/latest/api/scapy.interfaces.html
# https://readthedocs.org/projects/scapy/downloads/pdf/latest/

try:
    sniff(count=1,filter="port 12346", iface='\\Device\\NPF_Loopback', prn=lambda x:x.show())
except(KeyboardInterrupt):
    os._exit(1)