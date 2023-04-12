#!usr/bin/python

import threading
import NodeFunction

udp_host = "localhost"        # Host IP
udp_port = 12345              # specified port to connect
source_ip = "0x1A"
source_mac = "N1"
router_port = 12348

node1 = NodeFunction.Node_Socket(udp_host, udp_port, source_ip, source_mac, router_port)

if __name__ == "__main__":
    x = threading.Thread(target=node1.receive_message)
    y = threading.Thread(target=node1.send_message)
    x.start()
    y.start()
  
