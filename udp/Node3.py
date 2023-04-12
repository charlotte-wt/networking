#!usr/bin/python

import threading
import NodeFunction

udp_host = "localhost"		# Host IP
udp_port = 12347			# specified port to connect
source_ip = "0x2B"
source_mac = "N3"
router_port = 12349

node2 = NodeFunction.Node_Socket(udp_host, udp_port, source_ip, source_mac, router_port)

if __name__ == "__main__":
    x = threading.Thread(target=node2.receive_message)
    y = threading.Thread(target=node2.send_message)
    x.start()
    y.start()