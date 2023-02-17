import socket
import time

# set up a port in the router to receive packets
router = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
router.bind(("localhost", 8100))

# set up a port in the router to send packets 
router_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
router_send.bind(("localhost", 8200))

# router MAC address just for simulation purposes
router_mac = "R1"

# the server binding tuple
server = ("localhost", 8000)


# Procedure:
# 1. Let the clients come online.
# 2. Establish a connection to the server
# 3. Receive a very simple packet from the server
# 4. Strip the ethernet header from the received packet
# 5. Create a new ethernet header
# 6. Route the packet to the concerned  client

#####################################################################
# generate the ARP table. In a future version, we can have an automatic ARP table update, via different ports on each clients.




node2_ip = "0x2A"
node2_mac = "N2"
node3_ip = "0x2B"
node3_mac = "N3"


# accept the client connections
router_send.listen(4)

node2 = None
node3 = None

while (node2 == None or node3 == None):
    client, address = router_send.accept()
    
    if(node2 == None):
        node2 = client
        print("Node 1 is online")
    
    elif(node3 == None):
        node3 = client
        print("Node 2 is online")


arp_table_socket = {node2_ip : node2, node3_ip : node3}
arp_table_mac = {node2_ip : node2_mac, node3_ip : node3_mac}

#####################################################################


router.connect(server) # establish connection to the server


while True:

    received_message = router.recv(1024)
    received_message =  received_message.decode("utf-8")
    
    # several parts of the message being dissected
    # source_mac = received_message[0:2]
    # destination_mac = received_message[2:4]
    source_ip = received_message[0:4]
    destination_ip =  received_message[4:8]
    protocol = received_message[8:9]
    data_len = received_message[9:13]
    message = received_message[13:]

    # print("\nThe packet received:\n Source MAC address: {source_mac}, Destination MAC address: {destination_mac}".format(source_mac=source_mac, destination_mac=destination_mac))
    print("\nThe packet received:\nSource IP address: {source_ip}\nDestination IP address: {destination_ip}".format(source_ip=source_ip, destination_ip=destination_ip))
    print("\nProtocol: {protocol}".format(protocol=protocol))
    print("\nDataLength: " + data_len)
    print("\nMessage: " + message)
    print("***************************************************************")
    
    # ethernet_header = router_mac + arp_table_mac[destination_ip]
    IP_header = source_ip + destination_ip
    packet = IP_header + protocol + data_len + message
    
    destination_socket = arp_table_socket[destination_ip]
    
    destination_socket.send(bytes(packet, "utf-8"))
    time.sleep(2)