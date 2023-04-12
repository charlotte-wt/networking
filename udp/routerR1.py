import socket
import threading
import os

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)      # For UDP

udp_host = "localhost"        # Host IP
udp_port = 12348              # specified port to connect
current_ip = "0x11"
router1_mac = "R1"

# print type(sock) ============> 'type' can be used to see type
# of any variable ('sock' here)

sock.bind((udp_host, udp_port))

node1_ip = "0x1A"
node1_mac = "N1"
node2_ip = "0x2A"
node2_mac = "N2"
node3_ip = "0x2B"
node3_mac = "N3"

port_ip_table = {}
port_mac_table = {}

firewall = {}

protocol_num_array = [0,1,2,3,4,5,6,7]

# arp_table_mac = {node2_ip : node2_mac, node3_ip : node3_mac}
arp_table = {}
router1_mac_table = {node1_mac:12345}

def received_protocol(received_message):
    source_ip = received_message[0:4]
    destination_ip =  received_message[4:8]
    protocol = received_message[8:9]
    data_len = received_message[9:13]
    message = received_message[13:]

    print("\nThe packet received:\nSource IP address: {source_ip}\nDestination IP address: {destination_ip}".format(source_ip=source_ip, destination_ip=destination_ip))
    print("\nProtocol: {protocol}".format(protocol=protocol))
    print("\nDataLength: " + data_len)
    print("\nMessage: " + message)
    print("***************************************************************")
    
    # ethernet_header = router_mac + arp_table_mac[destination_ip]
    IP_header = source_ip + destination_ip
    packet = IP_header + protocol + data_len + message
    if(destination_ip == "0x2A" or destination_ip == "0x2B"):
        # Sending message to UDP server
        sock.sendto(packet.encode(), (udp_host, 12349))
    if (destination_ip == "0x1A"):
        # if (destination_ip in arp_table):
        sock.sendto(packet.encode(), (udp_host, 12345))
        # else:
        #     # ARP Broadcasting Request if destination IP is not in ARP table
        #     print("Broadcasting arp request to all nodes in LAN 1")
        #     # print("router mac table",router1_mac_table.keys())
        #     message = "Who has ip address of " + destination_ip + "?"
        #     print("message: ", message)
        #     ethernet_type = "0x0806" # arp
        #     for i in router1_mac_table.keys():
        #         ethernet_frame = ethernet_type + router1_mac + i + message # i is the mac address of the node
        #         print(ethernet_frame)
        #         sock.sendto(ethernet_frame.encode(), (udp_host, router1_mac_table[i]))
            
        #     arp_reply, addr = sock.recvfrom(1024)
        #     arp_reply = arp_reply.decode()
        #     port_num = addr[1]
        #     print(arp_reply)
        #     arp_table[arp_reply[0:3]] = arp_reply[-2:]
        #     print("arp_table", arp_table)
        #     sock.sendto(packet.encode(), (udp_host, port_num))


# ARP Request/Reply Function

# def arp_request_reply(ethernet_type, op_code, source_mac, destination_mac, source_ip, destination_ip, protocol, message_info, req_reply, recv_send, socket_name = None, port = None):
#     print("***************************************************************")
#     print("Address Resolution Protocol ({}) {}".format(req_reply, recv_send))
#     print("Source MAC address:", source_mac)            # e.g: N1
#     print("Destination MAC address:", destination_mac)  # e.g: R1
#     print("Source IP address:", source_ip)              # e.g: 0x1A
#     print("Destination IP address:", destination_ip)    # e.g: 0x2B
#     print("=== Makes routing decision ===")
#     print("***************************************************************")

#     if (recv_send == "sent"):
#         arp_request_reply = bytes.fromhex(ethernet_type[2:]) + op_code.encode() + source_mac.encode() + destination_mac.encode() + bytes.fromhex(source_ip[2:]) + bytes.fromhex(destination_ip[2:]) + protocol.encode() + message_info.encode()
#         print(arp_request_reply)
#         socket_name.sendto(arp_request_reply, ('127.0.0.1', port))

# Main Function Thread 

def wait_client():
    while True:
        try:
            print("Waiting for client...")
            data, addr = sock.recvfrom(1024)  # receive data from client
            print("Received Messages:", data.decode(), " from", addr)
            data = data.decode()
            # if(data[8:9] in str(protocol_num_array[:3])):
            #     received_protocol(data)
            received_protocol(data)
           
        except(KeyboardInterrupt, EOFError):
            print('\n[INFO]: Terminating..')
            sock.close()
            os._exit(1)

def exit():
    input()
    if(KeyboardInterrupt, EOFError):
        print('\n[INFO]: Terminating..')
        sock.close()
        os._exit(1)

if __name__ == "__main__":
    x = threading.Thread(target=wait_client)
    y = threading.Thread(target=exit)
    x.start()
    y.start()