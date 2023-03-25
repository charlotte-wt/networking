import argparse
import struct
import socket

arp_cache = []

source_ip = "0x2B"
source_mac = "N3"

# Create a UDP socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.bind(('127.0.0.1', 12347))

def arp_request_recv(ethernet_type, op_code, source_mac, destination_mac, source_ip, destination_ip):
    arp_request = bytes.fromhex(ethernet_type[2:]) + op_code.encode() + source_mac.encode() + destination_mac.encode() + bytes.fromhex(source_ip[2:]) + bytes.fromhex(destination_ip[2:])
    print("***************************************************************")
    print("Address Resolution Protocol (request) received")
    print("Source MAC address:", source_mac)            # e.g: N1
    print("Destination MAC address:", destination_mac)  # e.g: R1
    print("Source IP address:", source_ip)              # e.g: 0x1A
    print("Destination IP address:", destination_ip)    # e.g: 0x2B
    print("=== Makes routing decision ===")
    print("***************************************************************")
    # print(arp_request)

def arp_request_sent(ethernet_type, op_code, source_mac, destination_mac, source_ip, destination_ip, socket_name, port):
    print("***************************************************************")
    print("Address Resolution Protocol (request) sent")
    print("Source MAC address:", source_mac)            # e.g: N1
    print("Destination MAC address:", destination_mac)  # e.g: R1
    print("Source IP address:", source_ip)              # e.g: 0x1A
    print("Destination IP address:", destination_ip)    # e.g: 0x2B
    print("=== Makes routing decision ===")
    print("***************************************************************")
    arp_request = bytes.fromhex(ethernet_type[2:]) + op_code.encode() + source_mac.encode() + destination_mac.encode() + bytes.fromhex(source_ip[2:]) + bytes.fromhex(destination_ip[2:])
    # print(arp_request)
    socket_name.sendto(arp_request, ('127.0.0.1', port))

def arp_reply_sent(ethernet_type, op_code, source_mac, destination_mac, source_ip, destination_ip, socket_name, port):
    print("***************************************************************")
    print("Address Resolution Protocol (reply) sent")
    print("Source MAC address:", source_mac)            # e.g: N1
    print("Destination MAC address:", destination_mac)  # e.g: R1
    print("Source IP address:", source_ip)              # e.g: 0x1A
    print("Destination IP address:", destination_ip)    # e.g: 0x2B
    print("=== Makes routing decision ===")
    print("***************************************************************")
    arp_reply = bytes.fromhex(ethernet_type[2:]) + op_code.encode() + source_mac.encode() + destination_mac.encode() + bytes.fromhex(source_ip[2:]) + bytes.fromhex(destination_ip[2:])
    # print(arp_reply)
    socket_name.sendto(arp_reply, ('127.0.0.1', port))

def recv_ethernet_frame(source_mac, destination_mac, source_ip, destination_ip):
    print("***************************************************************")
    print("Ethernet frame received")
    print("Source MAC address:", source_mac)            # e.g: N1
    print("Destination MAC address:", destination_mac)  # e.g: R1
    print("Source IP address:", source_ip)              # e.g: 0x1A
    print("Destination IP address:", destination_ip)    # e.g: 0x2B
    print("=== Makes routing decision ===")
    print("***************************************************************")

def send_ethernet_frame(ethernet_type, source_mac, destination_mac, source_ip, destination_ip, message_len, message, socket_name, port):
    ethernet_frame = bytes.fromhex(ethernet_type[2:]) + source_mac.encode() + destination_mac.encode() + bytes.fromhex(source_ip[2:]) + bytes.fromhex(destination_ip[2:]) + struct.pack('B', int(message_len)) + message.encode()
    print("***** Sending Message ***** ", ethernet_frame)
    socket_name.sendto(ethernet_frame, ('127.0.0.1', port))

while True:
    # Receive a message from the router
    data, addr = client_socket.recvfrom(1024)
    decoded_arp_request_recv = data.decode('ascii')
    
    if (bytes.fromhex("0x0806"[2:]) in data):
        ether_type = "0x0806"
        op_code_recv = decoded_arp_request_recv[2]
        source_mac_recv = decoded_arp_request_recv[3:5]
        source_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[-2]))
        destination_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[-1]))
        arp_request_recv(ether_type, op_code_recv, source_mac_recv, "FF:FF:FF:FF:FF:FF", source_ip_recv, destination_ip_recv)

        # check if its intended recipent
        if (destination_ip_recv == source_ip and op_code_recv == "1"):
            op_code = "2"
            arp_reply_sent(ether_type, op_code, source_mac, source_mac_recv, source_ip_recv, destination_ip_recv, client_socket, 12349)
            print(destination_ip_recv, "is at", source_mac)
        else:
            print("Drop frame")
            
    if (bytes.fromhex("0x0800"[2:]) in data):
        print("Received message: ", decoded_arp_request_recv[9:])

        message = input("Enter message: ")
        message_len = len(message)
        
        ether_type = "0x0800"
        source_mac_recv = decoded_arp_request_recv[4:6]
        dest_mac_recv = decoded_arp_request_recv[2:4]
        source_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[6]))
        destination_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[7]))      
        send_ethernet_frame(ether_type, source_mac_recv, dest_mac_recv, source_ip_recv, destination_ip_recv, message_len, message, client_socket, 12349)
