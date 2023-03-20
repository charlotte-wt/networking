import argparse
import struct
import socket

arp_cache = []

source_ip = "0x2B"
source_mac = "N3"

router1_ip = "0x11"
router2_ip = "0x21"

import argparse

# Set up the command line arguments
parser = argparse.ArgumentParser()
parser.add_argument('--ping', type=str)
parser.add_argument('--arp-a', action='store_true', help="Dispay ARP table")

# Create a UDP socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.bind(('127.0.0.1', 3234))
        
# Parse the command line arguments
args = parser.parse_args()

if args.arp_a:
    if (len(arp_cache) == 0) :
        print("No ARP Entries Found")
    else:
        print(arp_cache)

elif (args.ping):
    destination_ip = args.ping
    destination_mac = "FF:FF:FF:FF:FF:FF"

    if (destination_ip not in arp_cache):
        # Create a UDP socket
        ether_type = "0x0806"
        arp_request = bytes.fromhex(ether_type[2:]) + bytes.fromhex(source_mac.encode('ascii').hex()) + bytes.fromhex(source_ip[2:]) + bytes.fromhex(destination_ip[2:]) + destination_mac.encode()
        
        # send a response message to the sender
        client_socket.sendto(arp_request, ('127.0.0.1', 1234))
        print("ARP Request sent from Node 3:", arp_request)
        
        while True:
        # receive data from the socket
            data, address = client_socket.recvfrom(1024)
            decoded_data = data.decode('ascii')

            if (bytes.fromhex("0x0806"[2:]) in data):
                source_mac_recv = decoded_data[2:4]
                destination_mac = source_mac_recv

                # add mac into arp cache
                arp_cache.append(destination_mac)
                print("Connection Established")
                
                message = input("Node 3: ")
                message_len = len(message)
                
                ether_type = "0x0800"
                ether_frame = bytes.fromhex(ether_type[2:]) + bytes.fromhex(source_mac.encode('ascii').hex()) + bytes.fromhex(source_ip[2:]) + bytes.fromhex(destination_ip[2:]) + destination_mac.encode() + struct.pack('B', int(message_len)) + message.encode()
                client_socket.sendto(ether_frame, ('127.0.0.1', 1234))

            else:
                print(decoded_data[9:])
                message = input("Node 3: ")
                message_len = len(message)
                
                ether_type = "0x0800"
                ether_frame = bytes.fromhex(ether_type[2:]) + bytes.fromhex(source_mac.encode('ascii').hex()) + bytes.fromhex(source_ip[2:]) + bytes.fromhex(destination_ip[2:]) + destination_mac.encode() + struct.pack('B', int(message_len)) + message.encode()
                client_socket.sendto(ether_frame, ('127.0.0.1', 1234))

else:
    while True:
        # Receive a message from the router
        response, _ = client_socket.recvfrom(1024)
        decoded_arp_request_recv = response.decode('ascii')

        source_mac_recv = decoded_arp_request_recv[2:4]
        source_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[4]))
        destination_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[5]))

        if (bytes.fromhex("0x0806"[2:]) in response):
            if (destination_ip_recv == source_ip):
                print(f"ARP Request recevied from Router: {response.decode()}")
                ether_type = "0x0806"
                arp_reply = bytes.fromhex(ether_type[2:]) + bytes.fromhex(source_mac.encode('ascii').hex()) + bytes.fromhex(source_ip[2:]) + bytes.fromhex(source_ip_recv[2:]) + source_mac_recv.encode()
                print(f"ARP Reply: {arp_reply}")
                client_socket.sendto(arp_reply, ('127.0.0.1', 1234))
            else:
                print("dropping frame")

        else:
            print(decoded_arp_request_recv[9:])
            message = input("Node 3: ")
            message_len = len(message)
            
            ether_type = "0x0800"
            ether_frame = bytes.fromhex(ether_type[2:]) + bytes.fromhex(source_mac.encode('ascii').hex()) + bytes.fromhex(source_ip[2:]) + bytes.fromhex(source_ip_recv[2:]) + source_mac_recv.encode() + struct.pack('B', int(message_len)) + message.encode()
            client_socket.sendto(ether_frame, ('127.0.0.1', 1234))
        

