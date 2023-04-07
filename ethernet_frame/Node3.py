#!usr/bin/python

import socket
import threading
import logging 
import os
from time import sleep
from pytimedinput import timedInput

source_ip = "0x2B"
source_mac = "N3"
udp_host = '127.0.0.1'
arp_cache = {}

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((udp_host, 12347))

def arp_request_reply(ethernet_type, op_code, source_mac, destination_mac, source_ip, destination_ip, protocol, message_info, req_reply, recv_send, socket_name = None, port = None):
    print("***************************************************************")
    print("Address Resolution Protocol ({}) {}".format(req_reply, recv_send))
    # print("Source MAC address:", source_mac)            # e.g: N1
    # print("Destination MAC address:", destination_mac)  # e.g: R1
    # print("Source IP address:", source_ip)              # e.g: 0x1A
    # print("Destination IP address:", destination_ip)    # e.g: 0x2B
    # print("=== Makes routing decision ===")
    # print("***************************************************************")

    if (recv_send == "sent"):
        arp_request_reply = bytes.fromhex(ethernet_type[2:]) + op_code.encode() + source_mac.encode() + destination_mac.encode() + bytes.fromhex(source_ip[2:]) + bytes.fromhex(destination_ip[2:]) + protocol.encode() + message_info.encode()
        socket_name.sendto(arp_request_reply, ('127.0.0.1', port))

def send_ethernet_frame(ethernet_type, source_mac, destination_mac, source_ip, destination_ip, protocol, message_info, socket_name, port):
    ethernet_frame = bytes.fromhex(ethernet_type[2:]) + source_mac.encode() + destination_mac.encode() + bytes.fromhex(source_ip[2:]) + bytes.fromhex(destination_ip[2:]) + protocol.encode() + message_info.encode()
    print("***** Sending Message ***** ", ethernet_frame)
    socket_name.sendto(ethernet_frame, ('127.0.0.1', port))

def receive_message():
    while True:
        # Receive a message from the router
        data, addr = sock.recvfrom(1024)
        decoded_arp_request_recv = data.decode('ascii')

        if (bytes.fromhex("0x0806"[2:]) in data):
            ether_type = "0x0806"
            op_code_recv = decoded_arp_request_recv[2]
            source_mac_recv = decoded_arp_request_recv[3:5]

            if ("FF:FF:FF:FF:FF:FF" in decoded_arp_request_recv):
                source_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[22]))
                destination_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[23]))
                protocol = decoded_arp_request_recv[24]
                message_info = decoded_arp_request_recv[25:]                            

            arp_request_reply(ether_type, op_code_recv, source_mac_recv, "FF:FF:FF:FF:FF:FF", source_ip_recv, destination_ip_recv, protocol, message_info, "request", "receive")

            # check if its intended recipent
            if (destination_ip_recv == source_ip and op_code_recv == "1"):
                op_code = "2"
                print(destination_ip_recv, "is at", source_mac)
                sleep(10)
                arp_request_reply(ether_type, op_code, source_mac, source_mac_recv, source_ip_recv, destination_ip_recv, protocol, message_info, "reply", "sent", sock, 12349)
            else:
                print("Not intended recipent")
                userText, timedOut = timedInput("Spoof? (Y/N): ", timeout=6)
                if(timedOut or userText == "N"):
                    print("Drop frame")
                else:
                    print("reply to router R2")
                    op_code = "2"
                    print(destination_ip_recv, "is at", source_mac)
                    arp_request_reply(ether_type, op_code, source_mac, source_mac_recv, source_ip_recv, destination_ip_recv, protocol, message_info, "reply", "sent", sock, 12349)

        if (bytes.fromhex("0x0800"[2:]) in data):
            print("Received message: ", decoded_arp_request_recv[10:])

            message = input("Enter message: ")
            message_len = len(message)
            message_info = str(message_len) + message

            ether_type = "0x0800"
            source_mac_recv = decoded_arp_request_recv[4:6]
            dest_mac_recv = decoded_arp_request_recv[2:4]
            source_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[6]))
            destination_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[7]))      
            protocol = "0"

            send_ethernet_frame(ether_type, source_mac_recv, dest_mac_recv, source_ip_recv, destination_ip_recv, protocol, message_info, sock, 12349)

if __name__ == "__main__":
    x = threading.Thread(target=receive_message)
    x.start()
