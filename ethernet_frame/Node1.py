#!usr/bin/python

import socket
import threading
import logging
import os
from time import sleep
from pytimedinput import timedInput
import struct

source_ip = "0x1A"
source_mac = "N1"
udp_host = '127.0.0.1'
arp_cache = {}
firewall = []

protocol_num_array = [0,1,2,3,4,5,6,7]

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((udp_host, 12345))

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
        # print(arp_request_reply)
        socket_name.sendto(arp_request_reply, ('127.0.0.1', port))

def send_ethernet_frame(ethernet_type, source_mac, destination_mac, source_ip, destination_ip, protocol, message_info, socket_name, port):
    ethernet_frame = bytes.fromhex(ethernet_type[2:]) + source_mac.encode() + destination_mac.encode() + bytes.fromhex(source_ip[2:]) + bytes.fromhex(destination_ip[2:]) + protocol.encode() + message_info.encode()
    print("***** Sending Message ***** ", ethernet_frame)
    socket_name.sendto(ethernet_frame, ('127.0.0.1', port))

def firewall_config():
    try:
        print("\nConfiguring Firewall...")
        configuration = input("\nEnter the ip address to block: ")
        firewall.append(configuration)
        print("IP address blocked: " + configuration)
        print("Firewall configured successfully!\n")
    except(KeyboardInterrupt, EOFError, ValueError):
        error_handler()



def start_console():
    print('console started')
    try:
        sleep(0.2)
        prompt = int(input("\nPlease enter the number of the action you want to perform:\n1. Send Protocol\n2. Configure Firewall \
                        \n3. IP Spoofing\n4. IP Filter\n5. Packet Sniffer\n6. Traceroute\n7. Exit (Close Socket)\n\nInput: "))
        if(prompt == 1):
            send_protocol()
        elif(prompt == 2): 
            firewall_config()
        # elif(prompt == 6):
        #     traceroute()
        elif(prompt == 7):
            print('\n[INFO]: Terminating..')
            sock.close()
            os._exit(1)
        else:
            print("Invalid Input!")

    except(KeyboardInterrupt, EOFError, ValueError):
        error_handler()

def send_protocol():
    print("pinging")

    try:
        message = input("\nEnter the text message to send: ")
        data_len = len(message)
        message_info = str(data_len) + message
        destination_ip = input("Enter the IP of the clients to send the message to:\n1. 0x2A\n2. 0x2B\n")
        protocol = input("\nPlease enter the protocol of the packet (in an integer):\n0: ping protocol\n1: log protocol\n2: kill protocol\n")
        # ethernet_header = ""
        IP_header = ""
        destination_mac = "R1"
        ether_type = "0x0806"
        op_code = "1"

        to_print = "\nSource MAC address: {source_mac}\nDestination MAC address: {destination_mac} \
                \nSource IP address: {source_ip}\nDestination IP address: {destination_ip} \
                \nProtocol: {protocol}\nDataLength: {data_len}\nMessage: {message}" \
                .format(source_mac= source_mac, destination_mac= destination_mac, source_ip=source_ip, destination_ip=destination_ip, protocol=protocol, data_len=data_len, message=message)
        
        print(to_print)
        print("***************************************************************")
        print("\nPlease enter the number of the action you want to perform:\n1. Send Protocol\n2. Configure Firewall \
                            \n3. IP Spoofing\n4. IP Filter\n5. Packet Sniffer\n6. Exit (Close Socket--)\n\nInput: ", end="")        
        if (protocol == "0"):
            if(destination_ip == "0x2A" or destination_ip == "0x2B") and len(arp_cache) == 0:
                arp_request_reply(ether_type, op_code, source_mac, destination_mac, source_ip, destination_ip, protocol, message_info, "request", "sent", sock, 12348)
            else:
                print("Wrong client IP inputted")

        elif(protocol == "1"):
            print("log")
            logging.basicConfig(filename="logs/node1.log", 
            format='%(asctime)s \n %(message)s', 
            filemode='w')
            logger=logging.getLogger() 
            logger.setLevel(logging.DEBUG) 
            logger.info(to_print)
            sock.close()
            os._exit(1)

        elif(protocol == "2"):
            print("kill")
            print('\n[INFO]: Protocol 2 Received. Terminating..')
            sock.close()
            os._exit(1)

    except(KeyboardInterrupt, EOFError, ValueError):
        error_handler()


def receive_message():
    while True:
        # Receive a message from the router
        data, addr = sock.recvfrom(1024)
        decoded_arp_request_recv = data.decode('ascii')
        print(data)

        if (bytes.fromhex("0x0806"[2:]) in data):
            ether_type = "0x0806"
            op_code_recv = decoded_arp_request_recv[2]
            source_mac_recv = decoded_arp_request_recv[3:5]
            source_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[7]))
            destination_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[8]))
            protocol = decoded_arp_request_recv[9]
            message_info = decoded_arp_request_recv[10:]

            if (source_ip_recv == source_ip and op_code_recv == "2"):
                arp_request_reply(ether_type, op_code_recv, source_mac_recv, source_mac, source_ip_recv, destination_ip_recv, protocol, message_info, "request", "receive")
                ether_type = "0x0800"
                destination_mac = source_mac_recv
                send_ethernet_frame(ether_type, source_mac, destination_mac, source_ip_recv, destination_ip_recv, protocol, message_info, sock, 12348)

        if (bytes.fromhex("0x0800"[2:]) in data):
            print("Received message: ", decoded_arp_request_recv[10:])

            message = input("Enter message: ")
            data_len = len(message)
            message_info = str(data_len) + message

            ether_type = "0x0800"
            source_mac_recv = decoded_arp_request_recv[4:6]
            dest_mac_recv = decoded_arp_request_recv[2:4]
            source_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[6]))
            destination_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[7]))
            protocol = "0"

            send_ethernet_frame(ether_type, source_mac_recv, dest_mac_recv, source_ip_recv, destination_ip_recv, protocol, message_info, sock, 12348)

def error_handler():
    print('\n[INFO]: Terminating..')
    sock.close()
    os._exit(1)

if __name__ == "__main__":
    x = threading.Thread(target=start_console)
    y = threading.Thread(target=receive_message)
    x.start()
    y.start()