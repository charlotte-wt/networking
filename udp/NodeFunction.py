#!usr/bin/python

import socket
import logging
import os
from time import sleep
from scapy.all import *

# import argparse

class Node_Socket:
    def __init__(self, udp_host, udp_port, source_ip, router_port):
        self.udp_host = udp_host
        self.udp_port = udp_port
        self.source_ip = source_ip
        self.router_port = router_port
        self.firewall = []
        self.protocol_num_array = [0,1,2,3,4,5,6,7]
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((udp_host, udp_port))

    def send_protocol(self):
        try:
            message = input("\nEnter the text message to send: ")
            destination_ip = ""
            if (self.source_ip == "0x1A"):
                destination_ip = input("Enter the IP of the clients to send the message to:\n1. 0x2A\n2. 0x2B\n")
            elif(self.source_ip == "0x2A"):
                destination_ip = input("Enter the IP of the clients to send the message to:\n1. 0x1A\n2. 0x2B\n")
            elif(self.source_ip == "0x2B"):
                destination_ip = input("Enter the IP of the clients to send the message to:\n1. 0x1A\n2. 0x2A\n")
            protocol = input("\nPlease enter the protocol of the packet (in an integer):\n0: ping protocol\n1: log protocol\n2: kill protocol\n")
            ethernet_header = ""
            IP_header = ""

            if(self.source_ip == "0x1A" and (destination_ip == "0x2A" or destination_ip == "0x2B")):
                IP_header = IP_header + self.source_ip + destination_ip
                # source_mac = server_mac
                # destination_mac = router_mac 
                # ethernet_header = ethernet_header + source_mac + destination_mac
                packet = IP_header + protocol + "0x{:02x}".format(len(message)) + message
            elif(self.source_ip == "0x2A" and (destination_ip == "0x1A" or destination_ip == "0x2B")):
                IP_header = IP_header + self.source_ip + destination_ip
                packet = IP_header + protocol + "0x{:02x}".format(len(message)) + message
            elif(self.source_ip == "0x2B" and (destination_ip == "0x1A" or destination_ip == "0x2A")):
                IP_header = IP_header + self.source_ip + destination_ip
                packet = IP_header + protocol + "0x{:02x}".format(len(message)) + message
            else:
                print("Wrong client IP inputted")

            # print("UDP target IP:", udp_host)
            # print("UDP target Port:", 12346)

         
            # Sending message to UDP server
            self.sock.sendto(packet.encode(), (self.udp_host, self.router_port))
        
        except(KeyboardInterrupt, EOFError, ValueError):
            self.error_handler()

    def firewall_config(self):
        try:
            print("\nConfiguring Firewall...")
            configuration = input("\nEnter the ip address to block: ")
            self.firewall.append(configuration)
            print("IP address blocked: " + configuration)
            print("Firewall configured successfully!\n")
        except(KeyboardInterrupt, EOFError, ValueError):
            self.error_handler()



    def ip_spoofing(self):
        spoof_ip = ""
        if (self.source_ip == "0x1A"):
            spoof_ip = input("Enter the IP of the clients to send the message to:\n1. 0x2A\n2. 0x2B\n")
        elif (self.source_ip== "0x2A"):
            spoof_ip = input("Enter the IP of the clients to send the message to:\n1. 0x1A\n2. 0x2B\n")
        elif (self.source_ip == "0x2B"):
            spoof_ip = input("Enter the IP of the clients to send the message to:\n1. 0x1A\n2. 0x2A\n")

        self.source_ip = spoof_ip


    def ip_sniffer(self):
        sniff_ip = ""
        if (self.source_ip == "0x1A"):
            sniff_ip = input("Enter the IP of the clients to send the message to:\n1. 0x2A\n2. 0x2B\n")
        elif (self.source_ip== "0x2A"):
            sniff_ip = input("Enter the IP of the clients to send the message to:\n1. 0x1A\n2. 0x2B\n")
        elif (self.source_ip == "0x2B"):
            sniff_ip = input("Enter the IP of the clients to send the message to:\n1. 0x1A\n2. 0x2A\n")

        num_packets = input("Enter the number of packets you would like to sniff")
        try:
            if (sniff_ip == "0x1A"):
                sniff(count=num_packets,filter="port 12345", iface='\\Device\\NPF_Loopback', prn=lambda x:x.show())
            elif (sniff_ip == "0x2A"):
                sniff(count=num_packets,filter="port 12346", iface='\\Device\\NPF_Loopback', prn=lambda x:x.show())
            elif (sniff_ip == "0x2B"):
                sniff(count=num_packets,filter="port 12347", iface='\\Device\\NPF_Loopback', prn=lambda x:x.show())
        except(KeyboardInterrupt):
            os._exit(1)
        



    # Receive message functions
        
    def received_protocol(self, received_packet):
        source_ip = received_packet[0:4]
        if(source_ip in self.firewall):
            print("Packet from " + source_ip + " blocked by firewall.")
            return

        destination_ip =  received_packet[4:8]
        protocol = received_packet[8:9]
        data_len = received_packet[9:13]
        message = received_packet[13:]
        to_print = "\nSource IP address: {source_ip}\nDestination IP address: {destination_ip} \
                \nProtocol: {protocol}\nDataLength: {data_len}\nMessage: {message}" \
                .format(source_ip=source_ip, destination_ip=destination_ip, protocol=protocol, data_len=data_len, message=message)

        print(to_print)
        print("***************************************************************")
        print("\nPlease enter the number of the action you want to perform:\n1. Send Protocol\n2. Configure Firewall\
            \n3. IP Spoofing\n4. Packet Sniffer\n5. TraceRoute\n6. Exit (Close Socket)\n\nInput: ", end="")

        protocol_num = int(protocol)
        if (protocol_num == 0):
            # ping
            new_destination_ip = source_ip
            new_source_ip = destination_ip
            new_protocol = "3"
            new_message = message
            new_packet = new_source_ip + new_destination_ip + new_protocol + "0x{:02x}".format(len(new_message)) + new_message

            if(new_source_ip == "0x2A" or new_source_ip == "0x2B"):
            # Sending message to UDP server
                self.sock.sendto(new_packet.encode(), (self.udp_host, 12349))
            elif(new_source_ip == "0x1A"):
                self.sock.sendto(new_packet.encode(), (self.udp_host, 12348))

        elif(protocol_num == 1):
            # log
            logging.basicConfig(filename="logs/node1.log", 
            format='%(asctime)s \n %(message)s', 
            filemode='w')
            logger=logging.getLogger() 
            logger.setLevel(logging.DEBUG) 
            logger.info(to_print) 
            # print(to_print)
            
        elif(protocol_num == 2):
            # kill
            print('\n[INFO]: Protocol 2 Received. Terminating..')
            self.sock.close()
            os._exit(1)
    
    def traceroute(self):
        address = int(input("\nWhich node would you like to ping?\n1. Node 2\n2. Node 3\n\n"))
        if address == 1:
            print(f"traceroute to Node 2 (0x2A), 3 hops max")
            sleep(0.2)
            print("\n1 Router1 (0x11)")
            sleep(0.6)
            print("2 Router2 (0x21)")
            sleep(0.4)
            print("3 Node 2 (0x2A)")
        elif address == 2:
            print(f"traceroute to Node 3 (0x2B), 3 hops max")
            sleep(0.2)
            print("\n1 Router1 (0x11)")
            sleep(0.6)
            print("2 Router2 (0x21)")
            sleep(0.4)
            print("3 Node 3 (0x2A)")
        else:
            print("Invalid Input!")


    # Main Thread functions

    def send_message(self):
        while True:
            try:
                sleep(0.2)
                prompt = int(input("\nPlease enter the number of the action you want to perform:\n1. Send Protocol\n2. Configure Firewall\
                    \n3. IP Spoofing\n4. Packet Sniffer\n5. TraceRoute\n6. Exit (Close Socket)\n\nInput: "))
                if(prompt == 1):
                    self.send_protocol()
                elif(prompt == 2): 
                    self.firewall_config()
                elif(prompt == 3):
                   self.ip_spoofing()
                elif(prompt == 4):
                    self.ip_sniffer()
                elif(prompt == 5):
                    self.traceroute()
                elif(prompt == 7):
                    print('\n[INFO]: Terminating..')
                    self.sock.close()
                    os._exit(1)
                else:
                    print("Invalid Input!")

            except(KeyboardInterrupt, EOFError, ValueError):
                self.error_handler()

    def receive_message(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(1024)  # receive data from client
                print("\n\nReceived Packet:", data.decode(), " from", addr)
                received_packet = data.decode()
                if(received_packet[8:9] in str(self.protocol_num_array[:3])):
                    self.received_protocol(received_packet)
            except(KeyboardInterrupt, EOFError, ValueError):
                self.error_handler()

    def error_handler(self):
        print('\n[INFO]: Terminating..')
        self.sock.close()
        os._exit(1)



