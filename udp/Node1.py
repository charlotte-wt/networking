#!usr/bin/python

import socket
import threading
import logging 
import os
from time import sleep

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)      # For UDP

udp_host = "localhost"        # Host IP
udp_port = 12345              # specified port to connect
source_ip = "0x1A"

# print type(sock) ============> 'type' can be used to see type
# of any variable ('sock' here)

sock.bind((udp_host, udp_port))

firewall = []

protocol_num_array = [0,1,2,3,4,5,6,7]

# Send message functions

def send_protocol():
    try:
        message = input("\nEnter the text message to send: ")
        destination_ip = input("Enter the IP of the clients to send the message to:\n1. 0x2A\n2. 0x2B\n")
        protocol = input("\nPlease enter the protocol of the packet (in an integer):\n0: ping protocol\n1: log protocol\n2: kill protocol\n")
        ethernet_header = ""
        IP_header = ""

        if(destination_ip == "0x2A" or destination_ip == "0x2B"):
            IP_header = IP_header + source_ip + destination_ip
            # source_mac = server_mac
            # destination_mac = router_mac 
            # ethernet_header = ethernet_header + source_mac + destination_mac
            packet = IP_header + protocol + "0x{:02x}".format(len(message)) + message
        else:
            print("Wrong client IP inputted")

        # print("UDP target IP:", udp_host)
        # print("UDP target Port:", 12346)

        if(destination_ip == "0x2A" or destination_ip == "0x2B"):
            # Sending message to UDP server
            sock.sendto(packet.encode(), (udp_host, 12348))
    
    except(KeyboardInterrupt, EOFError, ValueError):
        error_handler()

def firewall_config():
    try:
        print("\nConfiguring Firewall...")
        configuration = input("\nEnter the ip address to block: ")
        firewall.append(configuration)
        print("IP address blocked: " + configuration)
        print("Firewall configured successfully!\n")
    except(KeyboardInterrupt, EOFError, ValueError):
        error_handler()


# Receive message functions
    
def received_protocol(received_packet):
    source_ip = received_packet[0:4]
    if(source_ip in firewall):
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
    print("\nPlease enter the number of the action you want to perform:\n1. Send Protocol\n2. Configure Firewall \
                            \n3. IP Spoofing\n4. IP Filter\n5. Packet Sniffer\n6. Exit (Close Socket)\n\nInput: ", end="")

    protocol_num = int(protocol)
    if (protocol_num == 0):
        # ping
        new_destination_ip = source_ip
        new_source_ip = destination_ip
        new_protocol = "3"
        new_message = received_packet
        new_packet = new_source_ip + new_destination_ip + new_protocol + "0x{:02x}".format(len(new_message)) + new_message

        if(new_destination_ip == "0x2A" or new_destination_ip == "0x2B"):
        # Sending message to UDP server
            sock.sendto(new_packet.encode(), (udp_host, 12348))

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
        sock.close()
        os._exit(1)


# Main Thread functions

def send_message():
    while True:
        try:
            sleep(0.2)
            prompt = int(input("\nPlease enter the number of the action you want to perform:\n1. Send Protocol\n2. Configure Firewall \
                            \n3. IP Spoofing\n4. IP Filter\n5. Packet Sniffer\n6. Exit (Close Socket)\n\nInput: "))
            if(prompt == 1):
                send_protocol()
            elif(prompt == 2): 
                firewall_config()
            elif(prompt == 6):
                print('\n[INFO]: Terminating..')
                sock.close()
                os._exit(1)
            else:
                print("Invalid Input!")

        except(KeyboardInterrupt, EOFError, ValueError):
            error_handler()

def receive_message():
    while True:
        try:
            data, addr = sock.recvfrom(1024)  # receive data from client
            print("\n\nReceived Packet:", data.decode(), " from", addr)
            received_packet = data.decode()
            if(received_packet[8:9] in str(protocol_num_array[:3])):
                received_protocol(received_packet)
        except(KeyboardInterrupt, EOFError, ValueError):
            error_handler()

def error_handler():
    print('\n[INFO]: Terminating..')
    sock.close()
    os._exit(1)

if __name__ == "__main__":
    x = threading.Thread(target=receive_message)
    y = threading.Thread(target=send_message)
    x.start()
    y.start()
  
