import argparse
import struct
import socket
import threading

arp_cache = []

source_ip = "0x1A"
source_mac = "N1"

# Create a UDP socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.bind(('127.0.0.1', 12345))

def arp_request(source_mac, destination_mac, source_ip, destination_ip, port):
    ethernet_type = "0x0806"
    op_code = "1"
    arp_request = bytes.fromhex(ethernet_type[2:]) + op_code.encode() + source_mac.encode() + destination_mac.encode() + bytes.fromhex(source_ip[2:]) + bytes.fromhex(destination_ip[2:])
    print("***************************************************************")
    print("Address Resolution Protocol (request)")
    print("Source MAC address:", source_mac)            # e.g: N1
    print("Destination MAC address:", destination_mac)  # e.g: R1
    print("Source IP address:", source_ip)              # e.g: 0x1A
    print("Destination IP address:", destination_ip)    # e.g: 0x2B
    print("=== Makes routing decision ===")
    print("***************************************************************")
    client_socket.sendto(arp_request, ('127.0.0.1', port))

def arp_reply_recv(ethernet_type, op_code, source_mac, destination_mac, source_ip, destination_ip):
    arp_reply = bytes.fromhex(ethernet_type[2:]) + op_code.encode() + source_mac.encode() + destination_mac.encode() + bytes.fromhex(source_ip[2:]) + bytes.fromhex(destination_ip[2:])
    print("***************************************************************")
    print("Address Resolution Protocol (reply) received")
    print("Source MAC address:", source_mac)            # e.g: N3
    print("Destination MAC address:", destination_mac)         # e.g: R2
    print("Source IP address:", source_ip)              # e.g: 0x1A
    print("Destination IP address:", destination_ip)    # e.g: 0x2B
    print("=== Makes routing decision ===")
    print("***************************************************************")
    # print(arp_reply)

def send_ethernet_frame(ethernet_type, source_mac, destination_mac, source_ip, destination_ip, message_len, message, socket_name, port):
    ethernet_frame = bytes.fromhex(ethernet_type[2:]) + source_mac.encode() + destination_mac.encode() + bytes.fromhex(source_ip[2:]) + bytes.fromhex(destination_ip[2:]) + struct.pack('B', int(message_len)) + message.encode()
    print("***** Sending Message ***** ", ethernet_frame)
    socket_name.sendto(ethernet_frame, ('127.0.0.1', port))

if __name__ == "__main__":
    destination_mac = "R1"
    message = input("\nEnter the text message to send: ")
    message_len = len(message)
    destination_ip = input("Enter the IP of the clients to send the message to:\n1. 0x2A\n2. 0x2B\n")

    y = threading.Thread(target=arp_request(source_mac, destination_mac, source_ip, destination_ip, 12348))
    y.start()
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

            if (source_ip_recv == source_ip and op_code_recv == "2"):
                arp_reply_recv(ether_type, op_code_recv, source_mac_recv, source_mac, source_ip_recv, destination_ip_recv)
                ether_type = "0x0800"
                destination_mac = source_mac_recv

                # message = input("Enter message: ")
                # message_len = len(message)
                send_ethernet_frame(ether_type, source_mac, destination_mac, source_ip_recv, destination_ip_recv, message_len, message, client_socket, 12348)

        if (bytes.fromhex("0x0800"[2:]) in data):
            print("Received message: ", decoded_arp_request_recv[9:])

            message = input("Enter message: ")
            message_len = len(message)
            
            ether_type = "0x0800"
            source_mac_recv = decoded_arp_request_recv[4:6]
            dest_mac_recv = decoded_arp_request_recv[2:4]
            source_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[6]))
            destination_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[7]))      
            send_ethernet_frame(ether_type, source_mac_recv, dest_mac_recv, source_ip_recv, destination_ip_recv, message_len, message, client_socket, 12348)



