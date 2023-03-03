import socket
import struct

source_ip = "0x2B"
destination_ip = "0x2A"
router_ip = "0x21"

arp_table = {
    '0x1A': 'N1',
    '0x2A': 'N2',
    '0x2B': 'N3',
    '0x11': 'R1',
    '0x21': 'R2'
}

# Create a UDP socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# Bind the socket to a specific IP address and port number
client_socket.bind(('127.0.0.1', 3234))

while True:
    # Receive a message from the router
    response, _ = client_socket.recvfrom(1024)
    print(f"Client 2: {response.decode()[7:]}")

    # Send a message to the router
    message = input("Client 3: ")
    message_len = len(message)

    ip_packet = bytes.fromhex(source_ip[2:]) + bytes.fromhex(destination_ip[2:]) + struct.pack('B', int(message_len)) + message.encode()

    # to create the ethernet frame
    source_mac = arp_table.get(source_ip)
    destination_mac = arp_table.get(router_ip)
    ethernet_frame = bytes.fromhex(source_mac.encode('ascii').hex()) + bytes.fromhex(destination_mac.encode('ascii').hex()) + ip_packet

    client_socket.sendto(ethernet_frame, ('127.0.0.1', 1234))