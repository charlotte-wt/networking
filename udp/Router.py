import socket

router2_ip = "0x21"

arp_table = {
    '0x1A': 'N1',
    '0x2A': 'N2',
    '0x2B': 'N3',
    '0x11': 'R1',
    '0x21': 'R2'
}

# Create a UDP socket
router_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to a specific IP address and port number
router_socket.bind(('127.0.0.1', 1234))

while True:
    # Receive a message from either node 1 or node 2
    ethernet_frame_recv, address = router_socket.recvfrom(1024)
    decoded_ethernet_frame_recv = ethernet_frame_recv.decode('ascii')
    print(f"Received message from {address}: {decoded_ethernet_frame_recv}")

    # Forward the message to the other node
    if address[1] == 2234:
        # Message came from Node 2, forward to No 3
        destination_ip = "0x2B"
        new_source_mac = arp_table.get(router2_ip)
        new_destination_mac = arp_table.get(destination_ip)
        new_ethernet_frame = bytes.fromhex(new_source_mac.encode('ascii').hex()) + bytes.fromhex(new_destination_mac.encode('ascii').hex()) + ethernet_frame_recv[4:]

        router_socket.sendto(new_ethernet_frame, ('127.0.0.1', 3234))
    elif address[1] == 3234:
        # Message came from node 3, forward to node 2
        destination_ip = "0x2A"
        new_source_mac = arp_table.get(router2_ip)
        new_destination_mac = arp_table.get(destination_ip)
        new_ethernet_frame = bytes.fromhex(new_source_mac.encode('ascii').hex()) + bytes.fromhex(new_destination_mac.encode('ascii').hex()) + ethernet_frame_recv[4:]

        router_socket.sendto(new_ethernet_frame, ('127.0.0.1', 2234))