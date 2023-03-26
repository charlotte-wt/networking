import struct
import socket
import select
from tabulate import tabulate

router1_ip = "0x11"
router2_ip = "0x21"
router1_mac = "R1"
router2_mac = "R2"

# Define arp table
arp_table = []
arp_cache_R1 = {}
arp_cache_R2 = {}

# Create a UDP socket to receive from Node 1
external_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
external_sock.bind(('127.0.0.1', 12348))
external_sock.setblocking(0) # make the socket non-blocking

# Create a UDP socket to receive from Node 2 or 3
internal_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
internal_sock.bind(('127.0.0.1', 12349))
internal_sock.setblocking(0) # make the socket non-blocking

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
    print(arp_request)

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
    print(arp_request)
    socket_name.sendto(arp_request, ('127.0.0.1', port))

def arp_reply_recv(ethernet_type, op_code, source_mac, destination_mac, source_ip, destination_ip):
    arp_reply = bytes.fromhex(ethernet_type[2:]) + op_code.encode() + source_mac.encode() + destination_mac.encode() + bytes.fromhex(source_ip[2:]) + bytes.fromhex(destination_ip[2:])
    print("***************************************************************")
    print("Address Resolution Protocol (reply) received")
    print("Source MAC address:", source_mac)            # e.g: N3
    print("Destination MAC address:", destination_mac)  # e.g: R2
    print("Source IP address:", source_ip)              # e.g: 0x1A
    print("Destination IP address:", destination_ip)    # e.g: 0x2B
    print("=== Makes routing decision ===")
    print("***************************************************************")
    print(arp_reply)

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
    print(arp_reply)
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

def send_ethernet_frame(ethernet_type, source_mac, destination_mac, source_ip, destination_ip, data_payload, socket_name, port):
    print("***************************************************************")
    print("Ethernet frame sent")    
    print("Source MAC address:", source_mac)            # e.g: R1
    print("Destination MAC address:", destination_mac)  # e.g: R2
    print("Source IP address:", source_ip)              # e.g: 0x1A
    print("Destination IP address:", destination_ip)    # e.g: 0x2B
    print("=== Makes routing decision ===")
    print("***************************************************************")
    ethernet_frame = bytes.fromhex(ethernet_type[2:]) + source_mac.encode() + destination_mac.encode() + bytes.fromhex(source_ip_recv[2:]) + bytes.fromhex(destination_ip_recv[2:]) + data_payload
    print(ethernet_frame)
    socket_name.sendto(ethernet_frame, ('127.0.0.1', port))

def show_arp_table():
    columns = ['Internet Address', 'Physical Address']
    arp_cache_R1_list = list(arp_cache_R1.items())
    arp_cache_R2_list = list(arp_cache_R2.items())
    print("=== ARP table ===")
    print('Interface: ', router1_ip)
    print(tabulate(arp_cache_R1_list, headers=columns))
    print('Interface: ', router2_ip)
    print(tabulate(arp_cache_R2_list, headers=columns))

while True:
    # List of sockets to listen for incoming data
    sockets_list = [internal_sock, external_sock]

    # Use select to wait for incoming data on any of the sockets
    read_sockets, write_sockets, error_sockets = select.select(sockets_list, [], [])

    for sock in read_sockets:
        data, addr = sock.recvfrom(1024)
        decoded_arp_request_recv = data.decode('ascii')

        op_code_recv = decoded_arp_request_recv[2]
        source_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[-2]))
        destination_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[-1]))
        from_port = addr[1]
        # print(from_port)

        if (from_port == 12345):
            if (bytes.fromhex("0x0806"[2:]) in data):
                if (op_code_recv == "1"):
                    ether_type = "0x0806"
                    source_mac_recv = decoded_arp_request_recv[3:5]
                    dest_mac_recv = decoded_arp_request_recv[5:7]
                    arp_cache_R1[source_ip_recv] = source_mac_recv
                    arp_request_recv(ether_type, op_code_recv, source_mac_recv, dest_mac_recv, source_ip_recv, destination_ip_recv)

                    source_mac_recv = dest_mac_recv
                    dest_mac_recv = router2_mac
                    arp_request_sent(ether_type, op_code_recv, source_mac_recv, dest_mac_recv, source_ip_recv, destination_ip_recv, sock, 12348)
            
            if (bytes.fromhex("0x0800"[2:]) in data):
                source_mac_recv = decoded_arp_request_recv[2:4]
                dest_mac_recv = decoded_arp_request_recv[4:6]
                source_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[6]))
                destination_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[7]))
                recv_ethernet_frame(source_mac_recv, dest_mac_recv, source_ip_recv, destination_ip_recv)

                ether_type = "0x0800"
                source_mac_recv = dest_mac_recv
                dest_mac_recv = router2_mac
                data_payload = data[8:]
                send_ethernet_frame(ether_type, source_mac_recv, dest_mac_recv, source_ip_recv, destination_ip_recv, data_payload, sock, 12349)

        elif (from_port == 12348):
            if (bytes.fromhex("0x0806"[2:]) in data):
                if (op_code_recv == "1"):
                    ether_type = "0x0806"
                    source_mac_recv = decoded_arp_request_recv[3:5]
                    dest_mac_recv = decoded_arp_request_recv[5:7]
                    arp_request_recv(ether_type, op_code_recv, source_mac_recv, dest_mac_recv, source_ip_recv, destination_ip_recv)

                    if (destination_ip_recv not in arp_cache_R2.keys()):
                        source_mac_recv = dest_mac_recv
                        dest_mac_recv = "FF:FF:FF:FF:FF:FF"
                        print("Who has", destination_ip_recv, "?")
                        arp_request_sent(ether_type, op_code_recv, source_mac_recv, dest_mac_recv, source_ip_recv, destination_ip_recv, sock, 12346)
                        arp_request_sent(ether_type, op_code_recv, source_mac_recv, dest_mac_recv, source_ip_recv, destination_ip_recv, sock, 12347)
            
            if (bytes.fromhex("0x0800"[2:]) in data):
                source_mac_recv = decoded_arp_request_recv[2:4]
                dest_mac_recv = decoded_arp_request_recv[4:6]
                source_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[6]))
                destination_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[7]))                
                recv_ethernet_frame(source_mac_recv, dest_mac_recv, source_ip_recv, destination_ip_recv)

                ether_type = "0x0800"
                source_mac_recv = dest_mac_recv
                dest_mac_recv = arp_cache_R2.get(destination_ip_recv)
                data_payload = data[8:]
                send_ethernet_frame(ether_type, source_mac_recv, dest_mac_recv, source_ip_recv, destination_ip_recv, data_payload, sock, 12347 if dest_mac_recv == "N3" else 12346)

        elif (from_port == 12347):
            if (bytes.fromhex("0x0806"[2:]) in data):
                if (op_code_recv == "2"):
                    ether_type = "0x0806"
                    source_mac_recv = decoded_arp_request_recv[3:5]
                    dest_mac_recv = decoded_arp_request_recv[5:7]
                    arp_reply_recv(ether_type, op_code_recv, source_mac_recv, dest_mac_recv, source_ip_recv, destination_ip_recv)
                    arp_cache_R2[destination_ip_recv] = source_mac_recv

                    source_mac_recv = dest_mac_recv
                    dest_mac_recv = router1_mac                    
                    arp_reply_sent(ether_type, op_code_recv, source_mac_recv, dest_mac_recv, source_ip_recv, destination_ip_recv, sock, 12348)
            
            if (bytes.fromhex("0x0800"[2:]) in data):
                # print(data)
                source_mac_recv = decoded_arp_request_recv[2:4]
                dest_mac_recv = decoded_arp_request_recv[4:6]
                source_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[6]))
                destination_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[7]))                
                recv_ethernet_frame(source_mac_recv, dest_mac_recv, source_ip_recv, destination_ip_recv)

                ether_type = "0x0800"
                source_mac_recv = dest_mac_recv
                dest_mac_recv = router1_mac
                data_payload = data[8:]
                send_ethernet_frame(ether_type, source_mac_recv, dest_mac_recv, source_ip_recv, destination_ip_recv, data_payload, sock, 12348)

        elif (from_port == 12346):
            if (bytes.fromhex("0x0806"[2:]) in data):
                if (op_code_recv == "2"):
                    ether_type = "0x0806"
                    source_mac_recv = decoded_arp_request_recv[3:5]
                    dest_mac_recv = decoded_arp_request_recv[5:7]
                    arp_reply_recv(ether_type, op_code_recv, source_mac_recv, dest_mac_recv, source_ip_recv, destination_ip_recv)
                    arp_cache_R2[destination_ip_recv] = source_mac_recv

                    source_mac_recv = dest_mac_recv
                    dest_mac_recv = router1_mac                    
                    arp_reply_sent(ether_type, op_code_recv, source_mac_recv, dest_mac_recv, source_ip_recv, destination_ip_recv, sock, 12348)
            
            if (bytes.fromhex("0x0800"[2:]) in data):
                # print(data)
                source_mac_recv = decoded_arp_request_recv[2:4]
                dest_mac_recv = decoded_arp_request_recv[4:6]
                source_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[6]))
                destination_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[7]))                
                recv_ethernet_frame(source_mac_recv, dest_mac_recv, source_ip_recv, destination_ip_recv)

                ether_type = "0x0800"
                source_mac_recv = dest_mac_recv
                dest_mac_recv = router1_mac
                data_payload = data[8:]
                send_ethernet_frame(ether_type, source_mac_recv, dest_mac_recv, source_ip_recv, destination_ip_recv, data_payload, sock, 12348)


        elif (from_port == 12349):
            if (bytes.fromhex("0x0806"[2:]) in data):
                if (op_code_recv == "2"):
                    ether_type = "0x0806"            
                    source_mac_recv = decoded_arp_request_recv[3:5]
                    dest_mac_recv = decoded_arp_request_recv[5:7]
                    arp_reply_recv(ether_type, op_code_recv, source_mac_recv, dest_mac_recv, source_ip_recv, destination_ip_recv)

                    source_mac_recv = dest_mac_recv
                    dest_mac_recv = arp_cache_R1.get(source_ip_recv)
                    show_arp_table()

                    arp_reply_sent(ether_type, op_code_recv, source_mac_recv, dest_mac_recv, source_ip_recv, destination_ip_recv, sock, 12345)

            if (bytes.fromhex("0x0800"[2:]) in data):
                source_mac_recv = decoded_arp_request_recv[2:4]
                dest_mac_recv = decoded_arp_request_recv[4:6]
                source_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[6]))
                destination_ip_recv = '0x{:02X}'.format(ord(decoded_arp_request_recv[7]))
                recv_ethernet_frame(source_mac_recv, dest_mac_recv, source_ip_recv, destination_ip_recv)

                ether_type = "0x0800"
                source_mac_recv = dest_mac_recv
                dest_mac_recv = arp_cache_R1.get(source_ip_recv)
                data_payload = data[8:]
                send_ethernet_frame(ether_type, source_mac_recv, dest_mac_recv, source_ip_recv, destination_ip_recv, data_payload, sock, 12345)

