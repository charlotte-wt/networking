import socket
import threading
import os

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)      # For UDP

udp_host = "localhost"        # Host IP
udp_port = 12348              # specified port to connect
current_ip = "0x11"
current_mac = "R1"

# print type(sock) ============> 'type' can be used to see type
# of any variable ('sock' here)

sock.bind((udp_host, udp_port))

node2_ip = "0x2A"
node2_mac = "N2"
node3_ip = "0x2B"
node3_mac = "N3"

port_ip_table = {}
port_mac_table = {}

firewall = {}

protocol_num_array = [0,1,2,3,4,5,6,7]

# arp_table_mac = {node2_ip : node2_mac, node3_ip : node3_mac}

def received_protocol(received_message):
    source_ip = received_message[0:4]
    destination_ip =  received_message[4:8]
    protocol = received_message[8:9]
    data_len = received_message[9:13]
    message = received_message[13:]

    print("\nThe packet received:\nSource IP address: {source_ip}\nDestination IP address: {destination_ip}".format(source_ip=source_ip, destination_ip=destination_ip))
    print("\nProtocol: {protocol}".format(protocol=protocol))
    print("\nDataLength: " + data_len)
    print("\nMessage: " + message)
    print("***************************************************************")
    
    # ethernet_header = router_mac + arp_table_mac[destination_ip]
    IP_header = source_ip + destination_ip
    packet = IP_header + protocol + data_len + message
    
    if(destination_ip == "0x2A" or destination_ip == "0x2B"):
        # Sending message to UDP server
        sock.sendto(packet.encode(), (udp_host, 12349))
    elif (destination_ip == "0x1A"):
        sock.sendto(packet.encode(), (udp_host, 12345))


# Main Function Thread 

def wait_client():
    while True:
        try:
            print("Waiting for client...")
            data, addr = sock.recvfrom(1024)  # receive data from client
            print("Received Messages:", data.decode(), " from", addr)
            data = data.decode()
            # if(data[8:9] in str(protocol_num_array[:3])):
            #     received_protocol(data)
            received_protocol(data)
           
        except(KeyboardInterrupt, EOFError):
            print('\n[INFO]: Terminating..')
            sock.close()
            os._exit(1)

def exit():
    input()
    if(KeyboardInterrupt, EOFError):
        print('\n[INFO]: Terminating..')
        sock.close()
        os._exit(1)

if __name__ == "__main__":
    x = threading.Thread(target=wait_client)
    y = threading.Thread(target=exit)
    x.start()
    y.start()