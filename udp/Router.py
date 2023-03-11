import socket
import select

router1_ip = "0x11"
router2_ip = "0x21"

# Define the port numbers
PORT1 = 8765
PORT2 = 1234

# Create a UDP socket to receive from Node 2 or 3
internal_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
internal_sock.bind(('127.0.0.1', PORT2))
internal_sock.setblocking(0) # make the socket non-blocking

# Create a UDP socket to receive from Node 1
external_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
external_sock.bind(('0.0.0.0', PORT1))
external_sock.setblocking(0) # make the socket non-blocking

# Listen for incoming packets on both sockets
import socket
import select

while True:
    # List of sockets to listen for incoming data
    sockets_list = [internal_sock, external_sock]

    # Use select to wait for incoming data on any of the sockets
    read_sockets, write_sockets, error_sockets = select.select(sockets_list, [], [])

    for sock in read_sockets:
        data, addr = sock.recvfrom(1024)
        from_port = addr[1]

        if (from_port == 5678):
            if (bytes.fromhex("0x0806"[2:]) in data):   # arp reply-request
                # print("Broadcast message")
                sock.sendto(data, ('127.0.0.1', 2234))
                sock.sendto(data, ('127.0.0.1', 3234))
            else:
                if (bytes.fromhex("0x2A"[2:]) in data):                         
                    sock.sendto(data, ('127.0.0.1', 2234))
                else:
                    sock.sendto(data, ('127.0.0.1', 3234))
        elif (from_port == 2234):
            if (bytes.fromhex("0x2B"[2:]) in data):
                sock.sendto(data, ('127.0.0.1', 3234))
            else:
                sock.sendto(data, ('127.0.0.1', 5678))
            # break
        elif (from_port == 3234):
            if (bytes.fromhex("0x2A"[2:]) in data):
                sock.sendto(data, ('127.0.0.1', 2234))
            else:
                sock.sendto(data, ('127.0.0.1', 5678))
        
