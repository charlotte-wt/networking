#!usr/bin/python

import socket
import threading

sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)      # For UDP

udp_host = "localhost"		# Host IP
udp_port = 12346			        # specified port to connect
source_ip = "0x2A"

sock.bind((udp_host, udp_port))

def send_message():
    while True:
        try:
            message = input("\nEnter the text message to send: ")
            destination_ip = input("Enter the IP of the clients to send the message to:\n1. 0x1A\n2. 0x2B\n")
            protocol = input("\nPlease enter the protocol of the packet (in an integer):\n0: ping protocol\n1: log protocol\n2: kill protocol\n")
            ethernet_header = ""
            IP_header = ""
            
            if(destination_ip == "0x1A" or destination_ip == "0x2B"):
                    
                    IP_header = IP_header + source_ip + destination_ip
                    
                    # source_mac = server_mac
                    # destination_mac = router_mac 
                    # ethernet_header = ethernet_header + source_mac + destination_mac
                    
                    packet = IP_header + protocol + "0x{:02x}".format(len(message)) + message
                    
                
            else:
                print("Wrong client IP inputted")
            print("UDP target IP:", udp_host)
            print("UDP target Port:", 12345)

            if(destination_ip == "0x1A" or destination_ip == "0x2B"):
                # Sending message to UDP server
                sock.sendto(packet.encode(), (udp_host, 12349))
          

        except(KeyboardInterrupt, EOFError):
            print('\n[INFO]: Keyboard Interrupt Received')
            exit()

def wait_client():
    
    while True:
        try:
            print("Waiting for client...")
            data, addr = sock.recvfrom(1024)  # receive data from client
            print("Received Messages:", data.decode(), " from", addr)

            received_message = data.decode();

            source_ip = received_message[0:4]
            destination_ip =  received_message[4:8]
            protocol = received_message[8:9]
            data_len = received_message[9:13]
            message = received_message[13:]

            print("\nSource IP address: {source_ip}\nDestination IP address: {destination_ip}".format(source_ip=source_ip, destination_ip=destination_ip))
            print("\nProtocol: {protocol}".format(protocol=protocol))
            print("\nDataLength: " + data_len)
            print("\nMessage: " + message)
            print("***************************************************************")
        
        

        except(KeyboardInterrupt, EOFError):
            print('\n[INFO]: Keyboard Interrupt Received')
            exit()
        
if __name__ == "__main__":
    x = threading.Thread(target=wait_client)
    y = threading.Thread(target=send_message)
    x.start()
    y.start()
       
    