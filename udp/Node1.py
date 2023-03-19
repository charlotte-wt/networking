#!usr/bin/python

import socket
import threading
import logging 
import os

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)      # For UDP

udp_host = "localhost"        # Host IP
udp_port = 12345              # specified port to connect
source_ip = "0x1A"



# print type(sock) ============> 'type' can be used to see type
# of any variable ('sock' here)

sock.bind((udp_host, udp_port))


def send_message():
    
    while True:
        
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

            print("UDP target IP:", udp_host)
            print("UDP target Port:", 12346)

            if(destination_ip == "0x2A" or destination_ip == "0x2B"):
                # Sending message to UDP server
                sock.sendto(packet.encode(), (udp_host, 12348))
         
        except(KeyboardInterrupt, EOFError, ValueError):
            print('\n[INFO]: Terminating..')
            os._exit(1)

   

def wait_client():
    while True:
       
        try:
            print("Waiting for client...")
            data, addr = sock.recvfrom(1024)  # receive data from client
            print("Received Messages:", data.decode(), " from", addr)
            received_message = data.decode()

            source_ip = received_message[0:4]
            destination_ip =  received_message[4:8]
            protocol = received_message[8:9]
            data_len = received_message[9:13]
            message = received_message[13:]

            to_print = "\nSource IP address: {source_ip}\nDestination IP address: {destination_ip} \
                    \nProtocol: {protocol}\nDataLength: {data_len}\nMessage: {message}" \
                    .format(source_ip=source_ip, destination_ip=destination_ip, protocol=protocol, data_len=data_len, message=message)

            print(to_print)

            print("***************************************************************")

            protocol_num = int(protocol)

            if ( protocol_num == 0 ):
                # ping

                new_destination_ip = source_ip
                new_source_ip = destination_ip
                new_protocol = "3"
                new_message = received_message
                

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
                os._exit(1)



        except(KeyboardInterrupt, EOFError, ValueError):
            print('\n[INFO]: Terminating..')
            os._exit(1)


    



if __name__ == "__main__":
    x = threading.Thread(target=wait_client)
    y = threading.Thread(target=send_message)
    x.start()
    y.start()
  
