import socket

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost", 8000))
server.listen(2)

# having sample addresses for the server
server_ip = "0x1A"
server_mac = "N1"

router_mac = "R1"

while True:
    routerConnection, address = server.accept()
    if(routerConnection != None):
        print(routerConnection)
        break

while True:
    try:
        ethernet_header = ""
        IP_header = ""
        
        message = input("\nEnter the text message to send: ")
        destination_ip = input("Enter the IP of the clients to send the message to:\n1. 0x2A\n2. 0x2B\n")
        protocol = input("\nPlease enter the protocol of the packet (in an integer):\n0: ping protocol\n1: log protocol\n2: kill protocol\n")
        if(destination_ip == "0x2A" or destination_ip == "0x2B"):
            source_ip = server_ip
            IP_header = IP_header + source_ip + destination_ip
            
            # source_mac = server_mac
            # destination_mac = router_mac 
            # ethernet_header = ethernet_header + source_mac + destination_mac
            
            packet = IP_header + protocol + "0x{:02x}".format(len(message)) + message
            
            routerConnection.send(bytes(packet, "utf-8"))  
        else:
            print("Wrong client IP inputted")
        
    except KeyboardInterrupt:
        print('\n[INFO]: Keyboard Interrupt Received')
        break

 