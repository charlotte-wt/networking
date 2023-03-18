import socket
import time
client2_ip = "0x2A"
client2_mac = "N2"

router = ("localhost", 8200)

client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

time.sleep(1)
client2.connect(router)

while True:
    received_message = client2.recv(1024)
    received_message = received_message.decode("utf-8")
    # source_mac = received_message[0:2]
    # destination_mac = received_message[2:4]
    source_ip = received_message[0:4]
    destination_ip =  received_message[4:8]
    protocol = received_message[8:9]
    data_len = received_message[9:13]
    message = received_message[13:]

    # print("\nPacket integrity:\ndestination MAC address matches client 1 MAC address: {mac}".format(mac=(client2_mac == destination_mac)))
    print("\nPacket integrity:\ndestination IP address matches client 1 IP address: {mac}".format(mac=(client2_ip == destination_ip)))
    # print("\nThe packet received:\nSource MAC address: {source_mac}, Destination MAC address: {destination_mac}".format(source_mac=source_mac, destination_mac=destination_mac))
    print("\nSource IP address: {source_ip}\nDestination IP address: {destination_ip}".format(source_ip=source_ip, destination_ip=destination_ip))
    print("\nProtocol: {protocol}".format(protocol=protocol))
    print("\nDataLength: " + data_len)
    print("\nMessage: " + message)
    print("***************************************************************")

    # if protocol == "0":
    #     IP_header = destination_ip + source_ip
    #     return_packet = IP_header + protocol + data_len + message
  