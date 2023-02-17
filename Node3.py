import socket
import time

client3_ip = "0x2B"
client3_mac = "N3"

router = ("localhost", 8200)
client3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

time.sleep(1)
client3.connect(router)

while True:
    received_message = client3.recv(1024)
    received_message = received_message.decode("utf-8")
    source_mac = received_message[0:2]
    destination_mac = received_message[2:4]
    source_ip = received_message[4:8]
    destination_ip =  received_message[8:12]
    protocol = received_message[12:13]
    data_len = received_message[13:17]
    message = received_message[17:]
    print("\nPacket integrity:\ndestination MAC address matches client 1 MAC address: {mac}".format(mac=(client3_mac == destination_mac)))
    print("\ndestination IP address matches client 1 IP address: {mac}".format(mac=(client3_ip == destination_ip)))
    print("\nThe packet received:\nSource MAC address: {source_mac}, Destination MAC address: {destination_mac}".format(source_mac=source_mac, destination_mac=destination_mac))
    print("\nSource IP address: {source_ip}, Destination IP address: {destination_ip}".format(source_ip=source_ip, destination_ip=destination_ip))
    print("\nProtocol: {protocol}".format(protocol=protocol))
    print("\nDataLength: " + data_len)
    print("\nMessage: " + message)
    print("***************************************************************")