﻿# Network Emulation

## About
Network Emulation is a project that aims to emulate behaviours in the Ethernet and network layer (IP), as shown in the diagram below.

![Diagram](./images/diagram.jpg)

The IP packets sent is in the following format:

![IP](./images/IP_datagram.jpg)


## Getting Started

### Pre-requisites
1. - [Python](https://www.python.org/downloads/) (version 3)

### Usage

#### UDP Folder
From root folder:
1. `cd udp` / open udp folder
2. Repeat step 1 for 5 terminals.


Run one command in each terminal (sequence of commands is not important since this is UDP):
1. `python3 routerR1.py`
2. `python3 routerR2.py`
3. `python3 Node1.py`
4. `python3 Node2.py`
5. `python3 Node3.py`

However, communication between Nodes requires the Router interfaces to be running.

#### Implementation

1. Each Interface is binded to a port in localhost and has its own individual socket:
    - Port Numbers:
        - Node1: `12345`
        - Node2: `12346`
        - Node3: `12347`
        - RouterR1: `12348`
        - RouterR2: `12349`

    - All IP Packets will go through the Router interfaces
        - packets will NOT be sent directly from one Node to another
        - e.g. 
            - Node 1 > R1 > R2 > Node 3
            - Node 2 > R2 > Node 3
            - Node 2 > R2 > R1 > Node 1


2. Protocol:
    - 0: ping
        - The recipient replies the sender with the same data
        - Example:
    ![Ping Details](./images/ping_eg.png)

    - 1: log
        - The recipient writes the received data to a log file
        - We log the datetime and the IP packet details.
        - Example:  
            ![Log Details](./images/log_details.png)

    - 2: kill
        - The recipient exits & terminates its application (i.e. stops running)
        - Example:
            1. Node1 and Node3 are initially running
                ![Kill Detail 1](./images/kill_1.png)
            2. Node1 sends Node3 an IP packet with the kill protocol
            3. Node3 is terminated
                ![Kill Detail 2](./images/kill_2.png)

    - 3: indicator (reply from ping)
        - simply indicates that this packet is a reply from a ping sent out 

3. IP Spoofing:
    - Node 3 is able to spoof Node 2's IP and send IP packets to Node 1
    - command: `python3 Node3.py --spoof`
        - send a message to Node 1 with protocol 1 (ping) to see results
        - Node 2 will receive a ping reply even though it did not send out any ping packets
