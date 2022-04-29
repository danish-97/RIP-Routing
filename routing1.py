"""
 Author: Liam Bullock - 34909160
 Author: Danish Jahangir - 28134926

 Implementing the RIP routing protocol
"""

import random
import socket
import json
import select
import sys
from copy import deepcopy

inputPorts = []
outputPorts = []
INFINITY = 16
TIMEOUT = 20
GARBAGE_COLLECTION = 1
GARBAGE_TIMER = 5


def main():
    """The main function of the file which runs the program"""
    timer = 0
    random_timer = random.randint(3, 9)  # Offsetting the 30-second timer by a random interval (30 +- 5)
    # Parses through the config file and formats the data into a table
    main_table = open_file()

    # Open the sockets for input ports and gets them ready for receiving packets
    newSocket = Socket(inputPorts, main_table)
    sockets = newSocket.open_socket()

    while True:
        timer = timer + 1
        newPacket = Packet(main_table)
        packet = newPacket.create_packet()
        routing = Routing(main_table, packet)
        routing.print_routing_table()

        # update_timer_table(main_table, timer, random_timer)
        if timer == random_timer:  # Waits for a random interval of 30+/-5 seconds and then sends a packet while resetting the timer
            newPacket.send_packet(packet)
            timer = 0
        for id in sorted(main_table.keys()):
            if main_table[id][3] >= TIMEOUT:  # Checks if the timer exceeds the timeout value
                main_table[id][0] = INFINITY  # Sets metric to infinity
                main_table[id][2] = True  # Sets flag to true
            else:
                main_table[id][3] += 1  # Timer goes up by 1

            if main_table[id][2]:  # Checks if the flag is true, and if yes increments the garbage collection
                main_table[id][4] += GARBAGE_COLLECTION
                if main_table[id][4] >= GARBAGE_TIMER:
                    del main_table[id]

        main_table = routing.response_messages(sockets, timeout=1)

    newSocket.close_socket(main_table)


class Socket:
    """ Class that handles the functions of the sockets"""
    def __init__(self, input_ports, socket_table):
        self.socket_table = socket_table
        self.input_ports = input_ports

    def open_socket(self):
        """Opens a socket for every input port"""
        self.socket_table = []
        for inputSocket in self.input_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.bind(("127.0.0.1", int(inputSocket)))
                self.socket_table.append(sock)
            except OSError as e:
                print(e)
                print("Socket bind unsuccessful\n")
                exit()
        return self.socket_table

    def close_socket(self):
        """Closes a socket for every port"""
        try:
            for entry in self.socket_table:
                entry.close()
        except OSError:
            print("Socket close failed\n")
            exit()


class Packet:
    """Class that handles the functions of the packets"""
    # create packet, check packet header and entry, send packet
    def __init__(self, table):
        self.table = table

    def create_packet(self):
        """The header and entry of the RIP packet"""
        command = 2
        version = 2
        zeroField = router_id
        entry = []
        header = [command, version, zeroField]
        for i in self.table.keys():
            cost = self.table[i][0]
            entry.append((i, cost))
        packet = {"Header": header, "Entry": entry}
        return packet

    def send_packet(self, packet):
        """Sending the UDP datagrams to neighbours"""
        for outputPort in outputPorts:
            table_copy = deepcopy(self.table)
            routing = Routing(table_copy, packet)
            poison_table = routing.split_horizon(outputPort)
            self.table = poison_table
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(json.dumps(self.create_packet()).encode('ascii'), ("127.0.0.1", int(outputPort)))
        print("Packet sent successfully!")


class Routing:
    """Class that handles the functions for routing"""
    def __init__(self, table, packet):
        self.table = table
        self.packet = packet

    def split_horizon(self, neighbour_id):
        """Implement split horizon poison reverse to prevent the occurrence of routing loops"""
        for destination, info in self.table.items():
            if destination == neighbour_id:
                info[0] = INFINITY
        return self.table

    def update_routing_table(self):
        """
        Implement a loop which create a packet for each router and sends its information to the neighbouring routers send
        routing information (destination and distance to the destination) to neighbour

        Check information from neighbour 'G'
        Add cost associated with G, call result 'D'
        Compare result distance with current entry in table
        If distance D is smaller than current distance update table entry to have new metric 'D'
        If G' is the router from which the existing router came, then use new metric even if it is larger than the old one
        """
        current = self.packet['Header'][2]
        neighbours = []
        for entry in self.packet['Entry']:
            neighbours.append(entry[0])

        if current not in self.table.keys():  # Checks if the router is present in the table and if not adds it
            for entries in range(len(self.packet['Entry'])):
                if self.packet['Entry'][entries][1] == router_id:
                    self.table[current] = [self.packet['Entry'][entries][0], current, False, 0, 0]
        else:
            for neighbour in range(len(neighbours)):
                n = neighbours[neighbour]
                if n == router_id:
                    for entry in range(len(self.packet['Entry'])):
                        if self.packet['Entry'][entry][0] == router_id:
                            if self.packet['Entry'][neighbour][1] < 16:
                                self.table[current] = [self.packet['Entry'][entry][1], current, False, 0,
                                                       0]  # Used new metric even if it is larger than the old one
                else:
                    cost = min(self.packet['Entry'][neighbour][1] + self.table[current][0],
                               INFINITY)  # Adding the cost associated with neighbour
                    if n not in self.table.keys():
                        if cost >= 16:
                            continue
                        else:
                            self.table[n] = [cost, current, False, 0, 0]
                    elif current == self.table[n][1]:
                        if self.table[n][0] == 16:
                            continue
                        else:
                            self.table[n] = [cost, current, False, 0, 0]
                    elif cost < self.table[n][0]:  # Compare result distance with current entry in the table
                        self.table[n][
                            0] = cost  # Since distance is smaller than current distance, new metric is the distance
                        self.table[n][1] = current
        return self.table

    def response_messages(self, sockets, timeout):
        """Processes the response messages for the packet received
            Reasons for response to be received:
        - Response to specific query
        - Regular update
        - Triggered update caused by a route change

        Validity checks - Datagram
        Response is ignored if it is not from RIP port
        Check datagram source address is from valid neighbour, source of datagram must be on a directly-connected network
        Check response is from one of the routers own addresses
        Ignore if a router processes its own output as a new input

        Validity checks - RTEs (entry)
        Check if destination address valid - unicast, not net 0 or 127
        Check if metric valid - Must be between 1 and 16 (inclusive)

        Check if explicit route for destination address

        First run loop to wait for packets to be received
        """

        packet_table = self.table
        read, write, err = select.select(sockets, [], [], timeout)
        if len(read) > 0:
            for i in read:
                rec_packet_raw = i.recvfrom(1023)
                message_packet = rec_packet_raw[0].decode('ascii')
                # address_packet = rec_packet_raw[1]
                message_packet_dict = json.loads(message_packet)  # Convert string to dictionary
                self.packet = message_packet_dict
                packet = Packet(packet_table)
                valid_header = check_packet_header(message_packet_dict)
                valid_entry = check_packet_entry(message_packet_dict)
                print('Packet Received')
                if valid_header and valid_entry:
                    packet_table = self.update_routing_table()
                else:
                    print('Dropped invalid packet')
        return packet_table

    def print_routing_table(self):
        """Prints routing table in pretty format"""
        print("==" * 40)
        print("                      Routing table for router {}".format(router_id))
        print("Destination      Metric      Next Hop      Timer      Garbage Timer")
        for key, data in self.table.items():
            print(
                "{:^12d} {:^14d} {:^12d} {:^12d} {:^14d}".format(key, data[0], data[1], data[3], data[4]))
        print("==" * 40)


""" HELPER FUNCTIONS"""


def open_file():
    """Reads the content of the file and formats it into a table"""
    global router_id
    arguments = sys.argv
    filename = arguments[1]
    if len(arguments) != 2:
        print("Invalid number of arguments.\n Please enter in format: python3 routing.py config_file_(number)")
        exit()
    router_id = int(filename[12])
    with open(filename) as f:
        contents = f.readlines()
        routerIdRaw = contents[0]
        inputPortsRaw = contents[1]
        outputPortsRaw = contents[2]
        routerIdList = routerIdRaw.strip().split(", ")
        inputPortsList = inputPortsRaw.strip().split(", ")
        outputPortsList = outputPortsRaw.strip().split(", ")
        table = {}

        if 1 > int(routerIdList[1]) or int(routerIdList[1]) > 64000:
            print("ERROR: Router-id must be between 1 and 64000")
            exit()
        for i in range(1, len(inputPortsList)):
            if 1024 >= int(inputPortsList[i]) or int(inputPortsList[i]) >= 64000:
                print("ERROR: Port number {0} must be between 1024 and 64000".format(inputPortsList[i]))
                exit()
            else:
                inputPorts.append(inputPortsList[i])

        if len(inputPorts) > len(set(inputPorts)):
            print("ERROR: Every input port number must be unique")
            exit()

        for j in range(1, len(outputPortsList)):
            output = outputPortsList[j].split('-')
            if 1024 >= int(output[0]) or int(output[0]) >= 64000:
                print("ERROR: Port number {0} must be between 1024 and 64000".format(output[0]))
                exit()
            else:
                outputPorts.append(output[0])
            flag = False
            timer = 0
            garbageTime = 0
            table[int(output[2])] = [int(output[1]), int(output[2]), flag, timer, garbageTime]
            # output[1] = metric/cost
            # output[2] = destination id

        if len(outputPorts) > len(set(outputPorts)):
            print("ERROR: Every output port number must be unique")
            exit()

        for i in range(0, len(inputPorts)):
            for j in range(0, len(outputPorts)):
                if inputPorts[i] == outputPorts[j]:
                    print("Port {0} in input and output ports must be unique".format(inputPorts[i]))
                    exit()

        return table


def check_packet_header(packet):
    """Verifies that the packet header format is as it should be"""
    checkHeader = True
    if int(packet['Header'][0]) != 2 or int(packet['Header'][1]) != 2:  # Check command and version are 2
        checkHeader = False
    elif int(packet['Header'][2]) < 1 or int(packet['Header'][2]) > 64000:  # Check header port is within range
        checkHeader = False
    return checkHeader


def check_packet_entry(packet):
    """Verifies that the packet entry format is as it should be"""
    checkEntry = True
    for entry in packet['Entry']:
        if int(entry[1]) > 16:
            checkEntry = False
        elif int(entry[0]) < 1 or int(entry[0]) > 64000:
            checkEntry = False
    return checkEntry


main()
