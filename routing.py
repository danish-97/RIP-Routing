"""Implementing a RIP routing protocol"""

import random
import socket
import json
import select
import sys

inputPorts = []
outputPorts = []
INFINITY = 16
TIMEOUT = 180
GARBAGE_COLLECTION = 1
GARBAGE_TIMER = 120


def open_file():
    """Reads the content of the file and formats it into a table"""
    arguments = sys.argv
    filename = arguments[1]
    if len(arguments) != 2:
        print("Invalid number of arguments.\n Please enter in format: python3 routing.py config_file_(number)")
        exit()
    global router_id
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


def create_packet(table):
    """The header and packet of the RIP packet"""
    command = 2
    version = 2
    zeroField = router_id
    entry = []
    header = [command, version, zeroField]
    for i in table.keys():
        cost = table[i][0]
        entry.append((i, cost))
    packet = {"Header": header, "Entry": entry}
    return packet


def check_packet_header(packet):
    """Check the packet header format is as it should be"""
    checkHeader = True
    if int(packet['header'][0]) != 2 or int(packet['header'][1]) != 2:  # Check command and version are 2
        checkHeader = False
    elif int(packet['header'][2]) < 1 or int(packet['header'][2]) > 64000:  # Check header port is within range
        checkHeader = False
    return checkHeader


def check_packet_entry(packet):
    """Check the packet entry format is as it should be"""
    checkEntry = True
    for entry in packet['entry']:
        if int(entry[1]) > 16:
            checkEntry = False
        elif int(entry[0]) < 1 or int(entry[0]) > 64000:
            checkEntry = False
    return checkEntry


def open_socket(input_ports):
    """Opens a socket for every input port"""
    socket_table = []
    for inputSocket in input_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("127.0.0.1", int(inputSocket)))
            socket_table.append(sock)
        except OSError as e:
            print(e)
            print("Socket bind unsuccessful\n")
            exit()
    return socket_table


def close_socket(socket_table):
    """Closes the socket for every port"""
    try:
        for entry in socket_table:
            entry.close()
    except OSError:
        print("Socket close failed\n")
        exit()


def split_horizon(table, neighbour_id):
    """Implement split horizon poison reverse to prevent the occurrence of routing loops"""
    for destination, info in table.items():
        if destination == neighbour_id:
            info[0] = INFINITY
    return table


def update_routing_table(table, packet):
    """Implement a loop which create a packet for each router and sends its information to the neighbouring routers"""

    # send routing information (destination and distance to the destination) to neighbour

    # Check information from neighbour 'G'
    # Add cost associated with G, call result 'D'
    # Compare result distance with current entry in table
    # If distance D is smaller than current distance update table entry to have new metric 'D'
    # If G' is the router from which the existing router came, then use new metric even if it is larger than the old one
    current = router_id
    neighbours = []
    for entry in packet['entry']:
        neighbours.append(entry[0])

    for neighbour in range(len(neighbours)):
        if neighbours[neighbour] == router_id:
            for entry in packet['entry']:
                if packet['entry'][entry][0] == router_id:
                    table[current] = [packet['entry'][entry][1], current, False, 0,
                                      0]  # Used new metric even if it is larger than the old one
        else:
            cost = min(packet['entry'][neighbour][1] + table[current][0],
                       INFINITY)  # Adding the cost associated with neighbour
            if cost < table[current][0]:  # Compare result distance with current entry in the table
                table[current][0] = cost  # Since distance is smaller than current distance, new metric is the distance
            else:
                continue
    return table


def send_packet(table):
    """Sending the UDP datagrams to neighbours"""
    for outputPort in outputPorts:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(json.dumps(create_packet(table)).encode('ascii'), ("127.0.0.1", int(outputPort)))
    print("Packet sent successfully!")


def response_messages(sockets, timeout, table):
    """Processes the response messages for the packet received"""

    # Reasons for response to be received:
    # - Response to specific query
    # - Regular update
    # - Triggered update caused by a route change

    # Validity checks - Datagram
    # Response is ignored if it is not from RIP port
    # Check datagram source address is from valid neighbour, source of datagram must be on a directly-connected network
    # Check response is from one of the routers own addresses
    # Ignore if a router processes its own output as a new input

    # Validity checks - RTEs (entry)
    # Check if destination address valid - unicast, not net 0 or 127
    # Check if metric valid - Must be between 1 and 16 (inclusive)

    # Check if explicit route for destination address

    # First run loop to wait for packets to be received
    packet_table = table
    read, write, err = select.select(sockets, [], [], timeout)
    if len(read) > 0:
        for i in read:
            rec_packet_raw = i.recvfrom(1023)
            message_packet = rec_packet_raw[0].decode('ascii')
            # address_packet = rec_packet_raw[1]
            valid_header = check_packet_header(message_packet)
            valid_entry = check_packet_entry(message_packet)
            if valid_header and valid_entry:
                packet_table = update_routing_table(table, message_packet)
            else:
                print('Dropped invalid packet')
    return packet_table


# def update_timer_table(main_table, timer, random_timer):
#     """Updates the table and the timer and sends the packets when the required conditions are met"""
#     # if timer == random_timer: # Waits for a random interval of 30+/-5 seconds and then sends a packet while resetting the timer
#     #     send_packet(main_table)
#     #     timer = 0
#     # for id in main_table.keys():
#     #     if main_table[id][3] >= TIMEOUT: # Checks if the timer exceeds the timeout value
#     #         main_table[id][0] = INFINITY # Sets metric to infinity
#     #         main_table[id][2] = True # Sets flag to true
#     #     else:
#     #         main_table[id][3] += 1 # Timer goes up by 1
#     #
#     #     if main_table[id][2]: # Checks if the flag is true, and if yes increments the garbage collection
#     #         main_table[id][4] += GARBAGE_COLLECTION
#     #         if main_table[id][4] >= GARBAGE_TIMER:
#     #             del main_table[id]


def print_routing_table(table):
    """Prints routing table in pretty format"""
    print("--" * 40)
    print("Routing table for router {}".format(router_id))
    for key, data in table.items():
        print(
            "Destination: {}  Metric: {}  Next Hop: {}  Timer: {}  Garbage Collection: {}".format(key, data[0], data[1],
                                                                                                  data[3], data[4]))
    print("--" * 40)


def main():
    """The main function of the file which runs the program"""
    # test = open_file()
    # print(create_packet(test))
    # print(test)
    # print_routing_table(test)
    timer = 0
    random_timer = random.randint(3, 9)  # Offsetting the 30-second timer by a random interval (30 +- 5)
    # Parses through the config file and formats the data into a table
    main_table = open_file()

    # Open the sockets for input ports and gets them ready for receiving packets
    sockets = open_socket(inputPorts)

    while True:
        timer = timer + 1
        print_routing_table(main_table)

        # update_timer_table(main_table, timer, random_timer)
        if timer == random_timer:  # Waits for a random interval of 30+/-5 seconds and then sends a packet while resetting the timer
            send_packet(main_table)
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

        main_table = response_messages(sockets, 1, main_table)

    close_socket(main_table)


main()
