"""Implementing a RIP routing protocol"""
import socket
import sys

inputPorts = []
outputPorts = []
router_id = 1


def open_file():
    """Reads the content of the file and formats it into a table"""
    with open('config_file_1') as f:
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


def create_packet(table, router_id):
    """The header of the RIP packet"""
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


def check_packet_entry(packet):
    """Check the packet entry format is as it should be"""
    checkEntry = True
    for entry in packet['entry']:
        if int(entry[1]) > 16:
            checkEntry = False
        elif int(entry[0]) < 1 or int(entry[0]) > 64000:
            checkEntry = False
    return checkEntry


def main_loop(table, packet):
    """Implement a loop which create a packet for each router and sends its information to the neighbouring routers"""


def open_socket(input_ports):
    """Opens a socket for every input port"""
    socket_table = []
    for inputSocket in input_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("127.0.0.1", int(inputSocket)))
            socket_table.append(sock)
        except OSError:
            print("Socket bind unsuccessful\n")
            exit()
    return socket_table


def close_socket(socket_table):
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
            info[0] = 16
    return table


def main():
    test = open_file()
    print(create_packet(test, router_id))
    print(test)


main()
