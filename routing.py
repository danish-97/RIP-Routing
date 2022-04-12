"""Implementing a RIP routing protocol"""

import sys

inputPorts = []
outputPorts = []


def open_file():
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
            print("ERROR: Every port number must be unique")
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

        if len(outputPorts) > len(set(outputPorts)):
            print("ERROR: Every port number must be unique")
            exit()

        for i in range(0, len(inputPorts)):
            for j in range(0, len(outputPorts)):
                if inputPorts[i] == outputPorts[j]:
                    print("Port {0} in input and output ports must be unique".format(inputPorts[i]))
                    exit()

        return table


def main():
    print(open_file())


main()
