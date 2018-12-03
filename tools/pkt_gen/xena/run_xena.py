"""
USAGE:
- Use python 3
- Run 'python run_xena --run module --speed 25'
"""
import argparse
from XenaDriver import *


def run(args):
    PACKET_SIZE = 128
    DURATION = 10
    if args.ip is not None:
        IP_ADDRESS = args.ip[0]
    else:
        IP_ADDRESS='10.19.15.19'

    DRIVER = XenaSocketDriver(IP_ADDRESS)
    X_MANAGER = XenaManager(DRIVER, 'vsperf', 'xena')
    
    run = str(args.run[0]).lower()
    if run == "module":
        speed = args.speed[0]
        if IP_ADDRESS == "10.73.130.19":
            run_10_73_130_19(X_MANAGER, speed)
        elif IP_ADDRESS == "10.73.88.3":
            run_10_73_130_19(X_MANAGER, speed)
        else:
            run_10_19_15_19(X_MANAGER, speed)
    else:
        print("Unknown --run parameter. Acceptable values are: module.")

#Function to change speed on NAY Xena
def run_10_73_130_19(X_MANAGER, speed):
    if args.port is not None:
        ports = args.port[0]
    elif speed == 25:
        ports = 8
    elif speed == 100:
        ports = 2
    else:
        print("Incorrect speed value. Supported values are 25(8*25), 100(2*100). For other configurations pass --speed and --port as argument")
        return 0

    print("Changing speed to {}G".format(speed))
    X_MODULE = XenaModule(X_MANAGER, 5)
    X_MODULE.change_speed(ports, speed)
    print("Media Speed Changed to {}G".format(speed))


#Function to change speed on Bos Xena
def run_10_19_15_19(X_MANAGER, speed):
    if speed == 25:
        media = "SFP28"
    elif speed == 100:
        media = "QSFP28"
    else:
        print("Incorrect speed value. Supported values are 25, 100.")
        return 0

    print("Changing speed to {}G".format(speed))     
    X_MODULE = XenaModule(X_MANAGER, 9)
    X_MODULE.change_media(media)
    print("Media Speed Changed to {}G".format(speed))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='To Access Xena Driver classes')
    parser.add_argument('--run', nargs='+', type=str, help='Class to run from XenaDriver')
    parser.add_argument('--speed', nargs=1, type=int, help='Module speed to change it to', required=True)
    parser.add_argument('--ip', nargs=1, type=str, help='IP Address of a chassis to use. Either 10.19.15.19 or 10.73.130.19')
    parser.add_argument('--port', nargs=1, type=int, help='Number of ports to configure')
 
    args = parser.parse_args()
    run(args) 
