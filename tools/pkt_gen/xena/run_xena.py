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
    DRIVER = XenaSocketDriver('10.19.15.19')
    X_MANAGER = XenaManager(DRIVER, 'vsperf', 'xena')
    
    run = str(args.run[0]).lower()
    if run == "module":
        speed = args.speed[0]
        run_module(X_MANAGER, speed)
    else:
        print("Unknown --run parameter. Acceptable values are: module.")
    

def run_module(X_MANAGER, speed):
    if speed == 25:
        media = "SFP28"
    elif speed == 100:
        media = "QSFP28"
    else:
        print("Incorrect speed value. Supported values are 25, 100.")
    
    print("Changing speed to {}G".format(speed)) 
    
    X_MODULE = XenaModule(X_MANAGER, 9)
    X_MODULE.change_media(media)
    
    print("Media Speed Changed to {}G".format(speed))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='To Access Xena Driver classes')
    parser.add_argument('--run', nargs='+', type=str, help='Class to run from XenaDriver')
    parser.add_argument('--speed', nargs=1, type=int, help='Module speed to change it to', required=True)
   
    args = parser.parse_args()
    run(args) 
