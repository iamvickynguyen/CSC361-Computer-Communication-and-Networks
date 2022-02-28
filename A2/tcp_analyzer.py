import sys
from packet_struct import *
from global_header import Global_Header

def main():
    with open(sys.argv[1], 'rb') as f:
        global_header = Global_Header(f.read(24))
        # print(global_header)

if __name__ == "__main__":
    main()