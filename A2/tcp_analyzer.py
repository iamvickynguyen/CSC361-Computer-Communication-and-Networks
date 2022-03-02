import sys
from pcap_parser import Global_Header, Packet_Header, parse_pkt_data

def main():
    with open(sys.argv[1], 'rb') as f:
        glob_header = Global_Header(f.read(24))
        packets = []

        while True:
            next_bytes = f.read(16)

            if not next_bytes:
                break

            p_header = Packet_Header(next_bytes, glob_header.byte_order)
            packet = parse_pkt_data(f.read(p_header.incl_len))
            if packet:
                packets.append(packet)
                print(packet)
    

if __name__ == "__main__":
    main()

# 0:45
# 0:57:13
# 0:45:0
# 0:45:0
# 1:30:0
# 0:45:0
# https://github.com/faucetsdn/python3-ryu/blob/3bd6ce1cf4c739f6e86eecb2fdf98a13b10ba22a/ryu/lib/pcaplib.py