import sys
from packet import Global_Header, Packet_Header, get_packet

def main():
    with open(sys.argv[1], 'rb') as f:
        glob_header = Global_Header(f.read(24))
        packets = []

        while True:
            next_bytes = f.read(16)
            if not next_bytes: break
            pkt_header = Packet_Header(next_bytes, glob_header.byte_order)
            pkt_data = f.read(pkt_header.incl_len)
            packet = get_packet(pkt_data, len(packets) + 1, pkt_header)
            if packet: packets.append(packet)

if __name__ == "__main__":
    main()