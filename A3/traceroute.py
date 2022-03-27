import sys
import struct
# from parser import Global_Header, Packet_Header


def main():
    with open(sys.argv[1], 'rb') as f:
        # glob_header = Global_Header(f.read(24))
        f.read(24)

        # while True:
        #     next_bytes = f.read(16)
        #     if not next_bytes: break
        #     p_header = Packet_Header(next_bytes, glob_header.byte_order)
        #     packet = parse_pkt_data(f.read(p_header.incl_len), len(packets) + 1, p_header)
        #     if packet: packets.append(packet)

        for i in range(2):
            test = f.read(16)
            a,b,c,d = struct.unpack_from('<IIII', test)
            f.read(c)
        
        test = f.read(16)
        print(test)
        a,b,c,d = struct.unpack_from('<IIII', test)
        data = f.read(c)
        data = data[14:] # rm ethernet
        print(data[4:8])

if __name__ == "__main__":
    main()