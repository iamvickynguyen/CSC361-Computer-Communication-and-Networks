import sys
from packet import Global_Header, Packet_Header, get_packet
from report import output_report
from collections import defaultdict

def main():
    id = 1
    src, dst = [], []
    fragments = defaultdict(lambda: (0, 0))
    src_ip, dst_ip = None, None
    is_linux = True
    with open(sys.argv[1], 'rb') as f:
        glob_header = Global_Header(f.read(24))

        while True:
            next_bytes = f.read(16)
            if not next_bytes: break
            pkt_header = Packet_Header(next_bytes, glob_header.byte_order)
            pkt_data = f.read(pkt_header.incl_len)
            packet = get_packet(pkt_data, id, pkt_header)
            id += 1
            if packet:
                if packet.udp_header:
                    (count, offset) = fragments[packet.ip_header.id]
                    fragments[packet.ip_header.id] = (count + 1, packet.ip_header.fragment_offset)
                    if packet.ip_header.ttl == 1:
                        src_ip = packet.ip_header.src_ip
                        dst_ip = packet.ip_header.dst_ip
                    if 33434 <= packet.udp_header.dst_port <= 33529:
                        src.append(packet)
                else:
                    dst.append(packet)
                    if packet.icmp_header.type == 8:
                        is_linux = False

    # print(is_linux)
    # print("SRC--------------")
    # for p in src:
    #     print(p)
    # print("DEST------------")
    # for p in dst:
    #     print(p)
    output_report(src_ip, dst_ip, src, dst, fragments, is_linux)

if __name__ == "__main__":
    main()