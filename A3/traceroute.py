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
    has_udp = False
    with open(sys.argv[1], 'rb') as f:
        glob_header = Global_Header(f.read(24))

        # treat as Linux first
        while True:
            next_bytes = f.read(16)
            if not next_bytes: break
            pkt_header = Packet_Header(next_bytes, glob_header.byte_order)
            pkt_data = f.read(pkt_header.incl_len)
            packet = get_packet(pkt_data, id, pkt_header)
            id += 1
            if packet:
                if packet.udp_header:
                    has_udp = True
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

    # change to Windows
    if not is_linux:
        src_tmp, dst_tmp = [], []
        fragments.clear()
        for packet in dst:
            if packet.ip_header.ttl == 1:
                src_ip = packet.ip_header.src_ip
                dst_ip = packet.ip_header.dst_ip
            if packet.icmp_header.type == 8:
                src_tmp.append(packet)
                (count, offset) = fragments[packet.ip_header.id]
                fragments[packet.ip_header.id] = (count + 1, packet.ip_header.fragment_offset)
            else:
                dst_tmp.append(packet)
        src = src_tmp
        dst = dst_tmp

    src = sorted(src, key=lambda p: p.ip_header.ttl)
    dst = sorted(dst, key=lambda p: p.ip_header.ttl)
    
    output_report(src_ip, dst_ip, src, dst, fragments, is_linux, has_udp)

if __name__ == "__main__":
    main()