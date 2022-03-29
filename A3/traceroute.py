import sys
from packet import Global_Header, Packet_Header, get_packet
from report import output_report

def main():
    packets = []
    with open(sys.argv[1], 'rb') as f:
        glob_header = Global_Header(f.read(24))
        src, dst = [], []
        src_ip, dst_ip = None, None

        while True:
            next_bytes = f.read(16)
            if not next_bytes: break
            pkt_header = Packet_Header(next_bytes, glob_header.byte_order)
            pkt_data = f.read(pkt_header.incl_len)
            packet = get_packet(pkt_data, len(packets) + 1, pkt_header)
            if packet:
                if packet.udp_header:
                    src.append(packet)
                    if packet.ip_header.ttl == 1:
                        src_ip = packet.ip_header.src_ip
                        dst_ip = packet.ip_header.dst_ip
                else: dst.append(packet)
        
    output_report(src_ip, dst_ip, src, dst)

if __name__ == "__main__":
    main()