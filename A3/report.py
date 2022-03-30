from collections import defaultdict

def print_intermediate_routers(dst_ip, dst_packets):
    i = 1
    seen = set()
    for p in dst_packets:
        ip = p.ip_header.src_ip
        if ip not in seen and ip != dst_ip:
            seen.add(ip)
            print(f"     router {i}: {ip}")
            i += 1

def print_fragment_info(src_packets, fragments):
    for p in src_packets:
        id = p.ip_header.id
        if id in fragments:
            print(f"The number of fragments created from the original datagram with id {id} is: {fragments[id][0]}")
            print(f"The offset of the last fragment is: {fragments[id][1]}")

def output_report(src_ip, dst_ip, src_packets, dst_packets, fragments):
    print(f"The IP address of the source node: {src_ip}")
    print(f"The IP address of ultimate destination node: {dst_ip}")
    print("The IP addresses of the intermediate destination nodes:")
    print_intermediate_routers(dst_ip, dst_packets)
    print()
    print("The values in protocol field of IP headers:")
    if dst_packets: print("    1: ICMP")
    if src_packets: print("    17: UDP")
    print()
    print_fragment_info(src_packets, fragments)
