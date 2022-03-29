def print_intermediate_routers(dst_ip, dst_packets):
    i = 1
    seen = set()
    for p in dst_packets:
        ip = p.ip_header.src_ip
        if ip not in seen and ip != dst_ip:
            seen.add(ip)
            print(f"     router {i}: {ip}")
            i += 1

def output_report(src_ip, dst_ip, src_packets, dst_packets):
    print(f"The IP address of the source node: {src_ip}")
    print(f"The IP address of ultimate destination node: {dst_ip}")
    print("The IP addresses of the intermediate destination nodes:")
    print_intermediate_routers(dst_ip, dst_packets)
    print()
    print("The values in protocol field of IP headers:")
    if dst_packets: print("    1: ICMP")
    if src_packets: print("    17: UDP")