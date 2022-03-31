from collections import defaultdict, OrderedDict

def print_intermediate_routers(routers, dst_ip):
    for i, ip in enumerate(routers.keys()):
        if ip != dst_ip:
            print(f"     router {i+1}: {ip}")

def print_fragment_info(src_packets, fragments):
    for p in src_packets:
        id = p.ip_header.id
        if id in fragments and fragments[id][0] > 1:
            print(f"The number of fragments created from the original datagram with id {id} is: {fragments[id][0]}")
            print(f"The offset of the last fragment is: {fragments[id][1]}")

def print_rtt_calculation(routers, src_ip):
    for ip, times in routers.items():
        avg = round(sum(times)/len(times), 6)
        sd = round((sum(map(lambda t: (t-avg)**2, times))/len(times))**(1/2), 6)
        print(f"The avg RTT between {src_ip} and {ip} is: {avg} ms, the s.d. is: {sd} ms")

def get_routers(src_packets, dst_packets, is_linux, src_ip):
    routers = OrderedDict()
    if is_linux:
        for a in src_packets:
            for b in dst_packets:
                if a.udp_header.src_port == b.icmp_header.src_port:
                    l = routers.get(b.ip_header.src_ip, [])
                    l.append(b.timestamp - a.timestamp)
                    routers[b.ip_header.src_ip] = l
    else:
        for a in src_packets:
            for b in dst_packets:
                if a.icmp_header.sequence == b.icmp_header.sequence:
                    l = routers.get(b.ip_header.src_ip, [])
                    l.append(b.timestamp - a.timestamp)
                    routers[b.ip_header.src_ip] = l
    return routers

def output_report(src_ip, dst_ip, src_packets, dst_packets, fragments, is_linux, has_udp):
    print(f"The IP address of the source node: {src_ip}")
    print(f"The IP address of ultimate destination node: {dst_ip}")

    routers = get_routers(src_packets, dst_packets, is_linux, src_ip)
    print("The IP addresses of the intermediate destination nodes:")
    print_intermediate_routers(routers, dst_ip)
    print()

    print("The values in protocol field of IP headers:")
    if dst_packets: print("    1: ICMP")
    if has_udp: print("    17: UDP")
    print()

    print_fragment_info(src_packets, fragments)
    print()

    print_rtt_calculation(routers, src_ip)
    