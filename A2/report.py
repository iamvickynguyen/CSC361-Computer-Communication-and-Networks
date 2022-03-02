def collect_connections_info(packets):
    connections = {}
    for p in packets:
        forward = (p.IP_header.src_ip, p.TCP_header.src_port, p.IP_header.dst_ip, p.TCP_header.dst_port)
        backward = (p.IP_header.dst_ip, p.TCP_header.dst_port, p.IP_header.src_ip, p.TCP_header.src_port)

        if forward not in connections:
            if backward not in connections:
                connections[forward] = {
                    "pkt_src_dest_count": 1,
                    "pkt_dest_src_count": 0,
                    "start_time": p.timestamp,
                    "end_time": p.timestamp,
                    "bytes_src_dest_count": 0, # TODO
                    "bytes_dest_src_count": 0 # TODO
                }
            else:
                updated_info = {
                    "pkt_src_dest_count": connections[backward]["pkt_src_dest_count"],
                    "pkt_dest_src_count": connections[backward]["pkt_dest_src_count"] + 1,
                    "start_time": connections[backward]["start_time"],
                    "end_time": p.timestamp,
                    "bytes_src_dest_count": connections[backward]["bytes_src_dest_count"], # TODO
                    "bytes_dest_src_count": connections[backward]["bytes_dest_src_count"] # TODO
                }
                connections[backward] = updated_info
        else:
            updated_info = {
                "pkt_src_dest_count": connections[forward]["pkt_src_dest_count"] + 1,
                "pkt_dest_src_count": connections[forward]["pkt_dest_src_count"],
                "start_time": connections[forward]["start_time"],
                "end_time": p.timestamp,
                "bytes_src_dest_count": connections[forward]["bytes_src_dest_count"], # TODO
                "bytes_dest_src_count": connections[forward]["bytes_dest_src_count"] # TODO
            }
            connections[forward] = updated_info

    return connections
                

def output_report(packets):
    connections = collect_connections_info(packets)
    for i, (k, v) in enumerate(sorted(connections.items(), key=lambda item: item[1]["start_time"])):
        print("Connection ", i + 1)
        print(k)
        print(v)
        print("-------------")