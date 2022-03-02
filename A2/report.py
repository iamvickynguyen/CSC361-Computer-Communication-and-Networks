def collect_connections_info(packets):
    if not packets: return {}

    offset = packets[0].timestamp
    connections = {}
    for p in packets:
        forward = (p.IP_header.src_ip, p.TCP_header.src_port, p.IP_header.dst_ip, p.TCP_header.dst_port)
        backward = (p.IP_header.dst_ip, p.TCP_header.dst_port, p.IP_header.src_ip, p.TCP_header.src_port)

        if forward not in connections:
            if backward not in connections:
                connections[forward] = {
                    "pkt_src_dest_count": 1,
                    "pkt_dest_src_count": 0,
                    "start_time": p.timestamp - offset,
                    "end_time": p.timestamp - offset,
                    "bytes_src_dest_count": 0, # TODO
                    "bytes_dest_src_count": 0 # TODO
                }
            else:
                updated_info = {
                    "pkt_src_dest_count": connections[backward]["pkt_src_dest_count"],
                    "pkt_dest_src_count": connections[backward]["pkt_dest_src_count"] + 1,
                    "start_time": connections[backward]["start_time"],
                    "end_time": p.timestamp - offset,
                    "bytes_src_dest_count": connections[backward]["bytes_src_dest_count"], # TODO
                    "bytes_dest_src_count": connections[backward]["bytes_dest_src_count"] # TODO
                }
                connections[backward] = updated_info
        else:
            updated_info = {
                "pkt_src_dest_count": connections[forward]["pkt_src_dest_count"] + 1,
                "pkt_dest_src_count": connections[forward]["pkt_dest_src_count"],
                "start_time": connections[forward]["start_time"],
                "end_time": p.timestamp - offset,
                "bytes_src_dest_count": connections[forward]["bytes_src_dest_count"], # TODO
                "bytes_dest_src_count": connections[forward]["bytes_dest_src_count"] # TODO
            }
            connections[forward] = updated_info

    return connections

def round_time(timestamp):
    return round(timestamp, 6)

def output_report(packets):
    connections = collect_connections_info(packets)
    print("A) Total number of connections:", len(connections))
    print()
    print("-----------------------------")

    print("B) Connection's details")
    for i, (k, v) in enumerate(sorted(connections.items(), key=lambda item: item[1]["start_time"])):
        print(f'Connection {i + 1}:')
        print(f'Source Address: {k[0]}')
        print(f'Destination Address: {k[2]}')
        print(f'Source Port: {k[1]}')
        print(f'Destination Port: {k[3]}')
        print(f'Status: TODO')
        print(f'Start time: {round_time(v["start_time"])} seconds')
        print(f'End Time: {round_time(v["end_time"])} seconds')
        print(f'Duration: {round_time(v["end_time"] - v["start_time"])} seconds')
        print(f'Number of packets sent from Source to Destination: {v["pkt_src_dest_count"]}')
        print(f'Number of packets sent from Destination to Source: {v["pkt_dest_src_count"]}')
        print(f'Total number of packets: {v["pkt_src_dest_count"] + v["pkt_dest_src_count"]}')
        print(f'Number of data bytes sent from Source to Destination: {v["bytes_src_dest_count"]}')
        print(f'Number of data bytes sent from Destination to Source: {v["bytes_dest_src_count"]}')
        print(f'Total number of data bytes: {v["bytes_src_dest_count"] + v["bytes_dest_src_count"]}')
        print("END")
        print("++++++++++++++++++++++++++++++++")
    print()
    print("-----------------------------")

