def round_time(timestamp):
    return round(timestamp, 6)
    
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
                    "bytes_src_dest_count": p.get_data_bytes(),
                    "bytes_dest_src_count": 0,
                    "syn": p.get_flags()["SYN"],
                    "fin": p.get_flags()["FIN"],
                    "rst": p.get_flags()["RST"]
                }
            else:
                updated_info = {
                    "pkt_src_dest_count": connections[backward]["pkt_src_dest_count"],
                    "pkt_dest_src_count": connections[backward]["pkt_dest_src_count"] + 1,
                    "start_time": connections[backward]["start_time"],
                    "end_time": connections[backward]["end_time"] if connections[backward]["fin"] == 1 else p.timestamp - offset,
                    "bytes_src_dest_count": connections[backward]["bytes_src_dest_count"], # TODO
                    "bytes_dest_src_count": connections[backward]["bytes_dest_src_count"] + p.get_data_bytes(),
                    "syn": connections[backward]["syn"] + p.get_flags()["SYN"],
                    "fin": connections[backward]["fin"] + p.get_flags()["FIN"],
                    "rst": connections[backward]["rst"] + p.get_flags()["RST"]
                }
                connections[backward] = updated_info
        else:
            updated_info = {
                "pkt_src_dest_count": connections[forward]["pkt_src_dest_count"] + 1,
                "pkt_dest_src_count": connections[forward]["pkt_dest_src_count"],
                "start_time": connections[forward]["start_time"],
                "end_time": connections[forward]["end_time"] if connections[forward]["fin"] == 1 else p.timestamp - offset,
                "bytes_src_dest_count": connections[forward]["bytes_src_dest_count"] + p.get_data_bytes(),
                "bytes_dest_src_count": connections[forward]["bytes_dest_src_count"],
                "syn": connections[forward]["syn"] + p.get_flags()["SYN"],
                "fin": connections[forward]["fin"] + p.get_flags()["FIN"],
                "rst": connections[forward]["rst"] + p.get_flags()["RST"]
            }
            connections[forward] = updated_info

    return connections

def get_complete_connetions(connections):
    return list(filter(lambda conn: conn['syn'] > 0 and conn['fin'] > 0, connections))

def count_reset_connections(connections):
    return sum(map(lambda conn: min(1, conn['rst']), connections))

def count_not_ended_connections(connections):
    return sum(map(lambda conn: min(1, conn['syn']) - min(1, conn['fin']), connections))

def get_min_duration(connections):
    return round_time(min(map(lambda conn: conn["end_time"] - conn["start_time"], connections)))

def get_max_duration(connections):
    return round_time(max(map(lambda conn: conn["end_time"] - conn["start_time"], connections)))

def get_mean_duration(connections):
    l = list(map(lambda conn: conn["end_time"] - conn["start_time"], connections))
    return round_time(sum(l)/len(l))

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
        print(f'Status: S{v["syn"]}F{v["fin"]}{"/R" if v["rst"] > 0 else ""}')
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

    complete_connections = get_complete_connetions(connections.values())
    print("C) General")
    print(f'Total number of complete TCP connections: {len(complete_connections)}')
    print(f'Number of reset TCP connections: {count_reset_connections(connections.values())}')
    print(f'Number of TCP connections that were still open when the trace capture ended: {count_not_ended_connections(connections.values())}')

    print()
    print("-----------------------------")
    print("D) Complete TCP connections")
    print(f'Minimum time duration: {get_min_duration(complete_connections)} seconds') # FIXME
    print(f'Mean time duration: {get_mean_duration(complete_connections)} seconds')
    print(f'Maximum time duration: {get_max_duration(complete_connections)} seconds')
    print()
    print("Minimum RTT value: TODO")
    print("Mean RTT value: TODO seconds")
    print("Maximum RTT value: TODO seconds")
    print()
    print("Minimum number of packets including both send/received: TODO")
    print("Mean number of packets including both send/received: TODO")
    print("Maximum number of packets including both send/received: TODO")
    print()
    print("Minimum receive window size including both send/received: TODO bytes")
    print("Mean receive window size including both send/received: TODO bytes")
    print("Maximum receive window size including both send/received: TODO bytes")
