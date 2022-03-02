def get_number_of_connections(packets):
    count = 0
    i = 0
    n = len(packets)
    while i < n:
        flags = packets[i].get_flags()
        if flags["SYN"] == 1:
            if i < n - 3 \
                and packets[i + 1].get_flags()["ACK"] == 1 and packets[i + 1].get_flags()["SYN"] == 1 \
                and packets[i + 2].get_flags()["ACK"] == 1:
                count += 1
                i += 3
            else:
                i += 1
        elif flags["RST"] == 1:
            count += 1
            i += 1
        else:
            i += 1
    return count
                

def output_report(packets):
    print(get_number_of_connections(packets))