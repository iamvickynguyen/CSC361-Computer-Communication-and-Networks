import struct

MAGIC_NUMBER_SAME = b'\xa1\xb2\xc3\xd4' # big endian
MAGIC_NUMBER_SWAPPED = b'\xd4\xc3\xb2\xa1' # little endian

class Global_Header:
    def __init__(self, data):
        self.byte_order = self._get_magic_number_order(data[:4])

    def _get_magic_number_order(self, bytes):
        if bytes == MAGIC_NUMBER_SAME:
            return 'big'
        if bytes == MAGIC_NUMBER_SWAPPED:
            return 'little'
        # raise ValueError("Invalid magic number")
        return 'little'

class Packet_Header:
    def __init__(self, data, byte_order='big'):
        fmt = '>' if byte_order == 'big' else '<'
        self.ts_sec, self.ts_usec, self.incl_len, self.orig_len = struct.unpack_from(fmt + 'IIII', data)

class IP_Header:    
    def __init__(self):
        self.ihl = 0 #int
        self.total_len = 0 #int
        self.id = None #int
        self.flags = None #int
        self.fragment_offset = 0 #int
        self.ttl = 0 #int
        self.protocol = None #int
        self.src_ip = None #str
        self.dst_ip = None #str
        
    def set_ihl(self, buffer):
        result = struct.unpack('B', buffer)[0]
        self.ihl = (result & 15)*4

    def set_total_len(self, buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        self.total_len = num1+num2+num3+num4

    def set_id(self, buffer):
        self.id = struct.unpack('>H', buffer)[0]

    def set_fragment_offset(self, buffer):
        result = struct.unpack('>H', buffer)[0]
        self.flags = (result & 0b1111111111111111) >> 13
        self.fragment_offset = (result & 0b1111111111111)

    def set_ttl(self, buffer):
        self.ttl = struct.unpack('B', buffer)[0]

    def set_protocol(self, buffer):
        self.protocol = struct.unpack('B', buffer)[0]

    def set_src_ip(self, buffer):
        src_addr = struct.unpack('BBBB',buffer)
        self.src_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])

    def set_dst_ip(self, buffer):
        dst_addr = struct.unpack('BBBB',buffer)
        self.dst_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])
        

class UDP_Header:
    def __init__(self):
        self.src_port = None #int
        self.dst_port = None #int
        self.udp_length = None #int
        self.checksum = None #int

    def set_src_port(self, buffer):
        self.src_port = struct.unpack('>H', buffer)[0]

    def set_dst_port(self, buffer):
        self.dst_port = struct.unpack('>H', buffer)[0]

    def set_udp_length(self, buffer):
        self.udp_length = struct.unpack('>H', buffer)[0]

    def set_checksum(self, buffer):
        self.checksum = struct.unpack('>H', buffer)[0]


class ICMP_Header:
    def __init__(self):
        self.type = None #int
        self.code = None #int
        # TODO

    def set_type(self, buffer):
        self.type = struct.unpack('B', buffer)[0]

    def set_code(self, buffer):
        self.code = struct.unpack('B', buffer)[0]

    #TODO


class Packet:
    def __init__(self):
        self.ip_header = IP_Header()
        self.udp_header = UDP_Header()
        self.icmp_header = ICMP_Header()
        self.timestamp = 0
        self.packet_no = 0

    def set_ip_header(self, ip_header):
        self.ip_header = ip_header

    def set_udp_header(self, udp_header):
        self.udp_header = udp_header

    def set_icmp_header(self, icmp_header):
        self.icmp_header = icmp_header

    def set_timestamp(self, seconds, microseconds, orig_time):
        self.timestamp = round(seconds+microseconds*0.000001-orig_time,6)

    def set_packet_number(self, packet_no):
        self.packet_no = packet_no

    def __str__(self):
        return str(self.__class__) + ": <IP>" + str(self.ip_header.__dict__) + ": <UDP>" + str(self.udp_header.__dict__) + ": <ICMP>" + str(self.icmp_header.__dict__)


def parse_ip_header(data) -> IP_Header:
    ip_header = IP_Header()
    ip_header.set_ihl(data[:1])
    ip_header.set_total_len(data[2:4])
    ip_header.set_id(data[4:6])
    ip_header.set_fragment_offset(data[6:8])
    ip_header.set_ttl(data[8:9])
    ip_header.set_protocol(data[9:10])
    ip_header.set_src_ip(data[12:16])
    ip_header.set_dst_ip(data[16:])
    return ip_header

def parse_udp_header(data) -> UDP_Header:
    udp_header = UDP_Header()
    udp_header.set_src_port(data[:2])
    udp_header.set_dst_port(data[2:4])
    udp_header.set_udp_length(data[4:6])
    udp_header.set_checksum(data[6:])
    return udp_header

# TODO
def parse_icmp_header(data) -> ICMP_Header:
    icmp_header = ICMP_Header()
    icmp_header.set_type(data[:1])
    icmp_header.set_code(data[1:2])
    return icmp_header

def get_packet(data, pkt_number: int, pkt_header: Packet_Header) -> Packet:
    packet = Packet()
    packet.set_packet_number(pkt_number)
    packet.set_timestamp(pkt_header.ts_sec, pkt_header.ts_usec, 0)

    ip_header = parse_ip_header(data[14:14+20])
    packet.set_ip_header(ip_header)

    offset = 14 + ip_header.ihl
    if ip_header.protocol == 1:
        icmp_header = parse_icmp_header(data[offset:offset+8])
        packet.set_icmp_header(icmp_header)
        return packet
    elif ip_header.protocol == 17:
        udp_header = parse_udp_header(data[offset:offset+8])
        packet.set_udp_header(udp_header)
        return packet
    return None