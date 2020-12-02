import struct
import socket
import binascii
import sys


class IPv6Packet:

    def __init__(self, ipv6_header, upper_layer_protocol, ethernet_frame):
        self.ipv6_header = ipv6_header
        self.upper_layer_protocol = upper_layer_protocol
        self.ethernet_frame = ethernet_frame


class IPv6Header:
    _version = 6
    _header_lenght = 40

    def __init__(self):

        self.version = self._version
        self.source_address = 0
        self.destination_address = 0
        self.traffic_class = 0
        self.flow_label = 0
        self.hop_limit = 0
        self.payload_length = 0
        self.next_header = 0
        self.new_data = 0

    def convert_to_ipaddress(self, mac_bytes):
        return socket.inet_ntop(socket.AF_INET6, mac_bytes).upper()

    def from_bytes(self, data):
        b = bytearray(data[:4])

        version = (b[0] >> 4) & 0x0F
        traffic_class = ((b[0] & 0x0F) << 4) | ((b[1] >> 4) & 0x0F)
        flow_label = ((b[1] & 0x0F) << 16) | (b[2] << 8) | b[3]

        payload_length = int(binascii.hexlify(data[4:6]).decode('ascii'), 16)
        next_header = data[6]
        hop_limit = data[7]
        src_addr = data[8:24]
        dst_addr = data[24:40]

        self.source_address = self.convert_to_ipaddress(src_addr)
        self.destination_address = self.convert_to_ipaddress(dst_addr)
        self.traffic_class = traffic_class
        self.flow_label = flow_label
        self.hop_limit = hop_limit
        self.payload_length = payload_length
        self.next_header = next_header
        self.new_data = data[40:]

    def get_next_header(self):
        return self.next_header, self.new_data



    def __repr__(self):
        return "\tSource: {} \n" \
               "\tDestination: {} \n" \
               "\tNext Header: {} \n" \
               "\tPayload Length: {} \n" \
               "\tHop Limit: {}, \n" \
               "\tTraffic Class: {} \n" \
               "\tFlow Label: {}".format(
            self.source_address, self.destination_address,
            self.next_header, self.payload_length, self.hop_limit,
            self.traffic_class, self.flow_label)


class UDPHeader:
    _header_length = 8

    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.payload_length = 0

    def from_bytes(self, data):
        self.src_port, self.dst_port, self.payload_length = struct.unpack('! H H 2x H', data[:8])

    def __repr__(self):
        return '\t\tSource Port: {} \n' \
               '\t\tDestination Port: {} \n' \
               '\t\tPayload Length: {} \n'.format(
                self.src_port, self.dst_port, self.payload_length)


class TCPHeader:
    _header_length = 8

    def __init__(self):
        self.src_port = 0
        self.dest_port = 0
        self.sequence = 0
        self.ack = 0
        self.flag_urg = 0
        self.flag_ack = 0
        self.flag_psh = 0
        self.flag_rst = 0
        self.flag_syn = 0
        self.flag_fin = 0
        self.p_data = 0

    def from_bytes(self, data):
        (self.src_port, self.dest_port, self.sequence, self.ack, offset_r_flags) = struct.unpack('! H H L L H', data[:14])
        offset = (offset_r_flags >> 12) * 4
        self.flag_urg = (offset_r_flags & 32) >> 5
        self.flag_ack = (offset_r_flags & 16) >> 4
        self.flag_psh = (offset_r_flags & 8) >> 3
        self.flag_rst = (offset_r_flags & 4) >> 2
        self.flag_syn = (offset_r_flags & 2) >> 1
        self.flag_fin = offset_r_flags & 1
        self.p_data = data[offset:]

    def __repr__(self):
        return '\t\tSource Port: {}\n' \
               '\t\tDestination Port: {}\n' \
               '\t\tSequence: {}\n' \
               '\t\tAcknowledgement: {}\n' \
               '\t\tPayload: {} bytes\n' \
               '\t\tFlags:\n' \
               '\t\t\tURG: {} \n' \
               '\t\t\tACK: {}\n'\
               '\t\t\tPSH: {}\n'\
               '\t\t\tRST: {}\n'\
               '\t\t\tSYN: {}\n'\
               '\t\t\tFIN: {}\n'.format(
                self.src_port, self.dest_port, self.sequence, self.ack, sys.getsizeof(self.p_data)-33,
                self.flag_urg, self.flag_ack, self.flag_psh, self.flag_rst, self.flag_syn, self.flag_fin
                )


class ICMPv6Header:

    def __init__(self):
        self.type = 0
        self.code = 0
        self.checksum = 0

    def from_bytes(self, data):
        self.type, self.code, self.checksum, x3, x4 = struct.unpack('! B B H H H', data[:8])


    def __repr__(self):
        return '\t\tType: {} \n' \
               '\t\tCode: {} \n' \
               '\t\tChecksome: {} \n'.format(
                self.type, self.code, self.checksum)
