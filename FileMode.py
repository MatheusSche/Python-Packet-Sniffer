#! /usr/local/bin/python3.5

import socket
import struct
import textwrap
import binascii
import sys
import dpkt
from IPV6.ipv6 import IPv6Header, TCPHeader, UDPHeader, ICMPv6Header
from Pcap.pcap import Pcap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

def file_mode(file_name):

    for ts, pkt in dpkt.pcap.Reader(open(file_name, 'rb')):

        raw_data = pkt
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        print('\nEthernet Frame: ')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_Packet(data)
            print(TAB_1 + "IPV4 Packet:")
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(TAB_3 + 'protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            # ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_type, code, checksum))
                print(TAB_2 + 'ICMP Data:')
                print(format_output_line(DATA_TAB_3, data))

            # TCP
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = struct.unpack(
            '! H H L L H H H H H H', raw_data[:24])
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(flag_urg, flag_ack, flag_psh))
                print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(flag_rst, flag_syn, flag_fin))

                if len(data) > 0:
                    # HTTP
                    if src_port == 80 or dest_port == 80:
                        print(TAB_2 + 'HTTP Data:')
                        try:
                            http = HTTP(data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print(format_output_line(DATA_TAB_3, data))
                    else:
                        print(TAB_2 + 'TCP Data:')
                        print(format_output_line(DATA_TAB_3, data))
            # UDP
            elif proto == 17:
                src_port, dest_port, length, data = udp_seg(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))

            # Other IPv4
            else:
                print(TAB_1 + 'Other IPv4 Data:')
                print(format_output_line(DATA_TAB_2, data))

        # must be IPv6 traffic
        elif eth_proto == 56710:
            print('\nEthernet Protocol: IPv6')
            header = IPv6Header()
            header.from_bytes(data)
            next_header, new_data = header.get_next_header()
            print(header)

            #ICMP
            if next_header == 58:
                print('\tProtocol: ICMPV6')
                icmpv6_header = ICMPv6Header()
                icmpv6_header.from_bytes(new_data)
                print(icmpv6_header)

            # TCP
            if next_header == '6x':
                print('\tProtocol: TCP')
                tcp_header = TCPHeader()
                tcp_header.from_bytes(new_data)
                print(tcp_header)

            # UDP
            elif next_header == 'x17':
                print('\tProtocol: UDP')
                udp_header = UDPHeader()
                udp_header.from_bytes(new_data)
                print(udp_header)

        else:
            print('Ethernet Data:')
            print(format_output_line(DATA_TAB_1, data))


# Unpack Ethernet Frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Format MAC Address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

# Unpack IPv4 Packets Recieved
def ipv4_Packet(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]


# Returns Formatted IP Address
def ipv4(addr):
    return '.'.join(map(str, addr))


# Unpacks for any ICMP Packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpacks for any UDP Packet
def udp_seg(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# Formats the output line
def format_output_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size-= 1
            return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


def filter_packets(filename, filters):

    F_IPV4_UDP = 1
    F_IPV4_TCP = 2
    F_IPV4_ICMP = 3
    F_IPV6_UDP = 4
    F_IPV6_TCP = 5
    F_IPV6_ICMP = 6

    FILTERS_LIST = []
    for c in filters:
        FILTERS_LIST.append(int(c))

    filtered_file = Pcap('filtered.pcap')

    for ts, pkt in dpkt.pcap.Reader(open(filename, 'rb')):

        raw_data = pkt
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        #ipv4 packet
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_Packet(data)

            # ICMP
            if proto == 1 and F_IPV4_ICMP in FILTERS_LIST:
                filtered_file.write(raw_data)
            # TCP
            elif proto == 6 and F_IPV4_TCP in FILTERS_LIST:
               filtered_file.write(raw_data)
            # UDP
            elif proto == 17 and F_IPV4_UDP in FILTERS_LIST:
                filtered_file.write(raw_data)

        # must be IPv6 traffic
        elif eth_proto == 56710:
            print('\nEthernet Protocol: IPv6')
            header = IPv6Header()
            header.from_bytes(data)
            next_header, new_data = header.get_next_header()

            #ICMP
            if next_header == 58 and F_IPV6_ICMP in FILTERS_LIST:
                filtered_file.write(raw_data)

            # TCP
            if next_header == 6 and F_IPV6_TCP in FILTERS_LIST:
                filtered_file.write(raw_data)

            # UDP
            elif next_header == 17 and F_IPV6_UDP in FILTERS_LIST:
                filtered_file.write(raw_data)

    filtered_file.close()

    file_mode('filtered.pcap')




