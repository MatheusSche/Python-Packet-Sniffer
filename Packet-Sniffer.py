#! /usr/local/bin/python3.5

import socket
import struct
import textwrap
import binascii
import sys

from Pcap.pcap import Pcap

from IPV6.ipv6 import IPv6Header, TCPHeader, UDPHeader, ICMPv6Header
from FileMode import file_mode, filter_packets

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

def capture_mode(file_name, number_of_packets):

    pcap = Pcap(file_name + '.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    count = 0
    while count <= number_of_packets:

        raw_data, addr = conn.recvfrom(65536)
        pcap.write(raw_data)

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
                print('\tProtocol: ICMPv6')
                icmpv6_header = ICMPv6Header()
                icmpv6_header.from_bytes(new_data)
                print(icmpv6_header)

            # TCP
            if next_header == 6:
                print('\tProtocol: TCP')
                tcp_header = TCPHeader()
                tcp_header.from_bytes(new_data)
                print(tcp_header)

            # UDP
            elif next_header == 17:
                print('\tProtocol: UDP')
                udp_header = UDPHeader()
                udp_header.from_bytes(new_data)
                print(udp_header)


        else:
            print('Ethernet Data:')
            print(format_output_line(DATA_TAB_1, data))

        count = count + 1

    pcap.close()



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



def capture_config():
    print('--------------------CONFIG----------------------------')
    file_name = input('Choose a name for the file .cap: ')
    packets_number = int(input('Number of packets captured: '))
    capture_mode(file_name=file_name, number_of_packets=packets_number)

def file_config():
    print('--------------------CONFIG-----------------------------')
    filename = input('Which file to open? ')
    filter_option = input('Add filter? Y/N: ')

    if filter_option.upper() == 'Y':
        print('---------------Filters----------------------------')
        print('--------------------------------------------------')
        print('1 - IPv4 UDP')
        print('2 - IPv4 TCP')
        print('3 - IPv4 ICMP')
        print('4 - IPv6 UDP')
        print('5 - IPv6 TCP')
        print('6 - IPv6 ICMP')

        filters = input('Enter the filter numbers: ')

        filter_packets(filename + '.pcap', filters)
    else:
        file_mode(filename+ '.pcap')



def menu():
    print('--------------------MENU----------------------------')
    print('1 - Start Capture Mode')
    print('2 - Start File Read Mode')

    option = input('Choose an option: ')

    if option == '1':
        capture_config()
    elif option == '2':
        file_config()
    else:
        print('Invalid Option')


menu()

