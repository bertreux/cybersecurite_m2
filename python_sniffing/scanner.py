# a lancer en mode admin

import ipaddress
import os
import socket
import struct
import sys
import threading
import time

# Subnet to target
SUBNET = '192.168.0.0/24'

# Magic string we'll check ICMP responses for
MESSAGE = 'PYTHONRULES!'


class IP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # Human-readable IP addresses
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # Protocol mapping
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        self.protocol = self.protocol_map.get(self.protocol_num, str(self.protocol_num))


class ICMP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]


def udp_sender():
    """
    Sprays out UDP datagrams with the magic message to the specified subnet.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for ip in ipaddress.ip_network(SUBNET).hosts():
            sender.sendto(bytes(MESSAGE, 'utf8'), (str(ip), 65212))


class Scanner:
    def __init__(self, host):
        self.host = host
        # Select protocol based on OS
        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP

        # Create the raw socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        self.socket.bind((host, 0))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Enable promiscuous mode on Windows
        if os.name == 'nt':
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    def sniff(self):
        """
        Start sniffing ICMP responses and check for the magic message.
        """
        hosts_up = set([f'{str(self.host)} *'])
        try:
            while True:
                # Read a packet
                raw_buffer = self.socket.recvfrom(65535)[0]

                # Parse the IP header from the first 20 bytes
                ip_header = IP(raw_buffer[0:20])

                # If it's an ICMP packet, we process it
                if ip_header.protocol == "ICMP":
                    offset = ip_header.ihl * 4
                    buf = raw_buffer[offset:offset + 8]

                    # Parse ICMP header
                    icmp_header = ICMP(buf)

                    # Check for ICMP Type 3 and Code 3 (Destination Unreachable)
                    if icmp_header.type == 3 and icmp_header.code == 3:
                        src_ip = ipaddress.ip_address(ip_header.src_address)

                        # If the source IP is within our target subnet
                        if src_ip in ipaddress.IPv4Network(SUBNET):

                            # Check if the packet contains our magic message
                            if raw_buffer[len(raw_buffer) - len(MESSAGE):] == bytes(MESSAGE, 'utf8'):
                                tgt = str(ip_header.src_address)

                                # Avoid printing the host that sent the message
                                if tgt != self.host and tgt not in hosts_up:
                                    hosts_up.add(tgt)
                                    print(f'Host Up: {tgt}')

        except KeyboardInterrupt:
            # Handle Ctrl-C and print a summary of hosts up
            if os.name == 'nt':
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

            print('\nUser interrupted.')
            if hosts_up:
                print(f'\nSummary: Hosts up on {SUBNET}')
                for host in sorted(hosts_up):
                    print(f'{host}')
            print('')
            sys.exit()


if __name__ == '__main__':
    # If a host is provided via command-line argument, use it; otherwise, default to 192.168.1.203
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '' # adresse ip local

    # Initialize the scanner
    s = Scanner(host)

    # Start the UDP sender in a separate thread
    time.sleep(5)  # Wait for 5 seconds before sending packets
    t = threading.Thread(target=udp_sender)
    t.start()

    # Start sniffing for ICMP responses
    s.sniff()