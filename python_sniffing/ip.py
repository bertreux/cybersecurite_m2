# a lancer en mode admin

import ipaddress
import os
import socket
import struct
import sys

class IP:
    def __init__(self, buff=None):
        # Unpack the IP header from the buffer
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4  # Extract version (4 bits)
        # The typical way you get the high-order nybble of a byte is to right-shift the byte by four places, which is the equivalent of prepending four zeros to the front of the byte, causing the last four bits to fall off
        self.ihl = header[0] & 0xF  # Internet Header Length (4 bits)
        self.tos = header[1]  # Type of Service
        self.len = header[2]  # Total Length
        self.id = header[3]  # Identification
        self.offset = header[4]  # Fragment Offset
        self.ttl = header[5]  # Time to Live
        self.protocol_num = header[6]  # Protocol
        self.sum = header[7]  # Header checksum
        self.src = header[8]  # Source IP
        self.dst = header[9]  # Destination IP

        # Human-readable IP addresses
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # Map protocol numbers to protocol names (ICMP, TCP, UDP)
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        self.protocol = self.protocol_map.get(self.protocol_num, str(self.protocol_num))

    def __repr__(self):
        return (f"IP(version={self.ver}, ihl={self.ihl}, tos={self.tos}, len={self.len}, "
                f"id={self.id}, offset={self.offset}, ttl={self.ttl}, protocol={self.protocol}, "
                f"checksum={self.sum}, src_address={self.src_address}, dst_address={self.dst_address})")


def sniff(host):
    # Define the socket protocol based on the OS
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    # Create a raw socket
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

    # Bind to the host and set the socket option to include the IP headers
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Enable promiscuous mode for Windows
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        while True:
            # Capture raw packets
            raw_buffer = sniffer.recvfrom(65535)[0]

            # Extract the IP header from the first 20 bytes
            ip_header = IP(raw_buffer[0:20])

            # Print protocol and source/destination IPs
            print(f"Protocol: {ip_header.protocol} {ip_header.src_address} -> {ip_header.dst_address}")

    except KeyboardInterrupt:
        # Disable promiscuous mode on Windows if interrupted
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit()

if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = ''  # adresse ip local

    sniff(host)