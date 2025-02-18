# a lancer en mode admin

import socket
import logging
import json
from datetime import datetime

# Host to listen on (the IP address of your machine)
HOST = '0.0.0.0'

# Set up logging
logging.basicConfig(filename='sniffer.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def save_packet_to_json(data):
    """Save captured packet data to a JSON file."""
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f"packet_{timestamp}.json"

    packet_data = {
        "timestamp": timestamp,
        "data": data
    }

    with open(filename, 'w') as json_file:
        json.dump(packet_data, json_file, indent=4)

    logging.info(f"Packet saved to {filename}")

def main():
    sniffer = None  # Define sniffer variable initially as None

    try:
        # On Linux, use IPPROTO_ICMP for ICMP packets (as it's common for network sniffing)
        socket_protocol = socket.IPPROTO_ICMP
        logging.info("Running on a non-Windows system, using IPPROTO_ICMP")

        # Create raw socket and bind it to the HOST
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        sniffer.bind((HOST, 0))
        logging.info(f"Socket bound to {HOST}")

        # Include the IP header in the capture
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        logging.info("Socket option IP_HDRINCL set")

        # Read one packet
        logging.info("Waiting for a packet...")
        packet, addr = sniffer.recvfrom(65565)
        logging.info(f"Packet received from {addr}")

        # Save packet to JSON file
        save_packet_to_json(packet.hex())

    except Exception as e:
        logging.error(f"An error occurred: {e}")

    finally:
        if sniffer:  # Check if sniffer is not None before closing
            sniffer.close()
            logging.info("Socket closed")

if __name__ == '__main__':
    main()