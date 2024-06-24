from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP
from scapy.layers.inet import ICMP
from scapy.layers.dhcp import BOOTP
from scapy.layers import *
import logging


def packet_sniffer(packet):
    if packet.haslayer(ARP):
        logging.info(f"ARP packet: {packet[ARP].op} {packet[ARP].hwsrc} -> {packet[ARP].hwdst}")
        if packet.haslayer(Raw):
            logging.info(f"ARP payload: {packet[Raw].load}")
    elif packet.haslayer(ICMP):
        logging.info(f"ICMP packet: type={packet[ICMP].type} code={packet[ICMP].code} from {packet[IP].src} to {packet[IP].dst}")
        if packet.haslayer(Raw):
            logging.info(f"ICMP payload: {packet[Raw].load}")
    elif packet.haslayer(BOOTP):
        logging.info(f"BOOTP packet: {packet[BOOTP].op} from {packet[IP].src} to {packet[IP].dst}")
        if packet.haslayer(Raw):
            logging.info(f"BOOTP payload: {packet[Raw].load}")


def sniffer(logfilename, num):
    logging.basicConfig(filename=logfilename+".log", level=logging.INFO)
    logging.info("Packet sniffer started")
    sniff(filter="arp or icmp or (udp and (port 67 or port 68))", prn=packet_sniffer, count=num)
