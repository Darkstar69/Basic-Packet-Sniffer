from scapy.all import sniff, IP, UDP, TCP
from scapy.all import *
from scapy.layers import *
import logging

def packet_sniffer(packet):
    if IP in packet:
        ipObj = packet[IP]
                
        if TCP in packet:
            tcpObj = packet[TCP]
            logging.info("TCP packets monitoring")
            logging.info(f"Source > {ipObj.src}:{tcpObj.sport}")
            logging.info(f"Destination > {ipObj.dst}:{tcpObj.dport}")
            
        if UDP in packet:
            udpObj = packet[UDP]
            logging.info("TCP packets monitoring")
            logging.info(f"Source > {ipObj.src}:{udpObj.sport}")
            logging.info(f"Destination > {ipObj.dst}:{udpObj.dport}")
            
        if Raw in packet:            
            logging.info(f"Payload > {bytes(ipObj[Raw])}\n")
        else:
            logging.info("No Payload found :(\n")
            
def sniffer(num):
    logging.basicConfig(filename="logs.log", level=logging.INFO)
    logging.info("Packet sniffer started\n")
    logging.info("-"*70)
    sniff(prn=packet_sniffer, count=num)
            
