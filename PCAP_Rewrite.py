import sys
from scapy.all import *

if __name__ == "__main__":
    mac = sys.argv[1]
    ip = sys.argv[2]
    port = sys.argv[3]
    input_path = sys.argv[4]
    output_path = sys.argv[5]

    packets = rdpcap(input_path)

    for pkt in packets:
        if Ether in pkt:
            pkt[Ether].src = mac
        if IP in pkt:
            pkt[IP].src = ip
        if TCP in pkt:
            pkt[TCP].sport = int(port)
        if UDP in pkt:
            pkt[UDP].sport = int(port)

    wrpcap(output_path, packets)