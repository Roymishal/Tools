import sys
import time
import socket
import struct

from scapy.all import *


# convert methods options to deal with MAC and IP
def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

def mac2int(addr):
    return int(addr.replace(":", ""), 16)

def int2mac(addr):
    mac_hex = "{:012x}".format(addr)
    return ":".join(mac_hex[i:i + 2] for i in range(0, len(mac_hex), 2))

if __name__ == "__main__":
    mac = mac2int(sys.argv[1])
    ip = ip2int(sys.argv[2])
    n = int(sys.argv[3])
    interval_secs = float(sys.argv[4])
    output_path = sys.argv[5]

    packets = []

    # we loop (n) times based on the required value
    for i in range(n):
        # build packet using IP and MAC arguments increase their value by one
        pkt = Ether(src="22:22:22:22:22:22", dst=int2mac(mac+i), type=0x0806) / ARP(op="is-at", psrc="2.2.2.2", hwsrc="", pdst=int2ip(ip+i), hwdst="")
        # space the packets (interval_secs) secnonds
        pkt.time = int(time.time()) + i * interval_secs
        packets.append(pkt)

    wrpcap(output_path, packets)
