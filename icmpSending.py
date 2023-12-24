#!/usr/bin/python3
import argparse
from scapy.all import *
import time

parser = argparse.ArgumentParser()
parser.add_argument("--list", nargs="*", default=["This", "is", "the", "default"])
packet = parser.parse_args().list

print(packet)

source = packet[4]
dest = packet[6]-(10-len(packet[6])-1)
packetID = packet[11]-(10-len(packet[11])-1)
packetSeq = packet[13]-(10-len(packet[13])-1)
packetType = packet[9]-(10-len(packet[9])-1)

print("Packet Type: %s" % packetType)
print("Source: " + source)
print("Destination: " + dest)
print("ID: " + packetID)
print("Sequence: " + packetSeq)

print("\n\n\n")

isRequest = False
if (packetType == "request"):
    isRequest = True

if (isRequest):
    send(IP(dst=dest, src=source)/ICMP(id=int(packetID), seq=int(packetSeq)))
else:
    #replying = IP(dst=dest, src=source)/ICMP(type=0, code=0, id=int(packetID), seq=int(packetSeq))
    #replying = replying/Raw(load="X"*32)
    #send(replying)
    t = time.time() - 330.854723498
    repl = (int(t)).to_bytes(8, 'little') + repl = (int(t)).to_bytes(8, 'little') + b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37'
    repl[ICMP].ts_ori = int(t)
    # repl.show()
    send(repl)
# "I" * 32 (0x49*32), "0" * 32 (0x30*32), "/01234567"
# send(IP(dst=source, src=dest)/ICMP(type=0, code=0))
