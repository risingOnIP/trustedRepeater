#!/bin/bash

echo > save.pcap
tcpdump -Q in -nn -l --immediate-mode -i any "icmp[0] == 8 || icmp[0] == 0" -w save.pcap | while read packets
do
  python3 icmpSending.py --list $packets
done & tcpdump -X "icmp[0] == 8 || icmp[0] == 0" -w save.pcap
