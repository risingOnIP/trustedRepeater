#!/bin/bash
echo > packetsStored.txt
tcpdump -nn -l --immediate-mode -i any "icmp[0] == 8 || icmp[0] == 0" >> packetsStored.txt &
