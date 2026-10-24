#!/bin/bash
# Trusted Repeater: log ICMP echo traffic as text.
#
# Requires root (tcpdump). Captures ICMP echo requests (type 8) and echo
# replies (type 0) on all interfaces and appends one text line per packet to
# packetsStored.txt. The capture runs in the background.
echo > packetsStored.txt
tcpdump -nn -l --immediate-mode -i any "icmp[0] == 8 || icmp[0] == 0" >> packetsStored.txt &
