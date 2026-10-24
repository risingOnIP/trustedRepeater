#!/bin/bash
# Trusted Repeater: capture and regenerate ICMP echo traffic.
#
# Run on the repeater host (192.168.5.3 in the lab) that receives ICMP
# redirected by the router's policy-based route. Requires root (tcpdump and
# raw packet sending) and Python 3 with scapy installed.
#
# Two capture processes run side by side:
#   1. A text capture of inbound ICMP echo requests and replies, written
#      line-buffered to stdout and piped line by line into icmpSending.py,
#      which builds and sends a regenerated packet with a known-safe payload.
#   2. A binary capture of the same ICMP echo traffic into save.pcap for later
#      review. This is the only process that writes the pcap file.
#
# Stop with Ctrl+C; the background regeneration loop is stopped on exit.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FILTER="icmp[0] == 8 || icmp[0] == 0"

tcpdump -Q in -nn -l --immediate-mode -i any "$FILTER" | while read -r packets
do
  # Word splitting is intentional: each tcpdump field becomes one argument.
  python3 "$SCRIPT_DIR/icmpSending.py" --list $packets
done &
REGEN_PID=$!
trap 'kill "$REGEN_PID" 2>/dev/null' EXIT

tcpdump "$FILTER" -w save.pcap
