#!/usr/bin/env python3
"""Regenerate a captured ICMP echo packet with the same control fields.

This is the packet generator of the Trusted Repeater. Outbound ICMP is
redirected to the repeater host by policy-based routing (see
config/router-r1.conf). The run script (run-icmpSending.sh) captures that
traffic with tcpdump and passes each text line to this script as a list of
whitespace-separated fields:

    python3 icmpSending.py --list <tcpdump line fields>

Expected tcpdump line (tcpdump 4.99 or later, options -nn -i any):

    12:00:00.000000 eth0 In IP 192.168.1.10 > 8.8.8.8: ICMP echo request, id 4321, seq 7, length 64

Field indices used (0-based, after splitting on whitespace):

    4   source address          192.168.1.10
    6   destination address     8.8.8.8:   (trailing ":" stripped)
    9   echo type               request,   (trailing "," stripped)
    11  identifier              4321,      (trailing "," stripped)
    13  sequence number         7,         (trailing "," stripped)

The original packet is never forwarded. A brand-new packet of the same type is
built from these control fields and sent instead:

    echo request: IP(src, dst) / ICMP(type 8, id, seq) / Raw(known-safe payload)
    echo reply:   IP(src, dst) / ICMP(type 0, id, seq) / Raw(known-safe payload)

The known-safe payload is the standard 56-byte echo data used by the Linux
ping utility: an 8-byte little-endian timestamp followed by the byte pattern
0x08 to 0x37. It is built without reading the original payload, so any
data hidden there is discarded by construction.

Parsing and building are separate from sending so that both can be tested
offline (see tests/test_icmp_sending.py). Sending requires root privileges.
"""

import argparse
import sys
import time
from dataclasses import dataclass
from typing import Optional, Sequence

from scapy.all import ICMP, IP, Raw, send

# Field positions in a whitespace-split tcpdump line (see module docstring).
SOURCE_INDEX = 4
DESTINATION_INDEX = 6
PROTOCOL_INDEX = 7
ECHO_INDEX = 8
TYPE_INDEX = 9
ID_INDEX = 11
SEQ_INDEX = 13

# Punctuation that tcpdump appends to some fields ("8.8.8.8:", "request,").
TRAILING_PUNCTUATION = ":,"

ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8

# Offset, in seconds, subtracted from the repeater clock when the payload
# timestamp is written, so that it aligns with the clock of the hosts in the
# sample topology. Set it to 0 to use the repeater clock unchanged.
TIMESTAMP_OFFSET_SECONDS = 330.854723498

# Known-safe echo data: the byte pattern 0x08 to 0x37 used by the Linux ping
# utility after its 8-byte timestamp.
ECHO_PATTERN = bytes(range(0x08, 0x38))


@dataclass(frozen=True)
class EchoFields:
    """Control fields extracted from one captured ICMP echo packet."""

    source: str
    destination: str
    echo_type: str  # "request" or "reply"
    ident: int
    seq: int


def _clean(field: str) -> str:
    """Remove the trailing ':' or ',' that tcpdump appends to a field."""
    return field.rstrip(TRAILING_PUNCTUATION)


def parse_tcpdump_fields(fields: Sequence[str]) -> EchoFields:
    """Extract echo control fields from a whitespace-split tcpdump line.

    Raises ValueError if the line does not match the expected layout.
    """
    if len(fields) <= SEQ_INDEX:
        raise ValueError(
            "expected at least %d fields, got %d: %r"
            % (SEQ_INDEX + 1, len(fields), list(fields))
        )
    if fields[PROTOCOL_INDEX] != "ICMP" or fields[ECHO_INDEX] != "echo":
        raise ValueError(
            "line is not an ICMP echo packet in the expected tcpdump format: %r"
            % list(fields)
        )

    echo_type = _clean(fields[TYPE_INDEX])
    if echo_type not in ("request", "reply"):
        raise ValueError("unsupported ICMP echo type: %r" % fields[TYPE_INDEX])

    return EchoFields(
        source=_clean(fields[SOURCE_INDEX]),
        destination=_clean(fields[DESTINATION_INDEX]),
        echo_type=echo_type,
        ident=int(_clean(fields[ID_INDEX])),
        seq=int(_clean(fields[SEQ_INDEX])),
    )


def build_safe_payload(now: Optional[float] = None) -> bytes:
    """Return the known-safe echo payload: timestamp plus ping pattern.

    The payload depends only on the clock, never on the captured packet.
    """
    if now is None:
        now = time.time()
    timestamp = int(now - TIMESTAMP_OFFSET_SECONDS)
    return timestamp.to_bytes(8, "little") + ECHO_PATTERN


def build_packet(fields: EchoFields, now: Optional[float] = None):
    """Build a new echo packet carrying the same control fields.

    The packet type follows the captured echo type, and the payload is always
    the known-safe payload from build_safe_payload(). Nothing is sent.
    """
    if fields.echo_type == "request":
        icmp_type = ICMP_ECHO_REQUEST
    else:
        icmp_type = ICMP_ECHO_REPLY
    return (
        IP(src=fields.source, dst=fields.destination)
        / ICMP(type=icmp_type, id=fields.ident, seq=fields.seq)
        / Raw(load=build_safe_payload(now))
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Parse one tcpdump line from the command line, then build and send it."""
    parser = argparse.ArgumentParser(
        description="Regenerate a captured ICMP echo packet with a known-safe payload."
    )
    parser.add_argument(
        "--list",
        nargs="*",
        required=True,
        help="the whitespace-separated fields of one tcpdump output line",
    )
    raw_fields = parser.parse_args(argv).list

    print(raw_fields)

    try:
        fields = parse_tcpdump_fields(raw_fields)
    except ValueError as error:
        print("Skipping line: %s" % error, file=sys.stderr)
        return 2

    print("Packet Type: %s" % fields.echo_type)
    print("Source: %s" % fields.source)
    print("Destination: %s" % fields.destination)
    print("ID: %d" % fields.ident)
    print("Sequence: %d" % fields.seq)
    print("\n\n\n")

    send(build_packet(fields))
    return 0


if __name__ == "__main__":
    sys.exit(main())
