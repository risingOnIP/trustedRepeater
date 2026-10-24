"""Offline tests for icmpSending.py.

Sample tcpdump lines are fed to the parsing and packet-building functions and
the resulting packets are inspected. Nothing is sent on the network: the one
test that exercises main() replaces scapy's send() with a mock.

Run from the repository root:

    python3 -m unittest discover -s tests -v
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import icmpSending  # noqa: E402
from scapy.all import ICMP, IP, Raw  # noqa: E402

# Lines in the format printed by tcpdump 4.99 with -nn -i any.
REQUEST_LINE = (
    "12:00:00.000000 eth0  In  IP 192.168.1.10 > 8.8.8.8: "
    "ICMP echo request, id 4321, seq 7, length 64"
)
REPLY_LINE = (
    "12:00:00.020000 eth0  In  IP 8.8.8.8 > 192.168.1.10: "
    "ICMP echo reply, id 4321, seq 7, length 64"
)
FIXED_NOW = 1_700_000_000.5


def expected_safe_payload():
    """The standard echo data: 8-byte timestamp plus the 0x08 to 0x37 pattern."""
    timestamp = int(FIXED_NOW - icmpSending.TIMESTAMP_OFFSET_SECONDS)
    return timestamp.to_bytes(8, "little") + bytes(range(0x08, 0x38))


class ParseTcpdumpFieldsTest(unittest.TestCase):
    def test_request_fields(self):
        fields = icmpSending.parse_tcpdump_fields(REQUEST_LINE.split())
        self.assertEqual(fields.source, "192.168.1.10")
        self.assertEqual(fields.destination, "8.8.8.8")
        self.assertEqual(fields.echo_type, "request")
        self.assertEqual(fields.ident, 4321)
        self.assertEqual(fields.seq, 7)

    def test_reply_fields(self):
        fields = icmpSending.parse_tcpdump_fields(REPLY_LINE.split())
        self.assertEqual(fields.source, "8.8.8.8")
        self.assertEqual(fields.destination, "192.168.1.10")
        self.assertEqual(fields.echo_type, "reply")
        self.assertEqual(fields.ident, 4321)
        self.assertEqual(fields.seq, 7)

    def test_short_line_is_rejected(self):
        with self.assertRaises(ValueError):
            icmpSending.parse_tcpdump_fields("12:00:00 eth0 In IP".split())

    def test_non_echo_line_is_rejected(self):
        line = (
            "12:00:00.000000 eth0 In IP 192.168.1.10 > 8.8.8.8: "
            "ICMP time exceeded in-transit, length 36 extra extra"
        )
        with self.assertRaises(ValueError):
            icmpSending.parse_tcpdump_fields(line.split())


class BuildPacketTest(unittest.TestCase):
    def test_request_packet(self):
        fields = icmpSending.parse_tcpdump_fields(REQUEST_LINE.split())
        packet = IP(bytes(icmpSending.build_packet(fields, now=FIXED_NOW)))

        self.assertEqual(packet[IP].src, "192.168.1.10")
        self.assertEqual(packet[IP].dst, "8.8.8.8")
        self.assertEqual(packet[ICMP].type, 8)
        self.assertEqual(packet[ICMP].code, 0)
        self.assertEqual(packet[ICMP].id, 4321)
        self.assertEqual(packet[ICMP].seq, 7)
        self.assertEqual(packet[Raw].load, expected_safe_payload())
        self.assertEqual(len(packet[Raw].load), 56)

    def test_reply_packet(self):
        fields = icmpSending.parse_tcpdump_fields(REPLY_LINE.split())
        packet = IP(bytes(icmpSending.build_packet(fields, now=FIXED_NOW)))
        expected_payload = expected_safe_payload()

        self.assertEqual(packet[IP].src, "8.8.8.8")
        self.assertEqual(packet[IP].dst, "192.168.1.10")
        self.assertEqual(packet[ICMP].type, 0)
        self.assertEqual(packet[ICMP].code, 0)
        self.assertEqual(packet[ICMP].id, 4321)
        self.assertEqual(packet[ICMP].seq, 7)
        self.assertEqual(packet[Raw].load, expected_payload)
        self.assertEqual(len(packet[Raw].load), 56)

    def test_safe_payload_uses_ping_pattern(self):
        payload = icmpSending.build_safe_payload(now=FIXED_NOW)
        self.assertEqual(payload[8:], bytes(range(0x08, 0x38)))

    def test_covert_payload_is_not_copied(self):
        # Simulates an ICMP tunnel: the captured request carried attacker data.
        # Only control fields reach build_packet(), so the regenerated payload
        # is the standard pattern and the original bytes cannot appear in it.
        covert = b"BEGIN-EXFIL:customer-records.csv".ljust(56, b"#")
        original = (
            IP(src="192.168.1.10", dst="8.8.8.8")
            / ICMP(type=8, id=4321, seq=7)
            / Raw(load=covert)
        )
        line = "12:00:00.000000 eth0  In  IP %s > %s: ICMP echo request, id %d, seq %d, length %d" % (
            original[IP].src,
            original[IP].dst,
            original[ICMP].id,
            original[ICMP].seq,
            len(original[ICMP]),
        )
        fields = icmpSending.parse_tcpdump_fields(line.split())
        packet = icmpSending.build_packet(fields, now=FIXED_NOW)

        self.assertEqual(packet[IP].src, original[IP].src)
        self.assertEqual(packet[IP].dst, original[IP].dst)
        self.assertEqual(packet[ICMP].id, original[ICMP].id)
        self.assertEqual(packet[ICMP].seq, original[ICMP].seq)
        self.assertEqual(len(packet[ICMP]), len(original[ICMP]))
        self.assertNotIn(b"EXFIL", bytes(packet))
        self.assertEqual(packet[Raw].load, expected_safe_payload())


class MainTest(unittest.TestCase):
    def test_main_sends_one_regenerated_packet(self):
        with mock.patch.object(icmpSending, "send") as fake_send, mock.patch(
            "sys.stdout"
        ):
            status = icmpSending.main(["--list"] + REQUEST_LINE.split())

        self.assertEqual(status, 0)
        fake_send.assert_called_once()
        packet = fake_send.call_args[0][0]
        self.assertEqual(packet[IP].dst, "8.8.8.8")
        self.assertEqual(packet[ICMP].id, 4321)

    def test_main_skips_unparseable_line(self):
        with mock.patch.object(icmpSending, "send") as fake_send, mock.patch(
            "sys.stdout"
        ), mock.patch("sys.stderr"):
            status = icmpSending.main(["--list", "not", "a", "packet"])

        self.assertEqual(status, 2)
        fake_send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
