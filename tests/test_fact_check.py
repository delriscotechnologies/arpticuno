import ctypes
import unittest
from ctypes import wintypes

from arpticuno.sandbox import build_demo_payload
from arpticuno.scanner import _arp


class FakeSendARP:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.calls = 0
        self.buffer_sizes = []

    def __call__(self, destination, source, mac, length_ptr):
        self.calls += 1
        self.buffer_sizes.append(ctypes.sizeof(mac))
        status, value = next(self.replies)
        length = ctypes.cast(length_ptr, ctypes.POINTER(wintypes.ULONG))
        if status:
            length.contents.value = 0
            return status
        ctypes.memmove(ctypes.addressof(mac), bytes.fromhex(value.replace(":", "")), 6)
        length.contents.value = 6
        return 0


class ScannerTests(unittest.TestCase):
    def test_resolution_uses_documented_buffer_and_stops_after_success(self):
        send = FakeSendARP([(0, "aa:bb:cc:dd:ee:ff"), (0, "00:00:00:00:00:00")])
        host = _arp(send, "192.168.1.10", 0, 5)
        self.assertIsNotNone(host)
        self.assertEqual(host.mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(send.calls, 1)
        self.assertGreaterEqual(send.buffer_sizes[0], 8)

    def test_resolution_retries_only_after_failure(self):
        send = FakeSendARP([(123, ""), (0, "10:20:30:40:50:60")])
        host = _arp(send, "192.168.1.10", 0, 1)
        self.assertIsNotNone(host)
        self.assertEqual(host.mac, "10:20:30:40:50:60")
        self.assertEqual(send.calls, 2)

    def test_schema_uses_resolution_terminology(self):
        payload = build_demo_payload()
        self.assertEqual(payload["schema_version"], "2.0")
        self.assertIn("resolve_ms", payload["hosts"][0])
        self.assertNotIn("arp_rtt_ms", payload["hosts"][0])


if __name__ == "__main__":
    unittest.main()
