import io
import socket
import unittest
from unittest.mock import patch

from dh_tux_initialize.discovery import (
    DEFAULT_SCAN_ROUNDS,
    DISCOVER_BROADCAST,
    DISCOVER_GROUP,
    DISCOVER_PORT,
    DiscoveredDevice,
    discover,
)
from dh_tux_initialize.protocol import encode_frame


class FakeSocket:
    def __init__(self, replies, clock):
        self.replies = sorted(replies, key=lambda reply: reply[0])
        self.clock = clock
        self.options = []
        self.sent = []
        self.timeouts = []
        self.current_timeout = None
        self.bound = None
        self.closed = False

    def setsockopt(self, level, option, value):
        self.options.append((level, option, value))

    def bind(self, address):
        self.bound = address

    def sendto(self, data, address):
        self.sent.append((data, address, self.clock.now))

    def settimeout(self, timeout):
        self.current_timeout = timeout
        self.timeouts.append(timeout)

    def recvfrom(self, _size):
        wait_deadline = self.clock.now + self.current_timeout
        if self.replies and self.replies[0][0] <= wait_deadline:
            at, datagram, sender = self.replies.pop(0)
            self.clock.now = max(self.clock.now, at)
            return datagram, sender
        self.clock.now = wait_deadline
        raise socket.timeout

    def close(self):
        self.closed = True


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now


def make_reply(
    *, at=0.05, mac=None, serial=None, ip="192.0.2.20", model="IPC-Test", init=None
):
    info = {"DeviceType": model}
    if mac is not None:
        info["Mac"] = mac
    if serial is not None:
        info["SerialNo"] = serial
    if init is not None:
        info["Init"] = init
    info["IPv4Address"] = {"IPAddress": ip}
    payload = {"method": "client.notifyDevInfo", "params": {"deviceInfo": info}}
    return at, encode_frame(payload), (ip, 37810)


class DiscoveryProbeTests(unittest.TestCase):
    def run_discovery(self, replies, *, debug=False, timeout=None, rounds=None):
        clock = FakeClock()
        fake_socket = FakeSocket(replies, clock)
        debug_stream = io.StringIO()
        expected_rounds = rounds if rounds is not None else DEFAULT_SCAN_ROUNDS
        with patch(
            "dh_tux_initialize.discovery.socket.socket",
            return_value=fake_socket,
        ) as socket_factory:
            with patch(
                "dh_tux_initialize.discovery.time.monotonic",
                side_effect=clock.monotonic,
            ):
                options = {"debug": debug, "debug_stream": debug_stream}
                if timeout is not None:
                    options["timeout"] = timeout
                if rounds is not None:
                    options["rounds"] = rounds
                devices = discover(**options)

        self.assertEqual(socket_factory.call_count, 1)
        self.assertEqual(
            [address for _frame, address, _at in fake_socket.sent],
            [
                (address, DISCOVER_PORT)
                for _ in range(expected_rounds)
                for address in (DISCOVER_GROUP, DISCOVER_BROADCAST)
            ],
        )
        self.assertTrue(
            all(
                frame == fake_socket.sent[0][0]
                for frame, _address, _at in fake_socket.sent
            )
        )
        self.assertIn(
            (socket.SOL_SOCKET, socket.SO_BROADCAST, 1),
            fake_socket.options,
        )
        self.assertTrue(fake_socket.closed)
        return devices, fake_socket, debug_stream.getvalue(), clock

    def test_returns_multicast_only_reply(self):
        devices, _fake_socket, _debug_output, _clock = self.run_discovery(
            [make_reply(mac="02:00:00:00:00:02", serial="TESTSERIAL-MULTICAST")]
        )

        self.assertEqual([device.serial_number for device in devices], ["TESTSERIAL-MULTICAST"])
        self.assertEqual(devices[0].discovery_sources, frozenset({"quick"}))

    def test_returns_broadcast_only_reply(self):
        devices, _fake_socket, _debug_output, _clock = self.run_discovery(
            [make_reply(mac="02:00:00:00:00:03", serial="TESTSERIAL-BROADCAST")]
        )

        self.assertEqual([device.serial_number for device in devices], ["TESTSERIAL-BROADCAST"])

    def test_distinct_ip_endpoints_remain_separate_even_with_same_mac(self):
        devices, _fake_socket, _debug_output, _clock = self.run_discovery(
            [
                make_reply(
                    mac="02:00:00:00:00:08",
                    serial="TESTSERIAL-FIRST",
                    ip="192.0.2.20",
                    model="IPC-Multicast",
                ),
                make_reply(
                    mac="0200.0000.0008",
                    serial="TESTSERIAL-SECOND",
                    ip="192.0.2.21",
                    model="IPC-Broadcast",
                ),
            ]
        )

        self.assertEqual(len(devices), 2)
        self.assertEqual(devices[0].model, "IPC-Multicast")

    def test_merges_mixed_multicast_and_broadcast_replies(self):
        devices, fake_socket, debug_output, _clock = self.run_discovery(
            [
                make_reply(
                    mac="02:00:00:00:00:02",
                    serial="TESTSERIAL-MULTICAST",
                    ip="192.0.2.20",
                ),
                make_reply(
                    mac="02:00:00:00:00:03",
                    serial="TESTSERIAL-BROADCAST",
                    ip="192.0.2.21",
                ),
            ],
            debug=True,
        )

        self.assertEqual(
            [device.serial_number for device in devices],
            ["TESTSERIAL-MULTICAST", "TESTSERIAL-BROADCAST"],
        )
        self.assertIn(f"TX multicast {DISCOVER_GROUP}:{DISCOVER_PORT}", debug_output.splitlines())
        self.assertIn(
            f"TX broadcast {DISCOVER_BROADCAST}:{DISCOVER_PORT}",
            debug_output.splitlines(),
        )
        self.assertEqual(len(fake_socket.sent), 2 * DEFAULT_SCAN_ROUNDS)
        for (_frame, _address, actual), expected in zip(
            fake_socket.sent,
            [0.0, 0.05, 0.5, 0.55, 1.0, 1.05],
        ):
            self.assertAlmostEqual(actual, expected)
        self.assertIn(f"Probe burst {DEFAULT_SCAN_ROUNDS}/{DEFAULT_SCAN_ROUNDS}", debug_output.splitlines())
        self.assertIn("Quick scan: 2.50 s", debug_output.splitlines())
        self.assertIn("Probe bursts: 3", debug_output.splitlines())
        self.assertIn("Unique DHIP devices: 2", debug_output.splitlines())
        self.assertIn("Uninitialized devices: 0", debug_output.splitlines())

    def test_debug_timing_counts_uninitialized_replies(self):
        devices, _fake_socket, debug_output, _clock = self.run_discovery(
            [make_reply(mac="02:00:00:00:00:01", init=3733)],
            debug=True,
        )

        self.assertEqual(len(devices), 1)
        self.assertIn("Quick scan: 2.50 s", debug_output.splitlines())
        self.assertIn("Probe bursts: 3", debug_output.splitlines())
        self.assertIn("Unique DHIP devices: 1", debug_output.splitlines())
        self.assertIn("Uninitialized devices: 1", debug_output.splitlines())

    def test_uses_serial_then_ip_when_mac_is_unavailable(self):
        devices, _fake_socket, _debug_output, _clock = self.run_discovery(
            [
                make_reply(serial="TESTSERIAL-SAME", ip="192.0.2.20"),
                make_reply(serial="testserial-same", ip="192.0.2.21"),
                make_reply(ip="192.0.2.30"),
                make_reply(ip="192.0.2.30"),
            ]
        )

        self.assertEqual(len(devices), 3)

    def test_unions_device_subsets_received_across_probe_rounds(self):
        devices, _fake_socket, debug_output, _clock = self.run_discovery(
            [
                make_reply(at=0.15, mac="02:00:00:00:00:04", serial="TESTSERIAL001", ip="192.0.2.20"),
                make_reply(at=0.45, mac="02:00:00:00:00:05", serial="TESTSERIAL002", ip="192.0.2.21"),
                make_reply(at=0.75, mac="02:00:00:00:00:06", serial="TESTSERIAL003", ip="192.0.2.22"),
                make_reply(at=1.05, mac="02:00:00:00:00:07", serial="TESTSERIAL004", ip="192.0.2.23"),
            ],
            debug=True,
            timeout=4.0,
            rounds=4,
        )

        self.assertEqual(
            [device.serial_number for device in devices],
            ["TESTSERIAL001", "TESTSERIAL002", "TESTSERIAL003", "TESTSERIAL004"],
        )
        self.assertIn("Unique DHIP devices: 4", debug_output.splitlines())


class DiscoveredDeviceTests(unittest.TestCase):
    def test_reads_common_dahua_fields_and_uses_reported_ip(self):
        message = {
            "mac": "02:00:00:00:00:08",
            "params": {
                "deviceInfo": {
                    "Mac": "02:00:00:00:00:08",
                    "IPv4Address": {"IPAddress": "192.0.2.20"},
                    "DeviceType": "IPC-Test-Camera",
                    "SerialNo": "TESTSERIAL002",
                    "Version": "2.800.1",
                    "Init": 1162,
                }
            },
        }
        device = DiscoveredDevice(message["params"]["deviceInfo"], message, "192.0.2.99")

        self.assertEqual(device.mac, "02:00:00:00:00:08")
        self.assertEqual(device.ipv4, "192.0.2.20")
        self.assertEqual(device.model, "IPC-Test-Camera")
        self.assertEqual(device.serial_number, "TESTSERIAL002")
        self.assertEqual(device.firmware, "2.800.1")
        self.assertEqual(device.init_value, 1162)

    def test_falls_back_to_source_ip_and_keeps_zero_init(self):
        info = {"DeviceType": "IPC", "Init": 0}
        device = DiscoveredDevice(info, {}, "192.0.2.10")

        self.assertEqual(device.ipv4, "192.0.2.10")
        self.assertEqual(device.init_value, 0)

    def test_distinguishes_missing_init_from_explicit_null(self):
        absent = DiscoveredDevice({"DeviceType": "IPC"}, {}, "192.0.2.10")
        explicit_null = DiscoveredDevice({"DeviceType": "IPC", "Init": None}, {}, "192.0.2.10")

        self.assertFalse(absent.has_init_value)
        self.assertTrue(explicit_null.has_init_value)

    def test_decodes_initialization_status_from_low_two_bits(self):
        examples = {
            3733: "Uninitialized",
            3734: "Initialized",
            154: "Initialized",
            1162: "Initialized",
            0: "Legacy",
            4: "Legacy",
            3: "Unknown",
            3735: "Unknown",
        }

        for init_value, expected in examples.items():
            with self.subTest(init_value=init_value):
                device = DiscoveredDevice({"Init": init_value}, {}, "192.0.2.10")
                self.assertEqual(device.initialization_status, expected)

    def test_missing_or_non_integer_init_is_unclear(self):
        examples = [
            {},
            {"Init": None},
            {"Init": "3733"},
            {"Init": 3733.0},
            {"Init": False},
            {"Init": True},
        ]

        for info in examples:
            with self.subTest(info=info):
                device = DiscoveredDevice(info, {}, "192.0.2.10")
                self.assertEqual(device.initialization_status, "Unknown")


if __name__ == "__main__":
    unittest.main()
