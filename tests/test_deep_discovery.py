import json
import ipaddress
import socket
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from dh_tux_initialize.discovery import (
    DISCOVER_PORT,
    DiscoveredDevice,
    merge_devices,
)
from dh_tux_initialize.diagnostic_discovery import direct_probe
from dh_tux_initialize.deep_discovery import (
    active_ipv4_networks,
    deep_discover,
    enrich_onvif_devices,
    probe_fallback,
)
from dh_tux_initialize.ip_ranges import parse_ipv4_range
from dh_tux_initialize.protocol import decode_json_datagram, encode_frame


def make_device(mac, ip, *, serial="TESTSERIAL001", source="quick"):
    info = {
        "Mac": mac,
        "SerialNo": serial,
        "DeviceType": "IPC-Test",
        "IPv4Address": {"IPAddress": ip},
        "Init": 1,
    }
    message = {"params": {"deviceInfo": info}}
    return DiscoveredDevice(
        info,
        message,
        ip,
        frozenset({source}),
        identity_sources={
            "model": "dhip",
            "mac": "dhip",
            "serial": "dhip",
            "init": "dhip",
        },
        valid_dhip_identity=True,
        dahua_verified=True,
    )


def make_datagram(mac, ip, serial):
    return encode_frame(
        {
            "method": "client.notifyDevInfo",
            "params": {
                "deviceInfo": {
                    "Mac": mac,
                    "SerialNo": serial,
                    "DeviceType": "IPC-Deep",
                    "IPv4Address": {"IPAddress": ip},
                    "Init": 2,
                }
            },
        }
    )


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now


class ReplySocket:
    def __init__(self, replies, sent):
        self.replies = replies
        self.sent = sent
        self.target = None
        self.current_timeout = None
        self.closed = False
        self.blocking = True
        self.port = DISCOVER_PORT
        self.options = []

    def setsockopt(self, *args):
        self.options.append(args)

    def bind(self, _address):
        pass

    def getsockname(self):
        return ("10.42.0.10", 41000)

    def connect(self, address):
        self.target = address[0]
        self.port = address[1]

    def setblocking(self, blocking):
        self.blocking = blocking

    def fileno(self):
        return id(self) & 0x7fffffff

    def send(self, datagram):
        self.sent.append((datagram, (self.target, self.port)))

    def sendto(self, datagram, address):
        self.sent.append((datagram, address))
        self.target = address[0]

    def settimeout(self, timeout):
        self.current_timeout = timeout

    def recvfrom(self, _size):
        datagram = self.replies.get(self.target)
        if datagram is not None:
            del self.replies[self.target]
            return datagram, (self.target, DISCOVER_PORT)
        if self.blocking:
            raise socket.timeout
        raise BlockingIOError

    def close(self):
        self.closed = True


class FakeSelector:
    def __init__(self, clock=None):
        self.entries = {}
        self.clock = clock
        self.timeouts = []
        self.closed = False

    def register(self, fileobj, events, data=None):
        key = SimpleNamespace(fileobj=fileobj, events=events, data=data)
        self.entries[fileobj] = key
        return key

    def unregister(self, fileobj):
        return self.entries.pop(fileobj)

    def select(self, timeout=None):
        self.timeouts.append(timeout)
        ready = [
            (key, key.events)
            for fileobj, key in self.entries.items()
            if getattr(fileobj, "target", None) in getattr(fileobj, "replies", {})
        ]
        if ready:
            return ready
        if self.clock is not None and timeout is not None:
            self.clock.now += timeout
        return []

    def close(self):
        self.closed = True


class DeepDiscoveryTests(unittest.TestCase):
    def test_active_subnet_detection_uses_up_non_loopback_ipv4_addresses(self):
        ip_output = [
            {
                "ifname": "eth0",
                "flags": ["UP", "BROADCAST"],
                "addr_info": [
                    {"family": "inet", "local": "10.42.0.10", "prefixlen": 24},
                    {"family": "inet6", "local": "fe80::1", "prefixlen": 64},
                ],
            },
            {
                "ifname": "lo",
                "flags": ["UP", "LOOPBACK"],
                "addr_info": [
                    {"family": "inet", "local": "127.0.0.1", "prefixlen": 8}
                ],
            },
        ]
        result = SimpleNamespace(returncode=0, stdout=json.dumps(ip_output))

        with patch("dh_tux_initialize.deep_discovery.subprocess.run", return_value=result):
            networks = active_ipv4_networks()

        self.assertIn(ipaddress.ip_network("10.42.0.0/24"), networks)
        self.assertNotIn(ipaddress.ip_network("127.0.0.0/8"), networks)

    def test_host_replying_only_to_unicast_deep_scan_is_discovered(self):
        responder = "10.42.0.2"
        replies = {responder: make_datagram("02:00:00:00:00:02", responder, "TESTSERIAL001")}
        sent = []
        sockets = []

        def socket_factory(*_args):
            sock = ReplySocket(replies, sent)
            sockets.append(sock)
            return sock

        with patch("dh_tux_initialize.deep_discovery.socket.socket", side_effect=socket_factory), patch(
            "dh_tux_initialize.deep_discovery.selectors.DefaultSelector", FakeSelector
        ), patch(
            "dh_tux_initialize.deep_discovery._screen_service_hosts",
            return_value={host: set() for host in ("10.42.0.1",)},
        ):
            progress = []
            devices = deep_discover(
                "10.42.0.0/30",
                timeout=0.1,
                workers=2,
                progress=progress.append,
            )

        self.assertEqual([device.serial_number for device in devices], ["TESTSERIAL001"])
        self.assertEqual(len(sockets), 2)
        self.assertEqual(
            {address for _frame, address in sent},
            {("10.42.0.1", DISCOVER_PORT), ("10.42.0.2", DISCOVER_PORT)},
        )
        self.assertTrue(all(decode_json_datagram(frame)["method"] == "DHDiscover.search" for frame, _ in sent))
        self.assertEqual(devices[0].discovery_sources, frozenset({"deep"}))
        self.assertIn("Deep scanning 10.42.0.0/30...", progress)
        self.assertIn("2/2", progress)

    def test_merge_returns_union_of_quick_and_deep_results(self):
        quick = make_device("02:00:00:00:00:02", "192.0.2.20", serial="TESTSERIAL001")
        deep = make_device("02:00:00:00:00:03", "10.42.0.20", source="deep", serial="TESTSERIAL001")

        merged = merge_devices([quick], [deep])

        self.assertEqual([device.mac for device in merged], [quick.mac, deep.mac])

    def test_quick_result_outside_deep_range_survives_deep_scan(self):
        quick = make_device("02:00:00:00:00:02", "203.0.113.20", serial="TESTSERIAL001")
        deep = make_device("02:00:00:00:00:03", "10.42.0.20", source="deep", serial="TESTSERIAL001")

        merged = merge_devices([quick], [deep])

        self.assertEqual({device.ipv4 for device in merged}, {"203.0.113.20", "10.42.0.20"})

    def test_duplicate_mac_on_different_ips_remains_two_endpoints(self):
        quick = make_device("02:00:00:00:00:08", "192.0.2.20", serial="TESTSERIAL001")
        deep = make_device("0200.0000.0008", "10.42.0.20", source="deep", serial="TESTSERIAL001")

        merged = merge_devices([quick], [deep])

        self.assertEqual(len(merged), 2)
        self.assertEqual({device.ipv4 for device in merged}, {quick.ipv4, deep.ipv4})

    def test_same_ip_merge_never_overwrites_dhip_fields_with_onvif(self):
        dhip = DiscoveredDevice(
            {
                "DeviceType": "DHIP-Model",
                "Mac": "02:00:00:00:00:02",
                "SerialNo": "TESTSERIAL001",
                "Version": "DHIP-FW",
                "Init": 3733,
                "IPv4Address": {"IPAddress": "10.42.0.62"},
            },
            {},
            "10.42.0.62",
            identity_sources={
                "model": "dhip", "mac": "dhip", "serial": "dhip",
                "firmware": "dhip", "init": "dhip",
            },
            valid_dhip_identity=True,
            dahua_verified=True,
        )
        fallback = DiscoveredDevice(
            {
                "DeviceType": "ONVIF-Model",
                "Mac": "02:00:00:00:00:25",
                "SerialNo": "TESTSERIAL001-ONVIF",
                "Version": "ONVIF-FW",
                "IPv4Address": {"IPAddress": "10.42.0.62"},
            },
            {},
            "10.42.0.62",
            identity_sources={
                "model": "onvif-get-device-information",
                "mac": "onvif-wsd-scope",
                "serial": "onvif-get-device-information",
                "firmware": "onvif-get-device-information",
            },
            dahua_verified=True,
        )

        merged = merge_devices([dhip], [fallback])

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].model, "DHIP-Model")
        self.assertEqual(merged[0].mac, "02:00:00:00:00:02")
        self.assertEqual(merged[0].serial_number, "TESTSERIAL001")
        self.assertEqual(merged[0].firmware, "DHIP-FW")
        self.assertEqual(merged[0].init_value, 3733)
        self.assertEqual(merged[0].identity_sources["model"], "dhip")

    def test_cidr_validation_canonicalizes_ipv4_and_rejects_invalid_ranges(self):
        self.assertEqual(parse_ipv4_range("10.42.0.12/24"), ipaddress.ip_network("10.42.0.0/24"))
        for value in (
            "not-a-cidr",
            "192.0.2.1",
            "2001:db8::/64",
            "8.8.8.0/24",
            "10.0.0.0/8",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_ipv4_range(value)

    def test_batch_uses_one_absolute_deadline_for_all_dhip_sockets(self):
        from dh_tux_initialize.deep_discovery import _probe_dhip_batch

        clock = FakeClock()
        selectors = []

        def selector_factory():
            selector = FakeSelector(clock)
            selectors.append(selector)
            return selector

        sent = []
        with patch(
            "dh_tux_initialize.deep_discovery.socket.socket",
            side_effect=lambda *_args: ReplySocket({}, sent),
        ), patch(
            "dh_tux_initialize.deep_discovery.selectors.DefaultSelector",
            side_effect=selector_factory,
        ), patch(
            "dh_tux_initialize.deep_discovery.time.monotonic",
            side_effect=clock.monotonic,
        ):
            result = _probe_dhip_batch(
                [f"10.42.0.{host}" for host in range(1, 255)],
                b"DHDiscover.search",
                timeout=2.5,
            )

        self.assertEqual(result, {})
        self.assertEqual(len(sent), 254)
        self.assertEqual(len(selectors), 1)
        self.assertEqual(selectors[0].timeouts, [2.5])
        self.assertAlmostEqual(clock.now, 2.5)

    def test_batch_rejects_valid_frame_from_a_different_sender_ip(self):
        from dh_tux_initialize.deep_discovery import _probe_dhip_batch

        class ForeignSenderSocket(ReplySocket):
            def recvfrom(self, _size):
                datagram = self.replies.pop(self.target, None)
                if datagram is None:
                    raise BlockingIOError
                return datagram, ("10.42.0.99", DISCOVER_PORT)

        target = "10.42.0.33"
        replies = {
            target: make_datagram("02:00:00:00:00:02", target, "TESTSERIAL001-FOREIGN")
        }
        with patch(
            "dh_tux_initialize.deep_discovery.socket.socket",
            side_effect=lambda *_args: ForeignSenderSocket(replies, []),
        ), patch(
            "dh_tux_initialize.deep_discovery.selectors.DefaultSelector",
            FakeSelector,
        ):
            devices = _probe_dhip_batch(
                [target],
                b"DHDiscover.search",
                timeout=0.01,
            )

        self.assertEqual(devices, {})

    def test_dhip_silent_tcp_37777_only_host_skips_vendor_fallback(self):
        target = "10.42.0.1"
        with patch(
            "dh_tux_initialize.deep_discovery._probe_dhip_batch",
            return_value={},
        ), patch(
            "dh_tux_initialize.deep_discovery._screen_service_hosts",
            return_value={target: {37777}},
        ), patch(
            "dh_tux_initialize.deep_discovery.probe_fallback",
        ) as fallback:
            devices = deep_discover("10.42.0.0/30", timeout=0.01)

        self.assertEqual(devices, [])
        fallback.assert_not_called()

    def test_onvif_failure_does_not_remove_detected_fallback_endpoint(self):
        target = "10.42.0.1"
        fallback_device = DiscoveredDevice(
            {
                "IPv4Address": {"IPAddress": target},
                "DiscoveryMethod": "rpc2-login-challenge",
            },
            {},
            target,
            dahua_verified=True,
            vendor_evidence=frozenset({"rpc2-login-challenge"}),
        )
        with patch(
            "dh_tux_initialize.deep_discovery._probe_dhip_batch",
            return_value={},
        ), patch(
            "dh_tux_initialize.deep_discovery._screen_service_hosts",
            return_value={target: {80}},
        ), patch(
            "dh_tux_initialize.deep_discovery.probe_fallback",
            return_value=fallback_device,
        ), patch(
            "dh_tux_initialize.deep_discovery.enrich_onvif_devices",
            side_effect=OSError("ONVIF timeout"),
        ):
            devices = deep_discover("10.42.0.0/30", timeout=0.01)

        self.assertEqual([device.ipv4 for device in devices], [target])
        self.assertTrue(devices[0].dahua_verified)
        self.assertFalse(devices[0].valid_dhip_identity)

    def test_ws_discovery_sends_one_probe_with_one_common_deadline(self):
        from dh_tux_initialize.deep_discovery import _ws_discover

        clock = FakeClock()
        sent = []
        selectors = []

        def socket_factory(*_args):
            sock = ReplySocket({}, sent)
            return sock

        def selector_factory():
            selector = FakeSelector(clock)
            selectors.append(selector)
            return selector

        with patch(
            "dh_tux_initialize.deep_discovery.socket.socket",
            side_effect=socket_factory,
        ), patch(
            "dh_tux_initialize.deep_discovery.selectors.DefaultSelector",
            side_effect=selector_factory,
        ), patch(
            "dh_tux_initialize.deep_discovery.time.monotonic",
            side_effect=clock.monotonic,
        ):
            result = _ws_discover(
                ["10.42.0.33", "10.42.0.58"],
                timeout=1.2,
            )

        self.assertEqual(
            result,
            {
                ip: {"xaddrs": set(), "scopes": set()}
                for ip in ("10.42.0.33", "10.42.0.58")
            },
        )
        self.assertEqual(len([entry for entry in sent if entry[1] == ("239.255.255.250", 3702)]), 1)
        self.assertEqual(selectors[0].timeouts, [1.2])
        self.assertAlmostEqual(clock.now, 1.2)

    def test_deep_scan_keeps_same_physical_camera_interfaces_as_separate_ip_rows(self):
        direct = make_device("02:00:00:00:00:25", "10.42.0.58", serial="TESTSERIAL001", source="deep")
        silent = DiscoveredDevice(
            {
                "IPv4Address": {"IPAddress": "10.42.0.33"},
                "DiscoveryMethod": "rpc2-login-challenge",
            },
            {},
            "10.42.0.33",
            frozenset({"deep"}),
            dahua_verified=True,
            vendor_evidence=frozenset({"rpc2-login-challenge"}),
        )

        with patch(
            "dh_tux_initialize.deep_discovery._probe_dhip_batch",
            return_value={"10.42.0.58": direct},
        ), patch(
            "dh_tux_initialize.deep_discovery._screen_service_hosts",
            side_effect=lambda hosts, **_kwargs: {
                host: ({80} if host == "10.42.0.33" else set()) for host in hosts
            },
        ), patch(
            "dh_tux_initialize.deep_discovery.probe_fallback",
            side_effect=lambda host: silent if str(host) == "10.42.0.33" else None,
        ), patch(
            "dh_tux_initialize.deep_discovery.enrich_onvif_devices",
            side_effect=lambda devices, **_kwargs: list(devices),
        ):
            devices = deep_discover("10.42.0.0/24", timeout=0.01, workers=16)

        self.assertEqual(
            [device.ipv4 for device in devices],
            ["10.42.0.33", "10.42.0.58"],
        )

    def test_deep_scan_adds_service_fallback_for_a_dhip_silent_host(self):
        responder = "10.42.0.2"
        replies = {
            responder: make_datagram("02:00:00:00:00:02", responder, "TESTSERIAL001")
        }
        fallback = DiscoveredDevice(
            {"IPv4Address": {"IPAddress": "10.42.0.1"}, "DiscoveryMethod": "rpc2-login-challenge"},
            {},
            "10.42.0.1",
            frozenset({"deep"}),
            dahua_verified=True,
            vendor_evidence=frozenset({"rpc2-login-challenge"}),
        )

        direct = make_device("02:00:00:00:00:02", responder, serial="TESTSERIAL001", source="deep")
        with patch(
            "dh_tux_initialize.deep_discovery._probe_dhip_batch",
            side_effect=lambda hosts, *_args, **_kwargs: (
                {responder: direct} if responder in hosts else {}
            ),
        ), patch(
            "dh_tux_initialize.deep_discovery._screen_service_hosts",
            side_effect=lambda hosts, **_kwargs: {
                host: ({80} if host == "10.42.0.1" else set()) for host in hosts
            },
        ), patch(
            "dh_tux_initialize.deep_discovery.probe_fallback",
            side_effect=lambda host: fallback if str(host) == "10.42.0.1" else None,
        ), patch(
            "dh_tux_initialize.deep_discovery.enrich_onvif_devices",
            side_effect=lambda devices, **_kwargs: list(devices),
        ) as enrich:
            devices = deep_discover("10.42.0.0/30", timeout=0.01, workers=2)

        self.assertEqual([device.ipv4 for device in devices], ["10.42.0.1", responder])
        self.assertEqual(devices[0].info["DiscoveryMethod"], "rpc2-login-challenge")
        self.assertEqual(devices[1].serial_number, "TESTSERIAL001")
        enrich.assert_called_once()
        self.assertEqual(
            [device.ipv4 for device in enrich.call_args.args[0]],
            ["10.42.0.1"],
        )

    def test_direct_probe_uses_a_fresh_ephemeral_socket_per_target(self):
        sockets = []

        def socket_factory(*_args):
            sock = ReplySocket({}, [])
            sock.bound_address = None
            original_bind = sock.bind
            sock.bind = lambda address: (setattr(sock, "bound_address", address), original_bind(address))
            sockets.append(sock)
            return sock

        with patch("dh_tux_initialize.deep_discovery.socket.socket", side_effect=socket_factory):
            direct_probe("10.42.0.33", timeout=0.01)
            direct_probe("10.42.0.58", timeout=0.01)

        self.assertEqual(len(sockets), 2)
        self.assertIsNot(sockets[0], sockets[1])
        self.assertEqual([sock.bound_address for sock in sockets], [("0.0.0.0", 0)] * 2)
        self.assertTrue(
            all(option[1] != socket.SO_REUSEADDR for sock in sockets for option in sock.options)
        )
        if hasattr(socket, "SO_REUSEPORT"):
            self.assertTrue(
                all(option[1] != socket.SO_REUSEPORT for sock in sockets for option in sock.options)
            )
        self.assertTrue(all(sock.closed for sock in sockets))

    def test_direct_probe_records_timeout_without_response(self):
        with patch(
            "dh_tux_initialize.deep_discovery.socket.socket",
            side_effect=lambda *_args: ReplySocket({}, []),
        ):
            records = direct_probe("10.42.0.33", timeout=0.01)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].destination_ip, "10.42.0.33")
        self.assertEqual(records[0].local_ip, "10.42.0.10")
        self.assertEqual(records[0].local_port, 41000)
        self.assertIsNotNone(records[0].send_timestamp)
        self.assertIsNone(records[0].receive_timestamp)
        self.assertIsNone(records[0].sender_ip)
        self.assertEqual(records[0].rejection_reason, "no_reply")

    def test_direct_probe_rejects_malformed_dhip_framing(self):
        frame = make_datagram("02:00:00:00:00:26", "10.42.0.33", "TESTSERIAL001-BAD")[:14]

        with patch(
            "dh_tux_initialize.deep_discovery.socket.socket",
            side_effect=lambda *_args: ReplySocket(
                {"10.42.0.33": frame}, []
            ),
        ):
            records = direct_probe("10.42.0.33", timeout=0.01)

        self.assertFalse(records[0].valid_dhip_framing)
        self.assertFalse(records[0].json_parse_success)
        self.assertFalse(records[0].accepted)
        self.assertEqual(records[0].rejection_reason, "invalid_dhip_framing")

    def test_direct_probe_accepts_valid_framed_reply_from_target(self):
        frame = make_datagram("02:00:00:00:00:26", "10.42.0.33", "TESTSERIAL001-OK")

        class SenderReplySocket(ReplySocket):
            def recvfrom(self, _size):
                return frame, ("10.42.0.33", DISCOVER_PORT)

        with patch(
            "dh_tux_initialize.deep_discovery.socket.socket",
            side_effect=lambda *_args: SenderReplySocket({}, []),
        ):
            records = direct_probe("10.42.0.33", timeout=0.01, stop_after_accept=True)

        self.assertTrue(records[0].valid_dhip_framing)
        self.assertTrue(records[0].json_parse_success)
        self.assertTrue(records[0].accepted)
        self.assertEqual(records[0].model, "IPC-Deep")
        self.assertIsNotNone(records[0].device)
        self.assertTrue(records[0].device.valid_dhip_identity)
        self.assertEqual(records[0].device.identity_sources["model"], "dhip")

    def test_direct_probe_rejects_sender_ip_mismatch(self):
        frame = make_datagram("02:00:00:00:00:26", "10.42.0.99", "TESTSERIAL001-WRONG")

        class SenderReplySocket(ReplySocket):
            def recvfrom(self, _size):
                return frame, ("10.42.0.99", DISCOVER_PORT)

        with patch(
            "dh_tux_initialize.deep_discovery.socket.socket",
            side_effect=lambda *_args: SenderReplySocket({}, []),
        ):
            records = direct_probe("10.42.0.33", timeout=0.01)

        self.assertTrue(records[0].valid_dhip_framing)
        self.assertTrue(records[0].json_parse_success)
        self.assertFalse(records[0].accepted)
        self.assertEqual(records[0].rejection_reason, "sender_ip_mismatch")

    def test_duplicate_replies_are_recorded_and_only_first_is_accepted(self):
        frame = make_datagram("02:00:00:00:00:26", "10.42.0.33", "TESTSERIAL001-DUPLICATE")

        class DuplicateReplySocket(ReplySocket):
            def __init__(self):
                super().__init__({}, [])
                self.pending = [
                    (frame, ("10.42.0.33", DISCOVER_PORT)),
                    (frame, ("10.42.0.33", DISCOVER_PORT)),
                ]

            def recvfrom(self, _size):
                if self.pending:
                    return self.pending.pop(0)
                raise socket.timeout

        with patch(
            "dh_tux_initialize.deep_discovery.socket.socket",
            side_effect=lambda *_args: DuplicateReplySocket(),
        ):
            records = direct_probe("10.42.0.33", timeout=0.01)

        self.assertEqual(len(records), 2)
        self.assertTrue(records[0].accepted)
        self.assertFalse(records[1].accepted)
        self.assertEqual(records[1].rejection_reason, "duplicate_reply")

    def test_unframed_non_dahua_identities_are_never_accepted(self):
        non_dahua = {
            "10.42.0.37": "Test-Vendor-Camera-A",
            "10.42.0.49": "Test-Vendor-Camera-B",
            "10.42.0.65": "Test-Vendor-Camera-C",
        }
        for ip, model in non_dahua.items():
            payload = {
                "method": "client.notifyDevInfo",
                "params": {"deviceInfo": {"DeviceType": model, "Mac": "02:00:00:00:00:24"}},
            }
            bare_json = json.dumps(payload).encode()

            class BareJsonSocket(ReplySocket):
                def recvfrom(self, _size):
                    return bare_json, (ip, DISCOVER_PORT)

            with self.subTest(ip=ip):
                with patch(
                    "dh_tux_initialize.deep_discovery.socket.socket",
                    side_effect=lambda *_args: BareJsonSocket({}, []),
                ):
                    records = direct_probe(ip, timeout=0.01)

                self.assertFalse(records[0].valid_dhip_framing)
                self.assertTrue(records[0].json_parse_success)
                self.assertFalse(records[0].accepted)
                self.assertEqual(records[0].rejection_reason, "invalid_dhip_framing")


class ProbeFallbackTests(unittest.TestCase):
    def test_rpc2_positive_dhip_silent_endpoint_is_inventory_only(self):
        class FakeResponse:
            status = 200

            def __init__(self, body):
                self.body = body

            def read(self, _limit):
                return self.body

            def getheader(self, _name, default=""):
                return default

        class FakeHttpConnection:
            def __init__(self, *_args, **_kwargs):
                self.calls = []
                self.closed = False

            def request(self, method, path, *, body=None, headers):
                self.calls.append((method, path, body, headers))

            def getresponse(self):
                return FakeResponse(
                    json.dumps({
                        "id": 1,
                        "result": False,
                        "params": {"realm": "TEST-REALM", "random": "TEST-RANDOM"},
                    }).encode()
                )

            def close(self):
                self.closed = True

        connections = []

        def connection_factory(*args, **kwargs):
            connection = FakeHttpConnection(*args, **kwargs)
            connections.append(connection)
            return connection

        with patch(
            "dh_tux_initialize.deep_discovery.http.client.HTTPConnection",
            side_effect=connection_factory,
        ):
            device = probe_fallback("10.42.0.33")

        self.assertIsNotNone(device)
        self.assertEqual(device.info["DiscoveryMethod"], "rpc2-login-challenge")
        self.assertEqual(device.vendor_evidence, frozenset({"rpc2-login-challenge"}))
        self.assertTrue(device.dahua_verified)
        self.assertFalse(device.valid_dhip_identity)
        self.assertFalse(device.provisionable)
        self.assertNotIn("Init", device.info)
        self.assertEqual(len(connections), 1)  # A conclusive RPC2 challenge skips CGI.
        rpc_call = connections[0].calls[0]
        self.assertEqual(rpc_call[0:2], ("POST", "/RPC2_Login"))
        rpc_payload = json.loads(rpc_call[2])
        self.assertEqual(rpc_payload["params"]["password"], "")
        self.assertNotIn("Authorization", rpc_call[3])
        self.assertNotIn("session", rpc_payload)

    def test_tcp_37777_open_alone_is_not_accepted_as_dahua(self):
        with patch(
            "dh_tux_initialize.deep_discovery.socket.create_connection",
            return_value=object(),
        ) as tcp_connect, patch(
            "dh_tux_initialize.deep_discovery._probe_rpc2_login_challenge",
            return_value=False,
        ), patch(
            "dh_tux_initialize.deep_discovery._probe_dahua_cgi_signature",
            return_value=False,
        ):
            device = probe_fallback("10.42.0.33")

        self.assertIsNone(device)
        tcp_connect.assert_not_called()

    def test_cgi_digest_remains_a_secondary_vendor_signature(self):
        with patch(
            "dh_tux_initialize.deep_discovery._probe_rpc2_login_challenge",
            return_value=False,
        ), patch(
            "dh_tux_initialize.deep_discovery._probe_dahua_cgi_signature",
            return_value=True,
        ):
            device = probe_fallback("10.42.0.62")

        self.assertEqual(device.info["DiscoveryMethod"], "http-digest-realm")
        self.assertEqual(device.vendor_evidence, frozenset({"http-digest-realm"}))
        self.assertFalse(device.provisionable)

    def test_known_non_dahua_http_responses_do_not_pass_fallback(self):
        for ip in ("10.42.0.37", "10.42.0.49", "10.42.0.65"):
            with self.subTest(ip=ip), patch(
                "dh_tux_initialize.deep_discovery._probe_rpc2_login_challenge",
                return_value=False,
            ), patch(
                "dh_tux_initialize.deep_discovery._probe_dahua_cgi_signature",
                return_value=False,
            ):
                self.assertIsNone(probe_fallback(ip))


class OnvifEnrichmentTests(unittest.TestCase):
    def fallback_device(self, ip="10.42.0.62"):
        return DiscoveredDevice(
            {
                "IPv4Address": {"IPAddress": ip},
                "DiscoveryMethod": "rpc2-login-challenge",
            },
            {},
            ip,
            frozenset({"deep"}),
            dahua_verified=True,
            vendor_evidence=frozenset({"rpc2-login-challenge"}),
        )

    def test_get_device_information_enriches_only_returned_fields_without_auth(self):
        from dh_tux_initialize.deep_discovery import enrich_onvif_devices

        ip = "10.42.0.62"
        xaddr = f"http://{ip}/onvif/device_service"
        soap = b'''<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
          <s:Body><tds:GetDeviceInformationResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
            <tds:Model>IPC-Test-Camera</tds:Model>
                    <tds:FirmwareVersion>TEST-FIRMWARE-001</tds:FirmwareVersion>
            <tds:SerialNumber>TESTSERIAL001</tds:SerialNumber>
          </tds:GetDeviceInformationResponse></s:Body></s:Envelope>'''

        class FakeResponse:
            status = 200

            def read(self, _limit):
                return soap

        class FakeConnection:
            def __init__(self, *args, **kwargs):
                self.args = args
                self.kwargs = kwargs
                self.closed = False

            def request(self, method, path, *, body, headers):
                self.request_args = (method, path, body, headers)

            def getresponse(self):
                return FakeResponse()

            def close(self):
                self.closed = True

        connection = FakeConnection()
        with patch(
            "dh_tux_initialize.deep_discovery._ws_discover",
            return_value={ip: {"xaddrs": {xaddr}, "scopes": set()}},
        ), patch(
            "dh_tux_initialize.deep_discovery.http.client.HTTPConnection",
            return_value=connection,
        ):
            result = enrich_onvif_devices([self.fallback_device()])[0]

        self.assertEqual(result.model, "IPC-Test-Camera")
        self.assertEqual(result.serial_number, "TESTSERIAL001")
        self.assertEqual(result.firmware, "TEST-FIRMWARE-001")
        self.assertIsNone(result.mac)
        self.assertEqual(result.identity_sources, {
            "model": "onvif-get-device-information",
            "serial": "onvif-get-device-information",
            "firmware": "onvif-get-device-information",
        })
        method, path, body, headers = connection.request_args
        self.assertEqual((method, path), ("POST", "/onvif/device_service"))
        self.assertIn(b"GetDeviceInformation", body)
        self.assertNotIn(b"UsernameToken", body)
        self.assertNotIn("Authorization", headers)
        self.assertTrue(connection.closed)

    def test_401_keeps_wsd_model_scope_without_other_identity(self):
        from dh_tux_initialize.deep_discovery import enrich_onvif_devices

        ip = "10.42.0.36"

        class FakeResponse:
            status = 401

            def read(self, _limit):
                return b""

        class FakeConnection:
            def __init__(self, *_args, **_kwargs):
                pass

            def request(self, method, path, *, body, headers):
                self.request_args = (method, path, body, headers)

            def getresponse(self):
                return FakeResponse()

            @staticmethod
            def close():
                pass

        scope = "onvif://www.onvif.org/hardware/IPC-Test-Camera"
        connections = []

        def connection_factory(*args, **kwargs):
            connection = FakeConnection(*args, **kwargs)
            connections.append(connection)
            return connection

        with patch(
            "dh_tux_initialize.deep_discovery._ws_discover",
            return_value={ip: {"xaddrs": set(), "scopes": {scope}}},
        ), patch(
            "dh_tux_initialize.deep_discovery.http.client.HTTPConnection",
            side_effect=connection_factory,
        ):
            result = enrich_onvif_devices([self.fallback_device(ip)])[0]

        self.assertEqual(result.model, "IPC-Test-Camera")
        self.assertIsNone(result.mac)
        self.assertIsNone(result.serial_number)
        self.assertIsNone(result.firmware)
        self.assertEqual(result.identity_sources, {
            "model": "onvif-wsd-scope",
        })
        request = connections[0].request_args
        self.assertEqual(request[0:2], ("POST", "/onvif/device_service"))
        self.assertNotIn("Authorization", request[3])

    def test_wsd_mac_scope_enriches_mac_without_credentials(self):
        from dh_tux_initialize.deep_discovery import enrich_onvif_devices

        ip = "10.42.0.55"
        scope = "onvif://www.onvif.org/macaddress/02:00:00:00:00:27"
        with patch(
            "dh_tux_initialize.deep_discovery._ws_discover",
            return_value={ip: {"xaddrs": set(), "scopes": {scope}}},
        ), patch(
            "dh_tux_initialize.deep_discovery._onvif_get_device_information",
            return_value={},
        ):
            result = enrich_onvif_devices([self.fallback_device(ip)])[0]

        self.assertEqual(result.mac, "02:00:00:00:00:27")
        self.assertIsNone(result.model)
        self.assertEqual(result.identity_sources, {"mac": "onvif-wsd-scope"})

    def test_onvif_never_overwrites_dhip_identity_or_probes_it(self):
        from dh_tux_initialize.deep_discovery import enrich_onvif_devices

        dhip = make_device("02:00:00:00:00:02", "10.42.0.62", serial="TESTSERIAL001")
        with patch("dh_tux_initialize.deep_discovery._ws_discover") as ws_discover, patch(
            "dh_tux_initialize.deep_discovery.http.client.HTTPConnection"
        ) as http_connection:
            result = enrich_onvif_devices([dhip])[0]

        self.assertIs(result, dhip)
        self.assertEqual(result.model, "IPC-Test")
        self.assertEqual(result.serial_number, "TESTSERIAL001")
        ws_discover.assert_not_called()
        http_connection.assert_not_called()


if __name__ == "__main__":
    unittest.main()
