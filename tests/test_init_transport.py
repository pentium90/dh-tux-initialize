import errno
import json
import socket
import struct
import unittest
import urllib.error
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives.asymmetric import rsa

from dh_tux_initialize.init_protocol import (
    DEFAULT_INIT_IP,
    InitializationClient,
    InitializationError,
    UrllibJsonTransport,
)
from dh_tux_initialize.init_transport import (
    DHIP_INIT_GROUP,
    DHIP_INIT_PORT,
    DhipInitializationTransport,
    DhipInitializationTransportError,
)
from dh_tux_initialize.protocol import decode_json_datagram, encode_frame


TARGET_IP = DEFAULT_INIT_IP
TARGET_MAC = "02:00:00:00:00:01"


class FakeSocket:
    def __init__(self, responses=(), *, send_error=None):
        self.responses = list(responses)
        self.send_error = send_error
        self.options = []
        self.bound = None
        self.sent = []
        self.timeout = None
        self.closed = False

    def setsockopt(self, level, option, value):
        self.options.append((level, option, value))

    def bind(self, address):
        self.bound = address

    def sendto(self, packet, address):
        if self.send_error is not None:
            raise self.send_error
        self.sent.append((packet, address))
        return len(packet)

    def settimeout(self, timeout):
        self.timeout = timeout

    def recvfrom(self, _maximum):
        if not self.responses:
            raise socket.timeout("timed out")
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response

    def close(self):
        self.closed = True


class SocketQueue:
    def __init__(self, sockets):
        self.sockets = list(sockets)
        self.created = []

    def __call__(self, *_args):
        sock = self.sockets.pop(0)
        self.created.append(sock)
        return sock


def response(message, *, request_id=0, ip=TARGET_IP):
    return encode_frame(message, request_id=request_id), (ip, DHIP_INIT_PORT)


class DhipInitializationTransportTests(unittest.TestCase):
    def test_status_uses_multicast_dhip_request(self):
        fake_socket = FakeSocket(
            [response({"method": "client.notifyDevInfo", "params": {"deviceInfo": {"Init": 1}}, "mac": TARGET_MAC})]
        )
        transport = DhipInitializationTransport(
            TARGET_IP, TARGET_MAC, socket_factory=lambda *_args: fake_socket
        )

        result = transport.post_json(
            "unused",
            {"method": "DevInit.getStatus", "params": None, "id": 9, "session": "invented"},
            timeout=0.25,
        )

        self.assertEqual(result["params"], {"Init": 1})
        self.assertEqual(fake_socket.sent[0][1], (DHIP_INIT_GROUP, DHIP_INIT_PORT))
        self.assertEqual(fake_socket.bound, ("0.0.0.0", DHIP_INIT_PORT))
        self.assertIn((socket.SOL_SOCKET, socket.SO_REUSEADDR, 1), fake_socket.options)
        self.assertIn(
            (
                socket.IPPROTO_IP,
                socket.IP_ADD_MEMBERSHIP,
                socket.inet_aton(DHIP_INIT_GROUP) + socket.inet_aton("0.0.0.0"),
            ),
            fake_socket.options,
        )
        sent = decode_json_datagram(fake_socket.sent[0][0])
        self.assertEqual(sent["method"], "DHDiscover.search")
        self.assertNotIn("mac", sent)
        self.assertEqual(sent["params"], {"mac": "", "uni": 1})
        self.assertNotIn("id", sent)
        self.assertNotIn("session", sent)
        header = struct.unpack("<8I", fake_socket.sent[0][0][:32])
        self.assertEqual(header[2:4], (0, 0))
        self.assertTrue(fake_socket.closed)

    def test_encrypt_info_callback_is_correlated_and_normalized(self):
        fake_socket = FakeSocket(
            [
                response(
                    {
                        "method": "client.notifyEncryptInfo",
                        "mac": TARGET_MAC,
                        "params": {
                            "result": True,
                            "asymmetric": "RSA",
                            "pub": "N:ABC,E:010001",
                            "cipher": ["AES-128"],
                        },
                    },
                )
            ]
        )
        transport = DhipInitializationTransport(
            TARGET_IP, TARGET_MAC, socket_factory=lambda *_args: fake_socket
        )

        result = transport.post_json(
            "unused",
            {"method": "Security.getEncryptInfo", "params": None, "id": 3},
            timeout=0.25,
        )

        self.assertEqual(result["id"], 3)
        self.assertTrue(result["result"])
        self.assertEqual(result["params"]["pub"], "N:ABC,E:010001")
        request = decode_json_datagram(fake_socket.sent[0][0])
        self.assertEqual(request["mac"], TARGET_MAC)
        self.assertEqual(request["params"], {"uni": 1})
        self.assertNotIn("id", request)

    def test_ignores_wrong_device_and_unrelated_notifications(self):
        fake_socket = FakeSocket(
            [
                response(
                    {"method": "client.notifyDevInfo", "mac": "02:00:00:00:00:02", "params": {"Init": 1}},
                ),
                response({"method": "client.notifyEncryptInfo", "mac": TARGET_MAC, "params": {}}),
                response({"method": "client.notifyDevInfo", "mac": TARGET_MAC, "params": {"deviceInfo": {"Init": 1}}}),
            ]
        )
        transport = DhipInitializationTransport(
            TARGET_IP, TARGET_MAC, socket_factory=lambda *_args: fake_socket
        )

        result = transport.post_json(
            "unused", {"method": "DevInit.getStatus", "params": None, "id": 4}, timeout=0.25
        )

        self.assertEqual(result["params"]["Init"], 1)
        self.assertEqual(len(fake_socket.sent), 1)

    def test_caps_query_ignores_multicast_loopback_echo(self):
        fake_socket = FakeSocket(
            [
                response({"method": "userManager.getCaps", "mac": TARGET_MAC, "params": {"uni": 1}}),
                response(
                    {
                        "method": "userManager.getCaps",
                        "mac": TARGET_MAC,
                        "result": True,
                        "params": {"caps": {"PwdSpeci": {"minLength": 8}}},
                    }
                ),
            ]
        )
        transport = DhipInitializationTransport(
            TARGET_IP, TARGET_MAC, socket_factory=lambda *_args: fake_socket
        )

        result = transport.post_json(
            "unused", {"method": "DevInit.getDevCaps", "params": None, "id": 12}, timeout=0.25
        )

        self.assertEqual(result["params"]["caps"]["PwdSpeci"]["minLength"], 8)

    def test_socket_error_is_preserved_without_including_request_data(self):
        fake_socket = FakeSocket(send_error=OSError(errno.ENETUNREACH, "Network is unreachable"))
        transport = DhipInitializationTransport(
            TARGET_IP, TARGET_MAC, socket_factory=lambda *_args: fake_socket
        )
        client = InitializationClient(TARGET_IP, target_mac=TARGET_MAC, transport=transport)

        with self.assertRaises(InitializationError) as caught:
            client.get_status()

        self.assertIn("DevInit.getStatus failed", str(caught.exception))
        self.assertIn("DHIP UDP/37810 transport failed", str(caught.exception))
        self.assertIn("Network is unreachable", str(caught.exception))
        self.assertNotIn("request failed", str(caught.exception))
        self.assertNotIn("pwd", str(caught.exception))
        self.assertTrue(fake_socket.closed)

    def test_udp_timeout_is_preserved_in_the_initialization_error(self):
        fake_socket = FakeSocket()
        transport = DhipInitializationTransport(
            TARGET_IP, TARGET_MAC, socket_factory=lambda *_args: fake_socket
        )
        client = InitializationClient(TARGET_IP, target_mac=TARGET_MAC, transport=transport)

        with self.assertRaises(InitializationError) as caught:
            client.get_status()

        self.assertIn(
            "DHIP UDP/37810 response timed out for DevInit.getStatus",
            str(caught.exception),
        )

    def test_http_transport_keeps_the_socket_error_detail(self):
        client = InitializationClient(TARGET_IP, transport=UrllibJsonTransport())
        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError(TimeoutError("connection timed out")),
        ):
            with self.assertRaises(InitializationError) as caught:
                client.get_status()

        self.assertIn("DevInit.getStatus failed", str(caught.exception))
        self.assertIn("HTTP transport failed", str(caught.exception))
        self.assertIn("connection timed out", str(caught.exception))

    def test_timeout_is_clear_and_write_is_sent_only_once(self):
        fake_socket = FakeSocket()
        transport = DhipInitializationTransport(
            TARGET_IP, TARGET_MAC, socket_factory=lambda *_args: fake_socket
        )

        with self.assertRaises(DhipInitializationTransportError) as caught:
            transport.post_json(
                "unused", {"method": "DevInit.account", "params": {}, "id": 1}, timeout=0.01
            )

        self.assertIn("response timed out for DevInit.account", str(caught.exception))
        self.assertEqual(len(fake_socket.sent), 1)
        self.assertTrue(fake_socket.closed)

    def test_account_requires_a_mac_before_opening_a_socket(self):
        socket_factory = Mock()
        transport = DhipInitializationTransport(TARGET_IP, socket_factory=socket_factory)

        with self.assertRaises(DhipInitializationTransportError) as caught:
            transport.post_json(
                "unused", {"method": "DevInit.account", "params": {}, "id": 1}, timeout=0.01
            )

        self.assertIn("requires the selected camera MAC", str(caught.exception))
        socket_factory.assert_not_called()

    def test_initialization_client_uses_dhip_by_default(self):
        client = InitializationClient(TARGET_IP, target_mac=TARGET_MAC)

        self.assertIsInstance(client.transport, DhipInitializationTransport)
        self.assertEqual(client.url, f"dhip://{TARGET_IP}:{DHIP_INIT_PORT}")

    def test_account_preflight_and_write_share_one_dhip_socket_per_request(self):
        private = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        public = private.public_key().public_numbers()
        pub = f"N:{public.n:X},E:{public.e:X}"
        replies = [
            response({"method": "client.notifyDevInfo", "mac": TARGET_MAC, "params": {"deviceInfo": {"Init": 1}}}),
            response(
                {"method": "userManager.getCaps", "mac": TARGET_MAC, "result": True, "params": {"definition": {"SupportDevInit": True}}},
            ),
            response(
                {
                    "method": "client.notifyEncryptInfo",
                    "mac": TARGET_MAC,
                    "params": {
                        "result": True,
                        "asymmetric": "RSA",
                        "pub": pub,
                        "cipher": ["AES-128"],
                        "SecurityBaselineVersion": "V1.4",
                    },
                },
            ),
            response({"method": "client.notifyDevInit", "mac": TARGET_MAC, "params": {"result": True}}),
        ]
        sockets = SocketQueue([FakeSocket([reply]) for reply in replies])
        transport = DhipInitializationTransport(TARGET_IP, TARGET_MAC, socket_factory=sockets)
        client = InitializationClient(TARGET_IP, target_mac=TARGET_MAC, transport=transport)
        secret = "unit-test-secret-4582"

        result = client.initialize_account(
            secret,
            random_key="0123456789012345",
            rsa_encryptor=lambda _public_key, key: b"fixed-salt-" + key,
        )

        self.assertEqual(result["result"], True)
        self.assertEqual(len(sockets.created), 4)
        requests = [decode_json_datagram(sock.sent[0][0]) for sock in sockets.created]
        self.assertEqual(
            [request["method"] for request in requests],
            ["DHDiscover.search", "userManager.getCaps", "Security.getEncryptInfo", "DevInit.account"],
        )
        self.assertEqual([struct.unpack("<8I", sock.sent[0][0][:32])[3] for sock in sockets.created], [0, 0, 0, 0])
        for request in requests:
            self.assertNotIn("session", request)
            self.assertNotIn("id", request)
            self.assertEqual(request["params"]["uni"], 1)
        self.assertNotIn("mac", requests[0])
        self.assertEqual(requests[0]["params"]["mac"], "")
        for request in requests[1:]:
            self.assertEqual(request["mac"], TARGET_MAC)
        self.assertEqual(set(requests[-1]["params"]), {"uni", "salt", "cipher", "content"})
        self.assertNotIn(secret, repr(requests[-1]))
        self.assertNotIn(secret, json.dumps(requests[-1]))


if __name__ == "__main__":
    unittest.main()
