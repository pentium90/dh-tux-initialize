import socket
import unittest
from unittest.mock import patch

from dh_tux_initialize.network_transport import (
    DHIP_NETWORK_METHOD,
    DhipNetworkTransport,
    DhipNetworkTransportError,
    _default_authentication_hashes,
    build_dhcp_device_config,
)
from dh_tux_initialize.protocol import decode_json_datagram, encode_frame
from dh_tux_initialize.provisioning import DahuaNetworkClient, ProvisioningError


TARGET_IP = "192.0.2.108"
TARGET_MAC = "02:00:00:00:00:01"


def synthetic_secret():
    return "".join(chr(code) for code in (78, 101, 116, 119, 111, 114, 107)) + "-" + str(625)


class FakeSocket:
    def __init__(self, responses=(), *, send_error=None):
        self.responses = list(responses)
        self.send_error = send_error
        self.options = []
        self.bound = None
        self.sent = []
        self.timeouts = []
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
        self.timeouts.append(timeout)

    def recvfrom(self, _maximum):
        if not self.responses:
            raise socket.timeout("timed out")
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response

    def close(self):
        self.closed = True


def reply(message, *, ip=TARGET_IP):
    return encode_frame(message), (ip, 37810)


def default_challenge(
    *,
    mac=TARGET_MAC,
    encryption="Default",
    realm="TEST-REALM",
    random="TEST-RANDOM",
):
    params = {
        "code": 16789511,
        "encryption": encryption,
        "result": False,
    }
    if realm is not None:
        params["realm"] = realm
    if random is not None:
        params["random"] = random
    return {
        "method": "client.notifyCfgChange",
        "mac": mac,
        "params": params,
        "result": False,
    }


def expected_request_password(credential):
    return _default_authentication_hashes(
        "admin",
        credential,
        "TEST-REALM",
        "TEST-RANDOM",
    )[1]


def default_success(*, mac=TARGET_MAC):
    return {
        "method": "client.notifyCfgChange",
        "mac": mac,
        "params": {"result": True, "encryption": "Default"},
        "result": True,
    }


class DhipNetworkTransportTests(unittest.TestCase):
    def test_default_authentication_test_vector(self):
        h1, h2 = _default_authentication_hashes(
            "admin",
            synthetic_secret(),
            "TEST-REALM",
            "TEST-RANDOM",
        )

        self.assertEqual(h1, "B963A8A1E3EC7C55355D610ECDC5CEDD")
        self.assertEqual(h2, "B50934098AE7E0DD55BB22EDA8A2BAA7")
        self.assertEqual(len(h1), 32)
        self.assertEqual(len(h2), 32)

    def test_dhcp_request_matches_dhip_multicast_envelope(self):
        fake_socket = FakeSocket(
            [
                reply(default_challenge()),
                reply(default_success()),
            ]
        )
        transport = DhipNetworkTransport(
            TARGET_IP, TARGET_MAC, socket_factory=lambda *_args: fake_socket
        )
        secret = synthetic_secret()

        result = transport.set_dhcp(
            username="admin",
            password=secret,
            device_config={
                "Port": 37777,
                "IPv4Address": {
                    "IPAddress": TARGET_IP,
                    "SubnetMask": "255.255.255.0",
                    "DefaultGateway": "192.0.2.1",
                    "DhcpEnable": True,
                },
            },
            timeout=0.25,
        )

        self.assertTrue(result["result"])
        self.assertEqual(len(fake_socket.sent), 2)
        self.assertEqual(fake_socket.sent[0][1], ("239.255.255.251", 37810))
        self.assertEqual(fake_socket.sent[1][1], ("239.255.255.251", 37810))
        self.assertEqual(fake_socket.bound, ("0.0.0.0", 37810))
        request1 = decode_json_datagram(fake_socket.sent[0][0])
        request2 = decode_json_datagram(fake_socket.sent[1][0])
        self.assertEqual(request1["method"], DHIP_NETWORK_METHOD)
        self.assertEqual(request1["mac"], TARGET_MAC)
        self.assertEqual(request1["params"]["userName"], "admin")
        self.assertEqual(request1["params"]["password"], "")
        self.assertNotIn("authorityType", request1["params"])
        self.assertEqual(request2["method"], request1["method"])
        self.assertEqual(request2["mac"], request1["mac"])
        self.assertEqual(request2["params"]["userName"], request1["params"]["userName"])
        self.assertEqual(
            request2["params"]["password"], "B50934098AE7E0DD55BB22EDA8A2BAA7"
        )
        self.assertNotEqual(request2["params"]["password"], secret)
        self.assertEqual(request2["params"]["authorityType"], "Default")
        self.assertEqual(request2["params"]["uni"], request1["params"]["uni"])
        self.assertEqual(
            request2["params"]["deviceConfig"], request1["params"]["deviceConfig"]
        )
        self.assertNotIn("realm", request2["params"])
        self.assertNotIn("random", request2["params"])
        self.assertEqual(
            request1["params"]["deviceConfig"]["IPv4Address"]["DhcpEnable"], True
        )
        self.assertEqual(request1["params"]["uni"], 1)
        self.assertNotIn("id", request1)
        self.assertNotIn("session", request1)
        self.assertNotIn("id", request2)
        self.assertNotIn("session", request2)
        self.assertTrue(secret not in repr(transport), "DHIP transport repr exposed the password")
        self.assertTrue(fake_socket.closed)

    def test_static_network_uses_the_same_default_setconfig_handshake(self):
        fake_socket = FakeSocket(
            [reply(default_challenge()), reply(default_success())]
        )
        transport = DhipNetworkTransport(
            TARGET_IP, TARGET_MAC, socket_factory=lambda *_args: fake_socket
        )
        secret = synthetic_secret()
        client = DahuaNetworkClient(
            TARGET_IP,
            TARGET_MAC,
            "admin",
            secret,
            device_info={"Port": 37777},
            transport=transport,
        )

        client.set_static_ipv4(
            "198.51.100.68", "255.255.255.0", "198.51.100.1"
        )

        request1 = decode_json_datagram(fake_socket.sent[0][0])
        request2 = decode_json_datagram(fake_socket.sent[1][0])
        self.assertEqual(request1["params"]["password"], "")
        self.assertNotIn("authorityType", request1["params"])
        self.assertEqual(
            request2["params"]["password"], "B50934098AE7E0DD55BB22EDA8A2BAA7"
        )
        self.assertEqual(request2["params"]["authorityType"], "Default")
        self.assertEqual(request2["params"]["deviceConfig"], request1["params"]["deviceConfig"])
        self.assertEqual(
            request2["params"]["deviceConfig"],
            {
                "Port": 37777,
                "IPv4Address": {
                    "IPAddress": "198.51.100.68",
                    "SubnetMask": "255.255.255.0",
                    "DefaultGateway": "198.51.100.1",
                    "DhcpEnable": False,
                },
            },
        )
        self.assertNotIn("realm", request2["params"])
        self.assertNotIn("random", request2["params"])
        self.assertTrue(fake_socket.closed)

    def test_config_builder_preserves_only_discovered_values_and_enables_dhcp(self):
        config = build_dhcp_device_config(
            {
                "Port": 37777,
                "IPv4Address": {
                    "IPAddress": TARGET_IP,
                    "SubnetMask": "255.255.255.0",
                    "DefaultGateway": "192.0.2.1",
                    "DhcpEnable": False,
                },
            },
            TARGET_IP,
        )

        self.assertEqual(
            config,
            {
                "Port": 37777,
                "IPv4Address": {
                    "IPAddress": TARGET_IP,
                    "SubnetMask": "255.255.255.0",
                    "DefaultGateway": "192.0.2.1",
                    "DhcpEnable": True,
                },
            },
        )

    def test_own_echoes_and_foreign_packets_are_ignored_in_both_phases(self):
        secret = synthetic_secret()
        config = {"IPv4Address": {"DhcpEnable": True}}
        request1_echo = {
            "method": DHIP_NETWORK_METHOD,
            "mac": TARGET_MAC,
            "params": {
                "userName": "admin",
                "password": "",
                "deviceConfig": config,
                "uni": 1,
            },
        }
        request2_echo = {
            "method": DHIP_NETWORK_METHOD,
            "mac": TARGET_MAC,
            "params": {
                "userName": "admin",
                "password": expected_request_password(secret),
                "deviceConfig": config,
                "uni": 1,
                "authorityType": "Default",
            },
        }
        foreign_packet = {
            "method": "client.notifyCfgChange",
            "mac": "02:00:00:00:00:02",
            "params": {"result": False, "encryption": "Other"},
            "result": False,
        }
        fake_socket = FakeSocket(
            [
                reply(request1_echo),
                reply(foreign_packet),
                reply(default_challenge()),
                reply(request2_echo),
                reply(foreign_packet),
                reply(default_success()),
            ]
        )
        transport = DhipNetworkTransport(
            TARGET_IP, TARGET_MAC, socket_factory=lambda *_args: fake_socket
        )
        result = transport.set_dhcp(
            username="admin",
            password=secret,
            device_config=config,
            timeout=0.25,
        )

        self.assertTrue(result["result"])
        self.assertEqual(len(fake_socket.sent), 2)
        sent1 = decode_json_datagram(fake_socket.sent[0][0])
        sent2 = decode_json_datagram(fake_socket.sent[1][0])
        self.assertEqual(sent1, request1_echo)
        self.assertEqual(sent2["method"], request2_echo["method"])
        self.assertEqual(sent2["mac"], request2_echo["mac"])
        self.assertEqual(sent2["params"]["userName"], "admin")
        self.assertEqual(sent2["params"]["password"], expected_request_password(secret))
        self.assertNotEqual(sent2["params"]["password"], secret)
        self.assertEqual(sent2["params"]["deviceConfig"], config)
        self.assertEqual(sent2["params"]["uni"], 1)
        self.assertEqual(sent2["params"]["authorityType"], "Default")

    def test_ignored_packets_do_not_restart_the_response_deadline(self):
        request1_echo = {
            "method": DHIP_NETWORK_METHOD,
            "mac": TARGET_MAC,
            "params": {
                "userName": "admin",
                "password": "",
                "deviceConfig": {"IPv4Address": {"DhcpEnable": True}},
                "uni": 1,
            },
        }
        foreign_packet = {
            "method": "client.notifyCfgChange",
            "mac": "02:00:00:00:00:02",
            "params": {"result": False},
        }
        fake_socket = FakeSocket([reply(request1_echo), reply(foreign_packet)])
        transport = DhipNetworkTransport(
            TARGET_IP, TARGET_MAC, socket_factory=lambda *_args: fake_socket
        )
        secret = synthetic_secret()
        clock_values = iter((0.0, 0.1, 0.4, 1.01))

        with patch(
            "dh_tux_initialize.network_transport.time.monotonic",
            side_effect=lambda: next(clock_values),
        ):
            with self.assertRaises(DhipNetworkTransportError) as caught:
                transport.set_dhcp(
                    username="admin",
                    password=secret,
                    device_config={"IPv4Address": {"DhcpEnable": True}},
                    timeout=1.0,
                )

        self.assertIn("response timed out for DHDiscover.setConfig challenge", str(caught.exception))
        self.assertEqual(fake_socket.timeouts, [0.9, 0.6])
        self.assertEqual(len(fake_socket.sent), 1)
        self.assertTrue(secret not in str(caught.exception), "timeout exposed the password")

    def test_unexpected_challenge_method_reports_full_redacted_response(self):
        secret = synthetic_secret()
        unexpected = {
            "method": "server.notifySomethingElse",
            "mac": TARGET_MAC,
            "result": False,
            "params": {
                "code": 16789511,
                "password": secret,
                "credential": secret,
                "credentials": {"primary": secret},
                "detail": f"camera echoed {secret}",
                "safeField": "preserved",
            },
            "vendorField": {"status": "unchanged"},
        }
        fake_socket = FakeSocket([reply(unexpected)])
        transport = DhipNetworkTransport(
            TARGET_IP, TARGET_MAC, socket_factory=lambda *_args: fake_socket
        )

        with self.assertRaises(DhipNetworkTransportError) as caught:
            transport.set_dhcp(
                username="admin",
                password=secret,
                device_config={"IPv4Address": {"DhcpEnable": True}},
                timeout=0.25,
            )

        message = str(caught.exception)
        self.assertIn("DHDiscover.setConfig challenge used unexpected response:", message)
        self.assertIn('"method": "server.notifySomethingElse"', message)
        self.assertIn(f'"mac": "{TARGET_MAC}"', message)
        self.assertIn('"result": false', message)
        self.assertIn('"code": 16789511', message)
        self.assertIn('"safeField": "preserved"', message)
        self.assertIn('"vendorField": {"status": "unchanged"}', message)
        self.assertIn('"password": "<redacted>"', message)
        self.assertIn('"credential": "<redacted>"', message)
        self.assertIn('"credentials": "<redacted>"', message)
        self.assertIn('"detail": "camera echoed <redacted>"', message)
        self.assertTrue(secret not in message, "unexpected response diagnostic exposed the password")
        self.assertEqual(len(fake_socket.sent), 1)

    def test_unknown_challenge_encryption_aborts_before_authenticated_write(self):
        fake_socket = FakeSocket([reply(default_challenge(encryption="Digest"))])
        transport = DhipNetworkTransport(
            TARGET_IP, TARGET_MAC, socket_factory=lambda *_args: fake_socket
        )
        secret = synthetic_secret()

        with self.assertRaises(DhipNetworkTransportError) as caught:
            transport.set_dhcp(
                username="admin",
                password=secret,
                device_config={"IPv4Address": {"DhcpEnable": True}},
                timeout=0.25,
            )

        self.assertIn("unsupported authentication mode", str(caught.exception))
        self.assertTrue(
            secret not in str(caught.exception),
            "encryption error exposed the configured password",
        )
        self.assertEqual(len(fake_socket.sent), 1)

    def test_missing_realm_or_random_aborts_before_request2(self):
        secret = synthetic_secret()
        for missing_field in ("realm", "random"):
            with self.subTest(missing_field=missing_field):
                challenge = default_challenge(
                    **{missing_field: None}
                )
                fake_socket = FakeSocket([reply(challenge)])
                transport = DhipNetworkTransport(
                    TARGET_IP,
                    TARGET_MAC,
                    socket_factory=lambda *_args: fake_socket,
                )

                with self.assertRaises(DhipNetworkTransportError) as caught:
                    transport.set_dhcp(
                        username="admin",
                        password=secret,
                        device_config={"IPv4Address": {"DhcpEnable": True}},
                        timeout=0.25,
                    )

                self.assertIn(missing_field, str(caught.exception))
                self.assertEqual(len(fake_socket.sent), 1)

    def test_challenge_must_report_result_false(self):
        challenge = default_challenge()
        challenge["result"] = True
        challenge["params"]["result"] = True
        fake_socket = FakeSocket([reply(challenge)])
        transport = DhipNetworkTransport(
            TARGET_IP, TARGET_MAC, socket_factory=lambda *_args: fake_socket
        )

        with self.assertRaises(DhipNetworkTransportError) as caught:
            transport.set_dhcp(
                username="admin",
                password=synthetic_secret(),
                device_config={"IPv4Address": {"DhcpEnable": True}},
                timeout=0.25,
            )

        self.assertIn("did not request authentication", str(caught.exception))
        self.assertEqual(len(fake_socket.sent), 1)

    def test_request2_false_result_is_error_and_response_diagnostics_redact_password(self):
        secret = synthetic_secret()
        h1, h2 = _default_authentication_hashes(
            "admin",
            secret,
            "TEST-REALM",
            "TEST-RANDOM",
        )
        failed = default_success()
        failed["result"] = False
        failed["params"] = {
            "result": False,
            "encryption": "Default",
            "password": secret,
            "detail": f"rejected {secret} {h1} {h2}",
            "hashEcho": f"{h1} {h2}",
        }
        fake_socket = FakeSocket([reply(default_challenge()), reply(failed)])
        transport = DhipNetworkTransport(
            TARGET_IP, TARGET_MAC, socket_factory=lambda *_args: fake_socket
        )
        client = DahuaNetworkClient(
            TARGET_IP, TARGET_MAC, "admin", secret, transport=transport
        )

        with self.assertRaises(ProvisioningError) as caught:
            client.enable_dhcp()

        message = str(caught.exception)
        self.assertIn("DHDiscover.setConfig failed", message)
        self.assertIn('"result": false', message)
        self.assertIn('"password": "<redacted>"', message)
        self.assertIn(
            '"detail": "rejected <redacted> <redacted> <redacted>"', message
        )
        self.assertIn('"hashEcho": "<redacted> <redacted>"', message)
        self.assertTrue(secret not in message, "DHIP failure exposed the password")
        self.assertNotIn(h1, message)
        self.assertNotIn(h2, message)
        self.assertEqual(len(fake_socket.sent), 2)

    def test_request2_foreign_mac_is_ignored_until_timeout(self):
        fake_socket = FakeSocket(
            [reply(default_challenge()), reply(default_success(mac="02:00:00:00:00:02"))]
        )
        transport = DhipNetworkTransport(
            TARGET_IP, TARGET_MAC, socket_factory=lambda *_args: fake_socket
        )
        secret = synthetic_secret()

        with self.assertRaises(DhipNetworkTransportError) as caught:
            transport.set_dhcp(
                username="admin",
                password=secret,
                device_config={"IPv4Address": {"DhcpEnable": True}},
                timeout=0.25,
            )

        self.assertIn("response timed out for DHDiscover.setConfig authenticated response", str(caught.exception))
        self.assertTrue(
            secret not in str(caught.exception),
            "response error exposed the configured password",
        )
        self.assertEqual(len(fake_socket.sent), 2)

    def test_socket_error_redacts_configured_password(self):
        secret = synthetic_secret()
        fake_socket = FakeSocket(send_error=OSError(f"send failed: {secret}"))
        transport = DhipNetworkTransport(
            TARGET_IP, TARGET_MAC, socket_factory=lambda *_args: fake_socket
        )

        with self.assertRaises(DhipNetworkTransportError) as caught:
            transport.set_dhcp(
                username="admin",
                password=secret,
                device_config={"IPv4Address": {"DhcpEnable": True}},
                timeout=0.25,
            )

        self.assertTrue(
            secret not in str(caught.exception),
            "socket error exposed the configured password",
        )
        self.assertTrue(fake_socket.closed)

    def test_timeout_does_not_retry_the_dhcp_write(self):
        fake_socket = FakeSocket()
        transport = DhipNetworkTransport(
            TARGET_IP, TARGET_MAC, socket_factory=lambda *_args: fake_socket
        )
        secret = synthetic_secret()

        with self.assertRaises(DhipNetworkTransportError) as caught:
            transport.set_dhcp(
                username="admin",
                password=secret,
                device_config={"IPv4Address": {"DhcpEnable": True}},
                timeout=0.01,
            )

        self.assertIn("response timed out for DHDiscover.setConfig challenge", str(caught.exception))
        self.assertEqual(len(fake_socket.sent), 1)
        self.assertTrue(fake_socket.closed)


if __name__ == "__main__":
    unittest.main()
