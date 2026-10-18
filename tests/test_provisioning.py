import unittest

from cryptography.hazmat.primitives.asymmetric import rsa

from dh_tux_initialize.discovery import DiscoveredDevice
from dh_tux_initialize.init_protocol import InitializationClient, InitializationError
from dh_tux_initialize.provisioning import (
    DahuaNetworkClient,
    ProvisioningError,
    provision_device,
)
from dh_tux_initialize.setup import SetupPlan


def make_device(init=3733):
    return DiscoveredDevice(
        {
            "Mac": "02:00:00:00:00:01",
            "IPv4Address": {"IPAddress": "192.0.2.108"},
            "DeviceType": "IPC-Test-Camera",
            "Init": init,
        },
        {},
        "192.0.2.108",
        valid_dhip_identity=True,
        dahua_verified=True,
    )


def synthetic_secret():
    return "".join(chr(code) for code in (80, 114, 111, 118, 105, 115, 105, 111, 110)) + "-" + str(582)


class FakeJsonTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post_json(self, url, body, *, timeout):
        self.calls.append((url, dict(body), timeout))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class FakeDhipDhcpTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def set_dhcp(self, *, username, password, device_config, timeout):
        self.calls.append((username, password, dict(device_config), timeout))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class ProvisioningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        public = rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key().public_numbers()
        cls.public_key = f"N:{public.n:X},E:{public.e:X}"

    def client_responses(self, *, account=None):
        status = {"result": True, "params": {"status": "uninitialized"}}
        caps = {
            "result": True,
            "params": {"definition": {"SupportDevInit": True}},
        }
        encrypt_info = {
            "result": True,
            "params": {
                "asymmetric": "RSA",
                "pub": self.public_key,
                "cipher": ["AES-128"],
                "SecurityBaselineVersion": "V1.4",
            },
        }
        return [
            status,
            caps,
            encrypt_info,
            account or {"result": True},
        ]

    def test_provisioning_orders_account_verification_then_dhcp(self):
        secret = synthetic_secret()
        json_transport = FakeJsonTransport(self.client_responses())
        network_transport = FakeDhipDhcpTransport([{"result": True}])
        client = InitializationClient(transport=json_transport)

        provision_device(
            SetupPlan(
                mac="02:00:00:00:00:01",
                model="IPC-Test-Camera",
                password=secret,
                network_mode="dhcp",
            ),
            make_device(),
            initialization_client_factory=lambda _ip: client,
            rediscover_fn=lambda: [make_device(init=3734)],
            network_transport=network_transport,
        )

        self.assertEqual(
            [call[1]["method"] for call in json_transport.calls],
            [
                "DevInit.getStatus",
                "userManager.getCaps",
                "Security.getEncryptInfo",
                "DevInit.account",
            ],
        )
        self.assertTrue(all(call[0].endswith("/OutsideCmd") for call in json_transport.calls))
        self.assertTrue(all("session" not in call[1] for call in json_transport.calls))
        self.assertEqual(len(network_transport.calls), 1)
        username, password, device_config, _timeout = network_transport.calls[0]
        self.assertEqual(username, "admin")
        self.assertTrue(password == secret)
        self.assertEqual(
            device_config,
            {"IPv4Address": {"IPAddress": "192.0.2.108", "DhcpEnable": True}},
        )
        self.assertTrue(secret not in repr(client), "initialization client repr exposed the password")

    def test_discovery_init_bitfield_authorizes_account_and_unknown_still_refuses(self):
        secret = synthetic_secret()

        # DHIP/DHDiscover reports Init=3733 (low bits 01), which is the
        # selected camera's authoritative uninitialized state. The separate
        # status read may omit that field on factory-default cameras.
        responses = self.client_responses()
        responses[0] = {"result": True, "params": {}}
        json_transport = FakeJsonTransport(responses)
        network_transport = FakeDhipDhcpTransport([{"result": True}])
        provision_device(
            SetupPlan(
                mac="02:00:00:00:00:01",
                model="IPC-Test-Camera",
                password=secret,
                network_mode="dhcp",
            ),
            make_device(),
            initialization_client_factory=lambda _ip: InitializationClient(transport=json_transport),
            rediscover_fn=lambda: [make_device(init=3734)],
            network_transport=network_transport,
        )
        self.assertIn("DevInit.account", [call[1]["method"] for call in json_transport.calls])

        # With neither a discovery Init value nor a known RPC state, the
        # existing write guard remains closed.
        unknown_responses = self.client_responses()
        unknown_responses[0] = {"result": True, "params": {}}
        unknown_transport = FakeJsonTransport(unknown_responses)
        with self.assertRaisesRegex(InitializationError, "initialization state is unknown"):
            InitializationClient(transport=unknown_transport).initialize_account(secret)
        self.assertEqual(
            [call[1]["method"] for call in unknown_transport.calls],
            ["DevInit.getStatus"],
        )

    def test_provisioning_continues_when_user_manager_caps_is_unavailable_or_empty(self):
        secret = synthetic_secret()
        for caps_response in (
            TimeoutError("caps response timed out"),
            {"result": True, "params": {}},
        ):
            with self.subTest(caps_response=type(caps_response).__name__):
                responses = self.client_responses()
                responses[1] = caps_response
                json_transport = FakeJsonTransport(responses)
                network_transport = FakeDhipDhcpTransport([{"result": True}])

                provision_device(
                    SetupPlan(
                        mac="02:00:00:00:00:01",
                        model="IPC-Test-Camera",
                        password=secret,
                        network_mode="dhcp",
                    ),
                    make_device(),
                    initialization_client_factory=lambda _ip: InitializationClient(transport=json_transport),
                    rediscover_fn=lambda: [make_device(init=3734)],
                    network_transport=network_transport,
                )

                self.assertEqual(
                    [call[1]["method"] for call in json_transport.calls],
                    [
                        "DevInit.getStatus",
                        "userManager.getCaps",
                        "Security.getEncryptInfo",
                        "DevInit.account",
                    ],
                )
                self.assertNotIn("DevInit.getDevCaps", [call[1]["method"] for call in json_transport.calls])

    def test_missing_or_invalid_encrypt_info_stops_before_account_and_dhcp(self):
        secret = synthetic_secret()
        for label, encrypt_info in (
            ("missing response", TimeoutError("encrypt info response timed out")),
            ("missing parameters", {"result": True}),
            ("reported failure", {"result": False, "error": {"code": 5, "message": "unavailable"}}),
        ):
            with self.subTest(encrypt_info=label):
                responses = self.client_responses()
                responses[2] = encrypt_info
                json_transport = FakeJsonTransport(responses)
                network_transport = FakeDhipDhcpTransport([])

                with self.assertRaises(ProvisioningError):
                    provision_device(
                        SetupPlan(
                            mac="02:00:00:00:00:01",
                            model="IPC-Test-Camera",
                            password=secret,
                            network_mode="dhcp",
                        ),
                        make_device(),
                        initialization_client_factory=lambda _ip: InitializationClient(transport=json_transport),
                        network_transport=network_transport,
                    )

                self.assertEqual(
                    [call[1]["method"] for call in json_transport.calls],
                    ["DevInit.getStatus", "userManager.getCaps", "Security.getEncryptInfo"],
                )
                self.assertEqual(network_transport.calls, [])

    def test_account_error_stops_before_verification_or_network_change(self):
        secret = synthetic_secret()
        json_transport = FakeJsonTransport(
            self.client_responses(account={"result": False, "error": {"code": 17, "message": "ErrorNotAllowed"}})
        )
        network_transport = FakeDhipDhcpTransport([])

        with self.assertRaises(ProvisioningError) as caught:
            provision_device(
                SetupPlan(
                    mac="02:00:00:00:00:01",
                    model="IPC-Test-Camera",
                    password=secret,
                    network_mode="dhcp",
                ),
                make_device(),
                initialization_client_factory=lambda _ip: InitializationClient(transport=json_transport),
                network_transport=network_transport,
            )

        self.assertIn("DevInit.account failed: 17: ErrorNotAllowed", str(caught.exception))
        self.assertEqual(
            [call[1]["method"] for call in json_transport.calls],
            ["DevInit.getStatus", "userManager.getCaps", "Security.getEncryptInfo", "DevInit.account"],
        )
        self.assertEqual(network_transport.calls, [])
        self.assertTrue(secret not in str(caught.exception), "provisioning error exposed the password")

    def test_account_verification_uses_fresh_dhip_state_and_ignores_post_account_status(self):
        secret = synthetic_secret()
        responses = self.client_responses()
        # This would fail verification if DevInit.getStatus were called after
        # DevInit.account. The fresh DHIP scan below supplies the authority.
        responses.append({"result": True, "params": {}})
        json_transport = FakeJsonTransport(responses)
        network_transport = FakeDhipDhcpTransport([{"result": True}])
        rediscoveries = []

        def rediscover_same_mac():
            rediscoveries.append(True)
            self.assertEqual(json_transport.calls[-1][1]["method"], "DevInit.account")
            self.assertEqual(network_transport.calls, [])
            return [make_device(init=3734)]

        provision_device(
            SetupPlan(
                mac="02:00:00:00:00:01",
                model="IPC-Test-Camera",
                password=secret,
                network_mode="dhcp",
            ),
            make_device(),
            initialization_client_factory=lambda _ip: InitializationClient(transport=json_transport),
            rediscover_fn=rediscover_same_mac,
            network_transport=network_transport,
        )

        self.assertEqual(
            [call[1]["method"] for call in json_transport.calls],
            ["DevInit.getStatus", "userManager.getCaps", "Security.getEncryptInfo", "DevInit.account"],
        )
        self.assertEqual(rediscoveries, [True])
        self.assertEqual(len(network_transport.calls), 1)

    def test_initialization_verification_failure_stops_before_dhcp(self):
        json_transport = FakeJsonTransport(self.client_responses())
        network_transport = FakeDhipDhcpTransport([])

        with self.assertRaisesRegex(ProvisioningError, "camera remains uninitialized"):
            provision_device(
                SetupPlan(
                    mac="02:00:00:00:00:01",
                    model="IPC-Test-Camera",
                    password=synthetic_secret(),
                    network_mode="dhcp",
                ),
                make_device(),
                initialization_client_factory=lambda _ip: InitializationClient(transport=json_transport),
                rediscover_fn=lambda: [make_device(init=3733)],
                network_transport=network_transport,
            )

        self.assertEqual(network_transport.calls, [])
        self.assertEqual(json_transport.calls[-1][1]["method"], "DevInit.account")

    def test_incomplete_static_plan_is_rejected_before_devinit_account(self):
        secret = synthetic_secret()
        json_transport = FakeJsonTransport(self.client_responses())
        network_transport = FakeDhipDhcpTransport([])

        with self.assertRaisesRegex(ProvisioningError, "static network plan is incomplete"):
            provision_device(
                SetupPlan(
                    mac="02:00:00:00:00:01",
                    model="IPC-Test-Camera",
                    password=secret,
                    network_mode="static",
                    ipv4="192.0.2.20",
                ),
                make_device(),
                initialization_client_factory=lambda _ip: InitializationClient(
                    transport=json_transport
                ),
                network_transport=network_transport,
            )

        self.assertEqual(json_transport.calls, [])
        self.assertEqual(network_transport.calls, [])

    def test_static_plan_uses_existing_setconfig_transport_with_static_device_config(self):
        secret = synthetic_secret()
        json_transport = FakeJsonTransport(self.client_responses())
        network_transport = FakeDhipDhcpTransport([{"result": True}])
        selected = make_device()
        selected.info["Port"] = 37777
        plan = SetupPlan(
            mac="02:00:00:00:00:01",
            model="IPC-Test-Camera",
            password=secret,
            network_mode="static",
            ipv4="198.51.100.68",
            netmask="255.255.255.0",
            gateway="198.51.100.1",
        )

        provision_device(
            plan,
            selected,
            initialization_client_factory=lambda _ip: InitializationClient(
                transport=json_transport
            ),
            rediscover_fn=lambda: [make_device(init=3734)],
            network_transport=network_transport,
        )

        self.assertEqual(
            [call[1]["method"] for call in json_transport.calls],
            ["DevInit.getStatus", "userManager.getCaps", "Security.getEncryptInfo", "DevInit.account"],
        )
        self.assertEqual(len(network_transport.calls), 1)
        username, password, device_config, _timeout = network_transport.calls[0]
        self.assertEqual(username, "admin")
        self.assertEqual(password, secret)
        self.assertEqual(
            device_config,
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

    def test_dhip_network_rpc_error_is_displayable_and_password_redacted(self):
        secret = synthetic_secret()
        network_transport = FakeDhipDhcpTransport(
            [
                {
                    "method": "client.notifyCfgChange",
                    "mac": "02:00:00:00:00:01",
                    "result": False,
                    "error": {"code": 13, "message": f"denied {secret}"},
                    "params": {
                        "code": 16789511,
                        "encryption": "Default",
                        "realm": "TEST-REALM",
                        "result": False,
                        "mode": "DHCP",
                        "pwd": secret,
                        "detail": f"credential {secret} rejected",
                    },
                    "diagnosticId": "rpc-42",
                    "vendorField": {"reason": "policy"},
                }
            ]
        )
        network = DahuaNetworkClient(
            "192.0.2.108",
            "02:00:00:00:00:01",
            "admin",
            secret,
            transport=network_transport,
        )

        with self.assertRaisesRegex(ProvisioningError, "DHDiscover.setConfig failed") as caught:
            network.enable_dhcp()

        message = str(caught.exception)
        self.assertNotIn(secret, message, "DHIP error exposed the password")
        self.assertIn('"method": "client.notifyCfgChange"', message)
        self.assertIn('"mac": "02:00:00:00:00:01"', message)
        self.assertIn('"result": false', message)
        self.assertIn('"code": 13', message)
        self.assertIn('"message": "denied <redacted>"', message)
        self.assertIn('"params":', message)
        self.assertIn('"code": 16789511', message)
        self.assertIn('"encryption": "Default"', message)
        self.assertIn('"realm": "TEST-REALM"', message)
        self.assertIn('"mode": "DHCP"', message)
        self.assertIn('"pwd": "<redacted>"', message)
        self.assertIn('"detail": "credential <redacted> rejected"', message)
        self.assertIn('"diagnosticId": "rpc-42"', message)
        self.assertIn('"vendorField": {"reason": "policy"}', message)
        self.assertNotIn("device_config", message)
        self.assertNotIn('"username"', message)
        self.assertEqual(len(network_transport.calls), 1)
