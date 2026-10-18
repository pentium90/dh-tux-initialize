import base64
import io
import json
import traceback
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import Mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from dh_tux_initialize.init_crypto import (
    CryptoProtocolError,
    IV,
    encrypt_content,
    encrypt_parameters,
    parse_security_encrypt_info,
)
from dh_tux_initialize.init_protocol import (
    DEFAULT_INIT_IP,
    MINIMUM_ACCESS_PARAMS,
    READ_METHODS,
    InitializationDiagnostics,
    InitializationClient,
    InitializationError,
    build_access_request,
    build_account_payload,
    build_account_request,
)
from dh_tux_initialize.setup import SetupPlan


def _synthetic_secret():
    # Construct the disposable test value at runtime; never keep a password
    # fixture or an actual credential in the test source.
    return "".join(chr(value) for value in (65, 66, 67, 45, 84, 101, 115, 116)) + "-" + str(1073)


class FakeTransport:
    def __init__(self, responses=()):
        self.responses = list(responses)
        self.calls = []

    def post_json(self, url, body, *, timeout):
        self.calls.append((url, dict(body), timeout))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class InitCryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        public = cls.private_key.public_key().public_numbers()
        cls.pub = f"N:{public.n:X},E:{public.e:X}"

    def encrypt_info(self, *, cipher=("AES",), baseline="V1.4", padding_names=None):
        params = {
            "result": True,
            "asymmetric": "RSA",
            "pub": self.pub,
            "cipher": list(cipher),
        }
        if padding_names is not None:
            params["AESPadding"] = list(padding_names)
        if baseline is not None:
            params["SecurityBaselineVersion"] = baseline
        return {"result": True, "params": params}

    def test_parses_security_encrypt_info_and_rsa_numbers(self):
        profile = parse_security_encrypt_info(
            self.encrypt_info(cipher=("RPAC",), baseline="V2.0", padding_names=("ZeroPadding",)),
            {"params": {"definition": {"SupportDevInit": True}}},
        )

        self.assertEqual(profile.asymmetric, "RSA")
        self.assertEqual(profile.cipher, "RPAC-256")
        self.assertEqual(profile.cipher_name, "AES-256-CBC")
        self.assertEqual(profile.security_baseline_version, "V2.0")
        self.assertEqual(profile.rsa_modulus_bits, 1024)
        self.assertEqual(profile.rsa_exponent, 65537)
        self.assertEqual(profile.session_key_bytes, 32)
        self.assertEqual(profile.rsa_salt_bytes, 128)
        self.assertNotIn(self.pub, repr(profile))

    def test_parses_security_baseline_with_alternate_documented_capitalization(self):
        profile = parse_security_encrypt_info(
            self.encrypt_info(cipher=("ROAE",), baseline=None),
            {"params": {"definition": {"SecurityBaseLineVersion": "V2.1"}}},
        )
        self.assertEqual(profile.security_baseline_version, "V2.1")
        self.assertEqual(profile.session_key_bytes, 32)
        self.assertEqual(profile.cipher, "ROAE-256")

    def test_uses_security_baseline_exposed_by_status_read(self):
        profile = parse_security_encrypt_info(
            self.encrypt_info(baseline=None),
            status={"params": {"SecurityBaselineVersion": "V1.4"}},
        )
        self.assertEqual(profile.session_key_bytes, 16)
        self.assertEqual(profile.cipher, "AES-128")

    def test_parses_pem_public_key(self):
        pem = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        response = self.encrypt_info(baseline="V1.9")
        response["params"]["pub"] = pem

        profile = parse_security_encrypt_info(response)

        self.assertEqual(profile.rsa_modulus_bits, 1024)
        self.assertEqual(profile.session_key_bytes, 16)

    def test_supports_legacy_aes128_profile_and_explicit_key_length(self):
        response = self.encrypt_info(baseline=None)
        response["params"].update({"cipher": ["AES-128-CBC"], "keyLength": 16})

        profile = parse_security_encrypt_info(response)

        self.assertEqual(profile.cipher_name, "AES-128-CBC")
        self.assertEqual(profile.cipher, "AES-128")
        self.assertEqual(profile.session_key_bytes, 16)

    def test_supports_aes256_from_device_advertised_cipher(self):
        response = self.encrypt_info(baseline=None, cipher=("AES-256-CBC",))

        profile = parse_security_encrypt_info(response)

        self.assertEqual(profile.cipher_name, "AES-256-CBC")
        self.assertEqual(profile.cipher, "AES-256")
        self.assertEqual(profile.session_key_bytes, 32)

    def test_zero_padding_and_ascii_zero_iv(self):
        key = b"0123456789012345"
        encrypted = encrypt_content(b'{"a":1}', key=key, cipher_name="AES-128-CBC")
        ciphertext = base64.b64decode(encrypted)
        decryptor = Cipher(algorithms.AES(key), modes.CBC(b"0000000000000000")).decryptor()

        self.assertEqual(IV, b"0000000000000000")
        self.assertEqual(decryptor.update(ciphertext) + decryptor.finalize(), b'{"a":1}' + b"\x00" * 9)

    def test_aes128_known_vector_with_injected_numeric_key(self):
        key = b"0123456789012345"

        encrypted = encrypt_content(b'{"a":1}', key=key, cipher_name="AES-128-CBC")

        self.assertEqual(encrypted, "KYvBcV7LgNUETC38mFKbaA==")

    def test_aes256_known_vector_with_injected_numeric_key(self):
        key = b"01234567890123456789012345678901"

        encrypted = encrypt_content(b'{"a":1}', key=key, cipher_name="AES-256-CBC")

        self.assertEqual(encrypted, "uPNk8k9Ea/zyfm840A8oIQ==")

    def test_deterministic_envelope_vector_uses_injected_key_and_rsa_encryptor(self):
        profile = parse_security_encrypt_info(self.encrypt_info(baseline="V1.4"))
        synthetic_secret = _synthetic_secret()
        encrypted = encrypt_parameters(
            {"pwd": synthetic_secret},
            profile,
            random_key="0123456789012345",
            rsa_encryptor=lambda _public_key, clear_key: b"fixed-rsa" + clear_key,
        )

        self.assertEqual(encrypted.salt, b"fixed-rsa0123456789012345".hex().upper())
        self.assertEqual(encrypted.cipher, "AES-128")
        self.assertEqual(encrypted.content, "x4aFKGJz7Twf9Omftoo7Xc5/HaEpm0SDaMmFV2RX4A8=")
        self.assertNotIn(synthetic_secret, repr(encrypted))

    def test_encrypt_parameters_rsa_encrypts_numeric_key_with_pkcs1_v15(self):
        profile = parse_security_encrypt_info(self.encrypt_info(baseline="V1.4"))
        envelope = encrypt_parameters(
            {"method": "DevInit.account"},
            profile,
            random_key="0123456789012345",
        )
        clear_key = self.private_key.decrypt(
            bytes.fromhex(envelope.salt),
            padding.PKCS1v15(),
        )

        self.assertEqual(clear_key, b"0123456789012345")
        self.assertEqual(len(bytes.fromhex(envelope.salt)), profile.rsa_modulus_bytes)

    def test_generates_only_the_device_required_count_of_numeric_digits(self):
        profile = parse_security_encrypt_info(self.encrypt_info(cipher=("RPAC",), baseline="V2.0"))
        provided = []
        encrypt_parameters(
            {},
            profile,
            random_digits=lambda count: provided.append(count) or "7" * count,
            rsa_encryptor=lambda _public_key, clear_key: clear_key,
        )
        self.assertEqual(provided, [32])

    def test_rejects_malformed_or_unsupported_capabilities(self):
        with self.assertRaises(CryptoProtocolError):
            parse_security_encrypt_info({"result": True})
        with self.assertRaises(CryptoProtocolError):
            parse_security_encrypt_info(self.encrypt_info(cipher=("DES",), baseline="V1.4"))
        with self.assertRaises(CryptoProtocolError):
            parse_security_encrypt_info(self.encrypt_info(baseline=None))
        with self.assertRaises(CryptoProtocolError):
            parse_security_encrypt_info(self.encrypt_info(baseline="future"))
        with self.assertRaises(CryptoProtocolError):
            parse_security_encrypt_info(
                self.encrypt_info(baseline="V2.0"),
                {"params": {"definition": {"keyLength": 16}}},
            )

    def test_rejects_padding_not_advertised_by_device(self):
        with self.assertRaises(CryptoProtocolError):
            parse_security_encrypt_info(
                self.encrypt_info(baseline="V1.4", padding_names=("PKCS7",))
            )

    def test_unsupported_crypto_diagnostic_still_shows_safe_key_metrics(self):
        public = self.private_key.public_key().public_numbers()
        diagnostics = InitializationDiagnostics(
            ip="192.168.1.108",
            status={"result": True},
            dev_caps={"params": {"SecurityBaselineVersion": "V1.4"}},
            encrypt_info={
                "result": True,
                "params": {
                    "asymmetric": "RSA",
                    "pub": {"N": f"{public.n:X}", "E": public.e},
                    "cipher": ["UNSUPPORTED"],
                },
            },
        )

        report = diagnostics.report()

        self.assertFalse(report["crypto_profile"]["supported"])
        self.assertEqual(report["crypto_profile"]["rsa_modulus_bits"], 1024)
        self.assertEqual(report["crypto_profile"]["rsa_exponent"], 65537)
        self.assertEqual(report["crypto_profile"]["session_key_length_bytes"], 16)
        shortened_n = report["Security.getEncryptInfo"]["params"]["pub"]["N"]
        self.assertLess(len(shortened_n), len(f"{public.n:X}"))


class InitProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        public = cls.private_key.public_key().public_numbers()
        cls.pub = f"N:{public.n:X},E:{public.e:X}"
        cls.status = {"result": True, "params": {"status": "uninitialized"}}
        cls.caps = {
            "result": True,
            "params": {
                "definition": {
                    "SupportDevInit": True,
                    "SecurityBaselineVersion": "V2.0",
                    "DevInit": {"account": True, "access": True},
                }
            },
        }
        cls.encrypt_info = {
            "result": True,
            "params": {"asymmetric": "RSA", "pub": cls.pub, "cipher": ["RPAC"]},
        }

    def responses(self, tail=()):
        return [self.status, self.caps, self.encrypt_info, *tail]

    def test_account_payload_has_exact_fields_but_redacts_repr(self):
        secret = _synthetic_secret()

        payload = build_account_payload(secret)

        self.assertEqual(dict(payload.items()), {
            "name": "admin",
            "pwd": secret,
            "CellPhone": "",
            "Mail": "",
        })
        self.assertNotIn(secret, repr(payload))

    def test_account_request_is_encrypted_and_sessionless(self):
        secret = _synthetic_secret()
        profile = parse_security_encrypt_info(self.encrypt_info, self.caps)
        request = build_account_request(
            secret,
            profile,
            random_key="01234567890123456789012345678901",
            rsa_encryptor=lambda _public_key, key: b"rsa" + key,
        )

        self.assertEqual(request["method"], "DevInit.account")
        self.assertEqual(request["id"], 1)
        self.assertNotIn("session", request)
        self.assertEqual(set(request["params"]), {"salt", "cipher", "content"})
        self.assertEqual(request["params"]["cipher"], "RPAC-256")
        self.assertNotIn(secret, repr(request))

        decryptor = Cipher(
            algorithms.AES(b"01234567890123456789012345678901"),
            modes.CBC(b"0000000000000000"),
        ).decryptor()
        ciphertext = base64.b64decode(request["params"]["content"])
        clear_content = decryptor.update(ciphertext) + decryptor.finalize()
        self.assertEqual(
            json.loads(clear_content.rstrip(b"\x00").decode("utf-8")),
            {"name": "admin", "pwd": secret, "CellPhone": "", "Mail": ""},
        )

    def test_inspection_uses_only_the_three_sessionless_outsidecmd_reads(self):
        transport = FakeTransport(self.responses())
        client = InitializationClient(transport=transport)

        report = client.inspect().report()

        self.assertEqual(DEFAULT_INIT_IP, "192.168.1.108")
        self.assertEqual([call[1]["method"] for call in transport.calls], list(READ_METHODS))
        self.assertTrue(all(call[0].endswith("/OutsideCmd") for call in transport.calls))
        self.assertTrue(all("session" not in call[1] for call in transport.calls))
        self.assertTrue(all(call[1]["params"] is None for call in transport.calls))
        self.assertEqual(report["crypto_profile"]["encryption_scheme"], "RSA/PKCS#1 v1.5 + AES-256-CBC")
        self.assertEqual(report["crypto_profile"]["device_cipher"], "RPAC-256")
        self.assertEqual(report["crypto_profile"]["rsa_exponent"], 65537)
        self.assertEqual(report["crypto_profile"]["session_key_length_bytes"], 32)
        self.assertEqual(report["supported_DevInit_capabilities"], {
            "SupportDevInit": True,
            "account": True,
            "access": True,
        })
        self.assertLess(len(report["Security.getEncryptInfo"]["params"]["pub"]), len(self.pub))
        self.assertIn("65537", json.dumps(report))

    def test_inspection_continues_through_all_three_reads_after_one_transport_error(self):
        secret = _synthetic_secret()
        transport = FakeTransport([RuntimeError(secret), self.caps, self.encrypt_info])
        client = InitializationClient(transport=transport)

        report = client.inspect().report()

        self.assertEqual([call[1]["method"] for call in transport.calls], list(READ_METHODS))
        self.assertEqual(
            report["DevInit.getStatus"],
            {"diagnostic_error": "DevInit.getStatus request failed"},
        )
        self.assertEqual(report["crypto_profile"]["session_key_length_bytes"], 32)
        self.assertNotIn(secret, json.dumps(report))

    def test_account_write_uses_same_sessionless_outsidecmd_and_encrypted_payload(self):
        transport = FakeTransport(self.responses(tail=({"result": True},)))
        client = InitializationClient(transport=transport)
        secret = _synthetic_secret()

        result = client.initialize_account(
            secret,
            random_key="01234567890123456789012345678901",
            rsa_encryptor=lambda _public_key, key: b"opaque" + key,
        )

        self.assertEqual(result, {"result": True})
        self.assertEqual(
            [call[1]["method"] for call in transport.calls],
            ["DevInit.getStatus", "userManager.getCaps", "Security.getEncryptInfo", "DevInit.account"],
        )
        request = transport.calls[-1][1]
        self.assertEqual(transport.calls[-1][0], "http://192.168.1.108:80/OutsideCmd")
        self.assertNotIn("session", request)
        self.assertNotIn(secret, repr(request))
        self.assertEqual(set(request["params"]), {"salt", "cipher", "content"})

    def test_minimum_access_builder_leaves_optional_features_disabled(self):
        profile = parse_security_encrypt_info(self.encrypt_info, self.caps)
        key = "01234567890123456789012345678901"
        request = build_access_request(
            profile,
            random_key=key,
            rsa_encryptor=lambda _public_key, session_key: b"opaque" + session_key,
        )

        self.assertEqual(request["method"], "DevInit.access")
        self.assertEqual(set(request["params"]), {"salt", "cipher", "content"})
        self.assertEqual(request["params"]["cipher"], "RPAC-256")
        decryptor = Cipher(
            algorithms.AES(key.encode("ascii")),
            modes.CBC(b"0000000000000000"),
        ).decryptor()
        clear_content = decryptor.update(base64.b64decode(request["params"]["content"])) + decryptor.finalize()
        self.assertEqual(json.loads(clear_content.rstrip(b"\x00").decode()), MINIMUM_ACCESS_PARAMS)
        self.assertNotIn("session", request)

    def test_access_write_is_sessionless_and_uses_only_minimum_values(self):
        transport = FakeTransport(self.responses(tail=({"result": True},)))
        client = InitializationClient(transport=transport)
        key = "01234567890123456789012345678901"
        client.configure_minimum_access(
            random_key=key,
            rsa_encryptor=lambda _public_key, session_key: b"opaque" + session_key,
        )
        request = transport.calls[-1][1]
        self.assertEqual(
            [call[1]["method"] for call in transport.calls],
            [*READ_METHODS, "DevInit.access"],
        )
        self.assertEqual(request["method"], "DevInit.access")
        decryptor = Cipher(
            algorithms.AES(key.encode("ascii")),
            modes.CBC(b"0000000000000000"),
        ).decryptor()
        clear_content = decryptor.update(base64.b64decode(request["params"]["content"])) + decryptor.finalize()
        self.assertEqual(json.loads(clear_content.rstrip(b"\x00").decode()), MINIMUM_ACCESS_PARAMS)
        self.assertNotIn("session", request)

    def test_password_is_absent_from_plan_repr_json_logs_and_errors(self):
        secret = _synthetic_secret()
        plan = SetupPlan(
            mac="02:00:00:00:00:02",
            model="IPC-Test",
            password=secret,
            network_mode="dhcp",
        )
        profile = parse_security_encrypt_info(self.encrypt_info, self.caps)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            request = build_account_request(
                secret,
                profile,
                random_key="01234567890123456789012345678901",
                rsa_encryptor=lambda _public_key, key: b"fixed" + key,
            )

        output = stdout.getvalue() + stderr.getvalue()
        visible = repr(plan) + json.dumps(plan.to_json_dict()) + repr(request) + output
        self.assertNotIn(secret, visible)

        with self.assertRaises(CryptoProtocolError) as caught:
            encrypt_parameters(
                {"pwd": secret},
                profile,
                random_key="01234567890123456789012345678901",
                rsa_encryptor=lambda *_args: (_ for _ in ()).throw(RuntimeError(secret)),
            )
        rendered = "".join(traceback.format_exception(caught.exception))
        self.assertNotIn(secret, str(caught.exception))
        self.assertNotIn(secret, rendered)

    def test_transport_exception_is_replaced_without_secret_context(self):
        secret = _synthetic_secret()
        transport = FakeTransport(self.responses(tail=(RuntimeError(secret),)))
        client = InitializationClient(transport=transport)

        with self.assertRaises(InitializationError) as caught:
            client.configure_minimum_access()

        self.assertEqual(str(caught.exception), "DevInit.access request failed")
        self.assertNotIn(secret, "".join(traceback.format_exception(caught.exception)))

    def test_rejects_non_ipv4_targets(self):
        with self.assertRaises(InitializationError):
            InitializationClient("camera.example.invalid", transport=Mock())


if __name__ == "__main__":
    unittest.main()
