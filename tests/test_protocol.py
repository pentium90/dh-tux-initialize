import json
import struct
import unittest

from dh_tux_initialize.protocol import (
    DHIP_HEADER_SIZE,
    DHIP_MAGIC,
    ProtocolError,
    decode_json_datagram,
    encode_frame,
    extract_device_info,
    has_valid_dhip_framing,
)


class FrameEncodingTests(unittest.TestCase):
    def test_encodes_json_with_dhip_header(self):
        payload = {"method": "DHDiscover.search", "params": {"mac": "", "uni": 1}}

        frame = encode_frame(payload)

        header = struct.unpack("<8I", frame[:DHIP_HEADER_SIZE])
        body = frame[DHIP_HEADER_SIZE:]
        expected_body = json.dumps(payload, separators=(",", ":")).encode()
        self.assertEqual(header, (32, DHIP_MAGIC, 0, 0, len(expected_body), 0, len(expected_body), 0))
        self.assertEqual(body, expected_body)
        self.assertEqual(frame[4:8], b"DHIP")

    def test_encodes_unicode_json_as_utf8(self):
        frame = encode_frame({"name": "Kamera ä"})
        self.assertEqual(decode_json_datagram(frame), {"name": "Kamera ä"})


class FrameParsingTests(unittest.TestCase):
    def test_valid_dhip_framing_is_distinct_from_supported_bare_json(self):
        framed = encode_frame({"method": "client.notifyDevInfo"})
        bare = json.dumps({"method": "client.notifyDevInfo"}).encode()

        self.assertTrue(has_valid_dhip_framing(framed))
        self.assertFalse(has_valid_dhip_framing(bare))

        malformed = bytearray(framed)
        struct.pack_into("<I", malformed, 16, 1)
        self.assertFalse(has_valid_dhip_framing(bytes(malformed)))

    def test_parses_framed_device_info_and_preserves_raw_init_value(self):
        payload = {
            "method": "client.notifyDevInfo",
            "mac": "02:00:00:00:00:08",
            "params": {
                "deviceInfo": {
                    "DeviceType": "IPC-Test-Camera",
                    "SerialNo": "TESTSERIAL002",
                    "Init": 1162,
                }
            },
        }

        message = decode_json_datagram(encode_frame(payload))
        info = extract_device_info(message)

        self.assertIsNotNone(info)
        self.assertEqual(info["Init"], 1162)
        self.assertIs(type(info["Init"]), int)
        self.assertEqual(info["SerialNo"], "TESTSERIAL002")

    def test_parses_bare_json_and_null_terminated_json(self):
        payload = {"params": {"DeviceType": "IPC", "Init": False}}
        bare = json.dumps(payload).encode() + b"\x00\x00"

        self.assertEqual(decode_json_datagram(bare), payload)
        self.assertEqual(extract_device_info(payload)["Init"], False)

    def test_rejects_truncated_frame_and_invalid_json(self):
        frame = encode_frame({"method": "DHDiscover.search"})

        with self.assertRaises(ProtocolError):
            decode_json_datagram(frame[:16])
        with self.assertRaises(ProtocolError):
            decode_json_datagram(b"not json")

    def test_rejects_inconsistent_header_lengths(self):
        frame = bytearray(encode_frame({"method": "DHDiscover.search"}))
        struct.pack_into("<I", frame, 16, 1)

        with self.assertRaises(ProtocolError):
            decode_json_datagram(bytes(frame))

    def test_ignores_envelopes_without_device_fields(self):
        self.assertIsNone(extract_device_info({"method": "other", "params": {"ok": True}}))

    def test_does_not_treat_search_probe_as_device_info(self):
        probe = {"method": "DHDiscover.search", "params": {"mac": "", "uni": 1}}
        self.assertIsNone(extract_device_info(probe))


if __name__ == "__main__":
    unittest.main()
