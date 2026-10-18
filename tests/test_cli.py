import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from dh_tux_initialize.cli import build_parser, main, run_diagnostics
from dh_tux_initialize.diagnostic_discovery import ProbeRecord
from dh_tux_initialize.discovery import (
    DEFAULT_SCAN_ROUNDS,
    DEFAULT_SCAN_TIMEOUT,
    DiscoveredDevice,
)


class ScanOptionTests(unittest.TestCase):
    def test_empty_argument_list_dispatches_to_interactive_setup(self):
        output = io.StringIO()
        with patch("dh_tux_initialize.cli.discover", return_value=[]) as scan:
            with patch("dh_tux_initialize.cli.run_setup") as setup:
                with redirect_stdout(output):
                    status = main([])

        self.assertEqual(status, 0)
        scan.assert_called_once_with(
            timeout=DEFAULT_SCAN_TIMEOUT,
            rounds=DEFAULT_SCAN_ROUNDS,
            interface_ip=None,
            debug=False,
        )
        setup.assert_called_once()
        self.assertIn("Scanning for Dahua devices...", output.getvalue())

    def test_top_level_help_without_a_subcommand_stays_top_level_help(self):
        output = io.StringIO()

        with redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            main(["--help"])

        self.assertEqual(raised.exception.code, 0)
        self.assertIn("usage: dh-tux-initialize", output.getvalue())
        self.assertIn("COMMAND", output.getvalue())
        self.assertNotIn("Scanning for Dahua devices...", output.getvalue())

    def test_init_capabilities_command_defaults_to_known_uninitialized_camera(self):
        args = build_parser().parse_args(["init-capabilities"])

        self.assertEqual(args.ip, "192.168.1.108")
        self.assertEqual(args.timeout, 2.5)
        self.assertEqual(args.port, 80)
        self.assertFalse(args.https)

    def test_init_capabilities_cli_prints_only_diagnostic_report(self):
        output = io.StringIO()
        with patch("dh_tux_initialize.cli.InitializationClient") as client:
            client.return_value.inspect.return_value.report.return_value = {
                "crypto_profile": {"encryption_scheme": "RSA/PKCS#1 v1.5 + AES-128-CBC"}
            }
            with redirect_stdout(output):
                status = main(["init-capabilities", "--ip", "192.168.1.108"])

        self.assertEqual(status, 0)
        self.assertIn("AES-128-CBC", output.getvalue())
        self.assertEqual(output.getvalue().count("encryption_scheme"), 1)
        client.assert_called_once_with(
            "192.168.1.108", timeout=2.5, port=80, scheme="http"
        )
        client.return_value.inspect.assert_called_once_with()

    def test_scan_tuning_options_accept_explicit_values(self):
        args = build_parser().parse_args(
            ["scan", "--scan-timeout", "4", "--scan-rounds", "4"]
        )

        self.assertEqual(args.scan_timeout, 4.0)
        self.assertEqual(args.scan_rounds, 4)

    def test_setup_uses_robust_defaults_and_keeps_timeout_alias(self):
        defaults = build_parser().parse_args(["setup"])
        args = build_parser().parse_args(["setup", "--timeout", "3.5"])

        self.assertEqual(defaults.scan_timeout, DEFAULT_SCAN_TIMEOUT)
        self.assertEqual(defaults.scan_rounds, DEFAULT_SCAN_ROUNDS)
        self.assertEqual(args.scan_timeout, 3.5)
        self.assertEqual(args.scan_rounds, DEFAULT_SCAN_ROUNDS)
        self.assertEqual(DEFAULT_SCAN_TIMEOUT, 2.5)

    def test_setup_no_longer_accepts_a_deep_scan_cidr_override(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            build_parser().parse_args(["setup", "--range", "10.42.0.0/24"])

        self.assertEqual(raised.exception.code, 2)

    def test_diagnostic_defaults_and_explicit_deep_range(self):
        defaults = build_parser().parse_args(["diagnose"])
        selected = build_parser().parse_args(
            ["diagnose", "--phase", "deep", "--range", "10.42.0.0/24"]
        )

        self.assertEqual(defaults.phase, "quick")
        self.assertEqual(defaults.timeout, 2.5)
        self.assertEqual(str(selected.scan_range), "10.42.0.0/24")
        self.assertEqual(selected.phase, "deep")

    def test_frozen_cli_omits_deep_diagnostic_phase(self):
        with patch("dh_tux_initialize.cli.sys.frozen", True, create=True):
            parser = build_parser()
            args = parser.parse_args(["diagnose"])
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                parser.parse_args(["diagnose", "--phase", "deep", "--range", "10.42.0.0/24"])

        self.assertEqual(args.phase, "quick")
        self.assertIsNone(args.scan_range)
        self.assertEqual(raised.exception.code, 2)

    def test_direct_diagnostic_prints_selected_record_fields_as_jsonl(self):
        record = ProbeRecord(
            destination_ip="198.51.100.21",
            local_ip="198.51.100.10",
            local_port=40000,
            send_timestamp="2030-01-02T03:04:05+00:00",
            receive_timestamp="2030-01-02T03:04:05.010+00:00",
            elapsed_ms=10.0,
            sender_ip="198.51.100.21",
            sender_port=37810,
            response_length=100,
            valid_dhip_framing=True,
            json_parse_success=True,
            model="IPC-Test-Camera",
            mac="02:00:00:00:00:02",
            serial="TESTSERIAL001",
            init_raw=2,
            accepted=True,
        )
        args = build_parser().parse_args(
            ["diagnose", "--phase", "probe", "--ip", "198.51.100.21"]
        )
        output = io.StringIO()

        with patch("dh_tux_initialize.diagnostic_discovery.direct_probe", return_value=[record]):
            with redirect_stdout(output):
                run_diagnostics(args)

        self.assertEqual(output.getvalue().count("\n"), 1)
        self.assertIn('"destination_ip":"198.51.100.21"', output.getvalue())
        self.assertIn('"valid_dhip_framing":true', output.getvalue())
        self.assertNotIn("device", output.getvalue())
        self.assertNotIn("password", output.getvalue().casefold())

    def test_quick_diagnostic_uses_quick_scan_without_target_specific_matching(self):
        info = {
            "Mac": "02:00:00:00:00:01",
            "SerialNo": "TESTSERIAL-UNINITIALIZED",
            "DeviceType": "IPC-Test-Camera",
            "Init": 1,
        }
        device = DiscoveredDevice(info, {}, "192.0.2.108")
        args = build_parser().parse_args(["diagnose", "--phase", "quick"])
        output = io.StringIO()

        with patch("dh_tux_initialize.cli.discover", return_value=[device]) as quick_scan:
            with redirect_stdout(output):
                run_diagnostics(args)

        quick_scan.assert_called_once_with(
            timeout=2.5,
            rounds=DEFAULT_SCAN_ROUNDS,
            debug=False,
        )
        self.assertIn("Found", output.getvalue())
        self.assertIn("02:00:00:00:00:01", output.getvalue())
        self.assertIn("Uninitialized", output.getvalue())

    def test_deep_diagnostic_requests_phase_timings(self):
        args = build_parser().parse_args(
            ["diagnose", "--phase", "deep", "--range", "10.42.0.0/24", "--debug"]
        )
        output = io.StringIO()
        with patch("dh_tux_initialize.deep_discovery.deep_discover", return_value=[]) as deep_scan:
            with redirect_stdout(output):
                run_diagnostics(args)

        self.assertTrue(deep_scan.call_args.kwargs["debug"])
        self.assertEqual(deep_scan.call_args.args[0], "10.42.0.0/24")
        self.assertIn("Found 0 device(s)", output.getvalue())


if __name__ == "__main__":
    unittest.main()
