import io
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from dh_tux_initialize.release_cli import build_parser, main


class ReleaseCliTests(unittest.TestCase):
    def test_help_lists_only_public_options(self):
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            main(["--help"])

        self.assertEqual(raised.exception.code, 0)
        help_text = output.getvalue()
        self.assertIn("DH-Tux-Initialize", help_text)
        self.assertIn("Initialize Dahua IP cameras from Linux.", help_text)
        self.assertIn("--version", help_text)
        self.assertNotIn("positional arguments", help_text.casefold())
        self.assertNotIn("COMMAND", help_text)
        self.assertNotIn("setup", help_text.casefold())
        self.assertNotIn("diagnose", help_text)
        self.assertNotIn("deep", help_text.casefold())
        self.assertNotIn("debug", help_text.casefold())

    def test_version_exits_successfully(self):
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            main(["--version"])

        self.assertEqual(raised.exception.code, 0)
        self.assertIn("dh-tux-initialize", output.getvalue())

    def test_release_parser_rejects_commands_and_positional_arguments(self):
        for argument in ("setup", "diagnose", "deep-scan"):
            with self.subTest(argument=argument):
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                    build_parser().parse_args([argument])
                self.assertEqual(raised.exception.code, 2)

    def test_no_arguments_starts_normal_setup(self):
        with patch("dh_tux_initialize.release_cli.discover", return_value=[]) as scan:
            with patch("dh_tux_initialize.release_cli.run_setup") as setup:
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(main([]), 0)

        scan.assert_called_once_with()
        setup.assert_called_once_with([], rescan_fn=scan)

    def test_release_import_does_not_load_developer_modules(self):
        command = (
            "import sys; import dh_tux_initialize.release_cli; "
            "assert 'dh_tux_initialize.cli' not in sys.modules; "
            "assert 'dh_tux_initialize.diagnostic_discovery' not in sys.modules; "
            "assert 'dh_tux_initialize.deep_discovery' not in sys.modules"
        )
        result = subprocess.run(
            [sys.executable, "-c", command],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
