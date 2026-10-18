import io
import unittest
from unittest.mock import call, patch

from dh_tux_initialize import password


class PasswordInputTests(unittest.TestCase):
    def collect(self, keys):
        key_iterator = iter(keys)
        feedback = []

        result = password._collect_password(lambda: next(key_iterator), feedback.append)

        return result, feedback

    def test_backspace_removes_one_character_and_one_asterisk(self):
        result, feedback = self.collect(["x", "y", "\x08", "z", "\n"])

        self.assertEqual(result, "xz")
        self.assertEqual(feedback, ["*", "*", "\b \b", "*"])

    def test_delete_key_sequence_removes_one_character_and_one_asterisk(self):
        result, feedback = self.collect(["x", "y", "\x1b", "[", "3", "~", "z", "\r"])

        self.assertEqual(result, "xz")
        self.assertEqual(feedback, ["*", "*", "\b \b", "*"])

    @unittest.skipIf(password.termios is None, "POSIX termios is unavailable")
    def test_each_completed_password_prompt_starts_on_own_line(self):
        class Terminal:
            def __init__(self, keys):
                self.keys = iter(keys)

            def isatty(self):
                return True

            def fileno(self):
                return 19

            def read(self, _size):
                return next(self.keys)

        terminal = password.termios
        original = [0, 0, 0, terminal.ECHO | terminal.ICANON, 0, 0, [0] * 32]
        output = io.StringIO()

        with (
            patch.object(terminal, "tcgetattr", return_value=original),
            patch.object(terminal, "tcsetattr") as set_attributes,
        ):
            first = password.read_password(
                "Admin password: ",
                input_stream=Terminal(["x", "y", "\x7f", "z", "\n"]),
                output_stream=output,
            )
            second = password.read_password(
                "Confirm admin password: ",
                input_stream=Terminal(["a", "b", "\n"]),
                output_stream=output,
            )

        self.assertEqual(first, "xz")
        self.assertEqual(second, "ab")
        self.assertEqual(output.getvalue(), "Admin password: **\b \b*\nConfirm admin password: **\n")
        self.assertEqual(set_attributes.call_count, 4)
        self.assertEqual(set_attributes.call_args_list[-1], call(19, terminal.TCSADRAIN, original))

    @unittest.skipIf(password.termios is None, "POSIX termios is unavailable")
    def test_ctrl_c_restores_terminal_attributes(self):
        class InterruptingTerminal:
            def isatty(self):
                return True

            def fileno(self):
                return 19

            def read(self, _size):
                raise KeyboardInterrupt

        terminal = password.termios
        original = [0, 0, 0, terminal.ECHO | terminal.ICANON, 0, 0, [0] * 32]
        output = io.StringIO()

        with (
            patch.object(terminal, "tcgetattr", return_value=original),
            patch.object(terminal, "tcsetattr") as set_attributes,
        ):
            with self.assertRaises(KeyboardInterrupt):
                password.read_password(
                    "Admin password: ", input_stream=InterruptingTerminal(), output_stream=output
                )

        self.assertEqual(set_attributes.call_count, 2)
        self.assertEqual(
            set_attributes.call_args_list[-1],
            call(19, terminal.TCSADRAIN, original),
        )
        self.assertEqual(output.getvalue(), "Admin password: \n")

    def test_non_tty_uses_getpass_fallback(self):
        class NonTerminal:
            def isatty(self):
                return False

        output = io.StringIO()
        def fake_getpass(prompt, stream):
            stream.write(prompt)
            return "dummy"

        with patch.object(password.getpass, "getpass", side_effect=fake_getpass) as getpass:
            result = password.read_password(
                "Admin password: ", input_stream=NonTerminal(), output_stream=output
            )

        self.assertEqual(result, "dummy")
        self.assertEqual(output.getvalue(), "Admin password: \n")
        getpass.assert_called_once_with("Admin password: ", stream=output)

    @unittest.skipIf(password.termios is None, "POSIX termios is unavailable")
    def test_failed_terminal_mode_change_restores_state_before_fallback(self):
        class Terminal:
            def isatty(self):
                return True

            def fileno(self):
                return 19

        terminal = password.termios
        original = [0, 0, 0, terminal.ECHO | terminal.ICANON, 0, 0, [0] * 32]
        output = io.StringIO()

        def fake_getpass(prompt, stream):
            stream.write(prompt)
            stream.write("\n")
            return "dummy"

        with (
            patch.object(terminal, "tcgetattr", return_value=original),
            patch.object(terminal, "tcsetattr", side_effect=[OSError("unsupported"), None]) as set_attributes,
            patch.object(password.getpass, "getpass", side_effect=fake_getpass),
        ):
            result = password.read_password(
                "Admin password: ", input_stream=Terminal(), output_stream=output
            )

        self.assertEqual(result, "dummy")
        self.assertEqual(output.getvalue(), "Admin password: \n")
        self.assertEqual(set_attributes.call_count, 2)
        self.assertEqual(set_attributes.call_args_list[-1], call(19, terminal.TCSADRAIN, original))


if __name__ == "__main__":
    unittest.main()
