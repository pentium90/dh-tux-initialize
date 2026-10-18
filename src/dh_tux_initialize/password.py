"""Password input with terminal echo disabled and masked character feedback."""

from __future__ import annotations

import getpass
import sys
from collections.abc import Callable
from typing import TextIO

try:
    import termios
except ImportError:  # pragma: no cover - exercised on non-POSIX platforms
    termios = None  # type: ignore[assignment]


def read_password(
    prompt: str,
    *,
    input_stream: TextIO | None = None,
    output_stream: TextIO | None = None,
) -> str:
    """Read a password, showing one asterisk per character on POSIX terminals.

    ``getpass`` is used when stdin is not a TTY or terminal mode control is not
    available. The password itself is never written to the output stream.
    """
    source = input_stream if input_stream is not None else sys.stdin
    sink = output_stream if output_stream is not None else sys.stdout

    if termios is None or not _is_tty(source):
        return _fallback_getpass(prompt, source, sink)

    try:
        fd = source.fileno()
        original_attributes = termios.tcgetattr(fd)
    except (AttributeError, OSError, ValueError, termios.error):
        return _fallback_getpass(prompt, source, sink)

    attributes = list(original_attributes)
    attributes[3] &= ~(termios.ECHO | termios.ICANON)
    attributes[6] = list(original_attributes[6])
    attributes[6][termios.VMIN] = 1
    attributes[6][termios.VTIME] = 0

    configuration_failed = False
    result = ""
    try:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, attributes)
        except (OSError, termios.error):
            configuration_failed = True
        if not configuration_failed:
            sink.write(prompt)
            sink.flush()
            try:
                result = _collect_password(
                    lambda: source.read(1),
                    lambda value: _write_feedback(sink, value),
                )
            finally:
                _write_feedback(sink, "\n")
    finally:
        # Restore even if Ctrl+C lands during setup, prompt output, or input.
        termios.tcsetattr(fd, termios.TCSADRAIN, original_attributes)

    if configuration_failed:
        return _fallback_getpass(prompt, source, sink)
    return result


def _fallback_getpass(prompt: str, source: TextIO, sink: TextIO) -> str:
    """Use the standard-library fallback and separate non-TTY prompts by a line."""
    result = getpass.getpass(prompt, stream=sink)
    # A redirected input stream has no terminal echo to provide the Enter newline.
    if not _is_tty(source):
        _write_feedback(sink, "\n")
    return result


def _is_tty(stream: TextIO) -> bool:
    try:
        return stream.isatty()
    except (AttributeError, OSError, ValueError):
        return False


def _write_feedback(stream: TextIO, value: str) -> None:
    stream.write(value)
    stream.flush()


def _collect_password(
    read_char: Callable[[], str], write_feedback: Callable[[str], None]
) -> str:
    """Collect typed characters and handle backspace and the Delete key."""
    characters: list[str] = []
    escape_sequence = ""

    while True:
        char = read_char()
        if char == "":
            raise EOFError

        if escape_sequence:
            if escape_sequence == "\x1b":
                if char == "[":
                    escape_sequence = "\x1b["
                elif char == "O":
                    escape_sequence = "\x1bO"
                else:
                    escape_sequence = ""
                continue
            if escape_sequence == "\x1bO":
                escape_sequence = ""
                continue
            if escape_sequence == "\x1b[" and char == "3":
                escape_sequence += char
                continue
            if escape_sequence == "\x1b[3" and char == "~":
                escape_sequence = ""
                _erase_character(characters, write_feedback)
                continue
            if escape_sequence == "\x1b[" and ord(char) not in range(0x40, 0x7F):
                escape_sequence += char
                continue
            if escape_sequence == "\x1b[3" and ord(char) not in range(0x40, 0x7F):
                escape_sequence += char
                continue
            # This is the final byte of an unsupported CSI sequence.
            escape_sequence = ""
            continue

        if char == "\x1b":
            escape_sequence = "\x1b"
        elif char in {"\x08", "\x7f"}:
            _erase_character(characters, write_feedback)
        elif char in {"\r", "\n"}:
            return "".join(characters)
        elif char == "\x04":
            raise EOFError
        elif char.isprintable():
            characters.append(char)
            write_feedback("*")


def _erase_character(
    characters: list[str], write_feedback: Callable[[str], None]
) -> None:
    if characters:
        characters.pop()
        write_feedback("\b \b")
