import contextlib
import io
import os
import sys
import threading
import unittest
from unittest.mock import patch

from prompt_toolkit.application.current import get_app_session
from prompt_toolkit.data_structures import Size
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput
from wcwidth import wcwidth

from noisechat.terminal import chat_input


class ScreenOutput(DummyOutput):
    """Small terminal surface for exercising the actual prompt renderer."""

    def __init__(self):
        self.cells = {}
        self.row = self.column = 0
        self.autowrap = True
        self.changed = threading.Condition()

    def get_size(self):
        return Size(rows=40, columns=38)

    def write(self, text):
        for char in text:
            if char == "\r":
                self.column = 0
            elif char == "\n":
                self.row += 1
                self.column = 0
            else:
                width = max(0, wcwidth(char))
                if self.autowrap and self.column + width > 38:
                    self.row += 1
                    self.column = 0
                self.cells[self.row, self.column] = char
                for offset in range(1, width):
                    self.cells[self.row, self.column + offset] = ""
                self.column += width

    write_raw = write

    def flush(self):
        with self.changed:
            self.changed.notify_all()

    def disable_autowrap(self):
        self.autowrap = False

    def enable_autowrap(self):
        self.autowrap = True

    def cursor_goto(self, row=0, column=0):
        self.row, self.column = row, column

    def cursor_up(self, amount):
        self.row -= amount

    def cursor_down(self, amount):
        self.row += amount

    def cursor_forward(self, amount):
        self.column += amount

    def cursor_backward(self, amount):
        self.column -= amount

    def erase_end_of_line(self):
        self.cells = {pos: char for pos, char in self.cells.items()
                      if pos[0] != self.row or pos[1] < self.column}

    def erase_down(self):
        self.cells = {pos: char for pos, char in self.cells.items()
                      if pos[0] < self.row or (pos[0] == self.row and pos[1] < self.column)}

    def text(self):
        return "".join(self.cells[pos] for pos in sorted(self.cells))

    def wait_for(self, text):
        with self.changed:
            if not self.changed.wait_for(lambda: text in self.text(), timeout=5):
                raise AssertionError(f"Terminal did not display {text!r}: {self.text()!r}")


class TerminalTests(unittest.TestCase):
    def submit(self, draft, incoming=None, ending="\r"):
        screen = ScreenOutput()
        errors = []
        original_stdout, original_stderr = sys.stdout, sys.stderr
        # Match the CLI's default app session, shared by background output
        # threads, while supplying a real pipe input and test terminal surface.
        with create_pipe_input() as pipe, \
                patch.object(get_app_session(), "_input", pipe), \
                patch.object(get_app_session(), "_output", screen), \
                patch.dict(os.environ, {"TERM": "xterm-256color"}), \
                patch.object(sys.stdin, "isatty", return_value=True), \
                patch.object(sys.stdout, "isatty", return_value=True):
            with chat_input() as read_message:
                print("[16:57] Alice: earlier", flush=True)
                screen.wait_for("[16:57] Alice: earlier")

                def type_message():
                    try:
                        pipe.send_text(draft)
                        screen.wait_for(draft)
                        if incoming:
                            print(incoming, flush=True)
                            screen.wait_for(incoming)
                            screen.wait_for(draft)
                    except BaseException as error:
                        errors.append(error)
                    finally:
                        pipe.send_text(ending)

                writer = threading.Thread(target=type_message, daemon=True)
                writer.start()
                try:
                    result = read_message("> ")
                finally:
                    writer.join(timeout=6)
                self.assertFalse(writer.is_alive())
                if errors:
                    raise errors[0]
                self.assertNotIn(draft, screen.text())
                print(f"[16:58] Bob: {result}", flush=True)
            self.assertIs(sys.stdout, original_stdout)
            self.assertIs(sys.stderr, original_stderr)
        return result, screen.text()

    def test_submitted_input_is_replaced_by_one_formatted_message(self):
        result, visible = self.submit("hello")
        self.assertEqual(result, "hello")
        self.assertEqual(visible, "[16:57] Alice: earlier[16:58] Bob: hello")

    def test_wrapped_unicode_draft_survives_incoming_output_and_is_erased(self):
        draft = "世界👋" * 24
        incoming = "[16:58] Alice: arriving"
        result, visible = self.submit(draft, incoming)
        self.assertEqual(result, draft)
        self.assertEqual(visible, f"[16:57] Alice: earlier{incoming}[16:58] Bob: {draft}")

    def test_interruption_restores_output_streams(self):
        stdout, stderr = sys.stdout, sys.stderr
        with self.assertRaises(KeyboardInterrupt):
            self.submit("unsent", ending="\x03")
        self.assertIs(sys.stdout, stdout)
        self.assertIs(sys.stderr, stderr)

    def test_redirected_input_has_no_terminal_control_sequences(self):
        stream = io.StringIO("hello\n")
        output = io.StringIO()
        with patch.object(sys, "stdin", stream), contextlib.redirect_stdout(output), chat_input() as read_message:
            self.assertEqual(read_message("> "), "hello")
        self.assertEqual(output.getvalue(), "> ")
