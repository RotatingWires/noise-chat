import contextlib
import io
import os
import sys
import threading
import unittest
from unittest.mock import Mock, patch

from prompt_toolkit.application.current import get_app_session
from prompt_toolkit.data_structures import Size
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput
from wcwidth import wcwidth

from noisechat.terminal import TerminalAttention, _write_title, chat_input


class ScreenOutput(DummyOutput):
    """Small terminal surface for exercising the actual prompt renderer."""

    def __init__(self):
        self.cells = {}
        self.row = self.column = 0
        self.autowrap = True
        self.changed = threading.Condition()
        self.title_controls = []
        self.tab_format = "%d : %n"
        self.window_title = ""

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

    def write_raw(self, text):
        if text.startswith(("\x1b]2;", "\x1b]30;")) and text.endswith("\x1b\\"):
            self.title_controls.append(text)
            if text.startswith("\x1b]30;"):
                self.tab_format = text[5:-2]
            else:
                self.window_title = text[4:-2]
        else:
            self.write(text)

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

    def wait_for_title(self, title, minimum=1):
        with self.changed:
            if not self.changed.wait_for(lambda: len(self.title_controls) >= minimum and
                                         self.title_controls[-1] == f"\x1b]2;{title}\x1b\\", timeout=5):
                raise AssertionError(f"Terminal did not set {title!r}: {self.title_controls!r}")


class TerminalTests(unittest.TestCase):
    def submit(self, draft, incoming=None, ending="\r", attention=None):
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
            with chat_input(attention) as read_message:
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
                        if attention is not None:
                            attention.message_received()
                            screen.wait_for_title("New Message - NoiseChat")
                            attention.focus = lambda: True
                            attention.refresh_focus()
                            screen.wait_for_title("NoiseChat", minimum=3)
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
            self.assertTrue(all("\x07" not in control for control in screen.title_controls))
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

    def test_unread_title_bypasses_stdout_escaping_and_preserves_draft(self):
        notify = Mock()
        attention = TerminalAttention(lambda: False, notify)
        result, visible = self.submit("my draft", "[16:58] Alice: arriving", attention=attention)
        self.assertEqual(result, "my draft")
        self.assertEqual(visible, "[16:57] Alice: earlier[16:58] Alice: arriving[16:58] Bob: my draft")
        notify.assert_called_once_with()
        self.assertFalse(attention.thread.is_alive())
        attention.message_received()  # A late long-poll response after exit stays quiet.
        notify.assert_called_once_with()

    def test_konsole_title_overrides_directory_and_program_tab_format(self):
        screen = ScreenOutput()
        with patch.dict(os.environ, {"KONSOLE_VERSION": "260800"}), \
                patch("noisechat.terminal.sys.platform", "linux"):
            for title in ("NoiseChat", "New Message - NoiseChat", "NoiseChat"):
                _write_title(screen, title)
                self.assertEqual(screen.tab_format.replace("%w", screen.window_title), title)
        self.assertTrue(all("\x07" not in control for control in screen.title_controls))
        self.assertEqual(screen.text(), "")

    def test_title_watcher_stops_when_input_is_interrupted(self):
        attention = TerminalAttention(lambda: False, Mock())
        with self.assertRaises(KeyboardInterrupt):
            self.submit("unsent", ending="\x03", attention=attention)
        self.assertTrue(attention.stop.is_set())
        self.assertFalse(attention.thread.is_alive())

    def test_windows_vt_output_uses_raw_title_without_a_bell(self):
        # Windows10_Output wraps, rather than subclasses, Win32Output.
        # It must flush OSC through its VT-enabled output path.
        from types import SimpleNamespace
        output = Mock()
        with patch("noisechat.terminal.sys.platform", "win32"), \
                patch.dict(sys.modules, {"prompt_toolkit.output.win32": SimpleNamespace(Win32Output=type("LegacyOutput", (), {}))}):
            _write_title(output, "New Message - NoiseChat")
        output.write_raw.assert_called_once_with("\x1b]2;New Message - NoiseChat\x1b\\")
        output.flush.assert_called_once_with()
        output.set_title.assert_not_called()

    def test_focused_or_unknown_window_never_marks_title_unread(self):
        for focus in (True, None):
            with self.subTest(focus=focus):
                notify = Mock()
                attention = TerminalAttention(lambda: focus, notify)
                attention.app = Mock()
                attention.message_received()
                self.assertFalse(attention.unread)
                notify.assert_not_called()
                attention.app.invalidate.assert_not_called()

    def test_redirected_input_has_no_terminal_control_sequences(self):
        stream = io.StringIO("hello\n")
        output = io.StringIO()
        attention = TerminalAttention(lambda: False, Mock())
        with patch.object(sys, "stdin", stream), contextlib.redirect_stdout(output), chat_input(attention) as read_message:
            self.assertEqual(read_message("> "), "hello")
        self.assertEqual(output.getvalue(), "> ")
        self.assertIsNone(attention.thread)
