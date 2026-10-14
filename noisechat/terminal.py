"""Interactive input that clears submitted text and preserves incoming output."""

import os
import sys
import threading
from contextlib import contextmanager


def _normal_backspace():
    if sys.platform == "win32":
        return "\x08"
    try:
        import curses
    except ImportError:
        return "\x7f"
    try:
        curses.setupterm()
        key = curses.tigetstr("kbs")
        if key in (b"\x08", b"\x7f"):
            return key.decode("ascii")
    except (curses.error, OSError):
        pass
    return "\x7f"


def _editing_bindings():
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.key_binding.bindings.named_commands import get_by_name

    bindings = KeyBindings()
    normal_backspace = _normal_backspace()
    delete_word = get_by_name("backward-kill-word")
    delete_character = get_by_name("backward-delete-char")

    @bindings.add("c-left")
    def previous_word(event):
        buffer = event.current_buffer
        offset = buffer.document.find_previous_word_beginning()
        buffer.cursor_position = buffer.cursor_position + offset if offset is not None else 0

    @bindings.add("c-right")
    def next_word(event):
        buffer = event.current_buffer
        offset = buffer.document.find_next_word_beginning()
        buffer.cursor_position = buffer.cursor_position + offset if offset is not None else len(buffer.text)

    bindings.add("c-up")(get_by_name("beginning-of-buffer"))
    bindings.add("c-down")(get_by_name("end-of-buffer"))
    bindings.add("c-delete")(get_by_name("kill-word"))
    bindings.add("c-w")(delete_word)

    @bindings.add("c-h")
    def backspace(event):
        # prompt_toolkit names both BS and DEL as Backspace. Preserve the raw
        # byte: Konsole/xterm use DEL for Backspace and BS for Ctrl+Backspace;
        # Windows console input uses the opposite pair.
        raw = event.key_sequence[-1].data
        if raw in ("\x08", "\x7f") and raw != normal_backspace:
            delete_word.handler(event)
        else:
            delete_character.handler(event)

    # CSI-u and xterm modifyOtherKeys report Ctrl+Backspace explicitly.
    # Register key sequences through the normal binding API, leaving the
    # library's shared escape parser and bracketed-paste handling intact.
    for sequence in ("[127;5u", "[8;5u", "[27;5;127~", "[27;5;8~"):
        bindings.add("escape", *sequence)(delete_word)
    return bindings


def _write_title(output, title):
    # Use the renderer's output, never patch_stdout's escaped text stream.
    # ST ends the OSC command without emitting a BEL character.
    if sys.platform == "win32":
        from prompt_toolkit.output.win32 import Win32Output
        if isinstance(output, Win32Output):
            output.set_title(title)
            return
    if sys.platform != "win32" and (os.environ.get("KONSOLE_VERSION") or os.environ.get("KONSOLE_DBUS_SESSION")):
        # Konsole's default %d : %n tab format ignores OSC 2. OSC 30
        # switches this session to the shell-controlled title (%w), without
        # modifying the saved profile; the shell can reclaim it after exit.
        output.write_raw("\x1b]30;%w\x1b\\")
    output.write_raw(f"\x1b]2;{title}\x1b\\")
    output.flush()  # Windows10_Output enables VT processing during flush.


class TerminalAttention:
    """Own the unread title and focus watcher for one interactive chat."""

    def __init__(self, focus, notify):
        self.focus, self.notify = focus, notify
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.app = None
        self.unread = False
        self.rendered_title = None
        self.thread = None

    def start(self, app):
        if sys.platform == "win32":
            # Resolve the hosting window before the first title update.
            self.focus()
        self.app = app
        app.before_render += self.render
        self.thread = threading.Thread(target=self.watch, daemon=True)
        self.thread.start()

    def message_received(self):
        with self.lock:
            if self.stop.is_set() or self.app is None or self.focus() is not False:
                return
            # Request desktop attention before changing the Windows title so
            # the visible window handle can be resolved from its existing title.
            self.notify()
            self.unread = True
            self.app.invalidate()

    def refresh_focus(self):
        with self.lock:
            if not self.stop.is_set() and self.unread and self.focus() is True:
                self.unread = False
                self.app.invalidate()

    def watch(self):
        while not self.stop.wait(.5):
            self.refresh_focus()

    def render(self, app):
        with self.lock:
            title = "New Message - NoiseChat" if self.unread else "NoiseChat"
            if title != self.rendered_title:
                _write_title(app.output, title)
                self.rendered_title = title

    def close(self):
        with self.lock:
            self.stop.set()
            if self.app is not None:
                self.app.before_render -= self.render
                _write_title(self.app.output, "NoiseChat")
                self.app = None
        if self.thread is not None:
            self.thread.join(timeout=1.5)


@contextmanager
def chat_input(attention=None):
    # Redirected input/output has no editable terminal line to clear.
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        yield input
        return

    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import DummyHistory
    from prompt_toolkit.patch_stdout import patch_stdout

    session = PromptSession(erase_when_done=True, history=DummyHistory(), key_bindings=_editing_bindings())
    # Incoming receiver/presence output prints above the current draft. Closing
    # this context flushes pending output and restores the original streams.
    if attention is not None:
        attention.start(session.app)
    try:
        with patch_stdout():
            yield session.prompt
    finally:
        if attention is not None:
            attention.close()
