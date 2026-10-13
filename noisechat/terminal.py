"""Interactive input that clears submitted text and preserves incoming output."""

import sys
from contextlib import contextmanager


@contextmanager
def chat_input():
    # Redirected input/output has no editable terminal line to clear.
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        yield input
        return

    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import DummyHistory
    from prompt_toolkit.patch_stdout import patch_stdout

    session = PromptSession(erase_when_done=True, history=DummyHistory())
    # Incoming receiver/presence output prints above the current draft. Closing
    # this context flushes pending output and restores the original streams.
    with patch_stdout():
        yield session.prompt
