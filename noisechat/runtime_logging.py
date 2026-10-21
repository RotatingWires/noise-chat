"""Bounded file logging for explicit relay console output only."""

import logging
from contextlib import contextmanager
from pathlib import Path

MAX_LOG_BYTES = 10 * 1024 * 1024
LOGGER = logging.getLogger("noisechat.console")
LOGGER.addHandler(logging.NullHandler())
LOGGER.setLevel(logging.INFO)
LOGGER.propagate = False


class SingleFileHandler(logging.FileHandler):
    """Replace the current file when the next record would exceed its limit."""

    def __init__(self, path: Path, max_bytes: int = MAX_LOG_BYTES):
        self.max_bytes = max_bytes
        path.parent.mkdir(parents=True, exist_ok=True)
        super().__init__(path, mode="a", encoding="utf-8")

    def _open(self):
        # Keep the byte limit consistent on Windows as well as Unix.
        return open(self.baseFilename, self.mode, encoding=self.encoding, newline="\n")

    def emit(self, record):
        try:
            message = (self.format(record) + self.terminator).encode("utf-8", errors="replace")
            # Even an unusually large console record must respect the file cap.
            message = message[:self.max_bytes].decode("utf-8", errors="ignore")
            self.stream.seek(0, 2)
            if self.stream.tell() + len(message.encode("utf-8")) > self.max_bytes:
                self.stream.seek(0)
                self.stream.truncate()
            self.stream.write(message)
            self.flush()
        except Exception:
            self.handleError(record)


@contextmanager
def relay_logging(path: Path):
    handler = SingleFileHandler(path)
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    LOGGER.addHandler(handler)
    try:
        yield
    finally:
        LOGGER.removeHandler(handler)
        handler.close()


def console_output(*values, file=None, flush=False):
    """Keep terminal output intact and persist only deliberately selected messages."""
    print(*values, file=file, flush=flush)
    LOGGER.info(" ".join(str(value) for value in values))
