"""Relay password verifiers, temporary sessions, and login cooldowns."""

import hashlib
import hmac
import json
import math
import os
import secrets
import tempfile
import threading
import time
from collections import OrderedDict
from pathlib import Path

from .crypto import NoiseChatError

PASSWORD_ITERATIONS = 600000
MAX_PASSWORD_BYTES = 1024
LOGIN_ATTEMPTS = 5
LOGIN_WINDOW = 60
MAX_LOGIN_IPS = 1024
SESSION_SECONDS = 12 * 60 * 60
MAX_SESSIONS = 1000


class ServerAccessError(NoiseChatError):
    """Authentication cannot continue with the supplied credentials."""


def password_bytes(password: str) -> bytes:
    if not isinstance(password, str):
        raise NoiseChatError("Server password must be text.")
    value = password.encode("utf-8")
    if not value or len(value) > MAX_PASSWORD_BYTES or any(char in password for char in "\r\n\x00"):
        raise NoiseChatError("Password incorrect")
    return value


class PasswordVerifier:
    def __init__(self, salt: bytes, digest: bytes):
        self.salt, self.digest = salt, digest

    @classmethod
    def create(cls, password: str):
        value = password_bytes(password)
        if len(password) < 12:
            raise NoiseChatError("Use a server password of at least 12 characters; several random words work well.")
        salt = secrets.token_bytes(16)
        return cls(salt, hashlib.pbkdf2_hmac("sha256", value, salt, PASSWORD_ITERATIONS))

    def verify(self, password: str) -> bool:
        try:
            value = password_bytes(password)
        except (NoiseChatError, UnicodeError):
            return False
        actual = hashlib.pbkdf2_hmac("sha256", value, self.salt, PASSWORD_ITERATIONS)
        return hmac.compare_digest(actual, self.digest)

    @classmethod
    def load(cls, path: Path):
        try:
            with path.open("rb") as stream:
                data = stream.read(4097)
            if len(data) > 4096:
                raise ValueError()
            record = json.loads(data)
            if (not isinstance(record, dict) or set(record) != {"version", "iterations", "salt", "hash"}
                    or type(record["version"]) is not int or record["version"] != 1
                    or type(record["iterations"]) is not int or record["iterations"] != PASSWORD_ITERATIONS):
                raise ValueError()
            salt, digest = bytes.fromhex(record["salt"]), bytes.fromhex(record["hash"])
            if len(salt) != 16 or len(digest) != 32:
                raise ValueError()
            return cls(salt, digest)
        except (ValueError, TypeError, RecursionError):
            raise NoiseChatError("Invalid server authentication file. Restore it or use run --reset-password locally.") from None

    def save(self, path: Path, replace: bool = False) -> None:
        data = json.dumps(dict(version=1, iterations=PASSWORD_ITERATIONS,
                               salt=self.salt.hex(), hash=self.digest.hex())).encode()
        if not replace:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
            return
        if path.is_symlink():
            raise NoiseChatError("The server authentication file must not be a symbolic link.")
        # Replace atomically so an interrupted password change preserves the old verifier.
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".noisechat-auth-", delete=False) as stream:
            temporary = Path(stream.name)
            try:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            except BaseException:
                temporary.unlink()
                raise
        try:
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


class RelayAccess:
    def __init__(self, verifier: PasswordVerifier):
        self.verifier = verifier
        self.lock = threading.Lock()
        self.attempts = OrderedDict()
        self.sessions = {}

    def login_attempt(self, address: str) -> int:
        """Reserve an attempt before parsing or hashing; return remaining cooldown seconds."""
        with self.lock:
            now = time.monotonic()
            start, count = self.attempts.pop(address, (now, 0))
            if now - start >= LOGIN_WINDOW:
                start, count = now, 0
            retry = max(1, math.ceil(LOGIN_WINDOW - (now - start))) if count >= LOGIN_ATTEMPTS else 0
            self.attempts[address] = (start, count if retry else count + 1)
            while len(self.attempts) > MAX_LOGIN_IPS:
                self.attempts.popitem(last=False)
            return retry

    def prune_sessions(self) -> None:
        now = time.monotonic()
        self.sessions = {digest: deadline for digest, deadline in self.sessions.items() if deadline > now}

    def login(self, password: str) -> str | None:
        if not self.verifier.verify(password):
            return None
        with self.lock:
            self.prune_sessions()
            if len(self.sessions) >= MAX_SESSIONS:
                raise NoiseChatError("Relay session capacity reached.")
            token = secrets.token_hex(32)
            self.sessions[hashlib.sha256(token.encode("ascii")).digest()] = time.monotonic() + SESSION_SECONDS
            return token

    def authorized(self, headers: list[str]) -> bool:
        if len(headers) != 1 or not headers[0].startswith("Bearer "):
            return False
        token = headers[0][7:]
        if len(token) != 64 or any(char not in "0123456789abcdef" for char in token):
            return False
        digest = hashlib.sha256(token.encode("ascii")).digest()
        with self.lock:
            self.prune_sessions()
            return digest in self.sessions
