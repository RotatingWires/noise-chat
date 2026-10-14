"""Use native credential stores, never a plaintext keyring fallback."""

from __future__ import annotations

import os
import json
import re
from pathlib import Path

import keyring
from keyring.errors import KeyringError

from .crypto import MAX_KEY_FILE_BYTES, NoiseChatError, b64decode, b64encode, check_key, room_id

SERVICE = "noisechat.chat-key.v1"
INDEX_ALIAS = "__noisechat_alias_index__"
ALIAS_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
NATIVE_MODULES = {
    "keyring.backends.Windows", "keyring.backends.SecretService",
    "keyring.backends.libsecret", "keyring.backends.kwallet", "keyring.backends.macOS",
}


def check_alias(alias: str) -> str:
    if not ALIAS_PATTERN.fullmatch(alias):
        raise NoiseChatError("Chat names use 1–64 letters, numbers, dots, underscores, or hyphens.")
    return alias


def native_backend():
    backend = keyring.get_keyring()
    candidates = backend.backends if type(backend).__module__ == "keyring.backends.chainer" else [backend]
    for candidate in candidates:
        if type(candidate).__module__ in NATIVE_MODULES:
            return candidate
    raise NoiseChatError("No native OS keyring is available. Configure Windows Credential Manager or "
                         "Linux Secret Service/KWallet, or use a password-encrypted --key-file. "
                         "Plaintext keyring backends are not accepted.")


class KeyStore:
    def get(self, alias: str) -> bytes:
        check_alias(alias)
        try:
            return self._read_key(native_backend(), alias)
        except KeyringError:
            raise NoiseChatError("Could not unlock/read the OS keyring.") from None

    def put(self, alias: str, key: bytes, replace: bool = False) -> None:
        check_alias(alias)
        check_key(key)
        try:
            backend = native_backend()
            if backend.get_password(SERVICE, alias) is not None and not replace:
                raise NoiseChatError("That chat already has a key. Use another name or --replace explicitly.")
            backend.set_password(SERVICE, alias, b64encode(key))
            aliases = self._aliases(backend)
            if alias not in aliases:
                aliases.append(alias)
                self._save_aliases(backend, aliases)
        except KeyringError:
            raise NoiseChatError("Could not save the key in the OS keyring.") from None

    def remove(self, alias: str) -> None:
        self.get(alias)
        try:
            backend = native_backend()
            backend.delete_password(SERVICE, alias)
            self._save_aliases(backend, [item for item in self._aliases(backend) if item != alias])
        except KeyringError:
            raise NoiseChatError("Could not remove the key from the OS keyring.") from None

    def list(self) -> list[tuple[str, str]]:
        """Return local aliases and room IDs without exposing any key material."""
        try:
            backend = native_backend()
            aliases = self._aliases(backend)
            result = []
            valid = []
            for alias in aliases:
                try:
                    key = self._read_key(backend, alias)
                except NoiseChatError:
                    continue
                valid.append(alias)
                result.append((alias, room_id(key)))
            if valid != aliases:
                self._save_aliases(backend, valid)
            return result
        except KeyringError:
            raise NoiseChatError("Could not unlock/read the OS keyring.") from None

    @staticmethod
    def _read_key(backend, alias: str) -> bytes:
        try:
            value = backend.get_password(SERVICE, alias)
        except KeyringError:
            raise NoiseChatError("Could not unlock/read the OS keyring.") from None
        if value is None:
            raise NoiseChatError("Chat key not found. Create it or import your friend's encrypted key file.")
        key = b64decode(value)
        check_key(key)
        return key

    @staticmethod
    def _aliases(backend) -> list[str]:
        raw = backend.get_password(SERVICE, INDEX_ALIAS)
        if raw is None:
            return []
        try:
            aliases = json.loads(raw)
        except (TypeError, ValueError, UnicodeError):
            return []
        if not isinstance(aliases, list):
            return []
        return [alias for alias in aliases if isinstance(alias, str) and ALIAS_PATTERN.fullmatch(alias)]

    @staticmethod
    def _save_aliases(backend, aliases: list[str]) -> None:
        backend.set_password(SERVICE, INDEX_ALIAS, json.dumps(aliases, separators=(",", ":")))


def read_key_file(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_KEY_FILE_BYTES + 1)
    if len(data) > MAX_KEY_FILE_BYTES:
        raise NoiseChatError("Key file is too large.")
    return data


def write_key_file(path: Path, data: bytes) -> None:
    # Exclusive creation also refuses existing files and existing symlinks.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
