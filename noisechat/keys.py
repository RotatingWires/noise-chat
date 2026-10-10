"""Use native credential stores, never a plaintext keyring fallback."""

import os
import re
from pathlib import Path

import keyring
from keyring.errors import KeyringError

from .crypto import NoiseChatError, b64decode, b64encode, check_key

SERVICE = "noisechat.chat-key.v1"
NATIVE_MODULES = {
    "keyring.backends.Windows", "keyring.backends.SecretService",
    "keyring.backends.libsecret", "keyring.backends.kwallet", "keyring.backends.macOS",
}


def check_alias(alias: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", alias):
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
            value = native_backend().get_password(SERVICE, alias)
        except KeyringError:
            raise NoiseChatError("Could not unlock/read the OS keyring.") from None
        if value is None:
            raise NoiseChatError("Chat key not found. Create it or import your friend's encrypted key file.")
        key = b64decode(value)
        check_key(key)
        return key

    def put(self, alias: str, key: bytes, replace: bool = False) -> None:
        check_alias(alias)
        check_key(key)
        try:
            backend = native_backend()
            if backend.get_password(SERVICE, alias) is not None and not replace:
                raise NoiseChatError("That chat already has a key. Use another name or --replace explicitly.")
            backend.set_password(SERVICE, alias, b64encode(key))
        except KeyringError:
            raise NoiseChatError("Could not save the key in the OS keyring.") from None

    def remove(self, alias: str) -> None:
        check_alias(alias)
        self.get(alias)
        try:
            native_backend().delete_password(SERVICE, alias)
        except KeyringError:
            raise NoiseChatError("Could not remove the key from the OS keyring.") from None


def read_key_file(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(4097)
    if len(data) > 4096:
        raise NoiseChatError("Key file is too large.")
    return data


def write_key_file(path: Path, data: bytes) -> None:
    # Exclusive creation also refuses existing files and existing symlinks.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
