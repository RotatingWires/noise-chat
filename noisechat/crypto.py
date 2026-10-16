"""Versioned message and password-protected key-file formats."""

import base64
import hashlib
import json
import os
import re
import struct
import uuid
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAX_TEXT_BYTES = 4096
MAX_KEY_FILE_BYTES = 4096
MAX_POLL_MESSAGES = 100
MAX_PADDED_BYTES = 8192
MAX_ENVELOPE_CHARS = 11000
PRESENCE_TTL = 60
PRESENCE_HEARTBEAT = 20
MAX_PRESENCE_PER_ROOM = 100
PACKET_HEADER = b"NC1"
KEY_AAD = b"noisechat/key-file/v1"
KEY_FIELDS = {"format", "version", "kdf", "salt", "nonce", "ciphertext"}


class NoiseChatError(Exception):
    """An error safe to report without dumping secrets or remote content."""


class ChannelDeletedError(NoiseChatError):
    """The relay operator permanently disabled this room ID."""
    def __init__(self):
        super().__init__("Channel deleted by the relay operator. Use a new shared key for a new channel.")


def b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise NoiseChatError("Invalid encoded data.")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError:
        raise NoiseChatError("Invalid encoded data.") from None
    if b64encode(decoded) != value:
        raise NoiseChatError("Noncanonical encoded data.")
    return decoded


def check_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) != 32:
        raise NoiseChatError("Invalid chat key.")


def generate_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def room_id(key: bytes) -> str:
    check_key(key)
    return hashlib.sha256(b"noisechat/room/v1\x00" + key).hexdigest()


def _message_key(key: bytes, salt: bytes) -> bytes:
    check_key(key)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"noisechat/message-key/v1").derive(key)


def validate_sender(sender: str) -> None:
    if not isinstance(sender, str) or not sender.strip() or len(sender.encode("utf-8")) > 64:
        raise NoiseChatError("Names must contain 1–64 UTF-8 bytes.")


def validate_message(message: object) -> dict:
    fields = {"kind", "id", "sender", "text", "sent_at"}
    if not isinstance(message, dict) or set(message) != fields:
        raise NoiseChatError("Unsupported message format.")
    if not all(isinstance(message[field], str) for field in fields):
        raise NoiseChatError("Invalid message fields.")
    if message["kind"] not in {"text", "join", "leave", "presence"}:
        raise NoiseChatError("Unsupported message format.")
    if not re.fullmatch(r"[0-9a-f]{32}", message["id"]):
        raise NoiseChatError("Invalid message ID.")
    validate_sender(message["sender"])
    if message["kind"] != "text" and message["text"] != "":
        raise NoiseChatError("Invalid presence event.")
    if message["kind"] == "text" and (not message["text"].strip() or len(message["text"].encode("utf-8")) > MAX_TEXT_BYTES):
        raise NoiseChatError("Messages must contain 1–4096 UTF-8 bytes.")
    try:
        date = datetime.fromisoformat(message["sent_at"])
        if date.tzinfo is None or not 1970 <= date.year <= 9998 or len(message["sent_at"]) > 40:
            raise ValueError
    except ValueError:
        raise NoiseChatError("Invalid message timestamp.") from None
    return message


def encrypt_message(key: bytes, sender: str, text: str) -> str:
    return _encrypt_message(key, sender, text, "text")


def encrypt_event(key: bytes, sender: str, kind: str) -> str:
    if kind not in {"join", "leave", "presence"}:
        raise NoiseChatError("Unsupported presence event.")
    return _encrypt_message(key, sender, "", kind)


def _encrypt_message(key: bytes, sender: str, text: str, kind: str) -> str:
    message = validate_message({"kind": kind, "id": uuid.uuid4().hex,
                                "sender": sender, "text": text,
                                "sent_at": datetime.now(timezone.utc).isoformat(timespec="seconds")})
    payload = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    size = ((4 + len(payload) + 255) // 256) * 256
    if size > MAX_PADDED_BYTES:
        raise NoiseChatError("Message is too large.")
    padded = struct.pack(">I", len(payload)) + payload + os.urandom(size - 4 - len(payload))
    # Independent per-message keys reduce coordination demands on shared-key clients.
    salt, nonce = os.urandom(32), os.urandom(12)
    aad = b"noisechat/message/v1\x00" + room_id(key).encode("ascii")
    encrypted = AESGCM(_message_key(key, salt)).encrypt(nonce, padded, aad)
    return b64encode(PACKET_HEADER + salt + nonce + encrypted)


def validate_envelope(envelope: str) -> bytes:
    if not isinstance(envelope, str) or len(envelope) > MAX_ENVELOPE_CHARS:
        raise NoiseChatError("Encrypted message is too large or invalid.")
    packet = b64decode(envelope)
    if not packet.startswith(PACKET_HEADER) or not 319 <= len(packet) <= 63 + MAX_PADDED_BYTES:
        raise NoiseChatError("Unsupported encrypted message format.")
    if (len(packet) - 63) % 256:
        raise NoiseChatError("Invalid encrypted message length.")
    return packet


def decrypt_message(key: bytes, envelope: str) -> dict:
    packet = validate_envelope(envelope)
    aad = b"noisechat/message/v1\x00" + room_id(key).encode("ascii")
    try:
        padded = AESGCM(_message_key(key, packet[3:35])).decrypt(packet[35:47], packet[47:], aad)
    except InvalidTag:
        raise NoiseChatError("Message authentication failed; wrong key or altered ciphertext.") from None
    size = struct.unpack(">I", padded[:4])[0]
    if size < 1 or size > len(padded) - 4:
        raise NoiseChatError("Invalid decrypted message length.")
    try:
        return validate_message(json.loads(padded[4:4 + size]))
    except (ValueError, TypeError, RecursionError):
        raise NoiseChatError("Invalid decrypted message.") from None


def _password_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise NoiseChatError("The key-file passphrase cannot be empty.")
    # Fixed parameters: key-file input cannot request unbounded memory or work.
    return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(password.encode("utf-8"))


def encrypt_key_file(key: bytes, password: str) -> bytes:
    check_key(key)
    if len(password) < 12:
        raise NoiseChatError("Use a key-file passphrase of at least 12 characters.")
    salt, nonce = os.urandom(16), os.urandom(12)
    encrypted = AESGCM(_password_key(password, salt)).encrypt(nonce, key, KEY_AAD)
    return (json.dumps({"format": "noisechat-key", "version": 1,
                        "kdf": "scrypt-n131072-r8-p1", "salt": b64encode(salt),
                        "nonce": b64encode(nonce), "ciphertext": b64encode(encrypted)}, indent=2) + "\n").encode()


def decrypt_key_file(data: bytes, password: str) -> bytes:
    if len(data) > MAX_KEY_FILE_BYTES:
        raise NoiseChatError("Key file is too large.")
    try:
        document = json.loads(data)
    except (ValueError, RecursionError):
        raise NoiseChatError("Invalid key file.") from None
    if (not isinstance(document, dict) or set(document) != KEY_FIELDS
            or document["format"] != "noisechat-key" or type(document["version"]) is not int
            or document["version"] != 1 or document["kdf"] != "scrypt-n131072-r8-p1"):
        raise NoiseChatError("Unsupported key-file format.")
    salt, nonce, encrypted = (b64decode(document[field]) for field in ("salt", "nonce", "ciphertext"))
    if len(salt) != 16 or len(nonce) != 12 or len(encrypted) != 48:
        raise NoiseChatError("Invalid key-file fields.")
    try:
        key = AESGCM(_password_key(password, salt)).decrypt(nonce, encrypted, KEY_AAD)
    except InvalidTag:
        raise NoiseChatError("Wrong passphrase or damaged key file.") from None
    check_key(key)
    return key
