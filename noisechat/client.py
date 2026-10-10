"""Client transport and terminal-safe rendering."""

import json
import secrets
import threading
import unicodedata
from collections import OrderedDict
from datetime import datetime
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .auth import ServerAccessError, password_bytes
from .crypto import (MAX_ENVELOPE_CHARS, MAX_PRESENCE_PER_ROOM, PRESENCE_HEARTBEAT, PRESENCE_TTL,
                     ChannelDeletedError, NoiseChatError, decrypt_message, encrypt_event, encrypt_message, room_id)


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, server: str, key: bytes, password: str | None = None):
        try:
            parsed = urlsplit(server)
            port = parsed.port
        except ValueError:
            raise NoiseChatError("Invalid relay URL.") from None
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}
                or port == 0):
            raise NoiseChatError("Use a relay URL such as https://chat.example.com or http://HOST:PORT.")
        self.key = key
        self.server = server.rstrip("/")
        self.url = self.server + "/v1/rooms/" + room_id(key)
        if password is not None:
            password_bytes(password)
        self.password = password
        self.token = None
        self.login_lock = threading.Lock()
        self.opener = build_opener(NoRedirects())

    def _request(self, url: str, method: str, body: dict | None, timeout: int,
                 token: str | None = None, login: bool = False) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        request = Request(url, data=data, method=method, headers=headers)
        try:
            with self.opener.open(request, timeout=timeout) as response:
                raw = response.read(1200001)
        except HTTPError as error:
            status = error.code
            retry = error.headers.get("Retry-After", "60") if error.headers else "60"
            error.close()
            if status == 401:
                raise ServerAccessError("Incorrect server password." if login else "Server session expired or was revoked.") from None
            if status == 429 and login:
                seconds = int(retry) if retry.isascii() and retry.isdecimal() and len(retry) <= 3 else 60
                raise ServerAccessError(f"Too many login attempts. Try again in {max(1, min(seconds, 60))} seconds.") from None
            if status == 410:
                raise ChannelDeletedError() from None
            raise NoiseChatError(f"Relay returned HTTP {status}.") from None
        except (URLError, TimeoutError, OSError, HTTPException):
            raise NoiseChatError("Could not reach the relay. Check its URL and connection.") from None
        if len(raw) > 1200000:
            raise NoiseChatError("Relay response is too large.")
        try:
            value = json.loads(raw)
        except (UnicodeError, ValueError, RecursionError):
            raise NoiseChatError("Relay returned invalid JSON.") from None
        if not isinstance(value, dict):
            raise NoiseChatError("Relay returned an invalid response.")
        return value

    def authenticate(self, previous_token: str | None = None) -> str:
        with self.login_lock:
            if self.token is not None and self.token != previous_token:
                return self.token
            if self.password is None:
                raise ServerAccessError("A server access password is required.")
            value = self._request(self.server + "/v1/auth/login", "POST", {"password": self.password}, 5, login=True)
            token = value.get("token")
            if not isinstance(token, str) or len(token) != 64 or any(char not in "0123456789abcdef" for char in token):
                raise NoiseChatError("Relay returned an invalid server session.")
            self.token = token
            return token

    def request(self, method: str, query: dict | None = None, body: dict | None = None,
                resource: str = "messages", timeout: int = 25) -> dict:
        url = self.url + "/" + resource + ("?" + urlencode(query) if query else "")
        token = self.authenticate()
        try:
            return self._request(url, method, body, timeout, token)
        except ServerAccessError:
            # Relay restarts and expiry invalidate in-memory sessions. Reauthenticate once.
            token = self.authenticate(previous_token=token)
            return self._request(url, method, body, timeout, token)

    def send(self, sender: str, text: str) -> int:
        envelope = encrypt_message(self.key, sender, text)
        value = self.request("POST", body={"envelope": envelope})
        if type(value.get("sequence")) is not int or not 0 < value["sequence"] < 2**63:
            raise NoiseChatError("Relay returned an invalid message receipt.")
        return value["sequence"]

    def poll(self, after: int, wait: int = 20) -> list[dict]:
        value = self.request("GET", query={"after": after, "wait": wait})
        messages = value.get("messages")
        if not isinstance(messages, list) or len(messages) > 100:
            raise NoiseChatError("Relay returned an invalid message batch.")
        last = after
        for message in messages:
            if (not isinstance(message, dict) or set(message) != {"sequence", "envelope"}
                    or type(message["sequence"]) is not int or not last < message["sequence"] < 2**63
                    or not isinstance(message["envelope"], str) or len(message["envelope"]) > MAX_ENVELOPE_CHARS):
                raise NoiseChatError("Relay returned an invalid message batch.")
            last = message["sequence"]
        return messages

    def connect(self, token: str, sender: str) -> None:
        body = {"token": token, "envelope": encrypt_event(self.key, sender, "presence"),
                "announcement": encrypt_event(self.key, sender, "join")}
        value = self.request("POST", body=body, resource="presence", timeout=5)
        if type(value.get("joined")) is not bool:
            raise NoiseChatError("Relay returned an invalid presence receipt.")

    def disconnect(self, token: str) -> None:
        value = self.request("POST", body={"token": token}, resource="presence", timeout=5)
        if value.get("left") is not True:
            raise NoiseChatError("Relay returned an invalid departure receipt.")

    def users(self) -> list[dict]:
        value = self.request("GET", resource="presence", timeout=5)
        entries = value.get("users")
        if (not isinstance(entries, list) or len(entries) > MAX_PRESENCE_PER_ROOM
                or any(not isinstance(entry, str) or len(entry) > MAX_ENVELOPE_CHARS for entry in entries)):
            raise NoiseChatError("Relay returned an invalid user list.")
        users = {}
        for entry in entries:
            try:
                message = decrypt_message(self.key, entry)
            except NoiseChatError:
                continue
            if message["kind"] == "presence":
                users[message["id"]] = message
        return sorted(users.values(), key=lambda user: (user["sender"].casefold(), user["id"]))


class Presence:
    """Refresh one encrypted online session; its private token is never in the roster."""
    def __init__(self, client: Client, sender: str, output=print, stop: threading.Event | None = None):
        self.client, self.sender, self.output = client, sender, output
        self.token = secrets.token_hex(32)
        self.stop = stop if stop is not None else threading.Event()
        self.thread = threading.Thread(target=self.maintain, daemon=True)

    def start(self) -> None:
        self.client.connect(self.token, self.sender)
        self.thread.start()

    def maintain(self) -> None:
        delay, offline = PRESENCE_HEARTBEAT, False
        while not self.stop.wait(delay):
            try:
                self.client.connect(self.token, self.sender)
                if offline:
                    self.output("[Online status restored.]")
                delay, offline = PRESENCE_HEARTBEAT, False
            except (ChannelDeletedError, ServerAccessError) as error:
                if not self.stop.is_set():
                    self.stop.set()
                    self.output(f"[{error} Press Enter to exit.]")
            except NoiseChatError as error:
                if not offline:
                    self.output(f"[Online status not confirmed: {error} Retrying...]")
                delay, offline = 5, True

    def close(self) -> None:
        self.stop.set()
        # Heartbeats use a five-second request timeout. Finish one before leaving.
        self.thread.join()
        try:
            self.client.disconnect(self.token)
        except NoiseChatError:
            self.output(f"[Could not confirm departure; online status expires within {PRESENCE_TTL} seconds.]")


def terminal_text(value: str) -> str:
    # Remote text cannot inject ANSI escapes, carriage returns, or bidi controls.
    return "".join(f"\\u{ord(char):04x}" if unicodedata.category(char) in {"Cc", "Cf", "Cs"} else char for char in value)


def render_message(message: dict) -> str:
    timestamp = datetime.fromisoformat(message["sent_at"]).astimezone().strftime("%H:%M")
    if message["kind"] == "join":
        return f"[{timestamp}] [Wall] {terminal_text(message['sender'])} joined the chat."
    return f"[{timestamp}] {terminal_text(message['sender'])}: {terminal_text(message['text'])}"


class Receiver:
    def __init__(self, client: Client, output=print):
        self.client, self.output = client, output
        self.cursor = 0
        self.seen = OrderedDict()

    def receive(self, wait: int = 20) -> int:
        count = 0
        for record in self.client.poll(self.cursor, wait):
            # Bad packets must not block later valid messages in the same batch.
            self.cursor = record["sequence"]
            try:
                message = decrypt_message(self.client.key, record["envelope"])
            except NoiseChatError:
                self.output("[Ignored a message that could not be authenticated.]")
                continue
            if message["id"] in self.seen:
                continue
            if message["kind"] == "presence":
                continue
            self.seen[message["id"]] = None
            while len(self.seen) > 10000:
                self.seen.popitem(last=False)
            self.output(render_message(message))
            count += 1
        return count

    def listen(self, stop: threading.Event) -> None:
        offline = False
        while not stop.is_set():
            try:
                self.receive()
                if offline:
                    self.output("[Reconnected to relay.]")
                offline = False
            except (ChannelDeletedError, ServerAccessError) as error:
                if not stop.is_set():
                    stop.set()
                    self.output(f"[{error} Press Enter to exit.]")
                return
            except NoiseChatError as error:
                if stop.is_set():
                    return
                if not offline:
                    self.output(f"[{error} Retrying...]")
                offline = True
                stop.wait(2)
