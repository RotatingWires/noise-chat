"""Client transport and terminal-safe rendering."""

import json
import threading
import unicodedata
from collections import OrderedDict
from datetime import datetime
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .crypto import MAX_ENVELOPE_CHARS, NoiseChatError, decrypt_message, encrypt_message, room_id


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, server: str, key: bytes):
        try:
            parsed = urlsplit(server)
            port = parsed.port
        except ValueError:
            raise NoiseChatError("Invalid relay URL.") from None
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}
                or port == 0):
            raise NoiseChatError("Use a relay URL such as https://chat.example.com or http://127.0.0.1:8720.")
        self.key = key
        self.url = server.rstrip("/") + "/v1/rooms/" + room_id(key) + "/messages"
        self.opener = build_opener(NoRedirects())

    def request(self, method: str, query: dict | None = None, body: dict | None = None) -> dict:
        url = self.url + ("?" + urlencode(query) if query else "")
        data = json.dumps(body).encode() if body is not None else None
        request = Request(url, data=data, method=method, headers={"Content-Type": "application/json", "Accept": "application/json"})
        try:
            with self.opener.open(request, timeout=25) as response:
                raw = response.read(1200001)
        except HTTPError as error:
            status = error.code
            error.close()
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


def terminal_text(value: str) -> str:
    # Remote text cannot inject ANSI escapes, carriage returns, or bidi controls.
    return "".join(f"\\u{ord(char):04x}" if unicodedata.category(char) in {"Cc", "Cf", "Cs"} else char for char in value)


def render_message(message: dict) -> str:
    timestamp = datetime.fromisoformat(message["sent_at"]).astimezone().strftime("%H:%M")
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
            except NoiseChatError as error:
                if stop.is_set():
                    return
                if not offline:
                    self.output(f"[{error} Retrying...]")
                offline = True
                stop.wait(2)
