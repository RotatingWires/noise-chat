"""A bounded HTTP relay. It never imports client keys or decrypts messages."""

import hashlib
import json
import re
import sqlite3
import threading
import time
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .crypto import MAX_PRESENCE_PER_ROOM, PRESENCE_TTL, NoiseChatError, validate_envelope

MAX_REQUEST_BYTES = 16384
MAX_PRESENCE = 1000
ROOM_PATH = re.compile(r"/v1/rooms/([0-9a-f]{64})/(messages|presence)")


class RelayStore:
    def __init__(self, database: Path, history_per_room: int = 500, max_messages: int = 10000, max_rooms: int = 100):
        self.condition = threading.Condition(threading.RLock())
        self.closed = False
        self.presence = {}
        self.history_per_room, self.max_messages, self.max_rooms = history_per_room, max_messages, max_rooms
        self.connection = sqlite3.connect(database, check_same_thread=False)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA busy_timeout=5000")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS messages (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                room TEXT NOT NULL,
                digest TEXT NOT NULL,
                envelope TEXT NOT NULL,
                UNIQUE(room, digest)
            );
            CREATE INDEX IF NOT EXISTS messages_room_sequence ON messages(room, sequence);
        """)

    def post(self, room: str, envelope: str) -> int:
        validate_envelope(envelope)
        digest = hashlib.sha256(envelope.encode("ascii")).hexdigest()
        with self.condition:
            if self.closed:
                raise NoiseChatError("Relay is shutting down.")
            existing = self.connection.execute("SELECT sequence FROM messages WHERE room=? AND digest=?", (room, digest)).fetchone()
            if existing:
                return existing[0]
            self.check_room_capacity(room)
            with self.connection:
                cursor = self.connection.execute("INSERT INTO messages(room,digest,envelope) VALUES(?,?,?)", (room, digest, envelope))
                sequence = cursor.lastrowid
                self.connection.execute("""DELETE FROM messages WHERE room=? AND sequence NOT IN
                    (SELECT sequence FROM messages WHERE room=? ORDER BY sequence DESC LIMIT ?)""",
                    (room, room, self.history_per_room))
                self.connection.execute("""DELETE FROM messages WHERE sequence NOT IN
                    (SELECT sequence FROM messages ORDER BY sequence DESC LIMIT ?)""", (self.max_messages,))
            self.condition.notify_all()
            return sequence

    def prune_presence(self) -> None:
        now = time.monotonic()
        for session, (_, deadline) in list(self.presence.items()):
            if deadline <= now:
                del self.presence[session]

    def check_room_capacity(self, room: str) -> None:
        self.prune_presence()
        if (self.connection.execute("SELECT 1 FROM messages WHERE room=? LIMIT 1", (room,)).fetchone()
                or any(channel == room for channel, _ in self.presence)):
            return
        rooms = {row[0] for row in self.connection.execute("SELECT DISTINCT room FROM messages")}
        rooms.update(channel for channel, _ in self.presence)
        if room not in rooms and len(rooms) >= self.max_rooms:
            raise NoiseChatError("Relay room capacity reached.")

    def connect(self, room: str, token: str, envelope: str, announcement: str) -> bool:
        validate_envelope(envelope)
        validate_envelope(announcement)
        with self.condition:
            if self.closed:
                raise NoiseChatError("Relay is shutting down.")
            self.prune_presence()
            session = (room, token)
            joined = session not in self.presence
            if joined:
                if (len(self.presence) >= MAX_PRESENCE or
                        sum(channel == room for channel, _ in self.presence) >= MAX_PRESENCE_PER_ROOM):
                    raise NoiseChatError("Relay user capacity reached.")
                # Publish once per live session, including retries after a lost receipt.
                self.post(room, announcement)
            self.presence[session] = (envelope, time.monotonic() + PRESENCE_TTL)
            return joined

    def users(self, room: str) -> list[str]:
        with self.condition:
            if self.closed:
                raise NoiseChatError("Relay is shutting down.")
            self.prune_presence()
            return [envelope for (channel, _), (envelope, _) in self.presence.items() if channel == room]

    def disconnect(self, room: str, token: str) -> None:
        with self.condition:
            self.presence.pop((room, token), None)

    def poll(self, room: str, after: int, wait: float = 0) -> list[dict]:
        deadline = time.monotonic() + wait
        with self.condition:
            while not self.closed:
                rows = self.connection.execute("SELECT sequence,envelope FROM messages WHERE room=? AND sequence>? ORDER BY sequence LIMIT 100", (room, after)).fetchall()
                if rows or time.monotonic() >= deadline:
                    return [{"sequence": sequence, "envelope": envelope} for sequence, envelope in rows]
                self.condition.wait(max(0, deadline - time.monotonic()))
            raise NoiseChatError("Relay is shutting down.")

    def close(self) -> None:
        with self.condition:
            self.closed = True
            self.presence.clear()
            self.condition.notify_all()
            self.connection.close()


class RelayServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, store: RelayStore):
        self.store = store
        self.workers = threading.BoundedSemaphore(64)
        self.rate_lock = threading.Lock()
        self.rates = OrderedDict()
        super().__init__(address, RelayHandler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(10)
        return connection, address

    def process_request(self, request, client_address):
        if not self.workers.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.workers.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.workers.release()

    def allow_post(self, address: str) -> bool:
        with self.rate_lock:
            now = time.monotonic()
            tokens, last = self.rates.pop(address, (30.0, now))
            tokens = min(30.0, tokens + now - last)
            allowed = tokens >= 1
            self.rates[address] = (tokens - 1 if allowed else tokens, now)
            while len(self.rates) > 1024:
                self.rates.popitem(last=False)
            return allowed

    def handle_error(self, request, client_address):
        # Do not dump request details or remote content into server logs.
        pass


class RelayHandler(BaseHTTPRequestHandler):
    server_version = "NoiseChat"
    sys_version = ""

    def log_message(self, format, *args):
        pass

    def respond(self, status: int, body: dict) -> None:
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def route(self):
        parsed = urlsplit(self.path)
        if parsed.scheme or parsed.netloc or parsed.fragment:
            raise NoiseChatError("Invalid request target.")
        match = ROOM_PATH.fullmatch(parsed.path)
        return parsed, match.group(1) if match else None, match.group(2) if match else None

    def do_GET(self):
        try:
            parsed, room, resource = self.route()
            if parsed.path == "/health" and not parsed.query:
                self.respond(200, {"ok": True, "version": __version__, "protocol": 1})
                return
            if room is None:
                self.respond(404, {"error": "Not found."})
                return
            if resource == "presence":
                if parsed.query:
                    raise NoiseChatError("Invalid presence parameters.")
                self.respond(200, {"users": self.server.store.users(room)})
                return
            query = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=4)
            if set(query) - {"after", "wait"} or any(len(values) != 1 for values in query.values()):
                raise NoiseChatError("Invalid polling parameters.")
            after_text, wait_text = query.get("after", ["0"])[0], query.get("wait", ["0"])[0]
            if not re.fullmatch(r"[0-9]{1,18}", after_text) or not re.fullmatch(r"[0-9]{1,2}", wait_text):
                raise NoiseChatError("Invalid polling parameters.")
            after, wait = int(after_text), int(wait_text)
            if wait > 20:
                raise NoiseChatError("Polling wait must be 0–20 seconds.")
            messages = self.server.store.poll(room, after, wait)
            self.respond(200, {"messages": messages})
        except (NoiseChatError, ValueError):
            self.respond(400, {"error": "Invalid request or unavailable relay."})
        except sqlite3.Error:
            self.respond(503, {"error": "Relay storage unavailable."})

    def do_POST(self):
        try:
            parsed, room, resource = self.route()
            if room is None or parsed.query:
                self.respond(404, {"error": "Not found."})
                return
            if not self.server.allow_post(self.client_address[0]):
                self.respond(429, {"error": "Too many messages. Try again shortly."})
                return
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get("Transfer-Encoding") or len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,6}", lengths[0]):
                raise NoiseChatError("A valid Content-Length is required.")
            length = int(lengths[0])
            if length > MAX_REQUEST_BYTES:
                self.respond(413, {"error": "Request is too large."})
                return
            if self.headers.get_content_type() != "application/json":
                raise NoiseChatError("Expected JSON.")
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise NoiseChatError("Incomplete request.")
            body = json.loads(raw)
            if resource == "presence":
                if (not isinstance(body, dict) or set(body) not in ({"token"}, {"token", "envelope", "announcement"})
                        or not isinstance(body.get("token"), str) or not re.fullmatch(r"[0-9a-f]{64}", body["token"])):
                    raise NoiseChatError("Invalid presence request.")
                if set(body) == {"token"}:
                    self.server.store.disconnect(room, body["token"])
                    self.respond(200, {"left": True})
                else:
                    joined = self.server.store.connect(room, body["token"], body["envelope"], body["announcement"])
                    self.respond(200, {"joined": joined})
                return
            if not isinstance(body, dict) or set(body) != {"envelope"}:
                raise NoiseChatError("Expected one encrypted envelope.")
            sequence = self.server.store.post(room, body["envelope"])
            self.respond(201, {"sequence": sequence})
        except (NoiseChatError, UnicodeError, ValueError, RecursionError):
            self.respond(400, {"error": "Invalid encrypted message or relay capacity reached."})
        except sqlite3.Error:
            self.respond(503, {"error": "Relay storage unavailable."})


def serve(host: str, port: int, database: Path) -> None:
    store = RelayStore(database)
    try:
        server = RelayServer((host, port), store)
        print(f"NoiseChat v{__version__} relay on {host}:{server.server_port}", flush=True)
        print("Stores ciphertext only. Press Ctrl+C to stop.", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    finally:
        store.close()
