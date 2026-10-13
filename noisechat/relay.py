"""A bounded HTTP relay. It never imports client keys or decrypts messages."""

import hashlib
import ipaddress
import json
import re
import socket
import sqlite3
import sys
import threading
import time
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .auth import PasswordVerifier, RelayAccess
from .crypto import MAX_PRESENCE_PER_ROOM, PRESENCE_TTL, ChannelDeletedError, NoiseChatError, validate_envelope

MAX_REQUEST_BYTES = 16384
MAX_PRESENCE = 1000
ROOM_PATH = re.compile(r"/v1/rooms/([0-9a-f]{64})/(messages|presence)")


class RequestTooLargeError(NoiseChatError):
    pass


class TunnelRequestError(NoiseChatError):
    pass


def canonical_ip(value: str):
    if not value or len(value) > 45 or "%" in value:
        raise ValueError("Invalid IP address.")
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def tunnel_listen_host(host: str) -> str:
    if host.lower() == "localhost":
        return "127.0.0.1"
    try:
        address = canonical_ip(host)
        if address.is_loopback:
            return str(address)
    except ValueError:
        pass
    raise NoiseChatError("--cloudflare-tunnel requires a loopback listen address, such as http://127.0.0.1:8713. "
                         "Run cloudflared on the same machine and network namespace.")


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
            CREATE TABLE IF NOT EXISTS deleted_rooms (room TEXT PRIMARY KEY);
        """)

    def check_available(self, room: str) -> None:
        if self.closed:
            raise NoiseChatError("Relay is shutting down.")
        if self.connection.execute("SELECT 1 FROM deleted_rooms WHERE room=?", (room,)).fetchone():
            raise ChannelDeletedError()

    def post(self, room: str, envelope: str) -> int:
        validate_envelope(envelope)
        digest = hashlib.sha256(envelope.encode("ascii")).hexdigest()
        with self.condition:
            self.check_available(room)
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
            self.check_available(room)
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
            self.check_available(room)
            self.prune_presence()
            return [envelope for (channel, _), (envelope, _) in self.presence.items() if channel == room]

    def disconnect(self, room: str, token: str, announcement: str | None = None) -> None:
        with self.condition:
            session = (room, token)
            if session in self.presence:
                if announcement is not None:
                    validate_envelope(announcement)
                    self.post(room, announcement)
                self.presence.pop(session, None)

    def channels(self) -> list[dict]:
        with self.condition:
            if self.closed:
                raise NoiseChatError("Relay is shutting down.")
            self.prune_presence()
            counts = dict(self.connection.execute("SELECT room,COUNT(*) FROM messages GROUP BY room"))
            online = {}
            for room, _ in self.presence:
                online[room] = online.get(room, 0) + 1
            return [{"room": room, "packets": counts.get(room, 0), "online": online.get(room, 0)}
                    for room in sorted(counts.keys() | online.keys())]

    def delete_channel(self, room: str) -> tuple[int, int]:
        if not isinstance(room, str) or not re.fullmatch(r"[0-9a-f]{64}", room):
            raise NoiseChatError("Use the 64-character room ID, not a local chat name.")
        with self.condition:
            if self.closed:
                raise NoiseChatError("Relay is shutting down.")
            with self.connection:
                deleted = self.connection.execute("DELETE FROM messages WHERE room=?", (room,)).rowcount
                self.connection.execute("INSERT OR IGNORE INTO deleted_rooms(room) VALUES(?)", (room,))
            sessions = [session for session in self.presence if session[0] == room]
            for session in sessions:
                del self.presence[session]
            self.condition.notify_all()
            return deleted, len(sessions)

    def poll(self, room: str, after: int, wait: float = 0) -> list[dict]:
        deadline = time.monotonic() + wait
        with self.condition:
            while not self.closed:
                self.check_available(room)
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

    def __init__(self, address, store: RelayStore, verifier: PasswordVerifier, cloudflare_tunnel: bool = False):
        if cloudflare_tunnel:
            address = (tunnel_listen_host(address[0]), address[1])
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        self.store = store
        self.access = RelayAccess(verifier)
        self.cloudflare_tunnel = cloudflare_tunnel
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

    def respond(self, status: int, body: dict, headers: dict | None = None) -> None:
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        for name, value in (headers or {}).items():
            self.send_header(name, str(value))
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def require_access(self) -> bool:
        if self.server.access.authorized(self.headers.get_all("Authorization", [])):
            return True
        self.respond(401, {"error": "Server login required."}, {"WWW-Authenticate": 'Bearer realm="NoiseChat"'})
        return False

    def visitor_ip(self) -> str:
        peer = self.client_address[0]
        if not self.server.cloudflare_tunnel:
            # Direct mode never trusts IPs supplied in HTTP headers.
            return peer
        values = self.headers.get_all("CF-Connecting-IP", [])
        try:
            if not canonical_ip(peer).is_loopback or len(values) != 1:
                raise ValueError()
            return str(canonical_ip(values[0].strip()))
        except ValueError:
            # Fail closed rather than charging unrelated users to the connector's IP.
            raise TunnelRequestError() from None

    def read_json(self):
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get("Transfer-Encoding") or len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,6}", lengths[0]):
            raise NoiseChatError("A valid Content-Length is required.")
        length = int(lengths[0])
        if length > MAX_REQUEST_BYTES:
            raise RequestTooLargeError()
        if self.headers.get_content_type() != "application/json":
            raise NoiseChatError("Expected JSON.")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise NoiseChatError("Incomplete request.")
        return json.loads(raw)

    def login(self, address: str) -> None:
        retry = self.server.access.login_attempt(address)
        if retry:
            self.respond(429, {"error": "Too many login attempts.", "retry_after": retry}, {"Retry-After": retry})
            return
        body = self.read_json()
        if not isinstance(body, dict) or set(body) != {"password"} or not isinstance(body["password"], str):
            raise NoiseChatError("Expected a server password.")
        token = self.server.access.login(body["password"])
        if token is None:
            self.respond(401, {"error": "Incorrect server password."})
        else:
            self.respond(200, {"token": token})

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
            self.visitor_ip()
            if not self.require_access():
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
        except ChannelDeletedError:
            self.respond(410, {"error": "Channel deleted."})
        except TunnelRequestError:
            self.respond(403, {"error": "Cloudflare Tunnel requires a local connector and one valid CF-Connecting-IP header."})
        except (NoiseChatError, ValueError):
            self.respond(400, {"error": "Invalid request or unavailable relay."})
        except sqlite3.Error:
            self.respond(503, {"error": "Relay storage unavailable."})

    def do_POST(self):
        try:
            parsed, room, resource = self.route()
            address = self.visitor_ip()
            if parsed.path == "/v1/auth/login" and not parsed.query:
                self.login(address)
                return
            if not self.require_access():
                return
            if room is None or parsed.query:
                self.respond(404, {"error": "Not found."})
                return
            if not self.server.allow_post(address):
                self.respond(429, {"error": "Too many messages. Try again shortly."})
                return
            body = self.read_json()
            if resource == "presence":
                if (not isinstance(body, dict) or set(body) not in ({"token"}, {"token", "announcement"}, {"token", "envelope", "announcement"})
                        or not isinstance(body.get("token"), str) or not re.fullmatch(r"[0-9a-f]{64}", body["token"])):
                    raise NoiseChatError("Invalid presence request.")
                if set(body) in ({"token"}, {"token", "announcement"}):
                    self.server.store.disconnect(room, body["token"], body.get("announcement"))
                    self.respond(200, {"left": True})
                else:
                    joined = self.server.store.connect(room, body["token"], body["envelope"], body["announcement"])
                    self.respond(200, {"joined": joined})
                return
            if not isinstance(body, dict) or set(body) != {"envelope"}:
                raise NoiseChatError("Expected one encrypted envelope.")
            sequence = self.server.store.post(room, body["envelope"])
            self.respond(201, {"sequence": sequence})
        except ChannelDeletedError:
            self.respond(410, {"error": "Channel deleted."})
        except TunnelRequestError:
            self.respond(403, {"error": "Cloudflare Tunnel requires a local connector and one valid CF-Connecting-IP header."})
        except RequestTooLargeError:
            self.respond(413, {"error": "Request is too large."})
        except (NoiseChatError, UnicodeError, ValueError, RecursionError):
            self.respond(400, {"error": "Invalid encrypted message or relay capacity reached."})
        except sqlite3.Error:
            self.respond(503, {"error": "Relay storage unavailable."})


def console(store: RelayStore, server: RelayServer) -> None:
    print("Server console: help, channels, delete-channel ROOM_ID, quit", flush=True)
    while not store.closed:
        try:
            words = input("relay> ").split()
        except EOFError:
            return
        if not words:
            continue
        try:
            if words == ["help"]:
                print("channels: list room IDs, retained packet counts, and online sessions.")
                print("delete-channel ROOM_ID: erase that channel's history and permanently block its room ID.")
                print("quit: stop the relay.")
            elif words == ["channels"]:
                channels = store.channels()
                print(f"{'ROOM ID':<64}  PACKETS  ONLINE")
                for channel in channels:
                    print(f"{channel['room']}  {channel['packets']:>7}  {channel['online']:>6}")
                if not channels:
                    print("No active channels.")
            elif len(words) == 2 and words[0] == "delete-channel":
                packets, sessions = store.delete_channel(words[1])
                print(f"Channel deleted: {packets} packets removed, {sessions} sessions removed. Room ID permanently blocked.")
            elif words == ["quit"]:
                server.shutdown()
                return
            else:
                print("Unknown console command. Type help.")
        except NoiseChatError as error:
            print("Error:", error)
        except sqlite3.Error:
            print("Error: Relay database could not be updated.")


def serve(host: str, port: int, database: Path, verifier: PasswordVerifier, cloudflare_tunnel: bool = False) -> None:
    if cloudflare_tunnel:
        host = tunnel_listen_host(host)
    store = RelayStore(database)
    try:
        server = RelayServer((host, port), store, verifier, cloudflare_tunnel=cloudflare_tunnel)
        address = f"[{host}]" if ":" in host else host
        print(f"NoiseChat v{__version__} relay on http://{address}:{server.server_port}", flush=True)
        print("Server password required. Stores ciphertext only. Press Ctrl+C to stop.", flush=True)
        if cloudflare_tunnel:
            print("Cloudflare Tunnel mode: limits use CF-Connecting-IP from the local connector.", flush=True)
        if sys.stdin.isatty():
            threading.Thread(target=console, args=(store, server), daemon=True).start()
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    finally:
        store.close()
