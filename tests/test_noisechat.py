import contextlib
import http.client
import io
import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from collections import OrderedDict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import urlsplit

from noisechat import cli
from noisechat.auth import PasswordVerifier, RelayAccess, ServerAccessError, SESSION_SECONDS
from noisechat.client import Client, Presence, Receiver, terminal_text
from noisechat.crypto import (ChannelDeletedError, NoiseChatError, b64decode, b64encode, decrypt_key_file,
                              decrypt_message, encrypt_event, encrypt_key_file, encrypt_message, generate_key, room_id)
from noisechat.keys import KeyStore, native_backend, read_key_file, write_key_file
from noisechat.relay import RelayHandler, RelayStore, RelayServer, console

SERVER_PASSWORD = "correct server password words"
SERVER_VERIFIER = PasswordVerifier.create(SERVER_PASSWORD)


class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.key = generate_key()

    def test_unicode_and_randomized_whole_messages(self):
        text = "aaaa hello 世界 👋\nsecond line"
        packets = [encrypt_message(self.key, "Alice", text) for _ in range(100)]
        self.assertEqual(len(set(packets)), 100)
        for packet in packets:
            result = decrypt_message(self.key, packet)
            self.assertEqual(result["text"], text)
            self.assertEqual(result["sender"], "Alice")
            self.assertNotIn(text, packet)
        self.assertEqual(len(room_id(self.key)), 64)

    def test_wrong_key_tampering_and_room_binding(self):
        original = encrypt_message(self.key, "Alice", "secret")
        with self.assertRaises(NoiseChatError):
            decrypt_message(generate_key(), original)
        for index in [0, 3, 35, 47, -1]:
            changed = bytearray(b64decode(original))
            changed[index] ^= 1
            with self.assertRaises(NoiseChatError):
                decrypt_message(self.key, b64encode(changed))

    def test_size_and_malformed_inputs(self):
        for text in ["", " " * 20, "x" * 4097, "👋" * 1025]:
            with self.assertRaises(NoiseChatError):
                encrypt_message(self.key, "Alice", text)
        decrypt_message(self.key, encrypt_message(self.key, "Alice", "x" * 4096))
        for packet in [None, "", "abc=", "!", "a" * 11001, "AAAA"]:
            with self.assertRaises(NoiseChatError):
                decrypt_message(self.key, packet)

    def test_padding_hides_small_length_differences(self):
        first = encrypt_message(self.key, "Alice", "a")
        second = encrypt_message(self.key, "Alice", "aaaa")
        self.assertEqual(len(first), len(second))
        self.assertNotEqual(first, second)

    def test_key_file_round_trip_wrong_password_tampering(self):
        password = "four random words here"
        data = encrypt_key_file(self.key, password)
        self.assertEqual(decrypt_key_file(data, password), self.key)
        self.assertNotIn(b64encode(self.key).encode(), data)
        with self.assertRaises(NoiseChatError):
            decrypt_key_file(data, "different password")
        document = json.loads(data)
        ciphertext = bytearray(b64decode(document["ciphertext"]))
        ciphertext[-1] ^= 1
        document["ciphertext"] = b64encode(ciphertext)
        with self.assertRaises(NoiseChatError):
            decrypt_key_file(json.dumps(document).encode(), password)
        document["kdf"] = "scrypt-n9999999999"
        with self.assertRaises(NoiseChatError):
            decrypt_key_file(json.dumps(document).encode(), password)
        with self.assertRaises(NoiseChatError):
            encrypt_key_file(self.key, "short")


class MemoryKeyring:
    def __init__(self):
        self.values = {}

    def get_password(self, service, name):
        return self.values.get((service, name))

    def set_password(self, service, name, value):
        self.values[service, name] = value

    def delete_password(self, service, name):
        del self.values[service, name]


class KeyTests(unittest.TestCase):
    def test_passphrase_prompt_refuses_echoing_fallback(self):
        with patch("noisechat.cli.getpass.getpass",side_effect=cli.getpass.GetPassWarning("would echo")):
            with self.assertRaisesRegex(NoiseChatError,"hidden input"):
                cli.read_passphrase("Passphrase: ")

    def test_keyring_import_protection_and_removal(self):
        first, second = generate_key(), generate_key()
        with patch("noisechat.keys.native_backend", return_value=MemoryKeyring()):
            store = KeyStore()
            store.put("friends", first)
            self.assertEqual(store.get("friends"), first)
            with self.assertRaises(NoiseChatError):
                store.put("friends", second)
            store.put("friends", second, replace=True)
            self.assertEqual(store.get("friends"), second)
            store.remove("friends")
            with self.assertRaises(NoiseChatError):
                store.get("friends")

    def test_key_list_shows_local_aliases_and_room_ids_without_keys(self):
        first, second = generate_key(), generate_key()
        with patch("noisechat.keys.native_backend", return_value=MemoryKeyring()):
            store = KeyStore()
            store.put("friends", first)
            store.put("work", second)
            entries = store.list()
        self.assertEqual(entries, [("friends", room_id(first)), ("work", room_id(second))])
        self.assertNotIn(first.hex(), str(entries))

    def test_key_list_cli_prints_aliases_and_room_ids(self):
        key = generate_key()
        output = io.StringIO()
        with patch("noisechat.keys.native_backend", return_value=MemoryKeyring()):
            KeyStore().put("friends", key)
            with contextlib.redirect_stdout(output):
                self.assertEqual(cli.main(["key", "list"]), 0)
        self.assertIn("friends", output.getvalue())
        self.assertIn(room_id(key), output.getvalue())
        self.assertNotIn(key.hex(), output.getvalue())

    def test_unknown_or_plaintext_backends_are_rejected(self):
        with patch("noisechat.keys.keyring.get_keyring", return_value=MemoryKeyring()):
            with self.assertRaisesRegex(NoiseChatError, "Plaintext"):
                native_backend()

    def test_encrypted_exports_refuse_overwrite_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "friends.noise-key"
            data = encrypt_key_file(generate_key(), "four random words here")
            write_key_file(path, data)
            self.assertEqual(read_key_file(path), data)
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                write_key_file(path, b"overwrite")
            self.assertEqual(read_key_file(path), data)
            if os.name != "nt":
                link = Path(directory) / "link.noise-key"
                link.symlink_to(path)
                with self.assertRaises(FileExistsError):
                    write_key_file(link, b"overwrite")

    def test_cli_key_exchange_and_offline_ciphertext(self):
        with tempfile.TemporaryDirectory() as directory, patch("noisechat.keys.native_backend", return_value=MemoryKeyring()):
            path = Path(directory) / "friends.noise-key"
            output = io.StringIO()
            with contextlib.redirect_stdout(output), patch("noisechat.cli.getpass.getpass", return_value="four random words here"):
                self.assertEqual(cli.main(["key", "create", "alice", "--export", str(path)]), 0)
                self.assertEqual(cli.main(["key", "import", "bob", str(path)]), 0)
                self.assertEqual(KeyStore().get("alice"), KeyStore().get("bob"))
                self.assertEqual(cli.main(["key", "create", "fileonly", "--no-store", "--export", str(Path(directory)/"only.noise-key")]), 0)
                with self.assertRaises(NoiseChatError):
                    KeyStore().get("fileonly")
                self.assertEqual(cli.main(["key", "info", "fileonly", "--key-file", str(Path(directory)/"only.noise-key")]), 0)
            output = io.StringIO()
            with contextlib.redirect_stdout(output), patch("builtins.input", return_value="hello from Alice"):
                self.assertEqual(cli.main(["encrypt", "alice", "--name", "Alice"]), 0)
            ciphertext = output.getvalue().strip()
            self.assertEqual(decrypt_message(KeyStore().get("bob"), ciphertext)["text"], "hello from Alice")


class WireSocket:
    """Feed actual HTTP bytes through the stdlib handler without needing a network sandbox exception."""
    def __init__(self, data):
        self.input = io.BytesIO(data)
        self.output = bytearray()

    def makefile(self, mode, *args):
        return self.input

    def sendall(self, data):
        self.output.extend(data)


class InProcessHTTP:
    def __init__(self, store):
        self.server = SimpleNamespace(store=store, access=RelayAccess(SERVER_VERIFIER), cloudflare_tunnel=False,
                                      allow_post=lambda address: True)
        self.token = self.server.access.login(SERVER_PASSWORD)
        self.requests = []

    def raw(self, data, authenticated=True, address="127.0.0.1"):
        if authenticated and b"Authorization:" not in data:
            data = data.replace(b"\r\n\r\n", f"\r\nAuthorization: Bearer {self.token}\r\n\r\n".encode(), 1)
        socket = WireSocket(data)
        RelayHandler(socket, (address, 12345), self.server)
        response = http.client.HTTPResponse(WireSocket(bytes(socket.output)))
        response.begin()
        return response

    def open(self, request, timeout=25):
        path = urlsplit(request.full_url)
        target = path.path + ("?"+path.query if path.query else "")
        body = request.data or b""
        headers = {**request.headers, "Host": "relay.test", "Content-Length": str(len(body))}
        raw = (f"{request.method} {target} HTTP/1.0\r\n" + "".join(f"{key}: {value}\r\n" for key,value in headers.items()) + "\r\n").encode() + body
        self.requests.append(raw)
        response = self.raw(raw, authenticated=False)
        if response.status >= 400:
            raise HTTPError(request.full_url, response.status, "", response.headers, response)
        return response


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "relay.sqlite3"
        self.store = RelayStore(self.path, history_per_room=3, max_messages=5, max_rooms=2)
        self.wire = InProcessHTTP(self.store)
        self.key = generate_key()
        self.alice, self.bob = self.client(self.key), self.client(self.key)
        password_prompt = patch("noisechat.cli.read_server_password", return_value=SERVER_PASSWORD)
        password_prompt.start()
        self.addCleanup(password_prompt.stop)

    def client(self, key):
        client = Client("http://relay.test", key, SERVER_PASSWORD)
        client.opener = self.wire
        return client

    def tearDown(self):
        if not self.store.closed:
            self.store.close()
        self.directory.cleanup()

    def test_two_clients_exchange_ciphertext_over_real_http_serialization(self):
        secret = "private text never sent to the server"
        self.alice.send("Alice", secret)
        self.bob.send("Bob", "received")
        received = []
        receiver = Receiver(self.bob, received.append)
        self.assertEqual(receiver.receive(wait=0), 2)
        self.assertIn(secret, received[0])
        self.assertIn("Bob: received", received[1])
        self.assertEqual(receiver.receive(wait=0), 0)
        self.assertNotIn(secret.encode(), b"".join(self.wire.requests))
        self.assertNotIn(b"Alice", b"".join(self.wire.requests))
        self.assertNotIn(self.key, b"".join(self.wire.requests))
        self.store.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.assertNotIn(secret.encode(), self.path.read_bytes())
        self.assertNotIn(b"Alice", self.path.read_bytes())
        other = self.client(generate_key())
        self.assertEqual(other.poll(0, wait=0), [])

    def test_join_wall_and_roster_are_encrypted_and_channel_scoped(self):
        token = "a" * 64
        self.alice.connect(token, "Alice")
        self.assertEqual([user["sender"] for user in self.bob.users()], ["Alice"])
        self.assertEqual(self.client(generate_key()).users(), [])
        output = []
        receiver = Receiver(self.bob, output.append)
        self.assertEqual(receiver.receive(0), 1)
        self.assertIn("[Wall] Alice joined the chat.", output[0])
        self.alice.connect(token, "Alice")
        self.assertEqual(receiver.receive(0), 0, "A refresh must not broadcast another join.")
        self.assertEqual(len(self.bob.users()), 1)
        wire = b"".join(self.wire.requests)
        self.assertNotIn(b"Alice", wire)
        self.assertNotIn(self.key, wire)
        self.assertNotIn(b"joined the chat", wire)
        response = self.wire.raw(f"GET /v1/rooms/{room_id(self.key)}/presence HTTP/1.0\r\n\r\n".encode()).read()
        self.assertNotIn(token.encode(), response)
        self.store.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.assertNotIn(b"Alice", self.path.read_bytes())
        self.assertNotIn(token.encode(), self.path.read_bytes())
        self.alice.disconnect(token, "Alice")
        self.assertEqual(self.bob.users(), [])
        self.assertEqual(receiver.receive(0), 1)
        self.assertIn("[Wall] Alice left the chat.", output[-1])

    def test_refresh_expiry_and_rejoin_after_relay_restart(self):
        with patch("noisechat.relay.time.monotonic", return_value=100):
            self.alice.connect("a" * 64, "Alice")
            self.bob.connect("b" * 64, "Bob")
        with patch("noisechat.relay.time.monotonic", return_value=140):
            self.alice.connect("a" * 64, "Alice")
        with patch("noisechat.relay.time.monotonic", return_value=160):
            self.assertEqual([user["sender"] for user in self.bob.users()], ["Alice"])
        with patch("noisechat.relay.time.monotonic", return_value=200):
            self.assertEqual(self.bob.users(), [])
            self.alice.connect("a" * 64, "Alice")
            self.assertEqual(len(self.bob.poll(0, 0)), 3, "An expired session announces its new join.")
        self.store.close()
        self.store = RelayStore(self.path)
        self.wire.server.store = self.store
        self.assertEqual(self.bob.users(), [], "Restart must not restore stale online sessions.")
        self.alice.connect("a" * 64, "Alice")
        self.assertEqual([user["sender"] for user in self.bob.users()], ["Alice"])

    def test_same_name_sessions_and_private_departure_tokens(self):
        self.alice.connect("a" * 64, "Alice")
        self.bob.connect("b" * 64, "Alice")
        self.assertEqual(len(self.bob.users()), 2)
        self.bob.disconnect("c" * 64)
        self.assertEqual(len(self.bob.users()), 2)
        self.bob.disconnect("b" * 64)
        self.assertEqual(len(self.bob.users()), 1)
        other = self.client(generate_key())
        other.disconnect("a" * 64)
        self.assertEqual(len(self.bob.users()), 1, "A different channel cannot remove this session.")

    def test_presence_limits_and_failed_join_do_not_leave_ghost_users(self):
        with patch("noisechat.relay.MAX_PRESENCE_PER_ROOM", 1):
            self.alice.connect("a" * 64, "Alice")
            with self.assertRaises(NoiseChatError):
                self.bob.connect("b" * 64, "Bob")
            self.assertEqual([user["sender"] for user in self.bob.users()], ["Alice"])
            self.alice.connect("a" * 64, "Alice")
            self.alice.disconnect("a" * 64)
            self.bob.connect("b" * 64, "Bob")
        with patch("noisechat.relay.MAX_PRESENCE", 1):
            with self.assertRaises(NoiseChatError):
                self.client(generate_key()).connect("c" * 64, "Carol")
        self.client(generate_key()).send("Elsewhere", "fill room capacity")
        with self.assertRaises(NoiseChatError):
            self.client(generate_key()).connect("d" * 64, "Dave")
        self.assertEqual(len(self.store.presence), 1)

    def test_presence_http_validation_and_untrusted_roster_entries(self):
        room = room_id(self.key)
        post = f"POST /v1/rooms/{room}/presence HTTP/1.0\r\nContent-Type: application/json\r\n"
        for body in [{}, {"token": []}, {"token": "short"}, {"token": "a" * 64, "envelope": "plaintext"},
                     {"token": "a" * 64, "envelope": "bad", "announcement": "bad"}]:
            data = json.dumps(body).encode()
            response = self.wire.raw((post + f"Content-Length: {len(data)}\r\n\r\n").encode() + data)
            self.assertEqual(response.status, 400)
        self.assertEqual(self.wire.raw(f"GET /v1/rooms/{room}/presence?after=0 HTTP/1.0\r\n\r\n".encode()).status, 400)
        self.alice.connect("a" * 64, "Alice")
        self.store.connect(room, "b" * 64, encrypt_event(generate_key(), "Fake", "presence"),
                           encrypt_event(generate_key(), "Fake", "join"))
        self.store.connect(room, "c" * 64, encrypt_message(self.key, "Fake", "not presence"),
                           encrypt_event(self.key, "Fake", "join"))
        self.assertEqual([user["sender"] for user in self.bob.users()], ["Alice"])

    def test_users_cli_multiple_channels_and_join_users_leave(self):
        second_key = generate_key()
        other = self.client(second_key)
        self.alice.connect("a" * 64, "Alice")
        other.connect("c" * 64, "Carol")
        output = io.StringIO()
        with patch("noisechat.keys.native_backend", return_value=MemoryKeyring()):
            KeyStore().put("friends", self.key)
            KeyStore().put("same-room", self.key)
            KeyStore().put("work", second_key)
            def client_for(server, key, password):
                self.assertEqual(password, SERVER_PASSWORD)
                return self.client(key)
            with patch("noisechat.cli.Client", side_effect=client_for), contextlib.redirect_stdout(output):
                self.assertEqual(cli.main(["users", "friends", "same-room", "work", "--server", "http://relay.test"]), 0)
            lines = output.getvalue().splitlines()
            self.assertIn("USER", lines[0])
            self.assertIn("CHANNEL", lines[0])
            self.assertEqual(len(lines), 3)
            self.assertRegex(lines[1], r"Alice\s+friends$")
            self.assertRegex(lines[2], r"Carol\s+work$")
            self.assertEqual(len(self.store.presence), 2, "Listing users must not itself join a channel.")
            output = io.StringIO()
            def chat_input(prompt):
                users = self.alice.users()
                self.assertEqual([user["sender"] for user in users], ["Alice", "Bob"])
                return next(chat_input.commands)
            chat_input.commands = iter(["/users", "/quit"])
            with patch("noisechat.cli.Client", return_value=self.bob), contextlib.redirect_stdout(output), patch("builtins.input", side_effect=chat_input):
                self.assertEqual(cli.main(["join", "friends", "--server", "http://relay.test", "--name", "Bob"]), 0)
            self.assertRegex(output.getvalue(), r"Bob\s+friends")
            self.assertEqual([user["sender"] for user in self.alice.users()], ["Alice"])
            messages = [decrypt_message(self.key, record["envelope"]) for record in self.alice.poll(0, 0)]
            self.assertNotIn("/users", [message["text"] for message in messages])
            self.assertNotIn("/quit", [message["text"] for message in messages])

    def test_users_cli_key_file_empty_roster_and_failed_departure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "friends.noise-key"
            write_key_file(path, encrypt_key_file(self.key, "four random words here"))
            self.alice.connect("a" * 64, "Alice")
            output = io.StringIO()
            with patch("noisechat.cli.Client", return_value=self.bob), patch("noisechat.cli.getpass.getpass", return_value="four random words here"), contextlib.redirect_stdout(output):
                self.assertEqual(cli.main(["users", "friends", "--key-file", str(path), "--server", "http://relay.test"]), 0)
            self.assertRegex(output.getvalue(), r"Alice\s+friends")
            with contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(cli.main(["users", "friends", "work", "--key-file", str(path), "--server", "http://relay.test"]), 1)
            self.assertIn("one channel", errors.getvalue())
        presence = Presence(self.alice, "Alice", lambda text: None)
        presence.start()
        with patch.object(self.alice, "disconnect", side_effect=NoiseChatError("offline")):
            presence.close()
        self.assertFalse(presence.thread.is_alive())
        with patch("noisechat.relay.time.monotonic", return_value=time.monotonic() + 60):
            output = io.StringIO()
            with patch("noisechat.cli.load_key", return_value=self.key), patch("noisechat.cli.Client", return_value=self.bob), contextlib.redirect_stdout(output):
                self.assertEqual(cli.main(["users", "friends", "--server", "http://relay.test"]), 0)
            self.assertIn("No connected users", output.getvalue())

    def test_presence_background_refresh_and_departure_after_input_failure(self):
        output = []
        presence = Presence(self.alice, "Alice", output.append)
        with patch("noisechat.client.PRESENCE_HEARTBEAT", .01):
            presence.start()
            deadline = time.monotonic() + 1
            while len(self.wire.requests) < 2 and time.monotonic() < deadline:
                time.sleep(.005)
            presence.close()
        self.assertGreaterEqual(len(self.wire.requests), 3)
        self.assertEqual(self.bob.users(), [])
        self.assertEqual(len(self.bob.poll(0, 0)), 2, "Heartbeats must not fill message history.")
        with patch("noisechat.cli.load_key", return_value=self.key), patch("noisechat.cli.Client", return_value=self.bob), patch("builtins.input", side_effect=OSError("input failed")), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["join", "friends", "--server", "http://relay.test", "--name", "Bob"]), 1)
        self.assertEqual(self.alice.users(), [])

    def test_console_deletion_erases_one_channel_and_blocks_it_across_restarts(self):
        old_packet = encrypt_message(self.key, "Alice", "old message")
        room = room_id(self.key)
        self.store.post(room, old_packet)
        self.alice.connect("a" * 64, "Alice")
        other = self.client(generate_key())
        other.send("Bob", "different channel")
        self.assertEqual(len(self.store.channels()), 2)
        self.assertEqual(self.store.delete_channel(room), (2, 1))
        self.assertEqual(len(self.store.channels()), 1)
        self.assertEqual(self.store.connection.execute("SELECT COUNT(*) FROM messages WHERE room=?", (room,)).fetchone()[0], 0)
        for operation in [lambda: self.alice.send("Alice", "recreate"), lambda: self.alice.connect("a" * 64, "Alice"),
                          lambda: self.alice.users(), lambda: self.alice.poll(0, 0)]:
            with self.assertRaises(ChannelDeletedError):
                operation()
        self.assertEqual(decrypt_message(other.key, other.poll(0, 0)[0]["envelope"])["text"], "different channel")
        self.client(generate_key()).send("Carol", "freed capacity")
        self.assertEqual(self.store.delete_channel(room), (0, 0))
        self.store.close()
        self.store = RelayStore(self.path)
        self.wire.server.store = self.store
        with self.assertRaises(ChannelDeletedError):
            self.alice.send("Alice", "after restart")
        self.assertEqual(decrypt_message(self.key, old_packet)["text"], "old message", "Deleting a room does not erase anyone's key or captured ciphertext.")

    def test_failed_deletion_keeps_history_and_presence_intact(self):
        self.alice.connect("a" * 64, "Alice")
        room = room_id(self.key)
        self.store.connection.execute("CREATE TRIGGER prevent_delete BEFORE DELETE ON messages BEGIN SELECT RAISE(ABORT, 'storage failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.delete_channel(room)
        self.assertEqual(len(self.bob.poll(0, 0)), 1)
        self.assertEqual([user["sender"] for user in self.bob.users()], ["Alice"])
        self.assertEqual(self.store.connection.execute("SELECT COUNT(*) FROM deleted_rooms").fetchone()[0], 0)

    def test_server_console_lists_deletes_and_validates_room_id(self):
        self.alice.connect("a" * 64, "Alice")
        room = room_id(self.key)
        stopped = []
        server = SimpleNamespace(shutdown=lambda: stopped.append(True))
        output = io.StringIO()
        commands = ["help", "channels", "delete-channel friends", "delete-channel", "unknown", f"delete-channel {room}", "channels", "quit"]
        with patch("builtins.input", side_effect=commands), contextlib.redirect_stdout(output):
            console(self.store, server)
        text = output.getvalue()
        self.assertIn(room, text)
        self.assertNotIn("Alice", text)
        self.assertIn("64-character room ID", text)
        self.assertIn("1 packets removed, 1 sessions removed", text)
        self.assertIn("No active channels", text)
        self.assertEqual(stopped, [True])
        with self.assertRaises(ChannelDeletedError):
            self.bob.poll(0, 0)

    def test_remote_requests_and_client_cli_cannot_delete_channels(self):
        self.alice.send("Alice", "keep me")
        room = room_id(self.key)
        for path in ["/channels", "/delete-channel", f"/v1/rooms/{room}/delete-channel"]:
            self.assertEqual(self.wire.raw(f"GET {path} HTTP/1.0\r\n\r\n".encode()).status, 404)
            data = json.dumps({"room": room}).encode()
            raw = (f"POST {path} HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: {len(data)}\r\n\r\n").encode() + data
            self.assertEqual(self.wire.raw(raw).status, 404)
        self.assertEqual(self.wire.raw(f"DELETE /v1/rooms/{room}/messages HTTP/1.0\r\n\r\n".encode()).status, 501)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.main(["delete-channel", room])
        self.assertEqual(len(self.bob.poll(0, 0)), 1)

    def test_deletion_wakes_waiting_clients_and_stops_receiver_and_presence(self):
        stop = threading.Event()
        output = []
        presence = Presence(self.alice, "Alice", output.append, stop)
        presence.start()
        receiver = Receiver(self.bob, output.append)
        receiver.receive(0)
        thread = threading.Thread(target=receiver.listen, args=(stop,))
        thread.start()
        try:
            time.sleep(.02)
            self.store.delete_channel(room_id(self.key))
            thread.join(timeout=1)
            self.assertFalse(thread.is_alive(), "Deletion should wake the long poll rather than wait for timeout.")
            self.assertTrue(stop.is_set())
            self.assertIn("Channel deleted", "\n".join(output))
            self.assertNotIn("Retrying", "\n".join(output))
        finally:
            stop.set()
            presence.close()
            thread.join(timeout=1)
        self.assertFalse(presence.thread.is_alive())
        self.assertEqual(self.store.presence, {})

    def test_join_automatically_displays_retained_history_across_batches(self):
        self.store.history_per_room = 500
        self.store.max_messages = 1000
        for number in range(125):
            self.alice.send("Alice", f"history{number:03}")
        output = io.StringIO()
        def wait_for_history(prompt):
            deadline = time.monotonic() + 2
            while "history124" not in output.getvalue() and time.monotonic() < deadline:
                time.sleep(.005)
            return "/quit"
        with patch("noisechat.cli.load_key", return_value=self.key), patch("noisechat.cli.Client", return_value=self.bob), patch("builtins.input", side_effect=wait_for_history), contextlib.redirect_stdout(output):
            self.assertEqual(cli.main(["join", "friends", "--server", "http://relay.test", "--name", "Bob"]), 0)
        history = [line.split("Alice: ", 1)[1] for line in output.getvalue().splitlines() if "Alice: history" in line]
        self.assertEqual(history, [f"history{number:03}" for number in range(125)])

    def test_cli_send_listen_and_live_join_use_the_same_encrypted_transport(self):
        output=io.StringIO()
        with patch("noisechat.keys.native_backend",return_value=MemoryKeyring()):
            KeyStore().put("friends",self.key)
            with patch("noisechat.cli.Client",return_value=self.alice),contextlib.redirect_stdout(output),patch("builtins.input",return_value="from CLI send"):
                self.assertEqual(cli.main(["send","friends","--server","http://relay.test","--name","Alice"]),0)
            with patch("noisechat.cli.Client",return_value=self.bob),contextlib.redirect_stdout(output):
                self.assertEqual(cli.main(["listen","friends","--server","http://relay.test","--once"]),0)
            self.assertIn("Alice: from CLI send",output.getvalue())
            def chat_input(prompt):
                if "Bob: live chat works" not in output.getvalue():
                    if chat_input.sent:
                        deadline=time.monotonic()+1
                        while "Bob: live chat works" not in output.getvalue() and time.monotonic()<deadline:time.sleep(.01)
                        return "/quit"
                    chat_input.sent=True
                    return "live chat works"
                return "/quit"
            chat_input.sent=False
            with patch("noisechat.cli.Client",return_value=self.bob),contextlib.redirect_stdout(output),patch("builtins.input",side_effect=chat_input):
                self.assertEqual(cli.main(["join","friends","--server","http://relay.test","--name","Bob"]),0)
            self.assertIn("Bob: live chat works",output.getvalue())
        self.assertNotIn(b"live chat works",b"".join(self.wire.requests))

    def test_history_retention_duplicates_and_restart(self):
        envelope = encrypt_message(self.key,"Alice","one")
        first = self.store.post(room_id(self.key),envelope)
        self.assertEqual(self.store.post(room_id(self.key),envelope), first)
        for number in range(6):
            self.alice.send("Alice", str(number))
        self.assertEqual(len(self.bob.poll(0,0)),3)
        second_key = generate_key()
        for number in range(3):
            self.client(second_key).send("Bob",str(number))
        self.assertEqual(self.store.connection.execute("SELECT COUNT(*) FROM messages").fetchone()[0],5)
        with self.assertRaises(NoiseChatError):
            self.client(generate_key()).send("Unknown","too many rooms")
        self.store.close()
        self.store = RelayStore(self.path)
        self.wire.server.store = self.store
        self.assertTrue(self.bob.poll(0,0))

    def test_long_poll_wakes_for_new_ciphertext(self):
        result=[]
        thread=threading.Thread(target=lambda:result.extend(self.store.poll(room_id(self.key),0,2)))
        thread.start()
        time.sleep(.02)
        self.alice.send("Alice","wake up")
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(result),1)

    def test_replays_and_bad_packets_do_not_block_good_messages(self):
        envelope=encrypt_message(self.key,"Alice","original")
        packet=bytearray(b64decode(envelope));packet[-1]^=1
        self.store.post(room_id(self.key),b64encode(packet))
        self.store.post(room_id(self.key),envelope)
        output=[]
        receiver=Receiver(self.bob,output.append)
        self.assertEqual(receiver.receive(0),1)
        self.assertIn("could not be authenticated",output[0])
        # A malicious relay may replay a valid ciphertext under a fresh sequence.
        fake=SimpleNamespace(key=self.key,poll=lambda after,wait:[dict(sequence=after+1,envelope=envelope)])
        receiver.client=fake
        self.assertEqual(receiver.receive(0),0)

    def test_http_validation_and_health(self):
        health=self.wire.raw(b"GET /health HTTP/1.0\r\n\r\n")
        self.assertEqual(health.status,200)
        self.assertTrue(json.loads(health.read())["ok"])
        room=room_id(self.key)
        for target in [f"/v1/rooms/{room}/messages?after=-1",f"/v1/rooms/{room}/messages?wait=21",f"/v1/rooms/{room}/messages?after=0&after=1"]:
            self.assertEqual(self.wire.raw(f"GET {target} HTTP/1.0\r\n\r\n".encode()).status,400)
        post=f"POST /v1/rooms/{room}/messages HTTP/1.0\r\nContent-Type: application/json\r\n"
        self.assertEqual(self.wire.raw((post+"Content-Length: 17000\r\n\r\n").encode()).status,413)
        for body in [b'{"text":"plaintext"}',b'[]',b'{"envelope":null}',b'not json']:
            self.assertEqual(self.wire.raw((post+f"Content-Length: {len(body)}\r\n\r\n").encode()+body).status,400)
        self.assertEqual(self.wire.raw((post+"Transfer-Encoding: chunked\r\n\r\n").encode()).status,400)

    def test_native_loopback_when_host_allows_sockets(self):
        try:
            server=RelayServer(("127.0.0.1",0),self.store,SERVER_VERIFIER)
        except PermissionError:
            self.skipTest("This execution sandbox prohibits network sockets; HTTP serialization is covered in process.")
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            alice=Client(f"http://127.0.0.1:{server.server_port}",self.key,SERVER_PASSWORD)
            bob=Client(f"http://127.0.0.1:{server.server_port}",self.key,SERVER_PASSWORD)
            alice.send("Alice","network test")
            self.assertEqual(decrypt_message(self.key,bob.poll(0,0)[0]["envelope"])["text"],"network test")
        finally:
            server.shutdown();server.server_close();thread.join(timeout=2)


class AccessTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name)
        self.store = RelayStore(self.path / "relay.sqlite3")
        self.wire = InProcessHTTP(self.store)
        self.key = generate_key()
        self.room = room_id(self.key)

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    def client(self, password=SERVER_PASSWORD):
        client = Client("http://relay.test", self.key, password)
        client.opener = self.wire
        return client

    def login(self, password, address="127.0.0.1", extra_headers=""):
        body = json.dumps({"password": password}).encode()
        request = ("POST /v1/auth/login HTTP/1.0\r\nContent-Type: application/json\r\n"
                   f"Content-Length: {len(body)}\r\n{extra_headers}\r\n").encode() + body
        return self.wire.raw(request, authenticated=False, address=address)

    def test_password_and_session_gate_all_channel_operations(self):
        envelope = encrypt_message(self.key, "Alice", "private history")
        self.store.post(self.room, envelope)
        for resource in ("messages", "presence"):
            for method in ("GET", "POST"):
                with self.subTest(method=method, resource=resource):
                    response = self.wire.raw(f"{method} /v1/rooms/{self.room}/{resource} HTTP/1.0\r\n\r\n".encode(), authenticated=False)
                    self.assertEqual(response.status, 401)
                    self.assertNotIn(envelope.encode(), response.read())
        self.assertEqual(len(self.store.poll(self.room, 0)), 1)
        self.assertEqual(self.store.presence, {})
        other = room_id(generate_key())
        response = self.wire.raw(f"POST /v1/rooms/{other}/messages HTTP/1.0\r\n\r\n".encode(), authenticated=False)
        self.assertEqual(response.status, 401)
        self.assertEqual(len(self.store.channels()), 1)
        self.assertEqual(self.wire.raw(b"GET /health HTTP/1.0\r\n\r\n", authenticated=False).status, 200)
        with self.assertRaisesRegex(ServerAccessError, "Incorrect server password"):
            self.client("wrong password words").poll(0, 0)
        alice, bob = self.client(), self.client()
        alice.connect("a" * 64, "Alice")
        alice.send("Alice", "authenticated message")
        self.assertEqual([user["sender"] for user in bob.users()], ["Alice"])
        self.assertEqual(decrypt_message(self.key, bob.poll(0, 0)[-1]["envelope"])["text"], "authenticated message")
        alice.disconnect("a" * 64)
        self.assertEqual(bob.users(), [])
        self.assertNotIn(SERVER_PASSWORD.encode(), self.store.connection.execute("SELECT envelope FROM messages").fetchone()[0].encode())

    def test_login_cooldown_has_retry_after_and_does_not_extend_on_retries(self):
        with patch("noisechat.auth.time.monotonic", return_value=100):
            for _ in range(5):
                self.assertEqual(self.login("incorrect password words").status, 401)
            response = self.login(SERVER_PASSWORD, extra_headers="X-Forwarded-For: 192.0.2.1\r\n")
            self.assertEqual(response.status, 429)
            self.assertEqual(response.headers["Retry-After"], "60")
            self.assertEqual(json.loads(response.read())["retry_after"], 60)
            self.assertEqual(self.login(SERVER_PASSWORD, address="192.0.2.2").status, 200)
        with patch("noisechat.auth.time.monotonic", return_value=159.1):
            response = self.login(SERVER_PASSWORD)
            self.assertEqual(response.status, 429)
            self.assertEqual(response.headers["Retry-After"], "1")
        with patch("noisechat.auth.time.monotonic", return_value=160):
            self.assertEqual(self.login(SERVER_PASSWORD).status, 200)

    def test_malformed_logins_count_toward_cooldown(self):
        request = b"POST /v1/auth/login HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
        for _ in range(5):
            self.assertEqual(self.wire.raw(request, authenticated=False).status, 400)
        self.assertEqual(self.login(SERVER_PASSWORD).status, 429)
        self.assertEqual(len(self.wire.server.access.sessions), 1)

    def test_sessions_are_hashed_bounded_expire_and_require_a_single_header(self):
        access = RelayAccess(SERVER_VERIFIER)
        with patch("noisechat.auth.time.monotonic", return_value=100):
            token = access.login(SERVER_PASSWORD)
            self.assertTrue(access.authorized(["Bearer " + token]))
            self.assertNotIn(token, access.sessions)
            for headers in ([], ["Bearer " + "a" * 64], ["Basic abc"], ["Bearer " + token] * 2):
                self.assertFalse(access.authorized(headers))
            with patch("noisechat.auth.MAX_SESSIONS", 1), self.assertRaisesRegex(NoiseChatError, "session capacity"):
                access.login(SERVER_PASSWORD)
        with patch("noisechat.auth.time.monotonic", return_value=100 + SESSION_SECONDS):
            self.assertFalse(access.authorized(["Bearer " + token]))
            self.assertEqual(access.sessions, {})
        for address in range(1100):
            access.login_attempt(str(address))
        self.assertLessEqual(len(access.attempts), 1024)

    def test_client_reauthenticates_after_restart_and_stops_after_password_change(self):
        client = self.client()
        client.send("Alice", "before restart")
        old_token = client.token
        self.wire.server.access = RelayAccess(SERVER_VERIFIER)
        self.assertEqual(len(client.poll(0, 0)), 1)
        self.assertNotEqual(client.token, old_token)
        changed = PasswordVerifier.create("different server password words")
        self.wire.server.access = RelayAccess(changed)
        with self.assertRaisesRegex(ServerAccessError, "Incorrect server password"):
            client.poll(0, 0)
        stop, output = threading.Event(), []
        Receiver(client, output.append).listen(stop)
        self.assertTrue(stop.is_set())
        self.assertNotIn("Retrying", " ".join(output))
        stop, output = threading.Event(), []
        presence = Presence(client, "Alice", output.append, stop)
        with patch("noisechat.client.PRESENCE_HEARTBEAT", 0):
            presence.maintain()
        self.assertTrue(stop.is_set())
        self.assertNotIn("Retrying", " ".join(output))

    def test_client_reports_cooldown_without_repeated_background_attempts(self):
        for _ in range(5):
            self.login("incorrect password words")
        client = self.client()
        with self.assertRaisesRegex(ServerAccessError, "Try again in .* seconds"):
            client.poll(0, 0)
        self.assertEqual(len(self.wire.requests), 1)

    def test_client_reuses_login_and_never_forwards_credentials_on_redirect(self):
        client = self.client()
        client.poll(0, 0)
        client.users()
        self.assertEqual(sum(b"/v1/auth/login " in request for request in self.wire.requests), 1)
        room_requests = [request for request in self.wire.requests if b"/v1/rooms/" in request]
        self.assertTrue(all(b"Authorization: Bearer " in request for request in room_requests))
        self.assertTrue(all(SERVER_PASSWORD.encode() not in request for request in room_requests))
        from noisechat.client import NoRedirects
        self.assertIsNone(NoRedirects().redirect_request(None, None, 302, "", {}, "https://other.test"))

    def test_first_run_password_is_hashed_and_restart_does_not_prompt(self):
        auth_file = self.path / "relay.sqlite3.auth.json"
        args = ["run", "--database", str(self.path / "relay.sqlite3")]
        with patch("noisechat.relay.serve") as serve, patch("noisechat.cli.getpass.getpass", return_value=SERVER_PASSWORD) as prompt, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(args), 0)
            self.assertEqual(prompt.call_count, 2)
            self.assertEqual(prompt.call_args_list[0].args, ("Enter a server password (12+ characters): ",))
            self.assertTrue(serve.call_args.args[-1].verify(SERVER_PASSWORD))
            prompt.reset_mock()
            self.assertEqual(cli.main(args), 0)
            prompt.assert_not_called()
        data = auth_file.read_bytes()
        self.assertNotIn(SERVER_PASSWORD.encode(), data)
        self.assertEqual(json.loads(data)["iterations"], 600000)
        if os.name != "nt":
            self.assertEqual(auth_file.stat().st_mode & 0o777, 0o600)

    def test_local_password_reset_and_failed_reset_preserve_previous_verifier(self):
        auth_file = self.path / "relay.sqlite3.auth.json"
        SERVER_VERIFIER.save(auth_file)
        args = cli.parser().parse_args(["run", "--database", str(self.path / "relay.sqlite3"), "--reset-password"])
        with patch("noisechat.cli.getpass.getpass", return_value="new server password words"), contextlib.redirect_stdout(io.StringIO()):
            changed = cli.server_verifier(args)
        self.assertTrue(changed.verify("new server password words"))
        self.assertFalse(PasswordVerifier.load(auth_file).verify(SERVER_PASSWORD))
        before = auth_file.read_bytes()
        with patch("noisechat.auth.os.replace", side_effect=OSError("interrupted")), self.assertRaises(OSError):
            SERVER_VERIFIER.save(auth_file, replace=True)
        self.assertEqual(auth_file.read_bytes(), before)
        self.assertEqual(list(self.path.glob(".noisechat-auth-*")), [])

    def test_private_password_files_support_server_setup_and_all_client_commands(self):
        password_file = self.path / "server.noise-password"
        password_file.write_bytes(SERVER_PASSWORD.encode() + b"\r\n")
        password_file.chmod(0o600)
        args = cli.parser().parse_args(["run", "--database", str(self.path / "relay.sqlite3"), "--password-file", str(password_file)])
        with patch("noisechat.cli.getpass.getpass", side_effect=AssertionError("No hidden prompt needed")), contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(cli.server_verifier(args).verify(SERVER_PASSWORD))
            self.assertEqual(cli.read_server_password(args), SERVER_PASSWORD)
        for command in (["join", "friends", "--name", "Alice"], ["send", "friends", "--name", "Alice"], ["listen", "friends"], ["users", "friends"]):
            parsed = cli.parser().parse_args(command + ["--server", "http://relay.test", "--password-file", str(password_file)])
            self.assertEqual(cli.read_server_password(parsed), SERVER_PASSWORD)
        if os.name != "nt":
            password_file.chmod(0o644)
            with self.assertRaisesRegex(NoiseChatError, "only to its owner"):
                cli.read_server_password(args)
            password_file.chmod(0o600)
        for data in (b"", b"two\nlines", b"x" * 1027, b"\xff"):
            password_file.write_bytes(data)
            with self.assertRaises(NoiseChatError):
                cli.read_server_password(args)

    def test_cli_password_file_send_listen_join_and_users_use_real_authentication(self):
        password_file = self.path / "server.noise-password"
        password_file.write_text(SERVER_PASSWORD)
        password_file.chmod(0o600)
        def make_client(server, key, password):
            client = Client(server, key, password)
            client.opener = self.wire
            return client
        common = ["--server", "http://relay.test", "--password-file", str(password_file)]
        output = io.StringIO()
        with patch("noisechat.cli.load_key", return_value=self.key), patch("noisechat.cli.Client", side_effect=make_client), patch("noisechat.cli.getpass.getpass", side_effect=AssertionError("Password file should avoid prompts")), contextlib.redirect_stdout(output):
            with patch("noisechat.cli.sys.stdin", io.TextIOWrapper(io.BytesIO(b"piped message\n"))):
                self.assertEqual(cli.main(["send", "friends", "--name", "Alice", "--stdin"] + common), 0)
            self.assertEqual(cli.main(["listen", "friends", "--once"] + common), 0)
            self.assertIn("Alice: piped message", output.getvalue())
            with patch("builtins.input", return_value="/quit"):
                self.assertEqual(cli.main(["join", "friends", "--name", "Alice"] + common), 0)
            self.assertEqual(cli.main(["users", "friends"] + common), 0)
        self.assertEqual(self.store.presence, {})

    def test_multi_channel_users_uses_one_login_for_more_than_five_channels(self):
        keys = {f"channel{i}": generate_key() for i in range(8)}
        def make_client(server, key, password):
            client = Client(server, key, password)
            client.opener = self.wire
            return client
        with patch("noisechat.cli.load_key", side_effect=lambda args: keys[args.chat]), patch("noisechat.cli.Client", side_effect=make_client), patch("noisechat.cli.getpass.getpass", return_value=SERVER_PASSWORD) as prompt, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["users", *keys, "--server", "http://relay.test"]), 0)
            prompt.assert_called_once()
        self.assertEqual(sum(b"/v1/auth/login " in request for request in self.wire.requests), 1)

    def test_cli_wrong_password_fails_before_reading_or_sending_message_text(self):
        client = self.client("incorrect password words")
        with patch("noisechat.cli.load_key", return_value=self.key), patch("noisechat.cli.Client", return_value=client), patch("noisechat.cli.getpass.getpass", return_value="incorrect password words"), patch("noisechat.cli.read_text", side_effect=AssertionError("Do not read text after failed login")), contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(cli.main(["send", "friends", "--server", "http://relay.test", "--name", "Alice"]), 1)
        self.assertIn("Incorrect server password", errors.getvalue())
        self.assertEqual(self.store.channels(), [])

    def test_invalid_setup_does_not_start_relay_or_replace_authentication(self):
        args = ["run", "--database", str(self.path / "relay.sqlite3")]
        for replies in (["short", "short"], [SERVER_PASSWORD, "mismatch"]):
            with patch("noisechat.cli.getpass.getpass", side_effect=replies), patch("noisechat.relay.serve") as serve, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(args), 1)
                serve.assert_not_called()
        auth_file = self.path / "relay.sqlite3.auth.json"
        auth_file.write_text('{"unexpected":"data"}')
        with patch("noisechat.cli.getpass.getpass", side_effect=AssertionError("Do not silently reset")), patch("noisechat.relay.serve") as serve, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(args), 1)
            serve.assert_not_called()


class CloudflareTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = RelayStore(Path(self.directory.name) / "relay.sqlite3")
        self.wire = InProcessHTTP(self.store)
        self.wire.server.cloudflare_tunnel = True
        self.key = generate_key()
        self.room = room_id(self.key)

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    def request(self, target, method="GET", body=None, visitor="192.0.2.1", peer="127.0.0.1", extra_headers=""):
        headers = extra_headers
        if visitor is not None:
            headers += f"CF-Connecting-IP: {visitor}\r\n"
        data = b"" if body is None else json.dumps(body).encode()
        if body is not None:
            headers += f"Content-Type: application/json\r\nContent-Length: {len(data)}\r\n"
        raw = (f"{method} {target} HTTP/1.0\r\n{headers}\r\n").encode() + data
        return self.wire.raw(raw, address=peer)

    def login(self, visitor="192.0.2.1", password="incorrect password words", peer="127.0.0.1", extra_headers=""):
        return self.request("/v1/auth/login", "POST", {"password": password}, visitor, peer, extra_headers)

    def test_tunnel_visitors_get_separate_login_cooldowns_and_expiry(self):
        with patch("noisechat.auth.time.monotonic", return_value=100):
            for _ in range(5):
                self.assertEqual(self.login().status, 401)
            response = self.login(password=SERVER_PASSWORD)
            self.assertEqual(response.status, 429)
            self.assertEqual(response.headers["Retry-After"], "60")
            self.assertEqual(self.login(visitor="192.0.2.2", password=SERVER_PASSWORD).status, 200)
            self.assertNotIn("127.0.0.1", self.wire.server.access.attempts)
            self.assertEqual(self.request(f"/v1/rooms/{self.room}/messages?wait=0").status, 200)
        with patch("noisechat.auth.time.monotonic", return_value=160):
            self.assertEqual(self.login(password=SERVER_PASSWORD).status, 200)

    def test_ipv6_and_mapped_ipv4_cannot_split_cooldown_with_alternate_spellings(self):
        with patch("noisechat.auth.time.monotonic", return_value=100):
            for index in range(5):
                address = "2001:db8::1" if index % 2 else "2001:0db8:0000:0000:0000:0000:0000:0001"
                self.assertEqual(self.login(visitor=address, peer="::1").status, 401)
            self.assertEqual(self.login(visitor="2001:db8:0::1", peer="::ffff:127.0.0.1").status, 429)
            self.assertEqual(self.login(visitor="2001:db8::2", password=SERVER_PASSWORD, peer="::1").status, 200)
            for _ in range(5):
                self.assertEqual(self.login(visitor="192.0.2.1").status, 401)
            self.assertEqual(self.login(visitor="::ffff:c000:201").status, 429)

    def test_tunnel_rejects_missing_invalid_duplicate_or_untrusted_headers(self):
        invalid = [None, "", "not-an-ip", "192.0.2.1, 192.0.2.2", "192.0.2.1:1234",
                   "[2001:db8::1]", "fe80::1%eth0", "x" * 100, "192.000.002.001"]
        for visitor in invalid:
            with self.subTest(visitor=visitor):
                self.assertEqual(self.login(visitor=visitor).status, 403)
                self.assertEqual(self.request(f"/v1/rooms/{self.room}/messages", visitor=visitor).status, 403)
        self.assertEqual(self.login(extra_headers="CF-Connecting-IP: 192.0.2.2\r\n").status, 403)
        self.assertEqual(self.login(peer="192.168.1.20").status, 403)
        self.assertEqual(self.wire.server.access.attempts, {})
        self.assertEqual(self.store.channels(), [])
        # Health checks do not need a visitor identity or consume a login attempt.
        self.assertEqual(self.request("/health", visitor=None).status, 200)

    def test_direct_mode_ignores_cloudflare_and_other_forwarded_headers(self):
        self.wire.server.cloudflare_tunnel = False
        with patch("noisechat.auth.time.monotonic", return_value=100):
            for index in range(5):
                self.assertEqual(self.login(visitor=f"192.0.2.{index + 1}", extra_headers="X-Forwarded-For: 198.51.100.1\r\n").status, 401)
            self.assertEqual(self.login(visitor="192.0.2.99", password=SERVER_PASSWORD).status, 429)
            self.assertEqual(self.login(visitor=None, peer="192.0.2.3", password=SERVER_PASSWORD).status, 200)
        self.assertEqual(set(self.wire.server.access.attempts), {"127.0.0.1", "192.0.2.3"})

    def test_tunnel_message_and_presence_limits_use_visitor_ip(self):
        server = self.wire.server
        server.rate_lock, server.rates = threading.Lock(), OrderedDict()
        server.allow_post = lambda address: RelayServer.allow_post(server, address)
        envelope = encrypt_message(self.key, "Alice", "rate-limited message")
        target = f"/v1/rooms/{self.room}/messages"
        with patch("noisechat.relay.time.monotonic", return_value=100):
            for _ in range(30):
                self.assertEqual(self.request(target, "POST", {"envelope": envelope}).status, 201)
            self.assertEqual(self.request(target, "POST", {"envelope": envelope}).status, 429)
            body = {"token": "a" * 64, "envelope": encrypt_event(self.key, "Alice", "presence"),
                    "announcement": encrypt_event(self.key, "Alice", "join")}
            self.assertEqual(self.request(f"/v1/rooms/{self.room}/presence", "POST", body).status, 429)
            self.assertEqual(self.request(f"/v1/rooms/{self.room}/presence", "POST", body, visitor="192.0.2.2").status, 200)
            self.assertEqual(self.request(target, "POST", {"envelope": envelope}, visitor="192.0.2.2").status, 201)
            self.assertEqual(set(server.rates), {"192.0.2.1", "192.0.2.2"})
        with patch("noisechat.relay.time.monotonic", return_value=101):
            self.assertEqual(self.request(target, "POST", {"envelope": envelope}).status, 201)

    def test_tunnel_cli_accepts_only_loopback_before_password_setup(self):
        with patch("noisechat.cli.server_verifier", return_value=SERVER_VERIFIER) as verifier, patch("noisechat.relay.serve") as serve:
            for url, expected_host in (("http://127.0.0.1:8713", "127.0.0.1"), ("http://localhost:8713", "127.0.0.1"), ("http://[::1]:8713", "::1")):
                self.assertEqual(cli.main(["run", "--urls", url, "--cloudflare-tunnel"]), 0)
                serve.assert_called_with(expected_host, 8713, Path("relay.sqlite3"), SERVER_VERIFIER, cloudflare_tunnel=True)
            verifier.reset_mock()
            serve.reset_mock()
            for host in ("0.0.0.0", "192.168.1.20", "[::]", "[fe80::1%eth0]", "example.com"):
                with self.subTest(host=host), contextlib.redirect_stderr(io.StringIO()) as errors:
                    self.assertEqual(cli.main(["run", "--urls", f"http://{host}:8713", "--cloudflare-tunnel"]), 1)
                    self.assertIn("loopback", errors.getvalue())
            verifier.assert_not_called()
            serve.assert_not_called()

    def test_server_enforces_tunnel_bind_restriction_without_cli(self):
        for host in ("0.0.0.0", "192.168.1.20", "::", "example.com"):
            with self.subTest(host=host), patch("noisechat.relay.ThreadingHTTPServer.__init__") as bind:
                with self.assertRaisesRegex(NoiseChatError, "loopback"):
                    RelayServer((host, 8713), self.store, SERVER_VERIFIER, cloudflare_tunnel=True)
                bind.assert_not_called()
        with patch("noisechat.relay.ThreadingHTTPServer.__init__") as bind:
            server = RelayServer(("localhost", 8713), self.store, SERVER_VERIFIER, cloudflare_tunnel=True)
            bind.assert_called_once_with(("127.0.0.1", 8713), RelayHandler)
            self.assertTrue(server.cloudflare_tunnel)


class RunTests(unittest.TestCase):
    def test_relay_console_runs_only_with_an_attached_terminal(self):
        for interactive in [True, False]:
            with self.subTest(interactive=interactive), tempfile.TemporaryDirectory() as directory:
                stopped = threading.Event()
                server = SimpleNamespace(server_port=8713, shutdown=stopped.set, server_close=lambda: None,
                                         serve_forever=lambda: stopped.wait(1) if interactive else None)
                output = io.StringIO()
                with patch("noisechat.cli.server_verifier", return_value=SERVER_VERIFIER), patch("noisechat.relay.RelayServer", return_value=server), patch("noisechat.relay.sys.stdin.isatty", return_value=interactive), patch("builtins.input", side_effect=["help", "quit"]) as console_input, contextlib.redirect_stdout(output):
                    self.assertEqual(cli.main(["run", "--database", str(Path(directory) / "relay.sqlite3")]), 0)
                if interactive:
                    self.assertTrue(stopped.is_set())
                    self.assertEqual(console_input.call_count, 2)
                    self.assertIn("delete-channel ROOM_ID", output.getvalue())
                else:
                    console_input.assert_not_called()
                    self.assertNotIn("Server console", output.getvalue())

    def test_default_and_custom_listen_urls_start_relay_without_client_keys(self):
        with patch("noisechat.cli.server_verifier", return_value=SERVER_VERIFIER), patch("noisechat.relay.serve") as serve, patch("noisechat.cli.KeyStore", side_effect=AssertionError("A relay must not load client keys")):
            self.assertEqual(cli.main(["run"]), 0)
            serve.assert_called_with("127.0.0.1", 8713, Path("relay.sqlite3"), SERVER_VERIFIER, cloudflare_tunnel=False)
            self.assertEqual(cli.main(["run", "--urls", "http://0.0.0.0:9000", "--database", "custom.sqlite3"]), 0)
            serve.assert_called_with("0.0.0.0", 9000, Path("custom.sqlite3"), SERVER_VERIFIER, cloudflare_tunnel=False)
            self.assertEqual(cli.main(["run", "--urls", "http://localhost:0/"]), 0)
            serve.assert_called_with("localhost", 0, Path("relay.sqlite3"), SERVER_VERIFIER, cloudflare_tunnel=False)
            self.assertEqual(cli.main(["run", "--urls", "http://[::1]:8713"]), 0)
            serve.assert_called_with("::1", 8713, Path("relay.sqlite3"), SERVER_VERIFIER, cloudflare_tunnel=False)

    def test_invalid_listen_urls_do_not_start_server(self):
        invalid = ["", "localhost:8713", "http://localhost", "https://localhost:8713",
                   "http://localhost:-1", "http://localhost:65536", "http://localhost:abc",
                   "http://user:secret@localhost:8713", "http://localhost:8713/api",
                   "http://localhost:8713?x=1", "http://localhost:8713#fragment",
                   "http://localhost:8713 http://localhost:9000", "http://[::1:8713"]
        with patch("noisechat.relay.serve") as serve:
            for url in invalid:
                with self.subTest(url=url), contextlib.redirect_stderr(io.StringIO()) as errors:
                    self.assertEqual(cli.main(["run", "--urls", url]), 1)
                self.assertIn("HTTP listen URL", errors.getvalue())
            serve.assert_not_called()


class ClientTests(unittest.TestCase):
    def test_roster_validation_replay_suppression_and_terminal_escaping(self):
        key = generate_key()
        client = Client("http://relay.test", key)
        valid = encrypt_event(key, "Alice\x1b[2J", "presence")
        wrong_key = encrypt_event(generate_key(), "Fake", "presence")
        with patch.object(client, "request", return_value={"users": [valid, valid, wrong_key, "bad"]}):
            self.assertEqual(len(client.users()), 1)
            output = []
            cli.print_users([("friends", client)], output.append)
        self.assertNotIn("\x1b", "\n".join(output))
        self.assertIn("\\u001b", "\n".join(output))
        for value in [{"users": False}, {"users": [None]}, {"users": [valid] * 101}, {"users": ["a" * 11001]}]:
            with patch.object(client, "request", return_value=value), self.assertRaises(NoiseChatError):
                client.users()

    def test_transport_errors_are_reported_without_response_content(self):
        client=Client("http://relay.test",generate_key(),SERVER_PASSWORD)
        with patch.object(client.opener,"open",side_effect=http.client.BadStatusLine("untrusted response text")):
            with self.assertRaisesRegex(NoiseChatError,"Could not reach the relay") as caught:
                client.poll(0,0)
        self.assertNotIn("untrusted",str(caught.exception))

    def test_post_rate_limit_and_bounded_ip_cache(self):
        server=RelayServer.__new__(RelayServer)
        server.rate_lock=threading.Lock()
        server.rates=OrderedDict()
        with patch("noisechat.relay.time.monotonic",return_value=100):
            for _ in range(30):self.assertTrue(server.allow_post("one-client"))
            self.assertFalse(server.allow_post("one-client"))
            for ip in range(1100):server.allow_post(str(ip))
            self.assertLessEqual(len(server.rates),1024)
        with patch("noisechat.relay.time.monotonic",return_value=131):
            self.assertTrue(server.allow_post("one-client"))

    def test_terminal_escape_injection_is_rendered_inert(self):
        rendered=terminal_text("hello\x1b[2J\r\u202eworld")
        self.assertNotIn("\x1b",rendered)
        self.assertNotIn("\r",rendered)
        self.assertNotIn("\u202e",rendered)
        self.assertIn("\\u001b",rendered)

    def test_bad_urls_and_untrusted_response_metadata(self):
        key=generate_key()
        for url in ["ftp://relay.test","http://user:pass@relay.test","http://relay.test/a", "http://relay.test?x=y", "http://relay.test:0"]:
            with self.assertRaises(NoiseChatError):Client(url,key)
        client=Client("http://relay.test",key)
        for value in [{"messages":False},{"messages":[{"sequence":True,"envelope":"x"}]}, {"messages":[{"sequence":2,"envelope":"x"},{"sequence":1,"envelope":"x"}]}]:
            with patch.object(client,"request",return_value=value):
                with self.assertRaises(NoiseChatError):client.poll(0,0)


if __name__ == "__main__":
    unittest.main()
