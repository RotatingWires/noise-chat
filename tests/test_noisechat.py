import contextlib
import http.client
import io
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import urlsplit

from noisechat import cli
from noisechat.client import Client, Presence, Receiver, terminal_text
from noisechat.crypto import (NoiseChatError, b64decode, b64encode, decrypt_key_file,
                              decrypt_message, encrypt_event, encrypt_key_file, encrypt_message, generate_key, room_id)
from noisechat.keys import KeyStore, native_backend, read_key_file, write_key_file
from noisechat.relay import RelayHandler, RelayStore, RelayServer


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
        self.server = SimpleNamespace(store=store, allow_post=lambda address: True)
        self.requests = []

    def raw(self, data):
        socket = WireSocket(data)
        RelayHandler(socket, ("127.0.0.1", 12345), self.server)
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
        response = self.raw(raw)
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

    def client(self, key):
        client = Client("http://relay.test", key)
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
        self.alice.disconnect(token)
        self.assertEqual(self.bob.users(), [])
        self.assertEqual(receiver.receive(0), 0)

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

    def test_users_cli_multiple_channels_and_chat_users_leave(self):
        second_key = generate_key()
        other = self.client(second_key)
        self.alice.connect("a" * 64, "Alice")
        other.connect("c" * 64, "Carol")
        output = io.StringIO()
        with patch("noisechat.keys.native_backend", return_value=MemoryKeyring()):
            KeyStore().put("friends", self.key)
            KeyStore().put("same-room", self.key)
            KeyStore().put("work", second_key)
            def client_for(server, key):
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
                self.assertEqual(cli.main(["chat", "friends", "--server", "http://relay.test", "--name", "Bob"]), 0)
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
        self.assertEqual(len(self.bob.poll(0, 0)), 1, "Heartbeats must not fill message history.")
        with patch("noisechat.cli.load_key", return_value=self.key), patch("noisechat.cli.Client", return_value=self.bob), patch("builtins.input", side_effect=OSError("input failed")), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["chat", "friends", "--server", "http://relay.test", "--name", "Bob"]), 1)
        self.assertEqual(self.alice.users(), [])

    def test_cli_send_listen_and_live_chat_use_the_same_encrypted_transport(self):
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
                self.assertEqual(cli.main(["chat","friends","--server","http://relay.test","--name","Bob"]),0)
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
            server=RelayServer(("127.0.0.1",0),self.store)
        except PermissionError:
            self.skipTest("This execution sandbox prohibits network sockets; HTTP serialization is covered in process.")
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            alice=Client(f"http://127.0.0.1:{server.server_port}",self.key)
            bob=Client(f"http://127.0.0.1:{server.server_port}",self.key)
            alice.send("Alice","network test")
            self.assertEqual(decrypt_message(self.key,bob.poll(0,0)[0]["envelope"])["text"],"network test")
        finally:
            server.shutdown();server.server_close();thread.join(timeout=2)


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
        client=Client("http://relay.test",generate_key())
        with patch.object(client.opener,"open",side_effect=http.client.BadStatusLine("untrusted response text")):
            with self.assertRaisesRegex(NoiseChatError,"Could not reach the relay") as caught:
                client.poll(0,0)
        self.assertNotIn("untrusted",str(caught.exception))

    def test_post_rate_limit_and_bounded_ip_cache(self):
        server=RelayServer.__new__(RelayServer)
        server.rate_lock=threading.Lock()
        from collections import OrderedDict
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
