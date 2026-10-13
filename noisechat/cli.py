"""Command-line entry points. Passphrases and message text are never CLI arguments."""

import argparse
import getpass
import os
import sqlite3
import stat
import sys
import threading
import warnings
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__
from .auth import PasswordVerifier, password_bytes
from .client import Client, Presence, Receiver, notify_message_attention, terminal_text
from .crypto import NoiseChatError, decrypt_key_file, decrypt_message, encrypt_key_file, encrypt_message, generate_key, room_id, validate_sender
from .keys import KeyStore, check_alias, read_key_file, write_key_file
from .terminal import chat_input

DEFAULT_RELAY_URL = "http://127.0.0.1:8713"


def listen_address(url: str) -> tuple[str, int]:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        raise NoiseChatError("Use one HTTP listen URL with an explicit port, such as " + DEFAULT_RELAY_URL + ".") from None
    if (any(char.isspace() for char in url) or parsed.scheme != "http" or not parsed.hostname
            or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment
            or parsed.path not in {"", "/"} or port is None):
        raise NoiseChatError("Use one HTTP listen URL with an explicit port, such as " + DEFAULT_RELAY_URL +
                             ". For HTTPS, use a reverse proxy.")
    return parsed.hostname, port


def read_passphrase(prompt: str) -> str:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass(prompt)
    except getpass.GetPassWarning:
        raise NoiseChatError("Secret entry needs an interactive terminal with hidden input. "
                             "Use an OS keyring for chat keys or --password-file for server access in noninteractive commands.") from None


def read_server_password(args, prompt: str = "Server access password: ") -> str:
    if args.password_file is None:
        password = read_passphrase(prompt)
    else:
        descriptor = os.open(args.password_file, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or (os.name != "nt" and info.st_mode & 0o077):
                raise NoiseChatError("Use a regular server password file accessible only to its owner (chmod 600 on Unix).")
            raw = stream.read(1027)
        if len(raw) > 1026:
            raise NoiseChatError("Server password file is too large.")
        try:
            password = raw.decode("utf-8").removesuffix("\n").removesuffix("\r")
        except UnicodeError:
            raise NoiseChatError("Server password file must contain UTF-8 text.") from None
    password_bytes(password)
    return password


def server_verifier(args) -> PasswordVerifier:
    path = args.auth_file or args.database.with_name(args.database.name + ".auth.json")
    if path.exists() and not args.reset_password:
        return PasswordVerifier.load(path)
    password = read_server_password(args, "Enter a server password (12+ characters): ")
    if args.password_file is None and password != read_passphrase("Confirm server access password: "):
        raise NoiseChatError("Server passwords do not match.")
    verifier = PasswordVerifier.create(password)
    verifier.save(path, replace=args.reset_password)
    print("Server password configured. Authentication file:", path)
    return verifier


def new_passphrase() -> str:
    first = read_passphrase("Key-file passphrase (12+ characters): ")
    if first != read_passphrase("Confirm passphrase: "):
        raise NoiseChatError("Passphrases do not match.")
    if len(first) < 12:
        raise NoiseChatError("Use a passphrase of at least 12 characters; several random words work well.")
    return first


def load_key(args) -> bytes:
    check_alias(args.chat)
    if args.key_file:
        data = read_key_file(args.key_file)
        return decrypt_key_file(data, read_passphrase("Key-file passphrase: "))
    return KeyStore().get(args.chat)


def read_text(use_stdin: bool) -> str:
    if use_stdin:
        data = sys.stdin.buffer.read(4097)
        if len(data) > 4096:
            raise NoiseChatError("Messages are limited to 4096 UTF-8 bytes.")
        try:
            return data.decode("utf-8").removesuffix("\n").removesuffix("\r")
        except UnicodeError:
            raise NoiseChatError("Message input must be UTF-8.") from None
    return input("Message: ")


def key_command(args) -> None:
    store = KeyStore()
    if args.key_action == "create":
        check_alias(args.chat)
        if args.no_store and not args.export:
            raise NoiseChatError("--no-store requires --export so you keep the new key.")
        if args.export and args.export.exists():
            raise NoiseChatError("Export file already exists. Choose a new filename.")
        key = generate_key()
        exported = encrypt_key_file(key, new_passphrase()) if args.export else None
        if not args.no_store:
            store.put(args.chat, key)
        if exported is not None:
            write_key_file(args.export, exported)
        print("Chat key created." + (" Saved in the OS keyring." if not args.no_store else " Saved only in the encrypted file."))
        if args.export:
            print("Encrypted key file written. Share it and its passphrase with your friends in person.")
        print("Room:", room_id(key))
    elif args.key_action == "import":
        check_alias(args.chat)
        data = read_key_file(args.file)
        key = decrypt_key_file(data, read_passphrase("Key-file passphrase: "))
        store.put(args.chat, key, replace=args.replace)
        print("Key imported into the OS keyring. Room:", room_id(key))
    elif args.key_action == "export":
        check_alias(args.chat)
        key = store.get(args.chat)
        write_key_file(args.file, encrypt_key_file(key, new_passphrase()))
        print("Encrypted key file written. The raw chat key was not written to disk.")
    elif args.key_action == "remove":
        check_alias(args.chat)
        store.remove(args.chat)
        print("Local key removed. Existing exports and your friends' copies remain usable.")
    elif args.key_action == "info":
        check_alias(args.chat)
        key = load_key(args)
        print("Room:", room_id(key))
        print("Compare this room ID with a friend's to confirm that you imported the same key.")
    elif args.key_action == "list":
        entries = store.list()
        if not entries:
            print("No local chat keys.")
            return
        print(f"{'CHAT':<24}  ROOM ID")
        for alias, identity in entries:
            print(f"{alias:<24}  {identity}")


def join_command(args) -> None:
    key = load_key(args)
    client = Client(args.server, key, read_server_password(args))
    # Reject a bad name before starting the receiver, without transmitting anything.
    validate_sender(args.name)
    lock = threading.Lock()

    def output(text):
        with lock:
            print(text, flush=True)

    with chat_input() as read_message:
        receiver = Receiver(client, output, notify_message_attention)
        stop = threading.Event()
        presence = Presence(client, args.name, output, stop)
        thread = threading.Thread(target=receiver.listen, args=(stop,), daemon=True)
        presence.start()
        print(f"Chatting as {terminal_text(args.name)}. Type a message and press Enter.")
        print("Use /users to list users in this channel, and /quit to quit.")
        print("Names are chosen by key holders, not verified identities.")
        thread.start()
        try:
            while not stop.is_set():
                text = read_message("> ")
                if stop.is_set():
                    break
                if text == "/quit":
                    break
                if text == "/users":
                    try:
                        print_users([(args.chat, client)], output)
                    except NoiseChatError as error:
                        output(f"[Could not list users: {error}]")
                    continue
                if not text.strip():
                    continue
                try:
                    client.send(args.name, text)
                except NoiseChatError as error:
                    output(f"[Send not confirmed: {error}]")
        except (KeyboardInterrupt, EOFError):
            pass
        finally:
            stop.set()
            presence.close()
            # A receiver may be in a bounded long poll; it doesn't block CLI exit.
            thread.join(timeout=0.2)


def print_users(channels, output=print) -> None:
    rows = [(user["sender"], channel) for channel, client in channels for user in client.users()]
    if not rows:
        output("No connected users in the requested channels.")
        return
    rows = [(terminal_text(name), terminal_text(channel)) for name, channel in rows]
    width = max(len("USER"), *(len(name) for name, _ in rows))
    output(f"{'USER':<{width}}  CHANNEL")
    for name, channel in rows:
        output(f"{name:<{width}}  {channel}")


def users_command(args) -> None:
    if args.key_file and len(args.chats) != 1:
        raise NoiseChatError("--key-file supports one channel at a time.")
    channels = []
    seen = set()
    password = read_server_password(args)
    for channel in args.chats:
        args.chat = channel
        key = load_key(args)
        identity = room_id(key)
        if identity not in seen:
            client = Client(args.server, key, password)
            if channels:
                client.token = channels[0][1].authenticate()
            channels.append((channel, client))
            seen.add(identity)
    print_users(channels)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="noisechat", description="Encrypted CLI chat; only clients hold chat keys.")
    result.add_argument("--version", action="version", version=f"NoiseChat {__version__}")
    commands = result.add_subparsers(dest="command", required=True)
    server = commands.add_parser("run", help="run the ciphertext-only relay")
    server.add_argument("--urls", default=DEFAULT_RELAY_URL, metavar="HTTP_URL",
                        help="one HTTP listen URL, including IP/host and port (default: %(default)s)")
    server.add_argument("--database", type=Path, default=Path("relay.sqlite3"))
    server.add_argument("--auth-file", type=Path, metavar="FILE", help="password hash file (default: DATABASE.auth.json)")
    server.add_argument("--reset-password", action="store_true", help="set a new server password before starting the relay")
    server.add_argument("--password-file", type=Path, metavar="FILE", help="read the server password from a private file for setup/reset")
    server.add_argument("--cloudflare-tunnel", action="store_true", help="use Cloudflare visitor IPs for limits; requires a loopback listener and local cloudflared")

    key = commands.add_parser("key", help="create, import, export, inspect, or remove chat keys")
    actions = key.add_subparsers(dest="key_action", required=True)
    create = actions.add_parser("create", help="generate a random shared chat key")
    create.add_argument("chat")
    create.add_argument("--export", type=Path, metavar="FILE")
    create.add_argument("--no-store", action="store_true", help="save only a password-encrypted export, without an OS keyring")
    imp = actions.add_parser("import", help="import an encrypted USB key file into the OS keyring")
    imp.add_argument("chat")
    imp.add_argument("file", type=Path)
    imp.add_argument("--replace", action="store_true")
    export = actions.add_parser("export", help="write a password-encrypted copy of a key")
    export.add_argument("chat")
    export.add_argument("file", type=Path)
    remove = actions.add_parser("remove", help="remove a local keyring entry")
    remove.add_argument("chat")
    info = actions.add_parser("info", help="show the room ID, never the secret key")
    info.add_argument("chat")
    info.add_argument("--key-file", type=Path)
    actions.add_parser("list", help="list local chat aliases and their room IDs")

    users = commands.add_parser("users", help="list connected users and their channels (requires each channel's key)")
    users.add_argument("chats", nargs="+", metavar="CHAT", help="local names of channels to list")
    users.add_argument("--server", required=True, help="relay URL, including http:// or https://")
    users.add_argument("--key-file", type=Path, help="unlock an encrypted key file for a single channel")
    users.add_argument("--password-file", type=Path, metavar="FILE", help="read the server access password from a private file")

    for name, help_text in [("join", "join a channel and send and receive interactively"), ("send", "send one message"),
                            ("listen", "receive messages"), ("encrypt", "turn text into ciphertext offline"),
                            ("decrypt", "read pasted ciphertext offline")]:
        command = commands.add_parser(name, help=help_text)
        command.add_argument("chat", help="local name of the shared key")
        command.add_argument("--key-file", type=Path, help="unlock an encrypted key file instead of using the OS keyring")
        if name in {"join", "send", "listen"}:
            command.add_argument("--server", required=True, help="relay URL, including http:// or https://")
            command.add_argument("--password-file", type=Path, metavar="FILE", help="read the server access password from a private file")
        if name in {"join", "send", "encrypt"}:
            command.add_argument("--name", required=True, help="display name (encrypted along with your message)")
        if name in {"send", "encrypt"}:
            command.add_argument("--stdin", action="store_true", help="read message text from standard input instead of prompting")
        if name == "listen":
            command.add_argument("--once", action="store_true", help="read one batch immediately, then exit")
            command.add_argument("--after", type=int, default=0, help="start after this relay sequence number")
    return result


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "run":
            host, port = listen_address(args.urls)
            # Server setup does not touch the OS keyring or load a chat key.
            from .relay import serve, tunnel_listen_host
            if args.cloudflare_tunnel:
                host = tunnel_listen_host(host)
            serve(host, port, args.database, server_verifier(args), cloudflare_tunnel=args.cloudflare_tunnel)
        elif args.command == "key":
            key_command(args)
        elif args.command == "join":
            join_command(args)
        elif args.command == "users":
            users_command(args)
        else:
            key = load_key(args)
            client = Client(args.server, key, read_server_password(args)) if args.command in {"send", "listen"} else None
            if client is not None:
                client.authenticate()
            if args.command in {"send", "encrypt"}:
                text = read_text(args.stdin)
                if args.command == "encrypt":
                    print(encrypt_message(key, args.name, text))
                else:
                    receipt = client.send(args.name, text)
                    print(f"Accepted by relay (sequence {receipt}). This is not a read receipt.")
            elif args.command == "decrypt":
                envelope = input("Ciphertext: ").strip()
                from .client import render_message
                print(render_message(decrypt_message(key, envelope)))
            elif args.command == "listen":
                if args.after < 0 or args.after >= 2**63:
                    raise NoiseChatError("--after must be a nonnegative relay sequence number.")
                receiver = Receiver(client)
                receiver.cursor = args.after
                if args.once:
                    receiver.receive(wait=0)
                    print(f"[Cursor: {receiver.cursor}]")
                else:
                    receiver.listen(threading.Event())
    except sqlite3.Error:
        print("Error: Relay database could not be opened or updated.", file=sys.stderr)
        return 1
    except (NoiseChatError, OSError, UnicodeError) as error:
        # OS errors may contain local paths but never include key material.
        print("Error:", terminal_text(str(error)), file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        return 0
    return 0
