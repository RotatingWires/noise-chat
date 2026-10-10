"""Command-line entry points. Passphrases and message text are never CLI arguments."""

import argparse
import getpass
import sqlite3
import sys
import threading
import warnings
from pathlib import Path

from . import __version__
from .client import Client, Receiver, terminal_text
from .crypto import NoiseChatError, decrypt_key_file, decrypt_message, encrypt_key_file, encrypt_message, generate_key, room_id, validate_sender
from .keys import KeyStore, check_alias, read_key_file, write_key_file


def read_passphrase(prompt: str) -> str:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass(prompt)
    except getpass.GetPassWarning:
        raise NoiseChatError("Passphrase entry needs an interactive terminal with hidden input. "
                             "Use an OS keyring for noninteractive commands.") from None


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
    check_alias(args.chat)
    if args.key_action == "create":
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
        data = read_key_file(args.file)
        key = decrypt_key_file(data, read_passphrase("Key-file passphrase: "))
        store.put(args.chat, key, replace=args.replace)
        print("Key imported into the OS keyring. Room:", room_id(key))
    elif args.key_action == "export":
        key = store.get(args.chat)
        write_key_file(args.file, encrypt_key_file(key, new_passphrase()))
        print("Encrypted key file written. The raw chat key was not written to disk.")
    elif args.key_action == "remove":
        store.remove(args.chat)
        print("Local key removed. Existing exports and your friends' copies remain usable.")
    elif args.key_action == "info":
        key = load_key(args)
        print("Room:", room_id(key))
        print("Compare this room ID with a friend's to confirm that you imported the same key.")


def chat_command(args) -> None:
    key = load_key(args)
    client = Client(args.server, key)
    # Reject a bad name before starting the receiver, without transmitting anything.
    validate_sender(args.name)
    lock = threading.Lock()

    def output(text):
        with lock:
            print(text, flush=True)

    receiver = Receiver(client, output)
    stop = threading.Event()
    thread = threading.Thread(target=receiver.listen, args=(stop,), daemon=True)
    print(f"Chatting as {terminal_text(args.name)}. Type a message and press Enter. /quit exits.")
    print("Names are chosen by key holders, not verified identities.")
    thread.start()
    try:
        while True:
            text = input("> ")
            if text == "/quit":
                break
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
        # A receiver may be in a bounded long poll; it doesn't block CLI exit.
        thread.join(timeout=0.2)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="noisechat", description="Encrypted CLI chat; only clients hold chat keys.")
    result.add_argument("--version", action="version", version=f"NoiseChat {__version__}")
    commands = result.add_subparsers(dest="command", required=True)
    server = commands.add_parser("serve", help="run the ciphertext-only relay")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8720)
    server.add_argument("--database", type=Path, default=Path("relay.sqlite3"))

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

    for name, help_text in [("chat", "send and receive interactively"), ("send", "send one message"),
                            ("listen", "receive messages"), ("encrypt", "turn text into ciphertext offline"),
                            ("decrypt", "read pasted ciphertext offline")]:
        command = commands.add_parser(name, help=help_text)
        command.add_argument("chat", help="local name of the shared key")
        command.add_argument("--key-file", type=Path, help="unlock an encrypted key file instead of using the OS keyring")
        if name in {"chat", "send", "listen"}:
            command.add_argument("--server", required=True, help="relay URL, including http:// or https://")
        if name in {"chat", "send", "encrypt"}:
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
        if args.command == "serve":
            if not 0 <= args.port <= 65535:
                raise NoiseChatError("Port must be between 0 and 65535.")
            # Server setup does not touch the OS keyring or load a chat key.
            from .relay import serve
            serve(args.host, args.port, args.database)
        elif args.command == "key":
            key_command(args)
        elif args.command == "chat":
            chat_command(args)
        else:
            key = load_key(args)
            if args.command in {"send", "encrypt"}:
                text = read_text(args.stdin)
                if args.command == "encrypt":
                    print(encrypt_message(key, args.name, text))
                else:
                    receipt = Client(args.server, key).send(args.name, text)
                    print(f"Accepted by relay (sequence {receipt}). This is not a read receipt.")
            elif args.command == "decrypt":
                envelope = input("Ciphertext: ").strip()
                from .client import render_message
                print(render_message(decrypt_message(key, envelope)))
            elif args.command == "listen":
                if args.after < 0 or args.after >= 2**63:
                    raise NoiseChatError("--after must be a nonnegative relay sequence number.")
                receiver = Receiver(Client(args.server, key))
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
