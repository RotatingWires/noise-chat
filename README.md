# NoiseChat v0.1.0

A basic Windows/Linux CLI chat. You type a message and press Enter; your client encrypts it, a relay stores and forwards the ciphertext, and your friends' clients decrypt it locally. The relay never receives the chat key, display names, or message text.

One shared random key identifies one chat. Give friends a password-encrypted copy on a USB drive. They import it into their device's keyring, then connect to the same relay. No accounts, web interface, or audio in this first version.

## Install

Requires Python 3.11 or newer. From this project folder:

```sh
python -m pip install .
```

This installs `noisechat` plus two dependencies: `cryptography` and `keyring`. On Windows, `py` can be used instead of `python`. If the `noisechat` command isn't on your PATH, use `python -m noisechat` from this folder.

A virtual environment is useful if your Linux distribution restricts system-wide pip installs:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

On Windows PowerShell, create one with `py -m venv .venv`, then activate it with `.\.venv\Scripts\Activate.ps1`. Alternatively, run `.\.venv\Scripts\python.exe -m pip install .` and `.\.venv\Scripts\noisechat.exe` directly.

## Try it locally

Start the relay in one terminal:

```sh
noisechat serve
```

On your client, create the shared key once:

```sh
noisechat key create friends --export friends.noise-key
```

Choose a strong export passphrase when prompted. The raw key goes into your OS keyring; `friends.noise-key` contains an encrypted copy. The export won't overwrite an existing file.

Open two more terminals:

```sh
noisechat chat friends --server http://127.0.0.1:8720 --name Alice
```

```sh
noisechat chat friends --server http://127.0.0.1:8720 --name Bob
```

Type a message and press Enter. `/quit` or Ctrl+C exits. Existing retained messages appear when you connect. Incoming messages print as they arrive, so they may appear while you're typing in this basic terminal interface.

## Give a friend access

Copy `friends.noise-key` onto the USB drive. Give your friend the export passphrase in person. On their device:

```sh
noisechat key import friends /path/to/usb/friends.noise-key
noisechat key info friends
noisechat chat friends --server https://your-relay.example.com --name Bob
```

Windows paths work too, for example `E:\friends.noise-key`. Compare the room ID printed by `key info` with yours to confirm that you imported the same key. Their local chat name can differ; the key determines the room.

Each friend imports the **same exported key**. Running `key create` independently generates a different chat, even if everyone uses the name `friends`.

The server uses no USB key file and needs no chat key at all.

## Key storage

Default client storage uses a native OS credential store:

- Windows: Credential Manager.
- Linux: Secret Service (for example an unlocked GNOME Keyring) or KWallet.
- macOS native Keychain is also accepted, although this release targets Windows/Linux.

The client refuses unknown and plaintext keyring backends. Your keyring protects the key at rest according to its configuration; it can be accessible to programs running as your user while unlocked. It cannot protect a compromised client, and the chat key/plaintext necessarily exist in the client process's memory during use. Python does not guarantee secure memory erasure.

If a Linux machine has no desktop keyring, keep only an encrypted key file and unlock it each time:

```sh
noisechat key create friends --export friends.noise-key --no-store
noisechat chat friends --key-file friends.noise-key --server http://127.0.0.1:8720 --name Alice
```

The passphrase is prompted with input hidden; it is never a command-line argument or environment variable. With `--key-file`, the chat key is kept in process memory and isn't saved in a credential store. Exports are created with mode 0600 on Unix and remain password-encrypted on every OS.

Other key operations:

```sh
noisechat key export friends another-copy.noise-key
noisechat key remove friends
```

Removing a local key doesn't revoke anyone else's copy. To remove a person from a chat, create a new shared key, distribute it to the remaining participants, and start using its new room. Losing every copy of a key makes its messages unrecoverable.

## One-shot and offline commands

Send one message, prompted interactively:

```sh
noisechat send friends --server http://127.0.0.1:8720 --name Alice
```

Read one batch and exit, or listen continuously:

```sh
noisechat listen friends --server http://127.0.0.1:8720 --once
noisechat listen friends --server http://127.0.0.1:8720
```

`--once` prints a cursor that can be used as `--after NUMBER` on the next invocation. Each batch contains at most 100 messages. Continuous listening and live chat read further batches automatically. A relay acceptance confirms storage, not that a friend read the message.

Convert a message into copyable nonsense **without a server**, then paste it into another key holder's CLI:

```sh
noisechat encrypt friends --name Alice
noisechat decrypt friends
```

`encrypt` prompts for text and prints URL-safe Base64 ciphertext. `decrypt` prompts for the ciphertext. All client commands accept `--key-file` as an alternative to a keyring entry. `send` and `encrypt` also accept `--stdin` for UTF-8 input from another program. Avoid putting private message text or passphrases directly in shell commands; your shell may save them in history.

## Host the relay

For access from other machines on your LAN:

```sh
noisechat serve --host 0.0.0.0 --port 8720 --database relay.sqlite3
```

Allow the chosen port through your host firewall if needed. For internet hosting, place the relay behind an HTTPS reverse proxy and connect with `https://...`. `/health` returns the release and protocol versions. SQLite retains ciphertext across restarts. Copy the database safely with SQLite's backup tools if needed; an active WAL database cannot be backed up reliably by copying just the main file.

The defaults retain at most 500 messages per room and 10,000 messages total across at most 100 active rooms. The oldest retained messages are removed as limits are reached; this is a chat relay, not a permanent archive. SQLite may retain previously allocated disk pages after deletion. No plaintext transcript is written on clients.

Requests and responses are size-limited. The server permits at most 64 request handlers and bounds its rate-limit cache. POSTs use a per-source-IP token bucket (burst 30, refill one message/second). Behind a reverse proxy, clients may share the proxy's source-IP allowance; the relay doesn't trust arbitrary forwarding headers. Routine request logging is disabled so room URLs aren't written into its own access log. Your proxy may still log them.

## What the encryption does

This is symmetric, client-side end-to-end encryption using established primitives, rather than a fixed substitution for each letter:

- A cryptographically random 256-bit shared chat key.
- AES-256-GCM authenticated encryption from `cryptography`, with a fresh random 32-byte salt, an HKDF-derived message key, and a fresh 12-byte nonce for each message.
- Authentication binds each encrypted packet to its derived room ID and protocol version. Changed ciphertext and wrong keys are rejected.
- Display names, message IDs, timestamps, and text are encrypted together. UTF-8 message text is limited to 4096 bytes.
- Random padding rounds the encrypted plaintext to 256-byte buckets. It obscures small length differences, not all message lengths.
- USB exports use AES-256-GCM with a passphrase-derived scrypt key (N=131072, r=8, p=1), fresh salt, and a fresh nonce. Import parameters and sizes are fixed and validated.
- Repeated packet submissions are deduplicated by the relay while retained. Clients also suppress repeated authenticated message IDs within a bounded, in-memory session cache.
- Terminal control and bidi characters from messages are escaped rather than executed.

Sending the same plaintext twice produces different ciphertext. Base64 merely makes encrypted bytes copyable; it is not itself the encryption. See the [cryptography AEAD documentation](https://cryptography.io/en/stable/hazmat/primitives/aead/), [key derivation documentation](https://cryptography.io/en/stable/hazmat/primitives/key-derivation-functions/), and [keyring documentation](https://keyring.readthedocs.io/en/stable/).

## What it does not protect

HTTP still hides message contents from someone who lacks the key, but exposes room IDs, IP addresses, approximate sizes, timing, and traffic patterns. HTTP observers can also disrupt traffic or submit junk/replay packets. HTTPS protects the transport and authenticates the server, so use it when hosting publicly.

Room IDs are unguessable routing capabilities derived from the random key, but the relay has no separate accounts or access-control system. Anyone who learns a room ID can retrieve its ciphertext or submit packets. Clients reject forged contents without the key; that doesn't prevent bandwidth/storage abuse or denial of service.

All shared-key holders can read all messages and use any display name. Names are not cryptographic identities. A relay can delay, reorder, omit, or replay messages; client replay suppression is session-local and bounded. This version has no forward secrecy: if the shared key is later compromised, captured old ciphertext can be decrypted. Rotate by creating a new key and distributing it again.

This is an initial implementation built on standard cryptography libraries, not a security-audited messaging protocol. Audio, per-person identities/keys, forward secrecy, persistent replay state, and richer terminal input are future work.

## Development

```sh
python -m unittest discover -s tests -v
python -m compileall -q noisechat tests
```

Tests cover randomized encryption, Unicode, authentication failures, key-file tampering/passwords, keyring overwrite protection, exclusive exports, two-client exchange through the real HTTP handler, encrypted wire/database contents, room isolation, persistence/retention, rate limiting, polling, replay rejection, and terminal escapes. The native TCP test runs when sockets are allowed and explicitly skips in restricted environments. Keyring operations are tested with an in-memory test backend; a real OS keyring must be available for normal key creation/import.

`pyproject.toml` owns the release version and dependency declarations. `noisechat/` is split into crypto formats, OS-key storage, relay, client, and CLI responsibilities. There are no runtime overrides or frontend build tools. `python -m noisechat` works from the source checkout once dependencies are installed; installing the package provides the `noisechat` entry point.

## v0.1.0

- Add interactive chat, one-message send, continuous/one-batch receive, and offline encryption/decryption.
- Add random shared-key creation, native-keyring import/export/removal, and password-protected USB key files.
- Add a bounded ciphertext-only HTTP/SQLite relay with retained history and long polling.
- Keep plaintext, display names, passphrases, and chat keys off the relay.
- Include protocol/key handling tests and Windows/Linux setup instructions.
