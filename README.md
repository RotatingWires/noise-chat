> [!WARNING]
> This project is fully vibecoded, probably inefficient, but it does what I wanted lol

# NoiseChat v0.4.19

An encrypted terminal chat with a self-hosted relay, shared channel keys, persistent ciphertext history, and Windows/Linux clients.

**[Full manual](MANUAL.md)** — complete commands, hosting and Cloudflare Tunnel setup, desktop autostart, key management, protocol details, and release notes, preserved from the original README.

## Quickstart

Requires **Python 3.11+** and an unlocked native OS keyring (Windows Credential Manager, Linux Secret Service/KWallet, or macOS Keychain).

```sh
git clone https://github.com/RotatingWires/noise-chat.git
cd noise-chat
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

On Windows PowerShell, use `py -m venv .venv` and `.\.venv\Scripts\Activate.ps1` instead. Installation includes `cryptography`, `keyring`, and `prompt_toolkit`.

Start the relay in one terminal and choose a server access password of at least 12 characters:

```sh
noisechat run --urls "http://127.0.0.1:8713"
```

In another terminal with the environment activated, create a channel key once and choose a strong export passphrase:

```sh
noisechat key create friends --export friends.noise-key
noisechat join friends --server "http://127.0.0.1:8713" --name Alice
```

The raw chat key goes into your OS keyring; `friends.noise-key` is an encrypted export. Open another terminal and join the same channel as Bob to test. Clients prompt for the separate server access password. Type a message and press Enter; `/users` lists connected users and `/quit` exits.

For another device, share the **same encrypted key export**, its passphrase, and the server password privately. Import with `noisechat key import friends /path/to/friends.noise-key`, then join using your relay's HTTPS URL. Creating another key with the same local name creates a different channel. For systems without a desktop keyring, see [key-file mode](MANUAL.md#key-storage).

## Security and privacy

The relay's listener uses HTTP; place it behind an HTTPS reverse proxy or [Cloudflare Tunnel](MANUAL.md#cloudflare-tunnel) for remote connections. The local quickstart binds only to loopback. The relay password authorizes server access and is separate from the channel key and export passphrase. Server password hashes use salted PBKDF2-HMAC-SHA256 with 600,000 iterations; login allows five attempts per source IP per minute. Session tokens stay in memory, expire after 12 hours, and are invalidated by a relay restart.

`--password-file` files contain plaintext credentials: restrict them to the service/client account (`chmod 600` on Unix). Native keyrings protect keys at rest according to their configuration; unlocked keyrings can be accessible to programs running as your user. Keys and plaintext exist in client memory, and Python does not guarantee secure memory erasure.

A server-password holder who learns a room ID can download ciphertext and submit junk packets without that channel's key. Clients reject unauthenticated packets, but stored junk can consume retention capacity. The relay needs no chat key. Proxy logs may record room URLs. Cloudflare terminates public HTTPS and can see the login password, access tokens, and routing metadata; message contents remain encrypted. A public tunnel alone does not add authentication, and NoiseChat does not currently integrate with Cloudflare Access's browser login or service-token headers.

## What the encryption does

This is symmetric, client-side end-to-end encryption using established primitives, rather than a fixed substitution for each letter:

- A cryptographically random 256-bit shared chat key.
- AES-256-GCM authenticated encryption from `cryptography`, with a fresh random 32-byte salt, an HKDF-derived message key, and a fresh 12-byte nonce for each message.
- Authentication binds each encrypted packet to its derived room ID and protocol version. Changed ciphertext and wrong keys are rejected.
- Display names, message/event types, IDs, timestamps, and text are encrypted together. UTF-8 message text is limited to 4096 bytes. Presence and join announcements use the same authenticated encryption.
- Random padding rounds the encrypted plaintext to 256-byte buckets. It obscures small length differences, not all message lengths.
- USB exports use AES-256-GCM with a passphrase-derived scrypt key (N=131072, r=8, p=1), fresh salt, and a fresh nonce. Import parameters and sizes are fixed and validated.
- Repeated packet submissions are deduplicated by the relay while retained. Clients also suppress repeated authenticated message IDs within a bounded, in-memory session cache.
- Terminal control and bidi characters from messages are escaped rather than executed.

Sending the same plaintext twice produces different ciphertext. Base64 merely makes encrypted bytes copyable; it is not itself the encryption. See the [cryptography AEAD documentation](https://cryptography.io/en/stable/hazmat/primitives/aead/), [key derivation documentation](https://cryptography.io/en/stable/hazmat/primitives/key-derivation-functions/), and [keyring documentation](https://keyring.readthedocs.io/en/stable/).

## What it does not protect

HTTP still hides message contents from someone who lacks the chat key, but exposes the server login password, access tokens, room IDs, IP addresses, approximate sizes, timing, and traffic patterns. HTTP observers can steal relay access or disrupt traffic. HTTPS protects the transport and authenticates the server, so use it for remote connections. The relay password authorizes server use; it does not grant access to any channel's decrypted messages or make a shared-key holder a verified person.

Online status exposes connection counts and presence timing to the relay. Each chat session uses a random private token to refresh or remove its presence; that token is sent over the transport but is never in the public roster or SQLite database. HTTP observers can capture it, so use HTTPS to protect presence updates too. The roster is a relay-reported view, not proof of a person's identity or guaranteed connectivity; a relay or key holder can replay or fabricate presence.

All shared-key holders can read all messages and use any display name. Names are not cryptographic identities. A relay can delay, reorder, omit, or replay messages; client replay suppression is session-local and bounded. This version has no forward secrecy: if the shared key is later compromised, captured old ciphertext can be decrypted. Rotate by creating a new key and distributing it again.

This is an initial implementation built on standard cryptography libraries, not a security-audited messaging protocol. Audio, per-person identities/keys, forward secrecy, and persistent replay state are future work.

See the manual for [access and authentication](MANUAL.md#access-and-authentication), [key storage](MANUAL.md#key-storage), [remote hosting](MANUAL.md#host-the-relay), and [storage/retention](MANUAL.md#message-storage-and-retention).
