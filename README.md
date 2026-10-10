> [!WARNING]
> This project is fully vibecoded, probably inefficient, but it does what I wanted lol

# NoiseChat v0.3.0

A basic Windows/Linux CLI chat. You type a message and press Enter; your client encrypts it, a relay stores and forwards the ciphertext, and your friends' clients decrypt it locally. The relay never receives the chat key, display names, or message text.

One shared random key identifies one chat. Give friends a password-encrypted copy on a USB drive. They import it into their device's keyring, then connect to the same relay. No accounts, web interface, or audio in this first version.

## Project stack

- Python 3.11 or newer for the CLI client and relay.
- Python `argparse` for commands and options.
- Python `http.server.ThreadingHTTPServer` and `BaseHTTPRequestHandler` for the HTTP backend.
- Python `urllib.request` for client requests and long polling.
- SQLite through Python's built-in `sqlite3`, with WAL mode for retained ciphertext.
- `cryptography` for AES-256-GCM, HKDF, and scrypt.
- `keyring` for native OS credential storage on clients.
- `setuptools` and pip for packaging and the installed `noisechat` command.

## Backend

The relay backend lives in `noisechat/relay.py`. It runs on Python's built-in [`http.server.ThreadingHTTPServer`](https://docs.python.org/3/library/http.server.html#http.server.ThreadingHTTPServer), with a custom `BaseHTTPRequestHandler`. It is an HTTP web server exposing a JSON API: clients POST encrypted messages and use long-polling GET requests to receive them. A bounded number of request threads lets clients wait for incoming messages while other requests are handled.

SQLite stores encrypted messages and join announcements across restarts. Online presence is held in memory, refreshed by clients, and removed on departure or expiry. The backend routes packets by their derived room IDs and maintains retention, size, worker, and rate limits. All names and message contents are encrypted on clients; the relay never receives chat keys or decrypts these packets. Native keyrings and encrypted USB key files belong to the clients.

`noisechat run` starts this backend as a foreground process. Its HTTP listener defaults to `http://127.0.0.1:8713`; `--urls` sets the listen IP/host and port. For public HTTPS access, run the HTTP backend behind an HTTPS reverse proxy. Python describes `http.server` as a basic server with limited security checks; NoiseChat adds the bounds described below.

## Access and authentication

NoiseChat currently has **no server login, authentication cookie, or API-key requirement**. The shared chat key protects message contents and lets clients authenticate encrypted packets; it does not authorize access to the relay's HTTP API. Rate limits and capacity limits are not a login system.

With the default `http://127.0.0.1:8713` listener, only programs on the server machine can reach the relay directly. With `--urls "http://0.0.0.0:8713"`, anyone on the LAN who can reach that port through the firewall can contact the relay and use their own shared key to start their own channel. Your friends need your channel's key to read its messages or produce messages your clients will accept.

The room ID is an unguessable routing identifier derived from the key, not the key itself. Anyone who learns a room ID can fetch its encrypted history and submit structurally valid encrypted packets without proving they hold the key. Clients reject packets they cannot authenticate, but the server cannot distinguish a genuine message from junk encrypted with the wrong key. There is no public endpoint listing all room IDs. Plain HTTP exposes room IDs and session tokens to network observers; HTTPS protects the transport but does not add a NoiseChat login. Restrict network access to the people/devices you intend to let use the relay.

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

## Channels, keys, and local chat names

**On a given relay, each distinct shared chat key identifies its own channel (room).** The key determines the room ID; the name you type as `CHAT` does not. Different relays keep separate histories and online rosters even when you use the same key on both.

The chat name is **only a local alias** for a key in your device's OS keyring. It is not registered with the server or sent in requests, and it does not have to match anyone else's alias. With `--key-file`, `CHAT` is just your local label and the key inside the selected file determines the channel. `--name` is separate: it is your display name, encrypted inside messages and presence records.

| Keys and local aliases | Channel on the same relay |
| --- | --- |
| You use `friends`; Bob uses `gaming`; both imported the same shared key. | Same channel. |
| You and Bob both use `friends`, but each ran `key create` separately. | Different channels, because the generated keys differ. |
| You save the same key under two aliases on your device. | Both aliases address the same channel. |

Creating or importing a key is a local operation. A channel's retained history begins when a client first submits a message or join announcement; there is no separate server-side room registration or room-name record. Use `noisechat key info CHAT` to compare room IDs with a friend without revealing the key.

## Try it locally

Start the relay in one terminal:

```sh
noisechat run --urls "http://127.0.0.1:8713"
```

On your client, create the shared key once:

```sh
noisechat key create friends --export friends.noise-key
```

Choose a strong export passphrase when prompted. The raw key goes into your OS keyring; `friends.noise-key` contains an encrypted copy. The export won't overwrite an existing file.

Open two more terminals:

```sh
noisechat chat friends --server "http://127.0.0.1:8713" --name Alice
```

```sh
noisechat chat friends --server "http://127.0.0.1:8713" --name Bob
```

Type a message and press Enter. Everyone in the channel receives an encrypted `[Wall] Alice joined the chat.` announcement when Alice connects. `/users` lists connected users in your current channel; `/quit` or Ctrl+C exits. Existing retained messages and join announcements appear when you connect. Incoming messages print as they arrive, so they may appear while you're typing in this basic terminal interface.

## Command reference

`CHAT` is your local name for a shared key, such as `friends`. `SERVER` is the relay URL, including `http://` or `https://`. Every command and key subcommand accepts `-h` or `--help`.

| Command | What it does |
| --- | --- |
| `noisechat --help` | List the available commands. Use `noisechat COMMAND --help` for its arguments. |
| `noisechat --version` | Print the installed release version. |
| `noisechat run [--urls "HTTP_URL"]` | Run the HTTP relay; defaults to `http://127.0.0.1:8713`. Use `--urls` to specify its listen IP/host and port. An attached terminal also provides the server-only console below. |
| `noisechat key --help` | List the key-management subcommands. |
| `noisechat key create CHAT` | Generate a new shared key and save it in the OS keyring. |
| `noisechat key import CHAT FILE` | Unlock a password-encrypted key file and save its key in the OS keyring. |
| `noisechat key export CHAT FILE` | Write a password-encrypted copy of an existing key for USB distribution or backup. |
| `noisechat key info CHAT` | Show the derived room ID so friends can compare keys, without printing the secret key. |
| `noisechat key remove CHAT` | Delete your local keyring entry; other people's copies and exported files still work. |
| `noisechat chat CHAT --server "SERVER" --name NAME` | Join a channel, announce your arrival, and send and receive interactively. Keeps your online status refreshed while running. |
| `noisechat users CHAT [CHAT ...] --server "SERVER"` | List all connected chat sessions and their channels for one or more shared keys you hold. |
| `noisechat send CHAT --server "SERVER" --name NAME` | Prompt for one message, encrypt and send it, then exit. Does not join the online roster. |
| `noisechat listen CHAT --server "SERVER"` | Read retained messages and keep listening. This is an unnamed, receive-only command; it does not join the online roster. |
| `noisechat encrypt CHAT --name NAME` | Prompt for text and print copyable ciphertext without contacting a server. |
| `noisechat decrypt CHAT` | Prompt for ciphertext and decrypt it locally without contacting a server. |

| Option | Applies to | What it does |
| --- | --- | --- |
| `--urls "HTTP_URL"` | `run` | One HTTP listen URL with an explicit port; defaults to `http://127.0.0.1:8713`. Use `http://0.0.0.0:8713` for other machines. Port `0` asks the OS to choose an available port. |
| `--database FILE` | `run` | SQLite ciphertext database; defaults to `relay.sqlite3` in the current directory. |
| `--export FILE` | `key create` | Also write a password-encrypted copy of the new key. |
| `--no-store` | `key create` | Save only the encrypted export instead of using the keyring; requires `--export`. |
| `--replace` | `key import` | Explicitly allow replacing a key already saved under the local chat name. |
| `--key-file FILE` | `key info`, `chat`, `users`, `send`, `listen`, `encrypt`, `decrypt` | Unlock an encrypted file instead of reading the keyring. For `users`, this supports one channel per invocation. |
| `--server "URL"` | `chat`, `users`, `send`, `listen` | Required relay URL. |
| `--name NAME` | `chat`, `send`, `encrypt` | Required display name, encrypted before transmission. |
| `--stdin` | `send`, `encrypt` | Read UTF-8 message text from standard input instead of prompting. |
| `--once` | `listen` | Read one batch immediately, print its cursor, and exit. |
| `--after NUMBER` | `listen` | Start after a previous relay cursor; defaults to `0` for retained history. |

Inside interactive `chat`:

| Input | What it does |
| --- | --- |
| Any nonblank text | Encrypt and send a message to the channel. |
| `/users` | Show all connected users in the current channel without sending a chat message. |
| `/quit` | Leave the roster and exit. Ctrl+C or end-of-input also exits. |

Inside the running relay's **server console** (`relay>`), not a client chat or shell:

| Command | What it does |
| --- | --- |
| `help` | Explain the server console commands. |
| `channels` | List active room IDs, retained packet counts, and online session counts. Local chat names and encrypted usernames are unavailable to the server. |
| `delete-channel ROOM_ID` | Delete that room's retained history and online presence and persistently block the room ID. Clients cannot recreate it with the old key. |
| `quit` | Stop the relay. Ctrl+C also stops it. |

The console reads only the relay process's attached terminal. It is disabled without an interactive terminal, such as a background service with no console. There is no HTTP administration endpoint and no `noisechat delete-channel` client command. To administer a service this way, stop it and run the relay interactively with the same `--database` path; issue console commands, then stop the interactive relay and restart the service.

## Connected users and channels

From another terminal, list every connected chat session in one or more channels:

```sh
noisechat users friends --server "http://127.0.0.1:8713"
noisechat users friends work --server "http://127.0.0.1:8713"
```

The output has `USER` and `CHANNEL` columns. Channel labels are your local key aliases; two people can call the same channel different things. Duplicate aliases for the same shared key are listed once. Multiple connections using the same display name appear as separate sessions.

Usernames and join announcements remain encrypted. You need each channel's key to identify its connected users; there is no public server-wide directory of plaintext names or channels. `users` itself does not join or announce a new user. Invalid encrypted roster entries are ignored.

Interactive chat refreshes its presence every 20 seconds. A normal exit removes the session immediately; after a crash or lost connection it expires within 60 seconds of the last accepted refresh. The relay keeps this presence state only in memory. After a relay restart, running clients register again on their next refresh and announce their return. Historical join notices are retained like chat messages, so use `users` for current online status.

Upgrade both the relay and clients to v0.2.0 for presence and join announcements. Older clients can still exchange text messages, but cannot interpret the new encrypted event types.

## Give a friend access

Copy `friends.noise-key` onto the USB drive. Give your friend the export passphrase in person. On their device:

```sh
noisechat key import friends /path/to/usb/friends.noise-key
noisechat key info friends
noisechat chat friends --server "https://your-relay.example.com" --name Bob
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
noisechat chat friends --key-file friends.noise-key --server "http://127.0.0.1:8713" --name Alice
```

The passphrase is prompted with input hidden; it is never a command-line argument or environment variable. With `--key-file`, the chat key is kept in process memory and isn't saved in a credential store. Exports are created with mode 0600 on Unix and remain password-encrypted on every OS.

Export another password-encrypted copy:

```sh
noisechat key export friends another-copy.noise-key
```

## Remove a key or room

To remove a saved key from **your device's keyring**:

```sh
noisechat key remove friends
```

This removes only the keyring entry under your local alias `friends`. It does not delete the relay's messages, any other alias holding the same key, exported `.noise-key` files, or your friends' copies. If you use `--key-file`, delete that encrypted file separately using your file manager. The `key remove` command does not delete files.

There is no server-side key to delete. To revoke a person's future access, generate a **new** shared key and give it only to the remaining participants; they move to its new channel. Anyone keeping the old key can still decrypt captured or retained old messages. Losing every copy of a key makes that key's ciphertext unrecoverable.

To delete a channel, use the **running server's console**:

1. At `relay>`, enter `channels` to find its 64-character room ID. You can also get that ID on a key-holding device with `noisechat key info friends` before removing your local key.
2. At `relay>`, enter `delete-channel ROOM_ID`, replacing `ROOM_ID` with the full ID, not the local name `friends`.

```text
relay> channels
relay> delete-channel ROOM_ID
```

Deletion immediately removes that room's retained packets and online sessions and records its room ID in the database's `deleted_rooms` table. Other rooms are left intact. The blocked ID survives relay restarts; sending, joining, reading history, or listing users in that room returns HTTP 410. Connected clients stop listening and refreshing presence; an interactive client waiting for keyboard input exits when you press Enter. Use a new shared key to start a new channel.

This command does not erase local keys, exported key files, backups, or text already displayed in friends' terminals, and does not guarantee secure disk erasure. The old key can still decrypt old ciphertext held elsewhere, but cannot reopen the blocked room on this relay. Deletion applies only to this relay database. There is no remote deletion API or client command for it.

## One-shot and offline commands

Send one message, prompted interactively:

```sh
noisechat send friends --server "http://127.0.0.1:8713" --name Alice
```

Read one batch and exit, or listen continuously:

```sh
noisechat listen friends --server "http://127.0.0.1:8713" --once
noisechat listen friends --server "http://127.0.0.1:8713"
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
noisechat run --urls "http://0.0.0.0:8713" --database relay.sqlite3
```

`0.0.0.0` listens on all IPv4 interfaces. Clients connect using the server's actual LAN IP or hostname, such as `http://192.168.1.50:8713`; `0.0.0.0` is a bind address, not the address to give friends. `127.0.0.1` limits the relay to clients on the same machine. One listen URL is supported per process; it must use `http://` and include a port. IPv6 addresses use brackets, for example `http://[::1]:8713`.

### Change the port

The default port is **8713**. Set a different port in `--urls` when starting the relay:

```sh
noisechat run --urls "http://0.0.0.0:9000"
```

Clients must use the same port in `--server`:

```sh
noisechat chat friends --server "http://192.168.1.50:9000" --name Alice
```

If you save the relay command in a startup script or service, change `--urls` there to keep your chosen port across restarts. To change the program's built-in default instead, edit `DEFAULT_RELAY_URL` near the top of `noisechat/cli.py`, then reinstall with `python -m pip install .`. There is no separate port configuration file. Running `noisechat run` without `--urls` uses that default.

Allow the chosen port through your host firewall if needed. For internet hosting, place the relay behind an HTTPS reverse proxy and connect with `https://...`. `/health` returns the release and protocol versions. SQLite retains ciphertext across restarts. Copy the database safely with SQLite's backup tools if needed; an active WAL database cannot be backed up reliably by copying just the main file.

Requests and responses are size-limited. The server permits at most 64 request handlers and bounds its rate-limit cache. Online presence is limited to 100 sessions per channel and 1,000 total. POSTs, including presence refreshes and departures, use a per-source-IP token bucket (burst 30, refill one request/second). Behind a reverse proxy, clients may share the proxy's source-IP allowance; the relay doesn't trust arbitrary forwarding headers. Routine request logging is disabled so room URLs aren't written into its own access log. Your proxy may still log them.

### Cloudflare Tunnel

A Cloudflare Tunnel can forward a public HTTPS hostname to this relay. If `cloudflared` runs on the same machine, keep the relay bound to `http://127.0.0.1:8713` and point the tunnel's service URL there; clients use the public `https://...` hostname. This keeps the origin listener off the LAN and avoids opening an inbound router port, but the tunnel route still exposes the service through its public hostname.

**A public tunnel alone does not add authentication.** Cloudflare says a published application without an Access application is available to anyone on the Internet. Message contents remain encrypted, but strangers could create channels, fill the room/history limits, evict retained messages, or consume relay capacity. See [Cloudflare's Access setup guidance](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/).

Protect the hostname with Cloudflare Access rather than publishing the open API by itself. For a CLI, Access's [service tokens](https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/) authenticate requests using `CF-Access-Client-Id` and `CF-Access-Client-Secret` headers with a Service Auth policy. **NoiseChat does not currently supply those headers or perform Cloudflare's browser login**, so Access-protected public-hostname use needs client authentication integration first. Those Access credentials would be separate from the end-to-end chat key; Cloudflare must never receive that key. A private VPN/network is another way to restrict who can reach the relay without publishing an open API.

## Message storage and retention

**Yes, messages are stored.** The default `relay.sqlite3` database is created in the relay's working directory; `noisechat run --database FILE` selects a different path. It keeps encrypted history across server restarts so clients can retrieve messages they missed while offline. There is one database for all channels, not one file per key.

Each row in the `messages` table contains:

| Field | Stored value |
| --- | --- |
| `sequence` | A server-assigned integer cursor used to retrieve packets in order. |
| `room` | The derived room ID used to route packets. This is neither the secret key nor your local chat alias. |
| `digest` | A SHA-256 hash of the encrypted envelope, used to suppress duplicate submissions while retained. |
| `envelope` | The encrypted packet, including its encrypted message/event type, sender, text, message ID, and timestamp. Join announcements are stored here too. |

The database contains no raw chat keys, key-file passphrases, plaintext message bodies, plaintext display names, or local chat aliases. SQLite also keeps its indexes, sequence metadata, and a `deleted_rooms` table containing only blocked room IDs. Online presence, departure tokens, and the source-IP rate-limit cache are held only in memory; presence expires within 60 seconds of its last accepted refresh, and all presence is cleared on restart. The client does not write a plaintext transcript, although your terminal's scrollback or logging may retain displayed text.

History retention is **based on packet counts, not time**:

- At most **500 retained packets per room**, counting messages and join announcements.
- At most **10,000 retained packets across the relay**. This global limit can trim a room below 500 packets.
- At most **100 rooms** with retained history or active presence.
- New packets cause the oldest retained packets to be removed when a limit is exceeded. Reading a message does not delete it.
- There is **no age-based expiration**. If a room is quiet and the global limit is not reached, its encrypted history can remain indefinitely, including across restarts.

The history limits are defined by `RelayStore` defaults in `noisechat/relay.py`; there are currently no CLI flags to change them. SQLite can retain previously allocated disk pages after row deletion, so retention is not a promise of secure erasure. Server-console channel deletion is separate from removing a local key. Blocked room IDs do not count toward the active-room limit.

### How history appears when you connect

**Yes, retained history displays automatically when you start `noisechat chat`.** A new client session starts its in-memory cursor at `0`, requests the room's retained packets from the relay, decrypts them locally, and prints them in relay sequence order, oldest first. History includes retained join announcements and your own earlier messages. Responses contain at most 100 packets, and chat keeps reading further batches before long-polling for new messages. There is no separate restore command.

During a temporary connection loss, a still-running client keeps its cursor and resumes after the last packet it received. Closing and reopening the client starts a new session and displays all still-retained history again; no cursor is persisted to disk. Packets already evicted by retention or removed by channel deletion cannot be restored from the relay.

`noisechat listen` also starts from retained history by default. `listen --once` displays only one batch and exits with its cursor; `--after NUMBER` lets you request later batches without replaying earlier ones. `send`, `users`, and the offline encryption commands do not automatically display history.

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

HTTP still hides message contents from someone who lacks the key, but exposes room IDs, IP addresses, approximate sizes, timing, and traffic patterns. HTTP observers can also disrupt traffic or submit junk/replay packets. HTTPS protects the transport and authenticates the server, so use it when hosting publicly.

Online status exposes connection counts and presence timing to the relay. Each chat session uses a random private token to refresh or remove its presence; that token is sent over the transport but is never in the public roster or SQLite database. HTTP observers can capture it, so use HTTPS to protect presence updates too. The roster is a relay-reported view, not proof of a person's identity or guaranteed connectivity; a relay or key holder can replay or fabricate presence.

All shared-key holders can read all messages and use any display name. Names are not cryptographic identities. A relay can delay, reorder, omit, or replay messages; client replay suppression is session-local and bounded. This version has no forward secrecy: if the shared key is later compromised, captured old ciphertext can be decrypted. Rotate by creating a new key and distributing it again.

This is an initial implementation built on standard cryptography libraries, not a security-audited messaging protocol. Audio, per-person identities/keys, forward secrecy, persistent replay state, and richer terminal input are future work.

## Development

```sh
python -m unittest discover -s tests -v
python -m compileall -q noisechat tests
```

Tests cover randomized encryption, Unicode, authentication failures, key-file tampering/passwords, keyring overwrite protection, exclusive exports, two-client exchange through the real HTTP handler, encrypted wire/database contents, encrypted join notices and user rosters, presence expiry/refresh/departure, room isolation, persistence/retention, rate limiting, polling, replay rejection, and terminal escapes. The native TCP test runs when sockets are allowed and explicitly skips in restricted environments. Keyring operations are tested with an in-memory test backend; a real OS keyring must be available for normal key creation/import.

`pyproject.toml` owns the release version and dependency declarations. `noisechat/` is split into crypto formats, OS-key storage, relay, client, and CLI responsibilities. There are no runtime overrides or frontend build tools. `python -m noisechat` works from the source checkout once dependencies are installed; installing the package provides the `noisechat` entry point.

## v0.3.0

- Add server-console channel listing and deletion, without an HTTP administration API or client deletion command.
- Remove deleted channels' history and presence and persistently block their room IDs.
- Wake connected receivers and stop clients retrying a deleted channel.
- Document Cloudflare Tunnel access controls, database contents, and automatic history display.
- Replace the manual database deletion instructions with the server console command.

## v0.2.1

- Add Project stack and Backend sections describing the runtime, dependencies, HTTP API, and storage.
- Rename the relay command to `run` and set the listen IP/host and port with `--urls`.
- Change the default listen port to 8713 and update every connection example.
- Document custom ports, startup/service overrides, the source default, and IPv4/IPv6 listen addresses.

## v0.2.0

- Document every command, option, and interactive chat command.
- Explain the built-in Python HTTP server and JSON relay API.
- Broadcast encrypted wall announcements when a chat session joins or reconnects after expiry.
- Add `users` for connected users across specified channels and `/users` inside chat.
- Keep usernames encrypted; expire abandoned sessions and remove presence on normal exit.

## v0.1.0

- Add interactive chat, one-message send, continuous/one-batch receive, and offline encryption/decryption.
- Add random shared-key creation, native-keyring import/export/removal, and password-protected USB key files.
- Add a bounded ciphertext-only HTTP/SQLite relay with retained history and long polling.
- Keep plaintext, display names, passphrases, and chat keys off the relay.
- Include protocol/key handling tests and Windows/Linux setup instructions.
