> [!WARNING]
> This project is fully vibecoded, probably inefficient, but it does what I wanted lol

# NoiseChat v0.4.16

A basic Windows/Linux CLI chat. You type a message and press Enter; your client encrypts it, a relay stores and forwards the ciphertext, and your friends' clients decrypt it locally. The relay never receives the chat key, display names, or message text.

One shared random key identifies one chat. Give friends a password-encrypted copy on a USB drive and your separate server access password. They import the chat key into their device's keyring, then connect to the same relay. No accounts, web interface, or audio in this first version.

## Project stack

- Python 3.11 or newer for the CLI client and relay.
- Python `argparse` for commands and options.
- Python `http.server.ThreadingHTTPServer` and `BaseHTTPRequestHandler` for the HTTP backend.
- Python `urllib.request` for client requests and long polling.
- Python `hashlib` and `secrets` for salted server-password hashes and temporary access tokens.
- SQLite through Python's built-in `sqlite3`, with WAL mode for retained ciphertext.
- `cryptography` for AES-256-GCM, HKDF, and scrypt.
- `keyring` for native OS credential storage on clients.
- `prompt_toolkit` for editable chat input, clearing submitted text, and displaying incoming messages while you type.
- `setuptools` and pip for packaging and the installed `noisechat` command.

## Backend

The relay backend lives in `noisechat/relay.py`. It runs on Python's built-in [`http.server.ThreadingHTTPServer`](https://docs.python.org/3/library/http.server.html#http.server.ThreadingHTTPServer), with a custom `BaseHTTPRequestHandler`. It is an HTTP web server exposing a JSON API: clients first log in with the server access password, then POST encrypted messages and use long-polling GET requests to receive them. A bounded number of request threads lets clients wait for incoming messages while other requests are handled. `noisechat/auth.py` owns password verification, temporary sessions, and the login cooldown.

SQLite stores encrypted messages and join announcements across restarts. Online presence is held in memory, refreshed by clients, and removed on departure or expiry. The backend routes packets by their derived room IDs and maintains retention, size, worker, and rate limits. All names and message contents are encrypted on clients; the relay never receives chat keys or decrypts these packets. Native keyrings and encrypted USB key files belong to the clients.

`noisechat run` starts this backend as a foreground process. Its HTTP listener defaults to `http://127.0.0.1:8713`; `--urls` sets the listen IP/host and port. For public HTTPS access, run the HTTP backend behind an HTTPS reverse proxy. Python describes `http.server` as a basic server with limited security checks; NoiseChat adds the bounds described below.

## Access and authentication

NoiseChat requires a **server access password** before clients can read history, send packets, join, refresh or leave presence, or list connected users. It is separate from the shared chat key and from the passphrase used to encrypt a USB key export. The server password lets someone use your relay; a channel's key lets them read and produce valid messages in that channel. There are no accounts or authentication cookies.

On first run, the relay prompts for a server password of at least 12 characters and confirmation, with input hidden. It saves a random salt and a PBKDF2-HMAC-SHA256 hash with 600,000 iterations, following the [OWASP password-storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2). The default hash file is `DATABASE.auth.json`, beside the selected database; for the default database, that is `relay.sqlite3.auth.json`. Subsequent starts load that verifier without prompting. `--auth-file FILE` selects another location. The password is not stored in the database or hash file.

Clients prompt for the server password once per command, also with input hidden. Login uses `POST /v1/auth/login`; a successful login returns a random token sent in the `Authorization: Bearer` header on channel requests. Tokens are held in client memory and stored only as hashes in server memory. They expire after 12 hours, and a relay restart invalidates them. Clients log in again automatically after expiry or a restart while keeping their in-memory message cursor. An incorrect password or login cooldown stops background retries. `/health` remains public and exposes only basic health and version information.

The 12-hour lifetime applies to a token held by a running client. `/quit`, Ctrl+C, or closing the terminal ends that client process and discards its token. Starting `noisechat join`, `send`, `listen`, or `users` again asks for the server password and gets a new token. Tokens are not saved between commands, and the prompted server password is not saved in the OS keyring. A temporary network disconnection while the client keeps running preserves its token; it reconnects without prompting while that token remains valid.

Like TL and TLS, login permits **five attempts per source IP in a one-minute window**, including successful and malformed attempts. Further attempts receive HTTP 429 with `Retry-After` and the CLI reports how many seconds to wait. Retrying during the cooldown does not extend it. Normal authenticated polling and messages do not count as logins. Attempts and sessions are bounded and kept only in memory, so restarting the relay clears the cooldown. Direct mode uses the TCP peer's IP and ignores forwarded IP headers. With `run --cloudflare-tunnel`, a trusted local connector's `CF-Connecting-IP` identifies each visitor for both login and message limits; see the setup below. Existing message rate limits apply separately.

With the default `http://127.0.0.1:8713` listener, only programs on the server machine can reach the relay directly. With `--urls "http://0.0.0.0:8713"`, people on the LAN can contact its listener if the firewall allows it, but need the server password to use channel endpoints. Anyone you give that password can start their own channels with their own chat keys. Your friends still need your channel's key to read its messages or produce messages your clients will accept.

The room ID is an unguessable routing identifier derived from the chat key, not the key itself. A server-password holder who learns a room ID can fetch its encrypted history and submit structurally valid packets without proving they hold that channel's key. Clients reject packets they cannot authenticate, but the relay cannot decrypt packets to check them. There is no public endpoint listing room IDs, and knowing a room ID alone does not bypass the server login.

Specifically, authenticated `GET /v1/rooms/ROOM_ID/messages` returns encrypted envelopes and sequence numbers; authenticated `POST` to that same URL accepts an envelope with the expected format. A password holder could encrypt a packet with their own unrelated key and submit it to a known room ID. Your clients reject it, but the stored junk still consumes history capacity and can displace older packets. Downloading the ciphertext does not make it readable without the channel key. Those endpoints have no channel-deletion or password-reset capability.

**Use HTTPS for remote connections.** The server password is sent during login, and session tokens authorize later requests; plain HTTP exposes both to network observers even though message bodies remain encrypted. HTTPS protects these credentials in transit. Upgrade the relay and clients to v0.4.0 together: older clients cannot log in to the protected relay.

### Change the server password

Stop the running relay, then start it with the same database and authentication-file settings plus `--reset-password`:

```sh
noisechat run --urls "http://127.0.0.1:8713" --reset-password
```

Enter and confirm the new password. This local startup option also resets a forgotten password; there is no remote reset endpoint. Give the new password to your friends. Old sessions are invalid after the restart, and clients using the old password must reconnect with the new one. Channel keys and stored message history stay the same. Editing the hash file while the relay is running does not change its loaded verifier.

### Background commands and services

`--password-file FILE` reads a UTF-8 server password from a file instead of prompting. Use it on `join`, `send`, `listen`, or `users`; on `run`, it sets the password during first-run setup or `--reset-password`. An existing verifier is loaded on ordinary server restarts, so a configured service needs only the hash file and database. Changing a password file does not automatically reset an existing server password.

```sh
noisechat run --urls "http://127.0.0.1:8713" --password-file server.noise-password
noisechat listen friends --server "https://your-relay.example.com" --password-file server.noise-password
```

The password file contains **plaintext credentials**, unlike the server's hash file or encrypted USB key export. Restrict it to the service/client account: `chmod 600 server.noise-password` on Unix, or the equivalent Windows file permissions. Unix clients reject files readable or writable by other users. Files contain one line, with an optional final newline; passwords are limited to 1024 UTF-8 bytes. Passwords are never CLI arguments or environment variables. The client does not save a prompted server password to disk or the keyring, but retains it in process memory to renew its session. The relay keeps at most 1,000 live login sessions, expiring old sessions after 12 hours; multi-channel `users` shares one login.

## HTTP API

The default relay base URL is `http://localhost:8713`; use your relay's HTTPS hostname when connecting through a tunnel. Responses are JSON with `Cache-Control: no-store`. POST bodies must be UTF-8 JSON with `Content-Type: application/json` and one valid `Content-Length`; chunked request bodies are not supported. Bodies are limited to 16,384 bytes.

`/health` and `/v1/auth/login` do not require a session. Every room request needs exactly one `Authorization: Bearer TOKEN` header. A successful password login returns a 64-character lowercase hexadecimal token, valid for 12 hours in this running relay. Restarting the relay invalidates it. Tokens stay in client memory for that process; starting a new CLI command logs in again. Login/password handling is separate from the shared chat key used to encrypt/decrypt packets.

`ROOM_ID` below is the 64-character lowercase hexadecimal room ID derived from the chat key, not the local chat name. A room ID is routing information, not authorization. A valid server token can access any known room ID; there are no per-room accounts or permissions. Reading/decrypting or producing authentic chat contents still requires the room's shared key. The relay only validates envelope structure/size, so it cannot reject all junk submitted by a server-authorized caller.

| Method | Path | Request | Response / effect |
| --- | --- | --- | --- |
| GET | `/health` | Public; no body or query. | 200 `{ok: true, version, protocol: 1}`. Does not validate login or Cloudflare visitor headers. |
| POST | `/v1/auth/login` | Public JSON: `{password: "..."}`. | 200 `{token: "..."}`; 401 for an incorrect password. Five attempts per observed visitor IP per 60 seconds; excess returns 429 with `Retry-After` and JSON `retry_after`. |
| GET | `/v1/rooms/ROOM_ID/messages` | Bearer token; optional `after` and `wait` query values. | 200 `{messages: [{sequence, envelope}, ...]}` in ascending sequence order. Returns up to 100 retained packets newer than `after`. Defaults: `after=0`, `wait=0`. `wait` is an integer from 0 to 20 seconds for long polling; `after` is a nonnegative decimal integer of at most 18 digits. |
| POST | `/v1/rooms/ROOM_ID/messages` | Bearer token; JSON with exactly `{envelope: "..."}`. | Stores one encrypted packet, applies retention, wakes waiting readers; 201 `{sequence: N}`. The first accepted packet implicitly creates the room's retained history. |
| GET | `/v1/rooms/ROOM_ID/presence` | Bearer token; no body/query. | 200 `{users: ["encrypted presence envelope", ...]}` for currently live sessions. Decrypted names and presence tokens are not included. |
| POST | `/v1/rooms/ROOM_ID/presence` | Bearer token; JSON described below. | Joins/refreshes or leaves a presence session. Returns 200 `{joined: true/false}` or `{left: true}`. |

### Presence requests

To join or refresh, send exactly `{token, envelope, announcement}`. Here `token` is a client-generated 64-character lowercase hexadecimal **presence token**, separate from the server login token. `envelope` encrypts the user's presence/name, and `announcement` encrypts a join wall message. A new session stores the join announcement in normal room history and returns `joined: true`; refreshes update its expiry without storing another join announcement and return `joined: false`.

Presence expires after 60 seconds without refresh; the CLI refreshes every 20 seconds. The relay allows up to 100 live sessions per room and 1,000 in total. Expiry removes presence without generating a leave wall message.

To leave, send `{token}` or `{token, announcement}`, where the optional announcement encrypts a leave wall message. A live matching session is removed and its supplied announcement is retained in normal message history. Leaving an absent session is harmless and returns `left: true` without storing an announcement. The relay does not decrypt presence or announcement contents.

### History, errors, and limits

Start with `after=0` to retrieve retained history, then keep the highest returned `sequence` and poll after it. Sequences are allocated across the database, so gaps within one room are normal. More than 100 retained packets requires multiple calls. An empty array means no newer retained packets arrived during the requested wait. History retention applies to join/leave announcements as well as messages; it does not store plaintext.

Encrypted envelopes are protocol-1, URL-safe Base64 packets produced by the client encryption code. The relay checks their header, encoding and size, with a maximum envelope length of 11,000 characters; a generic string or raw plaintext is not a valid message body. Offline `encrypt`/`decrypt` commands document client-side usage elsewhere in this README.

Room POST requests, including presence refreshes/leaves, share a per-visitor-IP bucket with a burst capacity of 30 and refill of one request per second. Excess requests return 429. Login has its separate cooldown. Direct mode uses the socket peer IP; tunnel mode requires a loopback connector and one valid `CF-Connecting-IP` header for login and room requests, returning 403 if that requirement fails. See the Cloudflare Tunnel setup section for enabling this mode.

Errors use `{error: "..."}`: 400 for invalid fields/query/envelopes or reached relay capacity, 401 for missing/invalid/expired login (room responses include `WWW-Authenticate: Bearer`), 403 for tunnel-header failures, 404 for unknown room-route paths, 410 when message polling/posting or presence lookup/join encounters a deleted room, 413 for oversized POST bodies, 429 for rate limits, and 503 for SQLite failures. Presence-only leave requests are idempotent even after deletion. The relay caps concurrent request workers at 64; extra connections can close without a JSON error.

There is no HTTP channel-list, channel-delete, password-reset, or key-distribution endpoint. Channel deletion is restricted to the server console and erases retained messages plus live presence while permanently blocking that room ID. CLI `key list` lists local aliases and room IDs; server-console `channels` lists relay room IDs. Unknown room IDs can return empty history/presence without creating a stored room. Room POST query strings are rejected; presence GET allows no query parameters. Unknown room routes normally return 404 after authentication; other unsupported HTTP methods use the standard HTTP handler's error response.

## Install

Requires Python 3.11 or newer. From this project folder:

```sh
python -m pip install .
```

This installs `noisechat` and its dependencies: `cryptography`, `keyring`, and `prompt_toolkit`. On Windows, `py` can be used instead of `python`. If the `noisechat` command isn't on your PATH, use `python -m noisechat` from this folder.

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

On first run, choose and confirm the separate server access password. Each client below asks for that same password when connecting.

On your client, create the shared key once:

```sh
noisechat key create friends --export friends.noise-key
```

Choose a strong export passphrase when prompted. The raw key goes into your OS keyring; `friends.noise-key` contains an encrypted copy. The export won't overwrite an existing file.

Open two more terminals:

```sh
noisechat join friends --server "http://127.0.0.1:8713" --name Alice
```

```sh
noisechat join friends --server "http://127.0.0.1:8713" --name Bob
```

Type a message and press Enter. Everyone in the channel receives encrypted `[Wall] Alice joined the chat.` and `[Wall] Alice left the chat.` announcements as participants connect and disconnect. When you join, NoiseChat privately prints `Use /users to list users in this channel, and /quit to quit.` `/users` lists connected users in your current channel; `/quit` or Ctrl+C exits. Existing retained messages and announcements appear when you connect, followed by the “Chatting as” message and the `/users` and `/quit` instructions. Incoming messages appear above your current draft while you type; your own relay echo stays silent. After you press Enter, the typed line disappears; your message appears once in the relay's formatted output. Chat input history is not saved.

### Notifications

Incoming messages trigger desktop notifications only when the terminal window is out of focus. In interactive `join`, the title also changes from `NoiseChat` to `New Message - NoiseChat` and returns to `NoiseChat` when the terminal regains focus. NoiseChat emits no terminal bell. Focus is checked at the terminal window level: if a window has multiple tabs and another tab is selected, the window is still focused, so NoiseChat does not send a notification or mark its title unread. If focus cannot be determined, NoiseChat stays quiet.

Windows uses toast notifications and requests taskbar attention. KDE uses `notify-send`, `dunstify`, or `kdialog`; Fedora KDE Wayland also needs `kdotool` for focus detection (`sudo dnf install kdotool`). Hyprland/Arch uses `hyprctl` for focus detection and prefers `notify-send` or `dunstify` for desktop notifications, with native `hyprctl notify` as the fallback when neither sender is installed. On Arch, `libnotify` provides `notify-send`; run a notification daemon such as `mako`, `dunst`, or `swaync`. KDE already provides a notification service. X11 focus detection uses `xdotool`. macOS uses `osascript`.

Terminal settings can override application titles. In [Windows Terminal](https://learn.microsoft.com/en-us/windows/terminal/customize-settings/profile-advanced#suppress-title-changes), allow application title changes (`suppressApplicationTitle: false`). In Konsole, NoiseChat automatically switches the current session to the application-controlled tab title using its native session-title command; this does not edit your saved profile. The shell can update the title again after you quit.

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
| `noisechat key list` | List local key aliases and their derived room IDs without printing any key material. |
| `noisechat key remove CHAT` | Delete your local keyring entry; other people's copies and exported files still work. |
| `noisechat join CHAT --server "SERVER" --name NAME` | Join a channel, announce your arrival, and send and receive interactively. Keeps your online status refreshed while running. |
| `noisechat users CHAT [CHAT ...] --server "SERVER"` | List all connected chat sessions and their channels for one or more shared keys you hold. |
| `noisechat send CHAT --server "SERVER" --name NAME` | Prompt for one message, encrypt and send it, then exit. Does not join the online roster. |
| `noisechat listen CHAT --server "SERVER"` | Read retained messages and keep listening. This is an unnamed, receive-only command; it does not join the online roster. |
| `noisechat encrypt CHAT --name NAME` | Prompt for text and print copyable ciphertext without contacting a server. |
| `noisechat decrypt CHAT` | Prompt for ciphertext and decrypt it locally without contacting a server. |

| Option | Applies to | What it does |
| --- | --- | --- |
| `--urls "HTTP_URL"` | `run` | One HTTP listen URL with an explicit port; defaults to `http://127.0.0.1:8713`. Use `http://0.0.0.0:8713` for other machines. Port `0` asks the OS to choose an available port. |
| `--database FILE` | `run` | SQLite ciphertext database; defaults to `relay.sqlite3` in the current directory. |
| `--auth-file FILE` | `run` | Server password hash file; defaults to `DATABASE.auth.json` beside the database. |
| `--reset-password` | `run` | Set a new server password locally before starting; invalidates old sessions after restart. |
| `--password-file FILE` | `run`, `join`, `users`, `send`, `listen` | Read a server access password from a private UTF-8 file. For `run`, used only during first-run setup or password reset. |
| `--cloudflare-tunnel` | `run` | Use Cloudflare's visitor-IP header for login/message limits. Requires a loopback listener and trusted local `cloudflared`; invalid or missing headers are rejected. |
| `--export FILE` | `key create` | Also write a password-encrypted copy of the new key. |
| `--no-store` | `key create` | Save only the encrypted export instead of using the keyring; requires `--export`. |
| `--replace` | `key import` | Explicitly allow replacing a key already saved under the local chat name. |
| `--key-file FILE` | `key info`, `join`, `users`, `send`, `listen`, `encrypt`, `decrypt` | Unlock an encrypted file instead of reading the keyring. For `users`, this supports one channel per invocation. |
| `--server "URL"` | `join`, `users`, `send`, `listen` | Required relay URL. |
| `--name NAME` | `join`, `send`, `encrypt` | Required display name, encrypted before transmission. |
| `--stdin` | `send`, `encrypt` | Read UTF-8 message text from standard input instead of prompting. |
| `--once` | `listen` | Read one batch immediately, print its cursor, and exit. |
| `--after NUMBER` | `listen` | Start after a previous relay cursor; defaults to `0` for retained history. |

Inside interactive `join`:

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

Usernames and join/leave announcements remain encrypted. You need each channel's key to identify its connected users; there is no public server-wide directory of plaintext names or channels. `users` itself does not join or announce a new user. Invalid encrypted roster entries are ignored.

Interactive chat refreshes its presence every 20 seconds. A normal exit removes the session immediately and publishes a leave announcement; after a crash or lost connection it expires within 60 seconds of the last accepted refresh without publishing a leave event. The relay keeps this presence state only in memory. After a relay restart, running clients register again on their next refresh and announce their return. Historical join/leave notices are retained like chat messages, so use `users` for current online status.

Upgrade both the relay and clients to v0.4.16 for the current presence, join/leave, and notification behavior. Older clients can still exchange text messages, but cannot interpret the newer encrypted event types.

## Give a friend access

Copy `friends.noise-key` onto the USB drive. Give your friend its export passphrase and the separate server access password in person. On their device:

```sh
noisechat key import friends /path/to/usb/friends.noise-key
noisechat key info friends
noisechat join friends --server "https://your-relay.example.com" --name Bob
```

Windows paths work too, for example `E:\friends.noise-key`. Import asks for the export passphrase; connecting asks for the server access password. Compare the room ID printed by `key info` with yours to confirm that you imported the same key. Their local chat name can differ; the key determines the room.

Each friend imports the **same exported key**. Running `key create` independently generates a different chat, even if everyone uses the name `friends`.

The server uses no USB key file and needs no chat key at all.

## Key storage

Default client storage uses a native OS credential store:

- Windows: Credential Manager.
- Linux: Secret Service (for example an unlocked GNOME Keyring) or KWallet.
- macOS native Keychain is also accepted, although this release targets Windows/Linux.

The client refuses unknown and plaintext keyring backends. Your keyring protects the key at rest according to its configuration; it can be accessible to programs running as your user while unlocked. It cannot protect a compromised client, and the chat key/plaintext necessarily exist in the client process's memory during use. Python does not guarantee secure memory erasure.

`noisechat key list` reads a small alias index kept in the same native keyring and prints each local alias with its derived room ID. The index contains aliases only, never raw keys. Keys created or imported by older releases may not have an index entry; re-import them with `key import ... --replace` under the same alias to record them.

If a Linux machine has no desktop keyring, keep only an encrypted key file and unlock it each time:

```sh
noisechat key create friends --export friends.noise-key --no-store
noisechat join friends --key-file friends.noise-key --server "http://127.0.0.1:8713" --name Alice
```

The key-file passphrase is prompted with input hidden; it is never a command-line argument or environment variable. Connecting also prompts for the separate server access password. With `--key-file`, the chat key is kept in process memory and isn't saved in a credential store. Exports are created with mode 0600 on Unix and remain password-encrypted on every OS.

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
noisechat join friends --server "http://192.168.1.50:9000" --name Alice
```

If you save the relay command in a startup script or service, change `--urls` there to keep your chosen port across restarts. To change the program's built-in default instead, edit `DEFAULT_RELAY_URL` near the top of `noisechat/cli.py`, then reinstall with `python -m pip install .`. There is no separate port configuration file. Running `noisechat run` without `--urls` uses that default.

Allow the chosen port through your host firewall if needed. For internet hosting, place the relay behind an HTTPS reverse proxy and connect with `https://...`. `/health` returns the release and protocol versions. SQLite retains ciphertext across restarts. Copy the database safely with SQLite's backup tools if needed; an active WAL database cannot be backed up reliably by copying just the main file.

Requests and responses are size-limited. The server permits at most 64 request handlers and bounds its rate-limit cache. Online presence is limited to 100 sessions per channel and 1,000 total. POSTs, including presence refreshes and departures, use a per-source-IP token bucket (burst 30, refill one request/second). Direct mode uses the TCP peer's IP, so clients behind another reverse proxy can share its allowance. Cloudflare Tunnel mode uses the validated visitor IP instead. Routine request logging is disabled so room URLs aren't written into its own access log. Your proxy may still log them.

### Cloudflare Tunnel

A Cloudflare Tunnel forwards a public HTTPS hostname to NoiseChat through `cloudflared`. The connector and relay must run on the same machine and share the same network namespace for NoiseChat's tunnel mode. The origin listens only on loopback; clients connect to the public HTTPS hostname. You do not need an inbound router port or a publicly exposed relay listener. Follow [Cloudflare's tunnel setup guide](https://developers.cloudflare.com/tunnel/get-started/) for connector installation and tunnel creation.

#### What the mode does

```text
NoiseChat client → HTTPS → Cloudflare → encrypted tunnel → cloudflared → loopback HTTP → NoiseChat relay
```

Cloudflare adds the visitor's IP in [`CF-Connecting-IP`](https://developers.cloudflare.com/fundamentals/reference/http-headers/#cf-connecting-ip). Normally, the relay sees every tunnel request arriving from the local connector, so all visitors share the connector's cooldown. `--cloudflare-tunnel` uses that visitor header for **both** the five-login-attempts-per-minute limit and the separate POST/message rate limit. IPv6 spellings and IPv4-mapped IPv6 addresses are normalized so alternate spellings do not create extra allowances. Visitors with different public IPs get separate limits; people sharing a public IP still share a limit.

The option is off by default. When enabled, it refuses wildcard/LAN listener addresses, accepts requests only from a loopback peer, and requires exactly one valid IP in `CF-Connecting-IP` for login and channel requests. Missing, malformed, duplicate, or comma-separated values receive HTTP 403 before consuming any visitor's allowance. It does not fall back to a shared connector-IP bucket. `/health` stays available without that header. Direct mode ignores `CF-Connecting-IP`, `X-Forwarded-For`, and other forwarded IP headers.

Only enable this mode for a listener used by your trusted local connector. Loopback is a network restriction, not proof of which local process sent a request: other programs on that trusted machine can also supply headers. If using containers, the connector and relay must share a network namespace, such as supported host networking; separate bridge-network containers do not share `127.0.0.1`. Do not solve that by exposing this listener to the LAN. Remote connectors and arbitrary reverse proxies are not supported by this mode.

#### Set it up

1. Install/update NoiseChat from the checkout with `python -m pip install .`. Use v0.4.16 on the relay and clients so leave announcements and the current protocol behavior match. You also need a Cloudflare account and a domain managed by Cloudflare for a permanent public hostname.
2. Start NoiseChat on the machine that will run `cloudflared`:

   ```sh
   noisechat run --urls "http://127.0.0.1:8713" --cloudflare-tunnel
   ```

   On first run, set and confirm the server access password. On later starts, keep the same database/authentication-file paths; the saved password hash is loaded. Keep `--cloudflare-tunnel` in your startup command or service. For another local port, change both `--urls` and the tunnel's service URL.
3. In Cloudflare's dashboard, open **Networking → Tunnels**, create a tunnel, and follow the operating-system installation instructions to run `cloudflared` on this same machine. If you already have a connector/tunnel there, use it and add another route.
4. Add a **Published application** route with your chosen hostname, for example `chat.example.com`, and service URL **`http://127.0.0.1:8713`**. The origin service is HTTP on loopback; the public client URL is HTTPS. If the form separates service type and address, select HTTP and enter `127.0.0.1:8713`.
5. Keep Cloudflare's visitor-IP header enabled. Do not apply the **Remove visitor IP headers** transform to this hostname or remove/replace the header with another proxy or Worker. Tunnel mode rejects requests without a valid header.
   If Cloudflare blocks the CLI before it reaches the tunnel, add a WAF rule for the NoiseChat hostname (or subdomain) that skips **Browser Integrity Check**. The CLI is not a browser and may be challenged by that check.
6. Give friends the public HTTPS URL, server access password, and their channel's encrypted key export/passphrase. Once the chat key is imported, connect:

   ```sh
   noisechat join friends --server "https://chat.example.com" --name Alice
   ```

   Clients need neither `cloudflared` nor a tunnel-mode flag. They enter the server password when prompted. They should use the public hostname, including when testing on the relay machine; a direct local NoiseChat client cannot supply the connector header.

#### Check and troubleshoot

Check `https://chat.example.com/health` for health/version information, then connect with NoiseChat to test password login and messaging. Health alone does not verify visitor-header forwarding.

| Symptom | Check |
| --- | --- |
| Startup says the mode requires loopback. | Use `http://127.0.0.1:8713`, `http://[::1]:8713`, or `http://localhost:8713`; `localhost` is bound explicitly to IPv4 loopback. |
| Cloudflare returns HTTP 502. | Make sure the relay is running and the service URL matches its address/port. Verify that the connector shares its network namespace. |
| NoiseChat returns HTTP 403. | Connect through the public hostname. Ensure the connector supplies exactly one valid `CF-Connecting-IP`, and no transform/proxy removes it. |
| NoiseChat reports a login cooldown. | Wait for the reported time. Limits apply to your public IP; another person on the same public IP can share that allowance. |
| Clients still share the connector's allowance. | Restart the relay with `--cloudflare-tunnel` and confirm its startup message reports Cloudflare Tunnel mode. |

**A public tunnel alone does not add authentication.** NoiseChat now supplies its own server-password gate and login cooldown, so strangers cannot use channel endpoints without that password. Keep the origin bound to localhost, configure the server password locally first, and share only the public HTTPS URL with clients. The public hostname still receives unauthenticated traffic, and a shared-password holder can create channels or use relay capacity.

Cloudflare Access can provide an additional gate; see its [Access setup guidance](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/). For a CLI, Access's [service tokens](https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/) authenticate requests using `CF-Access-Client-Id` and `CF-Access-Client-Secret` headers with a Service Auth policy. **NoiseChat does not currently supply those headers or perform Cloudflare's browser login**, so that additional Access-protected setup needs client integration first. Tunnel mode only changes trusted visitor-IP handling; it does not enable Cloudflare Access. Cloudflare terminates public HTTPS and can see the server login password, access tokens, and routing metadata; message contents remain encrypted, and clients never send the chat key. A private VPN/network is another way to restrict who reaches the relay.

## Message storage and retention

The relay stores encrypted message history. The default `relay.sqlite3` database is created in the relay's working directory; `noisechat run --database FILE` selects a different path. It keeps encrypted history across server restarts so clients can retrieve messages they missed while offline. There is one database for all channels, not one file per key.

Each row in the `messages` table contains:

| Field | Stored value |
| --- | --- |
| `sequence` | A server-assigned integer cursor used to retrieve packets in order. |
| `room` | The derived room ID used to route packets. This is neither the secret key nor your local chat alias. |
| `digest` | A SHA-256 hash of the encrypted envelope, used to suppress duplicate submissions while retained. |
| `envelope` | The encrypted packet, including its encrypted message/event type, sender, text, message ID, and timestamp. Join announcements are stored here too. |

The database contains no raw chat keys, key-file passphrases, server access passwords or login tokens, plaintext message bodies, plaintext display names, or local chat aliases. SQLite also keeps its indexes, sequence metadata, and a `deleted_rooms` table containing only blocked room IDs. The separate `DATABASE.auth.json` file stores the salted server-password verifier. Login session hashes, cooldown counters, online presence, departure tokens, and source-IP rate-limit caches are held only in memory; presence expires within 60 seconds of its last accepted refresh, and all presence and login sessions are cleared on restart. The client does not write a plaintext transcript, although your terminal's scrollback or logging may retain displayed text.

History retention is **based on packet counts, not time**:

- At most **500 retained packets per room**, counting messages and join announcements.
- At most **10,000 retained packets across the relay**. This global limit can trim a room below 500 packets.
- At most **100 rooms** with retained history or active presence.
- New packets cause the oldest retained packets to be removed when a limit is exceeded. Reading a message does not delete it.
- There is **no age-based expiration**. If a room is quiet and the global limit is not reached, its encrypted history can remain indefinitely, including across restarts.

The history limits are defined by `RelayStore` defaults in `noisechat/relay.py`; there are currently no CLI flags to change them. SQLite can retain previously allocated disk pages after row deletion, so retention is not a promise of secure erasure. Server-console channel deletion is separate from removing a local key. Blocked room IDs do not count toward the active-room limit.

### How history appears when you connect

`noisechat join` automatically displays retained history when you connect. A new client session starts its in-memory cursor at `0`, requests the room's retained packets from the relay, decrypts them locally, and prints them in relay sequence order, oldest first. History includes retained join announcements and your own earlier messages. Responses contain at most 100 packets, and `join` keeps reading further batches before long-polling for new messages. The “Chatting as” message and command instructions print after the initial history has finished loading. Retained history does not trigger desktop notifications or unread titles; new messages received afterward do. There is no separate restore command.

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

HTTP still hides message contents from someone who lacks the chat key, but exposes the server login password, access tokens, room IDs, IP addresses, approximate sizes, timing, and traffic patterns. HTTP observers can steal relay access or disrupt traffic. HTTPS protects the transport and authenticates the server, so use it for remote connections. The relay password authorizes server use; it does not grant access to any channel's decrypted messages or make a shared-key holder a verified person.

Online status exposes connection counts and presence timing to the relay. Each chat session uses a random private token to refresh or remove its presence; that token is sent over the transport but is never in the public roster or SQLite database. HTTP observers can capture it, so use HTTPS to protect presence updates too. The roster is a relay-reported view, not proof of a person's identity or guaranteed connectivity; a relay or key holder can replay or fabricate presence.

All shared-key holders can read all messages and use any display name. Names are not cryptographic identities. A relay can delay, reorder, omit, or replay messages; client replay suppression is session-local and bounded. This version has no forward secrecy: if the shared key is later compromised, captured old ciphertext can be decrypted. Rotate by creating a new key and distributing it again.

This is an initial implementation built on standard cryptography libraries, not a security-audited messaging protocol. Audio, per-person identities/keys, forward secrecy, and persistent replay state are future work.

## Development

```sh
python -m unittest discover -s tests -v
python -m compileall -q noisechat tests
```

Tests cover randomized encryption, Unicode, authentication failures, server-password setup/reset/persistence, unauthenticated channel rejection, login cooldowns and session expiry/restart, Cloudflare visitor-IP isolation and normalization, rejected/untrusted forwarding headers, tunnel listener restrictions, private password files, key-file tampering/passwords, keyring overwrite protection, exclusive exports, two-client exchange through the real HTTP handler, encrypted message wire/database contents, encrypted join notices and user rosters, presence expiry/refresh/departure, room isolation, persistence/retention, rate limiting, polling, replay rejection, terminal escapes, submitted-input clearing, wrapped Unicode drafts during incoming output, and stream restoration on interruption. The native TCP test runs when sockets are allowed and explicitly skips in restricted environments. Keyring operations are tested with an in-memory test backend; a real OS keyring must be available for normal key creation/import.

`pyproject.toml` owns the release version and dependency declarations. `noisechat/` is split into crypto formats and shared protocol/file limits, OS-key storage, server access, relay, client, terminal input, and CLI responsibilities. There are no runtime overrides or frontend build tools. `python -m noisechat` works from the source checkout once dependencies are installed; installing the package provides the `noisechat` entry point.

## v0.4.16

- Fix NoiseChat failing to start because `KeyStore.list()` shadowed the built-in `list` in later class type annotations.
- Add regression coverage for the affected annotations, with no changes to stored keys, encryption, or the relay protocol.

## v0.4.15

- Document every relay HTTP route, password/session authorization, encrypted payloads, presence lifecycle, polling/history, errors, and request limits.
- Clarify room routing versus access, separate presence tokens from login tokens, and identify server-console-only operations.

## v0.4.14

- Consolidate Hyprland detection and the KDE/X11 focus-probe branches.
- Reuse the selected keyring while listing keys; share alias validation and remove unreachable reserved-name checks.
- Share message, key-file, password-file, and polling limits between their producers and consumers.
- Remove redundant CLI alias checks and an unused focus-timeout parameter.
- Preserve notification/title behavior, history ordering, encrypted formats, older-client compatibility, and relay retention.
- Audit found no orphan source files or unused imports; add no runtime dependencies.

## v0.4.13

- Update Konsole tab titles even when the profile normally shows the directory and program name.
- Print joining instructions after all initial history batches have loaded.
- Keep history loading quiet and preserve notification behavior for live messages.

## v0.4.12

- Route unread terminal titles through the prompt renderer, preserving drafts and avoiding escaped text and terminal bells.
- Reset the title on focus and keep Windows window detection stable across title changes.
- Prefer desktop notification services on Hyprland and allow its focus probe more time.
- Document notification setup and the behavior of focused windows with multiple tabs.

## v0.4.10

- Make KDE Wayland focus detection reliable when `kdotool` needs more than a short D-Bus startup window.
- Prefer `kdotool` over X11 tools on KDE Wayland so notifications are not incorrectly suppressed.

## v0.4.9

- Show desktop notifications and taskbar attention only after confirming the chat window is out of focus.
- Add KDE Wayland `kdotool` focus detection and keep unknown compositor focus states quiet.

## v0.4.8

- Remove terminal sound output completely; incoming messages use desktop notifications and Windows taskbar attention only.
- Add native Hyprland notifications plus `dunstify` fallback support for Arch/Linux desktops.
- Resolve a visible Windows Terminal window by console title before attempting taskbar flashing.

## v0.4.7

- Add best-effort desktop notifications for Windows, Fedora/KDE, and macOS.
- Correct the Windows `FLASHWINFO` structure and use taskbar/caption flashing when the terminal supports it.

## v0.4.6

- Print a private join-time help message with the `/users` and `/quit` commands.
- Notify only for received text messages; local relay echoes remain silent.

## v0.4.5

- Publish encrypted leave wall announcements for clean client disconnects.
- Add `noisechat key list` for local key aliases and room IDs.
- Add desktop attention notifications for incoming messages and request Windows taskbar flashes when supported.
- Document the Cloudflare Browser Integrity Check exception that may be needed for CLI traffic.

## v0.4.4

- Rename the interactive channel command to `join` and update the command reference, examples, and transport tests.
- Clarify the 12-hour token lifetime and why starting a new client prompts for the server password again.

## v0.4.3

- Simplify the invalid server-password input error to `Password incorrect`.

## v0.4.2

- Show the minimum length in the first-run server-password prompt.
- Clear submitted chat input so each message appears only in the relay output; preserve drafts when incoming messages arrive.
- Clarify retained-message storage and automatic history display.
- Verify that server-console channel deletion removes all of that channel's messages.

## v0.4.1

- Add an explicit Cloudflare Tunnel mode with loopback-only origin binding.
- Use validated, normalized `CF-Connecting-IP` addresses for login cooldowns and POST rate limits.
- Reject missing, malformed, duplicate, and nonlocal forwarding requests; preserve direct-mode IP handling.
- Document tunnel behavior, setup, password protection, and troubleshooting.

## v0.4.0

- Require a separate server access password and temporary login token for channel endpoints.
- Save a salted PBKDF2-HMAC-SHA256 verifier locally; configure/reset passwords only before starting the server.
- Match TL/TLS's five login attempts per source IP per minute, with cooldown messages and `Retry-After`.
- Add hidden client password prompts and private password files for noninteractive commands.
- Reauthenticate after session expiry or relay restart; stop background attempts on wrong passwords or login cooldowns.
- Update setup, command reference, database storage, and Cloudflare Tunnel instructions.

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
