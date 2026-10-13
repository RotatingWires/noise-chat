"""Client transport and terminal-safe rendering."""

import base64
import json
import os
import secrets
import shutil
import sys
import subprocess
import threading
import unicodedata
from collections import OrderedDict
from datetime import datetime
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .auth import ServerAccessError, password_bytes
from .crypto import (MAX_ENVELOPE_CHARS, MAX_PRESENCE_PER_ROOM, PRESENCE_HEARTBEAT, PRESENCE_TTL,
                     ChannelDeletedError, NoiseChatError, decrypt_message, encrypt_event, encrypt_message, room_id)


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, server: str, key: bytes, password: str | None = None):
        try:
            parsed = urlsplit(server)
            port = parsed.port
        except ValueError:
            raise NoiseChatError("Invalid relay URL.") from None
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}
                or port == 0):
            raise NoiseChatError("Use a relay URL such as https://chat.example.com or http://HOST:PORT.")
        self.key = key
        self.server = server.rstrip("/")
        self.url = self.server + "/v1/rooms/" + room_id(key)
        if password is not None:
            password_bytes(password)
        self.password = password
        self.token = None
        self.sent_message_ids = OrderedDict()
        self.login_lock = threading.Lock()
        self.opener = build_opener(NoRedirects())

    def _request(self, url: str, method: str, body: dict | None, timeout: int,
                 token: str | None = None, login: bool = False) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        request = Request(url, data=data, method=method, headers=headers)
        try:
            with self.opener.open(request, timeout=timeout) as response:
                raw = response.read(1200001)
        except HTTPError as error:
            status = error.code
            retry = error.headers.get("Retry-After", "60") if error.headers else "60"
            error.close()
            if status == 401:
                raise ServerAccessError("Incorrect server password." if login else "Server session expired or was revoked.") from None
            if status == 429 and login:
                seconds = int(retry) if retry.isascii() and retry.isdecimal() and len(retry) <= 3 else 60
                raise ServerAccessError(f"Too many login attempts. Try again in {max(1, min(seconds, 60))} seconds.") from None
            if status == 410:
                raise ChannelDeletedError() from None
            raise NoiseChatError(f"Relay returned HTTP {status}.") from None
        except (URLError, TimeoutError, OSError, HTTPException):
            raise NoiseChatError("Could not reach the relay. Check its URL and connection.") from None
        if len(raw) > 1200000:
            raise NoiseChatError("Relay response is too large.")
        try:
            value = json.loads(raw)
        except (UnicodeError, ValueError, RecursionError):
            raise NoiseChatError("Relay returned invalid JSON.") from None
        if not isinstance(value, dict):
            raise NoiseChatError("Relay returned an invalid response.")
        return value

    def authenticate(self, previous_token: str | None = None) -> str:
        with self.login_lock:
            if self.token is not None and self.token != previous_token:
                return self.token
            if self.password is None:
                raise ServerAccessError("A server access password is required.")
            value = self._request(self.server + "/v1/auth/login", "POST", {"password": self.password}, 5, login=True)
            token = value.get("token")
            if not isinstance(token, str) or len(token) != 64 or any(char not in "0123456789abcdef" for char in token):
                raise NoiseChatError("Relay returned an invalid server session.")
            self.token = token
            return token

    def request(self, method: str, query: dict | None = None, body: dict | None = None,
                resource: str = "messages", timeout: int = 25) -> dict:
        url = self.url + "/" + resource + ("?" + urlencode(query) if query else "")
        token = self.authenticate()
        try:
            return self._request(url, method, body, timeout, token)
        except ServerAccessError:
            # Relay restarts and expiry invalidate in-memory sessions. Reauthenticate once.
            token = self.authenticate(previous_token=token)
            return self._request(url, method, body, timeout, token)

    def send(self, sender: str, text: str) -> int:
        envelope = encrypt_message(self.key, sender, text)
        # The relay echoes ciphertext back to the sender. Remember local IDs
        # before posting so a fast poll cannot ring for the local echo.
        message_id = decrypt_message(self.key, envelope)["id"]
        self.sent_message_ids[message_id] = None
        while len(self.sent_message_ids) > 10000:
            self.sent_message_ids.popitem(last=False)
        try:
            value = self.request("POST", body={"envelope": envelope})
            if type(value.get("sequence")) is not int or not 0 < value["sequence"] < 2**63:
                raise NoiseChatError("Relay returned an invalid message receipt.")
        except NoiseChatError:
            self.sent_message_ids.pop(message_id, None)
            raise
        return value["sequence"]

    def poll(self, after: int, wait: int = 20) -> list[dict]:
        value = self.request("GET", query={"after": after, "wait": wait})
        messages = value.get("messages")
        if not isinstance(messages, list) or len(messages) > 100:
            raise NoiseChatError("Relay returned an invalid message batch.")
        last = after
        for message in messages:
            if (not isinstance(message, dict) or set(message) != {"sequence", "envelope"}
                    or type(message["sequence"]) is not int or not last < message["sequence"] < 2**63
                    or not isinstance(message["envelope"], str) or len(message["envelope"]) > MAX_ENVELOPE_CHARS):
                raise NoiseChatError("Relay returned an invalid message batch.")
            last = message["sequence"]
        return messages

    def connect(self, token: str, sender: str) -> None:
        body = {"token": token, "envelope": encrypt_event(self.key, sender, "presence"),
                "announcement": encrypt_event(self.key, sender, "join")}
        value = self.request("POST", body=body, resource="presence", timeout=5)
        if type(value.get("joined")) is not bool:
            raise NoiseChatError("Relay returned an invalid presence receipt.")

    def disconnect(self, token: str, sender: str | None = None) -> None:
        body = {"token": token}
        if sender is not None:
            body["announcement"] = encrypt_event(self.key, sender, "leave")
        value = self.request("POST", body=body, resource="presence", timeout=5)
        if value.get("left") is not True:
            raise NoiseChatError("Relay returned an invalid departure receipt.")

    def users(self) -> list[dict]:
        value = self.request("GET", resource="presence", timeout=5)
        entries = value.get("users")
        if (not isinstance(entries, list) or len(entries) > MAX_PRESENCE_PER_ROOM
                or any(not isinstance(entry, str) or len(entry) > MAX_ENVELOPE_CHARS for entry in entries)):
            raise NoiseChatError("Relay returned an invalid user list.")
        users = {}
        for entry in entries:
            try:
                message = decrypt_message(self.key, entry)
            except NoiseChatError:
                continue
            if message["kind"] == "presence":
                users[message["id"]] = message
        return sorted(users.values(), key=lambda user: (user["sender"].casefold(), user["id"]))


class Presence:
    """Refresh one encrypted online session; its private token is never in the roster."""
    def __init__(self, client: Client, sender: str, output=print, stop: threading.Event | None = None):
        self.client, self.sender, self.output = client, sender, output
        self.token = secrets.token_hex(32)
        self.stop = stop if stop is not None else threading.Event()
        self.thread = threading.Thread(target=self.maintain, daemon=True)

    def start(self) -> None:
        self.client.connect(self.token, self.sender)
        self.thread.start()

    def maintain(self) -> None:
        delay, offline = PRESENCE_HEARTBEAT, False
        while not self.stop.wait(delay):
            try:
                self.client.connect(self.token, self.sender)
                if offline:
                    self.output("[Online status restored.]")
                delay, offline = PRESENCE_HEARTBEAT, False
            except (ChannelDeletedError, ServerAccessError) as error:
                if not self.stop.is_set():
                    self.stop.set()
                    self.output(f"[{error} Press Enter to exit.]")
            except NoiseChatError as error:
                if not offline:
                    self.output(f"[Online status not confirmed: {error} Retrying...]")
                delay, offline = 5, True

    def close(self) -> None:
        self.stop.set()
        # Heartbeats use a five-second request timeout. Finish one before leaving.
        self.thread.join()
        try:
            self.client.disconnect(self.token, self.sender)
        except NoiseChatError:
            self.output(f"[Could not confirm departure; online status expires within {PRESENCE_TTL} seconds.]")


def terminal_text(value: str) -> str:
    # Remote text cannot inject ANSI escapes, carriage returns, or bidi controls.
    return "".join(f"\\u{ord(char):04x}" if unicodedata.category(char) in {"Cc", "Cf", "Cs"} else char for char in value)


def render_message(message: dict) -> str:
    timestamp = datetime.fromisoformat(message["sent_at"]).astimezone().strftime("%H:%M")
    if message["kind"] == "join":
        return f"[{timestamp}] [Wall] {terminal_text(message['sender'])} joined the chat."
    if message["kind"] == "leave":
        return f"[{timestamp}] [Wall] {terminal_text(message['sender'])} left the chat."
    return f"[{timestamp}] {terminal_text(message['sender'])}: {terminal_text(message['text'])}"


def _spawn_background(command: list[str], windows: bool = False) -> None:
    options = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if windows:
        options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    else:
        options["start_new_session"] = True
    try:
        process = subprocess.Popen(command, **options)
        threading.Thread(target=process.wait, daemon=True).start()
    except (OSError, ValueError, subprocess.SubprocessError):
        pass


def _windows_taskbar_window(ctypes):
    kernel32, user32 = ctypes.windll.kernel32, ctypes.windll.user32
    # Windows Terminal hosts CLI programs in a pseudoconsole. Its
    # GetConsoleWindow result is not the visible taskbar window, so first
    # resolve the visible top-level window by the current console title.
    title = ctypes.create_unicode_buffer(512)
    if kernel32.GetConsoleTitleW(title, len(title)):
        window = user32.FindWindowW(None, title.value)
        if window and user32.IsWindowVisible(window):
            return window
    window = kernel32.GetConsoleWindow()
    return window if window and user32.IsWindowVisible(window) else None


def _windows_window_is_focused() -> bool | None:
    try:
        import ctypes
        window = _windows_taskbar_window(ctypes)
        if not window:
            return None
        return ctypes.windll.user32.GetForegroundWindow() == window
    except (AttributeError, OSError, TypeError, ValueError):
        return None


_ATTENTION_TITLE = "New Message - NoiseChat"
_DEFAULT_TERMINAL_TITLE = "NoiseChat"
_attention_title_lock = threading.Lock()
_attention_title_active = False
_attention_title_stop = threading.Event()
_attention_title_thread = None
_windows_original_title = None


def _set_terminal_title(title: str) -> None:
    """Set the current terminal tab/window title without affecting chat input."""
    global _windows_original_title
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            if _windows_original_title is None:
                original = ctypes.create_unicode_buffer(512)
                kernel32.GetConsoleTitleW(original, len(original))
                _windows_original_title = original.value
            kernel32.SetConsoleTitleW(title)
        except (AttributeError, OSError, TypeError, ValueError):
            pass
        return
    try:
        sys.stdout.write(f"\033]0;{title}\a")
        sys.stdout.flush()
    except (AttributeError, OSError, UnicodeError):
        pass


def _restore_terminal_title() -> None:
    global _windows_original_title
    if sys.platform == "win32":
        try:
            import ctypes
            if _windows_original_title is not None:
                ctypes.windll.kernel32.SetConsoleTitleW(_windows_original_title)
        except (AttributeError, OSError, TypeError, ValueError):
            pass
        finally:
            _windows_original_title = None
        return
    _set_terminal_title(_DEFAULT_TERMINAL_TITLE)


def _watch_attention_title() -> None:
    while not _attention_title_stop.wait(.25):
        if _window_is_focused() is True:
            clear_attention_title()
            return


def _show_attention_title() -> None:
    global _attention_title_active, _attention_title_thread
    with _attention_title_lock:
        if _attention_title_active:
            return
        _set_terminal_title(_ATTENTION_TITLE)
        _attention_title_active = True
        _attention_title_stop.clear()
        _attention_title_thread = threading.Thread(target=_watch_attention_title, daemon=True)
        _attention_title_thread.start()


def clear_attention_title() -> None:
    global _attention_title_active, _attention_title_thread
    with _attention_title_lock:
        if not _attention_title_active:
            return
        _attention_title_active = False
        _attention_title_stop.set()
        _restore_terminal_title()
        _attention_title_thread = None


def _flash_windows_taskbar() -> None:
    try:
        import ctypes
        from ctypes import wintypes

        class FlashWindowInfo(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.UINT), ("hwnd", wintypes.HWND),
                        ("dwFlags", wintypes.DWORD), ("uCount", wintypes.UINT),
                        ("dwTimeout", wintypes.DWORD)]

        window = _windows_taskbar_window(ctypes)
        if window:
            # FLASHW_ALL | FLASHW_TIMERNOFG: flash the caption and taskbar
            # even when the console is not the foreground window.
            info = FlashWindowInfo(ctypes.sizeof(FlashWindowInfo), window, 3 | 12, 3, 0)
            ctypes.windll.user32.FlashWindowEx(ctypes.byref(info))
    except (AttributeError, OSError, TypeError, ValueError):
        pass


_WINDOWS_TOAST_SCRIPT = """
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml('<toast><visual><binding template="ToastGeneric"><text>NoiseChat</text><text>New message received.</text></binding></visual></toast>')
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
$appId = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)
""".strip()


def _desktop_notification() -> None:
    """Best-effort popup using the platform's already-installed notification service."""
    if sys.platform == "win32":
        powershell = shutil.which("powershell.exe") or shutil.which("pwsh")
        if powershell:
            encoded = base64.b64encode(_WINDOWS_TOAST_SCRIPT.encode("utf-16le")).decode("ascii")
            _spawn_background([powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
                               "-EncodedCommand", encoded], windows=True)
        return
    if sys.platform == "darwin":
        osascript = shutil.which("osascript")
        if osascript:
            _spawn_background([osascript, "-e", "display notification \"New message received.\" with title \"NoiseChat\""])
        return
    hyprctl = shutil.which("hyprctl")
    if hyprctl and (os.environ.get("HYPRLAND_INSTANCE_SIGNATURE") or
                    "hyprland" in os.environ.get("XDG_CURRENT_DESKTOP", "").casefold()):
        try:
            result = subprocess.run([hyprctl, "notify", "-1", "5000", "rgb(80aaff)",
                                     "NoiseChat: New message received."],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=1, check=False)
            if result.returncode == 0:
                return
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    for command_name in ("notify-send", "dunstify"):
        command = shutil.which(command_name)
        if command:
            _spawn_background([command, "--app-name=NoiseChat", "--urgency=normal", "--expire-time=5000",
                               "NoiseChat", "New message received."])
            return
    # KDE installations may have kdialog without libnotify's notify-send.
    kdialog = shutil.which("kdialog")
    if kdialog:
        _spawn_background([kdialog, "--title", "NoiseChat", "--passivepopup", "New message received.", "5"])


def _ancestor_pids() -> set[int]:
    """Return this process and its Linux/macOS parent chain where available."""
    pids = set()
    current = os.getpid()
    while current > 1 and current not in pids:
        pids.add(current)
        try:
            if sys.platform.startswith("linux"):
                with open(f"/proc/{current}/stat", encoding="ascii") as stat_file:
                    fields = stat_file.read().rsplit(") ", 1)[1].split()
                current = int(fields[1])
            else:
                result = subprocess.run(["ps", "-o", "ppid=", "-p", str(current)], capture_output=True,
                                        text=True, timeout=.2, check=False)
                current = int(result.stdout.strip()) if result.returncode == 0 and result.stdout.strip() else 1
        except (OSError, ValueError, subprocess.SubprocessError, IndexError):
            break
    return pids


def _focus_pid(command: list[str], timeout: float = 1.0) -> int | None:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        if result.returncode != 0:
            return None
        return int(result.stdout.strip())
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _linux_window_is_focused() -> bool | None:
    ancestors = _ancestor_pids()
    hyprctl = shutil.which("hyprctl")
    if hyprctl and (os.environ.get("HYPRLAND_INSTANCE_SIGNATURE") or
                    "hyprland" in os.environ.get("XDG_CURRENT_DESKTOP", "").casefold()):
        try:
            result = subprocess.run([hyprctl, "activewindow", "-j"], capture_output=True, text=True,
                                    timeout=.2, check=False)
            active_pid = json.loads(result.stdout).get("pid") if result.returncode == 0 else None
            return isinstance(active_pid, int) and active_pid in ancestors
        except (OSError, ValueError, TypeError, subprocess.SubprocessError):
            return None
    kde_wayland = (os.environ.get("XDG_SESSION_TYPE", "").casefold() == "wayland"
                   and (os.environ.get("KDE_FULL_SESSION") or os.environ.get("KDE_SESSION_VERSION")
                        or "kde" in os.environ.get("XDG_CURRENT_DESKTOP", "").casefold()))
    kdotool = shutil.which("kdotool")
    if kde_wayland and kdotool:
        active_pid = _focus_pid([kdotool, "getactivewindow", "getwindowpid"])
        return active_pid in ancestors if active_pid is not None else None
    xdotool = shutil.which("xdotool")
    if xdotool:
        active_pid = _focus_pid([xdotool, "getactivewindow", "getwindowpid"])
        return active_pid in ancestors if active_pid is not None else None
    if kdotool:
        active_pid = _focus_pid([kdotool, "getactivewindow", "getwindowpid"])
        return active_pid in ancestors if active_pid is not None else None
    return None


def _mac_window_is_focused() -> bool | None:
    osascript = shutil.which("osascript")
    if not osascript:
        return None
    active_pid = _focus_pid([osascript, "-e",
                             'tell application "System Events" to unix id of first application process whose frontmost is true'])
    return active_pid in _ancestor_pids() if active_pid is not None else None


def _window_is_focused() -> bool | None:
    if sys.platform == "win32":
        return _windows_window_is_focused()
    if sys.platform == "darwin":
        return _mac_window_is_focused()
    return _linux_window_is_focused()


def notify_message_attention() -> None:
    """Request desktop attention for a received message."""
    if _window_is_focused() is not False:
        return
    _show_attention_title()
    if sys.platform == "win32":
        _flash_windows_taskbar()
    _desktop_notification()


class Receiver:
    def __init__(self, client: Client, output=print, notify=None):
        self.client, self.output = client, output
        self.notify = notify or (notify_message_attention if output is print else lambda: None)
        self.cursor = 0
        self.seen = OrderedDict()

    def receive(self, wait: int = 20) -> int:
        count = 0
        for record in self.client.poll(self.cursor, wait):
            # Bad packets must not block later valid messages in the same batch.
            self.cursor = record["sequence"]
            try:
                message = decrypt_message(self.client.key, record["envelope"])
            except NoiseChatError:
                self.output("[Ignored a message that could not be authenticated.]")
                continue
            if message["id"] in self.seen:
                continue
            if message["kind"] == "presence":
                continue
            self.seen[message["id"]] = None
            while len(self.seen) > 10000:
                self.seen.popitem(last=False)
            local_message = message["id"] in getattr(self.client, "sent_message_ids", ())
            self.output(render_message(message))
            if message["kind"] == "text" and not local_message:
                self.notify()
            count += 1
        return count

    def listen(self, stop: threading.Event) -> None:
        offline = False
        while not stop.is_set():
            try:
                self.receive()
                if offline:
                    self.output("[Reconnected to relay.]")
                offline = False
            except (ChannelDeletedError, ServerAccessError) as error:
                if not stop.is_set():
                    stop.set()
                    self.output(f"[{error} Press Enter to exit.]")
                return
            except NoiseChatError as error:
                if stop.is_set():
                    return
                if not offline:
                    self.output(f"[{error} Retrying...]")
                offline = True
                stop.wait(2)
