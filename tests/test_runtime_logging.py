import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from noisechat import cli
from noisechat.relay import RelayHandler, RelayServer
from noisechat.runtime_logging import SingleFileHandler, console_output, relay_logging


class RuntimeLoggingTests(unittest.TestCase):
    def test_restart_appends_and_context_does_not_capture_other_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "logs" / "console.log"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                with relay_logging(path):
                    console_output("First startup 世界", flush=True)
                    print("private client text")
                console_output("Outside relay")
                with relay_logging(path):
                    console_output("Second startup")
            log = path.read_text()
            self.assertEqual(output.getvalue(), "First startup 世界\nprivate client text\nOutside relay\nSecond startup\n")
            self.assertEqual(log.count("First startup 世界"), 1)
            self.assertEqual(log.count("Second startup"), 1)
            self.assertNotIn("private client text", log)
            self.assertNotIn("Outside relay", log)
            self.assertRegex(log, r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d First startup")

    def test_rollover_uses_one_file_and_caps_utf8_records(self):
        import logging

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "console.log"
            with contextlib.closing(SingleFileHandler(path, max_bytes=20)) as handler:
                for message in ("old message", "世界世界"):
                    handler.handle(logging.makeLogRecord({"msg": message}))
                self.assertEqual(path.read_text(), "世界世界\n")
                handler.handle(logging.makeLogRecord({"msg": "世" * 100}))
                self.assertLessEqual(path.stat().st_size, 20)
                self.assertTrue(path.read_text())
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_run_errors_are_saved_without_password_file_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "relay.sqlite3"
            password = Path(directory) / "server.noise-password"
            password.write_text("private server password words")
            password.chmod(0o600)
            with patch("noisechat.relay.serve", side_effect=OSError("Cannot bind listener")), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(cli.main(["run", "--database", str(database), "--password-file", str(password)]), 1)
            log = (database.parent / "logs" / "console.log").read_text()
            self.assertIn("Server password configured.", log)
            self.assertIn("Error: Cannot bind listener", log)
            self.assertIn("Cannot bind listener", errors.getvalue())
            self.assertNotIn(password.read_text(), log)

    def test_request_and_handler_error_details_remain_suppressed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "console.log"
            with relay_logging(path), contextlib.redirect_stderr(io.StringIO()) as errors:
                RelayHandler.log_message(None, "secret room URL %s", "/v1/rooms/private")
                RelayServer.handle_error(None, None, ("192.0.2.1", 1))
            self.assertEqual(path.read_text(), "")
            self.assertEqual(errors.getvalue(), "")
