"""Client and MCP tests with the HTTP layer mocked: nothing leaves the machine."""
import json
import os
import tempfile
import unittest
from unittest import mock

from jev_sanitizer import Config, JevClient
from jev_sanitizer.mcp_server import Server

Q = {"urgent": {"type": "noul", "instructions": "Is it urgent?", "criteria": {"true": "yes", "false": "no"}}}
FAKE = {"model": "jev-test", "answers": {"urgent": {"type": "noul", "noul": 0.9}}, "usage": {"input_tokens": 10}}


def client(**kw):
    kw.setdefault("log_path", None)
    return JevClient(Config(**kw))


class Ask(unittest.TestCase):
    def test_ok_sends_sanitized_body(self):
        c = client()
        with mock.patch.object(c, "_http", return_value=FAKE) as http:
            out = c.ask("user bob@example.com waiting", Q)
        self.assertEqual(out["status"], "ok")
        sent = json.loads(http.call_args.args[2])
        self.assertIn("<EMAIL>", sent["state"])
        self.assertNotIn("bob@", sent["state"])

    def test_blocked_sends_nothing(self):
        c = client()
        with mock.patch.object(c, "_http") as http:
            out = c.ask("dsn redis://h", Q)
        self.assertEqual(out["status"], "blocked")
        http.assert_not_called()

    def test_questions_are_sanitized_too(self):
        c = client()
        q = {"x": {"type": "noul", "instructions": "about bob@example.com?", "criteria": {"true": "a", "false": "b"}}}
        self.assertNotIn("bob@", json.dumps(c.dry_run("s", q)["would_send"]))

    def test_failure_is_unavailable_not_exception(self):
        c = client()
        with mock.patch.object(c, "_http", side_effect=TimeoutError()):
            self.assertEqual(c.ask("s", Q), {"status": "unavailable", "reason": "TimeoutError"})

    def test_sanitize_off_is_explicit(self):
        c = client(sanitize=False)
        body = c.dry_run("bob@example.com", Q)
        self.assertFalse(body["sanitized"])
        self.assertIn("bob@example.com", body["would_send"]["state"])

    def test_validation(self):
        c = client()
        for state, q in [("", Q), ("s", {}), ("s", {"Bad": Q["urgent"]}),
                         ("s", {"x": {"type": "score", "instructions": "i", "criteria": ["one"]}}),
                         ("s", {"x": {"type": "choice", "instructions": "i", "criteria": {"a": "only"}}})]:
            with self.subTest(q=q):
                with self.assertRaises(ValueError):
                    c.prepare(state, q)

    def test_log_has_no_content_and_is_600(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "log.jsonl")
            c = client(log_path=path)
            with mock.patch.object(c, "_http", return_value=FAKE):
                c.ask("secret-ish state bob@example.com", Q, origin="test")
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            with open(path) as f:
                text = f.read()
            self.assertNotIn("bob", text)
            self.assertNotIn("state", text)


class ConfigKey(unittest.TestCase):
    def test_key_file_must_be_600(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("export TYPESAFE_API_KEY=fake\n")
        try:
            os.chmod(f.name, 0o644)
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(RuntimeError, "600"):
                    Config(key_file=f.name).api_key()
                os.chmod(f.name, 0o600)
                self.assertEqual(Config(key_file=f.name).api_key(), "fake")
        finally:
            os.unlink(f.name)

    def test_unknown_provider(self):
        with self.assertRaises(ValueError):
            Config(provider="evil").endpoint


class Mcp(unittest.TestCase):
    def test_protocol(self):
        c = client()
        s = Server(c)
        init = s.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertEqual(init["result"]["serverInfo"]["name"], "jev-sanitizer")
        self.assertIsNone(s.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        names = [t["name"] for t in s.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]]
        self.assertEqual(names, ["jev_ask", "jev_dry_run", "jev_models"])
        with mock.patch.object(c, "_http", return_value=FAKE):
            r = s.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                          "params": {"name": "jev_ask", "arguments": {"state": "s", "questions": Q}}})
        self.assertFalse(r["result"]["isError"])
        self.assertEqual(json.loads(r["result"]["content"][0]["text"])["status"], "ok")
        bad = s.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "jev_ask", "arguments": {}}})
        self.assertTrue(bad["result"]["isError"])


if __name__ == "__main__":
    unittest.main()
