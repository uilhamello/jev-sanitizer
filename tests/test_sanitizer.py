"""All data here is fictitious."""
import unittest

from jev_sanitizer import Sanitizer, sanitize


class Masks(unittest.TestCase):
    CASES = [
        ("cliente fulano@example.com reclamou", "<EMAIL>", "fulano@"),
        ("CPF 123.456.789-09 no cadastro", "<CPF>", "123.456"),
        ("CNPJ 12.345.678/0001-95", "<CNPJ>", "0001"),
        ("CPF sem máscara 12345678909", "<N>", "12345678909"),
        ("placa ABC1D23 e ABC-1234", "<PLATE>", "ABC1D23"),
        ("fone (11) 91234-5678", "<PHONE>", "91234"),
        ("origem 10.0.0.7 porta 6033", "<IP>", "10.0.0.7"),
        ("GET https://api.example.com/x?token=abc&id=9", "?<QUERY>", "token=abc"),
        ("senha=Hunter2 e password: 'x y'", "<SECRET>", "Hunter2"),
        ("Authorization: Bearer abcDEF123456789xyz", "<TOKEN>", "abcDEF"),
        ("cookie SID=deadbeef1234", "<SECRET>", "deadbeef"),
        ("id_empresa=48213 e user_id: 77", "id_empresa=<N>", "48213"),
        ("req 3f2b8c1e-9a4d-4e6f-8b2a-1c3d5e7f9a0b", "<UUID>", "3f2b8c1e"),
        ("jwt eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4", "<JWT>", "eyJhbGci"),
    ]

    def test_masks(self):
        for text, expected, leaked in self.CASES:
            with self.subTest(text=text):
                clean, report = sanitize(text)
                self.assertIn(expected, clean)
                self.assertNotIn(leaked, clean)
                self.assertTrue(report.ok, report.blocked)


class Blocks(unittest.TestCase):
    CASES = [
        ("aws AKIAABCDEFGHIJKLMNOP", "aws_key"),
        ('{"private_key": "x"}', "gcp_key"),
        ("-----BEGIN CERTIFICATE-----", "pem_header"),
        ("dsn mysql://root@db/app", "conn_string"),
        ("loose aZ9kQ2xP7mL4vB8nR3tY6wE1", "high_entropy"),
        ("x" * 20001, "too_long>20000"),
        (None, "not_text"),
    ]

    def test_blocks(self):
        for text, reason in self.CASES:
            with self.subTest(reason=reason):
                self.assertIn(reason, sanitize(text)[1].blocked)


class KeepsMetrics(unittest.TestCase):
    def test_metrics_untouched(self):
        text = "p95 624 s; CPU 1-3%; Rows_examined 30M-51M; 51.000.000 rows; 180 conns; 17:30-18:05; latency=310ms; 2026-09-27"
        clean, report = sanitize(text)
        self.assertEqual(clean, text)
        self.assertTrue(report.ok)

    def test_error_messages_untouched(self):
        text = "SQLSTATE[HY000] [2002] Connection timed out; Waiting for table metadata lock"
        self.assertEqual(sanitize(text)[0], text)


class Extensible(unittest.TestCase):
    def test_extra_patterns(self):
        s = Sanitizer(extra_masks=[("ticket", r"\bTCK-\d+\b", "<TICKET>")], extra_blocks=[("internal", r"(?i)confidencial")])
        clean, report = s.sanitize("TCK-42 aberto")
        self.assertEqual(clean, "<TICKET> aberto")
        self.assertIn("internal", s.sanitize("doc CONFIDENCIAL")[1].blocked)


if __name__ == "__main__":
    unittest.main()
