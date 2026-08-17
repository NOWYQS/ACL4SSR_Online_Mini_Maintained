import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from update_rules import convert_entries, parse_payload, render  # noqa: E402


class UpdateRulesTest(unittest.TestCase):
    def test_parse_provider_payload(self):
        data = b"payload:\n  - '+.example.com'\n  - '1.2.3.0/24'\n"
        self.assertEqual(parse_payload(data), ["+.example.com", "1.2.3.0/24"])

    def test_domain_conversion_and_deduplication(self):
        values = ["+.example.com", "example.com", "*.example.net"]
        self.assertEqual(
            convert_entries(values, "domain"),
            ["DOMAIN-SUFFIX,example.com", "DOMAIN-SUFFIX,example.net"],
        )

    def test_cidr_conversion(self):
        self.assertEqual(
            convert_entries(["192.168.1.0/24", "2001:db8::/32"], "cidr"),
            [
                "IP-CIDR,192.168.1.0/24,no-resolve",
                "IP-CIDR6,2001:db8::/32,no-resolve",
            ],
        )

    def test_classic_rules_are_preserved(self):
        self.assertEqual(
            convert_entries(["PROCESS-NAME,example", "PROCESS-NAME,example"], "classic"),
            ["PROCESS-NAME,example"],
        )

    def test_render_is_classic_list(self):
        output = render("direct.txt", ["DOMAIN-SUFFIX,example.com"])
        self.assertIn("# Provider payload converted", output)
        self.assertIn("DOMAIN-SUFFIX,example.com", output)
        self.assertNotIn("payload:", output)


if __name__ == "__main__":
    unittest.main()
