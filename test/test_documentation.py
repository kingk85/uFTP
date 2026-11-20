"""Checks on the documents that ship with the source: SECURITY.md must exist where GitHub looks for it,
say how to report a vulnerability, and have no placeholder left. A reminder for every release, not a
test of the server (it is quick and starts nothing).

What it cannot check: that private vulnerability reporting is switched on in the settings of the
repository, and that GitHub shows the policy (only visible after the push).
"""

import os
import re
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as f:
        return f.read()


class SecurityPolicyTests(unittest.TestCase):

    def test_the_policy_is_in_the_root_of_the_repository(self):
        self.assertTrue(os.path.isfile(os.path.join(ROOT, "SECURITY.md")),
                        "GitHub looks for SECURITY.md in the root, in docs/ or in .github/")

    def test_it_has_the_sections_that_a_reporter_needs(self):
        text = read("SECURITY.md")
        for heading in ("Supported versions", "Reporting a vulnerability", "What to expect"):
            self.assertRegex(text, r"(?m)^#+ " + re.escape(heading), heading)

    def test_it_tells_how_to_report_in_private(self):
        text = read("SECURITY.md")
        self.assertIn("https://github.com/kingk85/uFTP/security/advisories/new", text)
        self.assertRegex(text, r"(?i)do not open a public issue")

    def test_it_has_no_placeholder_left(self):
        text = read("SECURITY.md")
        for marker in ("TODO", "FIXME", "XXX", "<your", "example.com", "[email]"):
            self.assertNotIn(marker, text)

    def test_it_does_not_publish_an_email_address_by_mistake(self):
        """A contact is a decision of the maintainer: it is written by hand, not found by accident."""
        self.assertIsNone(re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", read("SECURITY.md")))

    def test_the_options_it_names_exist_in_the_sample_configuration(self):
        configuration = read("uftpd.cfg")
        for option in re.findall(r"`([A-Z][A-Z_]{5,})`", read("SECURITY.md")):
            if option.startswith(("MAX_", "MIN_", "FORCE_")):
                self.assertIn(option, configuration, option)

    def test_its_links_to_files_of_the_repository_exist(self):
        text = read("SECURITY.md")
        for target in re.findall(r"\]\(([^)#]+)\)", text):
            if not re.match(r"[a-z]+:", target):
                self.assertTrue(os.path.exists(os.path.join(ROOT, target)), target)


if __name__ == "__main__":
    unittest.main()
