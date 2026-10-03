from w3lib.psl import PSLMatch, PublicSuffixList

# A compact, self-contained rule set. It is intentionally not a copy of the
# full Public Suffix List, so tests do not depend on data that changes over
# time.
RULES = """
// ===BEGIN ICANN DOMAINS===
com
uk
co.uk
*.ck
!www.ck
食狮.cn
// ===END ICANN DOMAINS===

// ===BEGIN PRIVATE DOMAINS===
github.io
*.compute.amazonaws.com
// ===END PRIVATE DOMAINS===
"""

IDN = "食狮"
IDN_ASCII = "xn--85x722f"


class TestPublicSuffixList:
    psl = PublicSuffixList(RULES)
    psl_private = PublicSuffixList(RULES, include_private=True)

    def test_plain_rule(self):
        match = self.psl.lookup("www.example.com")
        assert match == PSLMatch("com", "example.com", "com", "icann")

    def test_multi_label_rule(self):
        match = self.psl.lookup("www.example.co.uk")
        assert match == PSLMatch("co.uk", "example.co.uk", "co.uk", "icann")

    def test_different_customers_under_co_uk(self):
        # The last-two-labels heuristic would merge these; the PSL does not.
        assert self.psl.registrable_domain("alice.co.uk") == "alice.co.uk"
        assert self.psl.registrable_domain("bob.co.uk") == "bob.co.uk"
        assert self.psl.registrable_domain("www.alice.co.uk") == "alice.co.uk"

    def test_host_equal_to_public_suffix(self):
        match = self.psl.lookup("co.uk")
        assert match == PSLMatch("co.uk", None, "co.uk", "icann")

    def test_wildcard_rule(self):
        match = self.psl.lookup("a.b.ck")
        assert match == PSLMatch("b.ck", "a.b.ck", "*.ck", "icann")

    def test_wildcard_rule_boundary(self):
        match = self.psl.lookup("b.ck")
        assert match == PSLMatch("b.ck", None, "*.ck", "icann")

    def test_exception_rule_overrides_wildcard(self):
        match = self.psl.lookup("www.ck")
        assert match == PSLMatch("ck", "www.ck", "!www.ck", "icann")

    def test_exception_rule_subdomain(self):
        match = self.psl.lookup("a.www.ck")
        assert match == PSLMatch("ck", "www.ck", "!www.ck", "icann")

    def test_idn_unicode_input(self):
        match = self.psl.lookup(f"www.{IDN}.cn")
        assert match == PSLMatch(
            f"{IDN_ASCII}.cn", f"www.{IDN_ASCII}.cn", f"{IDN_ASCII}.cn", "icann"
        )

    def test_idn_punycode_input(self):
        match = self.psl.lookup(f"www.{IDN_ASCII}.cn")
        assert match.registrable_domain == f"www.{IDN_ASCII}.cn"

    def test_normalization_case_and_trailing_dot(self):
        match = self.psl.lookup("WWW.Example.CO.UK.")
        assert match == PSLMatch("co.uk", "example.co.uk", "co.uk", "icann")

    def test_private_section_disabled_by_default(self):
        match = self.psl.lookup("user.github.io")
        assert match == PSLMatch("io", "github.io", None, None)

    def test_private_section_enabled(self):
        match = self.psl_private.lookup("user.github.io")
        assert match == PSLMatch("github.io", "user.github.io", "github.io", "private")

    def test_private_wildcard(self):
        match = self.psl_private.lookup("a.b.compute.amazonaws.com")
        assert match == PSLMatch(
            "b.compute.amazonaws.com",
            "a.b.compute.amazonaws.com",
            "*.compute.amazonaws.com",
            "private",
        )

    def test_unknown_tld_uses_implicit_rule(self):
        match = self.psl.lookup("www.example.unknown")
        assert match == PSLMatch("unknown", "example.unknown", None, None)

    def test_single_label_host(self):
        match = self.psl.lookup("localhost")
        assert match.registrable_domain is None
        assert match.rule is None

    def test_ipv4_literal(self):
        assert self.psl.lookup("127.0.0.1") == PSLMatch(None, None, None, None)

    def test_ipv6_literal(self):
        assert self.psl.lookup("::1") == PSLMatch(None, None, None, None)
        assert self.psl.lookup("[::1]") == PSLMatch(None, None, None, None)
        assert (
            self.psl.lookup("2001:db8::1") == PSLMatch(None, None, None, None)
        )

    def test_empty_labels_are_invalid(self):
        assert self.psl.lookup("a..com") == PSLMatch(None, None, None, None)
        assert self.psl.lookup("") == PSLMatch(None, None, None, None)
        assert self.psl.lookup(".") == PSLMatch(None, None, None, None)

    def test_convenience_methods(self):
        assert self.psl.public_suffix("www.example.co.uk") == "co.uk"
        assert self.psl.registrable_domain("www.example.co.uk") == "example.co.uk"
