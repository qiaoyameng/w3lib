from __future__ import annotations

import pytest

from w3lib.psl import (
    IDNA_VERSION,
    PublicSuffixList,
    PublicSuffixSection,
    RuleType,
)


PSL_RULES = """
// A compact fixture: no full, time-dependent PSL snapshot is used.
com
co.uk
// ===BEGIN ICANN DOMAINS===
*.ck
!www.ck
xn--bcher-kva.example
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
private.example
// ===END PRIVATE DOMAINS===
"""


@pytest.fixture
def psl() -> PublicSuffixList:
    return PublicSuffixList(PSL_RULES)


@pytest.fixture
def private_psl() -> PublicSuffixList:
    return PublicSuffixList(PSL_RULES, include_private=True)


def test_normal_rules_distinguish_clients_under_co_uk(psl: PublicSuffixList) -> None:
    result = psl.query("a.co.uk")

    assert result is not None
    assert result.public_suffix == "co.uk"
    assert result.registrable_domain == "a.co.uk"
    assert result.matched_rule == "co.uk"
    assert result.section == PublicSuffixSection.ICANN
    assert result.rule_type == RuleType.NORMAL

    assert psl.registrable_domain("customer-one.co.uk") == "customer-one.co.uk"
    assert psl.registrable_domain("customer-two.co.uk") == "customer-two.co.uk"


def test_wildcard_can_be_overridden_by_exception(psl: PublicSuffixList) -> None:
    wildcard = psl.query("shop.foo.ck")

    assert wildcard is not None
    assert wildcard.public_suffix == "foo.ck"
    assert wildcard.registrable_domain == "shop.foo.ck"
    assert wildcard.matched_rule == "*.ck"
    assert wildcard.rule_type == RuleType.WILDCARD

    exception = psl.query("www.ck")

    assert exception is not None
    assert exception.public_suffix == "ck"
    assert exception.registrable_domain == "www.ck"
    assert exception.matched_rule == "!www.ck"
    assert exception.rule_type == RuleType.EXCEPTION

    nested_exception = psl.query("shop.www.ck")

    assert nested_exception is not None
    assert nested_exception.public_suffix == "ck"
    assert nested_exception.registrable_domain == "www.ck"
    assert nested_exception.matched_rule == "!www.ck"


def test_trailing_dot_case_and_idna_are_normalized(psl: PublicSuffixList) -> None:
    result = psl.query("WWW.BÜCHER.EXAMPLE.")

    assert result is not None
    assert result.public_suffix == "xn--bcher-kva.example"
    assert result.registrable_domain == "www.xn--bcher-kva.example"
    assert result.matched_rule == "xn--bcher-kva.example"
    assert psl.public_suffix("bücher.example") == "xn--bcher-kva.example"


def test_private_rules_are_optional(private_psl: PublicSuffixList) -> None:
    assert private_psl.public_suffix("app.private.example") == "private.example"
    assert (
        private_psl.registrable_domain("app.private.example")
        == "app.private.example"
    )
    assert (
        private_psl.registrable_domain("tenant.private.example")
        == "tenant.private.example"
    )

    private_override = PublicSuffixList(
        """
com
// ===BEGIN PRIVATE DOMAINS===
com
// ===END PRIVATE DOMAINS===
""",
        include_private=True,
    )
    override_result = private_override.query("example.com")

    assert override_result is not None
    assert override_result.public_suffix == "com"
    assert override_result.section == PublicSuffixSection.PRIVATE

    icann_only = PublicSuffixList("com")
    assert icann_only.query("example.com").section == PublicSuffixSection.ICANN


def test_private_rules_are_ignored_by_default(psl: PublicSuffixList) -> None:
    assert psl.public_suffix("app.private.example") == "example"
    assert psl.registrable_domain("tenant.private.example") == "private.example"


def test_single_label_has_suffix_but_no_registrable_domain(
    psl: PublicSuffixList,
) -> None:
    result = psl.query("example")

    assert result is not None
    assert result.public_suffix == "example"
    assert result.registrable_domain is None
    assert result.matched_rule == "*"
    assert result.rule_type == RuleType.WILDCARD


@pytest.mark.parametrize(
    "host",
    ["192.0.2.1", "192.0.2.1.", "[2001:db8::1]", "2001:db8::1", "::1"],
)
def test_ip_addresses_are_not_registrable_domains(
    psl: PublicSuffixList,
    host: str,
) -> None:
    assert psl.query(host) is None
    assert psl.public_suffix(host) is None
    assert psl.registrable_domain(host) is None


@pytest.mark.parametrize(
    "host",
    [
        "",
        ".example.com",
        "example..com",
        "example.com..",
        "[2001:db8::1]example",
        "[not-an-ip]",
        "2001:db8::1.1",
    ],
)
def test_invalid_hosts_do_not_become_registrable_domains(
    psl: PublicSuffixList,
    host: str,
) -> None:
    assert psl.query(host) is None


def test_idna_version_is_explicit() -> None:
    assert IDNA_VERSION == 2003


@pytest.mark.parametrize("rule", ["*.", "!ck", "*.*.com", "example..com"])
def test_invalid_rules_are_rejected(rule: str) -> None:
    with pytest.raises(ValueError):
        PublicSuffixList(rule)


def test_idna_rule_and_invalid_a_label_are_normalized() -> None:
    valid = PublicSuffixList("BÜCHER.EXAMPLE.")
    assert valid.public_suffix("www.bücher.example") == "xn--bcher-kva.example"
    result = valid.query("www.bücher.example")

    assert result is not None
    assert result.matched_rule == "xn--bcher-kva.example"

    with pytest.raises(ValueError):
        PublicSuffixList("xn--0.example")


def test_numeric_single_label_is_not_ip_address(psl: PublicSuffixList) -> None:
    result = psl.query("2130706433")

    assert result is not None
    assert result.public_suffix == "2130706433"
    assert result.registrable_domain is None


def test_explicit_root_wildcard_reports_its_section() -> None:
    psl = PublicSuffixList(
        """
*
// ===BEGIN PRIVATE DOMAINS===
*
// ===END PRIVATE DOMAINS===
""",
        include_private=True,
    )
    result = psl.query("example")

    assert result is not None
    assert result.public_suffix == "example"
    assert result.matched_rule == "*"
    assert result.section == PublicSuffixSection.PRIVATE
    assert result.rule_type == RuleType.WILDCARD


def test_rule_text_must_be_str() -> None:
    with pytest.raises(TypeError):
        PublicSuffixList(b"com")


def test_host_must_be_str(psl: PublicSuffixList) -> None:
    with pytest.raises(TypeError):
        psl.query(b"example.com")
