from __future__ import annotations

import string
from enum import Enum
from ipaddress import IPv6Address, ip_address
from typing import NamedTuple


IDNA_VERSION = 2003

_BEGIN_ICANN_MARKER = "// ===BEGIN ICANN DOMAINS==="
_END_ICANN_MARKER = "// ===END ICANN DOMAINS==="
_BEGIN_PRIVATE_MARKER = "// ===BEGIN PRIVATE DOMAINS==="
_END_PRIVATE_MARKER = "// ===END PRIVATE DOMAINS==="
_ALLOWED_LABEL_CHARS = frozenset(
    string.ascii_lowercase + string.digits + "-_"
)


class RuleType(str, Enum):
    NORMAL = "normal"
    WILDCARD = "wildcard"
    EXCEPTION = "exception"


class PublicSuffixSection(str, Enum):
    ICANN = "icann"
    PRIVATE = "private"


class PublicSuffixResult(NamedTuple):
    public_suffix: str | None
    registrable_domain: str | None
    matched_rule: str | None
    section: PublicSuffixSection | None
    rule_type: RuleType | None


class _Rule(NamedTuple):
    rule_type: RuleType
    text: str
    section: PublicSuffixSection


def _encode_label(label: str) -> str:
    lowered = label.lower()
    if lowered.isascii():
        encoded = lowered.encode("ascii")
    else:
        encoded = lowered.encode("idna")

    if not encoded or b"." in encoded or len(encoded) > 63:
        raise ValueError("invalid domain label")
    if lowered.startswith("xn--"):
        decoded = encoded.decode("idna")
        if decoded.encode("idna") != encoded:
            raise ValueError("invalid IDNA label")
    if any(chr(char) not in _ALLOWED_LABEL_CHARS for char in encoded):
        raise ValueError("invalid domain label")

    return encoded.decode("ascii")


def _normalize_labels(domain: str) -> tuple[str, ...]:
    if domain.endswith(".."):
        raise ValueError("empty domain label")
    if domain.endswith("."):
        domain = domain[:-1]
    if not domain:
        raise ValueError("empty host")

    labels = domain.split(".")
    if any(not label for label in labels):
        raise ValueError("empty domain label")

    return tuple(_encode_label(label) for label in labels)


class PublicSuffixList:
    """Offline Public Suffix List matcher.

    Rules are supplied as PSL text. No network access is performed. Domain
    labels are compared after removing a single trailing dot, folding ASCII
    case, and applying Python's built-in IDNA 2003 codec. Matching rules and
    returned domains use normalized ASCII labels. IP addresses, single-label
    hosts, and malformed hosts never yield a registrable domain.
    """

    def __init__(self, rules_text: str, *, include_private: bool = False) -> None:
        if not isinstance(rules_text, str):
            raise TypeError("rules_text must be str")

        self.include_private = include_private
        self._exact_rules: dict[
            PublicSuffixSection, dict[tuple[str, ...], _Rule]
        ] = {
            PublicSuffixSection.ICANN: {},
            PublicSuffixSection.PRIVATE: {},
        }
        self._wildcard_rules: dict[
            PublicSuffixSection, dict[tuple[str, ...], _Rule]
        ] = {
            PublicSuffixSection.ICANN: {},
            PublicSuffixSection.PRIVATE: {},
        }
        self._exception_rules: dict[
            PublicSuffixSection, dict[tuple[str, ...], _Rule]
        ] = {
            PublicSuffixSection.ICANN: {},
            PublicSuffixSection.PRIVATE: {},
        }
        self._parse(rules_text)

    def _parse(self, rules_text: str) -> None:
        section = PublicSuffixSection.ICANN

        for line_number, raw_line in enumerate(rules_text.splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("// ===") and line.endswith("==="):
                if line == _BEGIN_ICANN_MARKER:
                    section = PublicSuffixSection.ICANN
                    continue
                if line == _BEGIN_PRIVATE_MARKER:
                    section = PublicSuffixSection.PRIVATE
                    continue
                if line in {_END_ICANN_MARKER, _END_PRIVATE_MARKER}:
                    section = PublicSuffixSection.ICANN
                    continue
                raise ValueError(f"unknown PSL section marker on line {line_number}")

            if line.startswith("//"):
                continue

            self._parse_rule(line, section, line_number)

    def _parse_rule(
        self,
        line: str,
        section: PublicSuffixSection,
        line_number: int,
    ) -> None:
        try:
            if line.startswith("!"):
                labels = _normalize_labels(line[1:])
                if len(labels) < 2 or "*" in labels:
                    raise ValueError
                key = tuple(reversed(labels))
                rule = _Rule(
                    RuleType.EXCEPTION,
                    "!" + ".".join(labels),
                    section,
                )
                self._exception_rules[section][key] = rule
                return

            labels = tuple(line.split("."))
            trailing_dot = line.endswith(".")
            if trailing_dot:
                labels = labels[:-1]
            if (
                any(not label for label in labels)
                or any("*" in label for label in labels[1:])
                or trailing_dot
                and len(labels) == 1
                and labels[0] == "*"
            ):
                raise ValueError

            if len(labels) == 1 and labels[0] == "*":
                self._wildcard_rules[section][()] = _Rule(
                    RuleType.WILDCARD,
                    "*",
                    section,
                )
                return

            if labels[0] == "*":
                if len(labels) < 2:
                    raise ValueError
                normalized_labels = tuple(_encode_label(label) for label in labels[1:])
                key = tuple(reversed(normalized_labels))
                rule = _Rule(
                    RuleType.WILDCARD,
                    "*." + ".".join(normalized_labels),
                    section,
                )
                self._wildcard_rules[section][key] = rule
                return

            normalized_labels = tuple(_encode_label(label) for label in labels)
            key = tuple(reversed(normalized_labels))
            rule = _Rule(
                RuleType.NORMAL,
                ".".join(normalized_labels),
                section,
            )
            self._exact_rules[section][key] = rule
        except (TypeError, UnicodeError, ValueError) as exc:
            raise ValueError(f"invalid PSL rule on line {line_number}: {line}") from exc

    def _active_sections(self) -> tuple[PublicSuffixSection, ...]:
        if self.include_private:
            return (PublicSuffixSection.PRIVATE, PublicSuffixSection.ICANN)
        return (PublicSuffixSection.ICANN,)

    @staticmethod
    def _lookup_rule(
        rules_by_section: dict[PublicSuffixSection, dict[tuple[str, ...], _Rule]],
        key: tuple[str, ...],
        sections: tuple[PublicSuffixSection, ...],
    ) -> _Rule | None:
        for section in sections:
            rule = rules_by_section[section].get(key)
            if rule is not None:
                return rule
        return None

    @staticmethod
    def _parse_host(host: str) -> tuple[str, ...]:
        if host.startswith("["):
            if not host.endswith("]"):
                raise ValueError("invalid bracketed host")
            candidate = host[1:-1]
            if not candidate or not isinstance(ip_address(candidate), IPv6Address):
                raise ValueError("invalid IPv6 host")
            raise ValueError("IP addresses have no registrable domain")

        if host.endswith("."):
            dns_host = host[:-1]
            if dns_host.endswith("."):
                raise ValueError("empty domain label")
        else:
            dns_host = host

        try:
            parsed_ip = ip_address(dns_host)
        except ValueError:
            pass
        else:
            raise ValueError("IP addresses have no registrable domain")

        return _normalize_labels(dns_host)

    def query(self, host: str) -> PublicSuffixResult | None:
        """Return suffix information, or ``None`` for an invalid domain.

        A single-label host still returns a result with its public suffix but
        no registrable domain.
        """
        if not isinstance(host, str):
            raise TypeError("host must be str")

        try:
            labels = self._parse_host(host)
        except (TypeError, UnicodeError, ValueError):
            return None

        reversed_labels = tuple(reversed(labels))
        sections = self._active_sections()

        for suffix_length in range(len(reversed_labels), 1, -1):
            exception_key = reversed_labels[:suffix_length]
            exception_rule = self._lookup_rule(
                self._exception_rules, exception_key, sections
            )
            if exception_rule is not None:
                return self._result(
                    labels,
                    suffix_length - 1,
                    exception_rule,
                )

        for suffix_length in range(len(reversed_labels), 0, -1):
            exact_key = reversed_labels[:suffix_length]
            exact_rule = self._lookup_rule(self._exact_rules, exact_key, sections)
            if exact_rule is not None:
                return self._result(labels, suffix_length, exact_rule)

            if suffix_length >= 2:
                wildcard_key = reversed_labels[: suffix_length - 1]
                wildcard_rule = self._lookup_rule(
                    self._wildcard_rules, wildcard_key, sections
                )
                if wildcard_rule is not None:
                    return self._result(
                        labels,
                        suffix_length,
                        wildcard_rule,
                    )

        fallback_rule = self._lookup_rule(
            self._wildcard_rules,
            (),
            sections,
        )
        return self._result(labels, 1, fallback_rule)

    @staticmethod
    def _result(
        labels: tuple[str, ...],
        suffix_length: int,
        rule: _Rule | None,
    ) -> PublicSuffixResult:
        public_suffix = ".".join(labels[-suffix_length:])
        registrable_domain = None
        if len(labels) > suffix_length:
            registrable_domain = ".".join(labels[-suffix_length - 1 :])

        return PublicSuffixResult(
            public_suffix,
            registrable_domain,
            rule.text if rule is not None else "*",
            rule.section if rule is not None else None,
            rule.rule_type if rule is not None else RuleType.WILDCARD,
        )

    def public_suffix(self, host: str) -> str | None:
        result = self.query(host)
        return result.public_suffix if result is not None else None

    def registrable_domain(self, host: str) -> str | None:
        result = self.query(host)
        return result.registrable_domain if result is not None else None

    def get_public_suffix(self, host: str) -> str | None:
        return self.public_suffix(host)

    def get_registrable_domain(self, host: str) -> str | None:
        return self.registrable_domain(host)
