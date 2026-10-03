"""
Offline querying of Public Suffix List (PSL) rules.

This module implements the `Public Suffix List matching algorithm
<https://publicsuffix.org/list/>`_ without any network access: the caller
supplies the rule text (e.g. a pinned snapshot of ``public_suffix_list.dat``
or a small hand-written rule set) and :class:`PublicSuffixList` parses it
once at construction time.

It supports plain rules (``co.uk``), wildcard rules (``*.ck``), exception
rules (``!www.ck``) and the ``PRIVATE`` section of the list, which is only
taken into account when explicitly requested.

Host names are normalized before comparison: a single trailing dot is
stripped, labels are lowercased and every label is converted to its ASCII
form (A-label) using IDNA 2003, the IDNA version implemented by Python's
built-in ``idna`` codec. IPv4 and IPv6 literals, single-label host names
and host names with empty labels never yield a registrable domain.

All returned domain names are in normalized ASCII (punycode) form.
"""

from __future__ import annotations

from ipaddress import ip_address
from typing import NamedTuple

__all__ = ["PSLMatch", "PublicSuffixList"]

ICANN_SECTION = "icann"
PRIVATE_SECTION = "private"

_BEGIN_ICANN = "// ===BEGIN ICANN DOMAINS==="
_BEGIN_PRIVATE = "// ===BEGIN PRIVATE DOMAINS==="
_END_ICANN = "// ===END ICANN DOMAINS==="
_END_PRIVATE = "// ===END PRIVATE DOMAINS==="


class PSLMatch(NamedTuple):
    """Result of a :meth:`PublicSuffixList.lookup` call.

    Every attribute is ``None`` when the input is not a valid,
    non-IP-literal host name.
    """

    #: The public suffix of the host name, e.g. ``"co.uk"`` for
    #: ``"www.example.co.uk"``. ``None`` for IP literals and invalid
    #: host names.
    public_suffix: str | None
    #: The registrable domain (public suffix plus one label), e.g.
    #: ``"example.co.uk"`` for ``"www.example.co.uk"``. ``None`` when the
    #: host name is a public suffix itself, has a single label, is an IP
    #: literal or is otherwise invalid.
    registrable_domain: str | None
    #: The PSL rule that matched, as written in the rule text after
    #: normalization (e.g. ``"co.uk"``, ``"*.ck"`` or ``"!www.ck"``).
    #: ``None`` when no rule matched and the implicit ``*`` rule of the
    #: PSL algorithm was applied.
    rule: str | None
    #: The section of the list the matched rule belongs to:
    #: ``"icann"`` or ``"private"``. ``None`` when no rule matched.
    section: str | None


_NO_MATCH = PSLMatch(None, None, None, None)


def _to_ascii_labels(hostname: str) -> list[str] | None:
    """Normalize *hostname* into IDNA 2003 ASCII labels.

    Return ``None`` for IP literals and invalid host names.
    """
    host = hostname.rstrip(".").lower()
    if not host or host.startswith("["):
        return None
    try:
        ip_address(host)
    except ValueError:
        pass
    else:
        return None
    labels = host.split(".")
    if any(label == "" for label in labels):
        return None
    try:
        return [label.encode("idna").decode("ascii") for label in labels]
    except (UnicodeError, ValueError):
        return None


def _normalize_rule(rule: str) -> str | None:
    """Normalize a single PSL rule line, keeping ``!`` and ``*.`` markers."""
    prefix = ""
    body = rule
    if body.startswith("!"):
        prefix, body = "!", body[1:]
    wildcard = body.startswith("*.")
    if wildcard:
        body = body[2:]
    labels = body.rstrip(".").lower().split(".")
    if any(label == "" for label in labels):
        return None
    try:
        ascii_labels = [label.encode("idna").decode("ascii") for label in labels]
    except (UnicodeError, ValueError):
        return None
    if wildcard:
        ascii_labels.insert(0, "*")
    return prefix + ".".join(ascii_labels)


class PublicSuffixList:
    """An offline Public Suffix List built from caller-supplied rule text.

    :param text: PSL rules in the ``public_suffix_list.dat`` format, or any
        subset of it: blank lines and ``//`` comments are ignored, and the
        ``// ===BEGIN/END ICANN/PRIVATE DOMAINS===`` markers are honored.
    :param include_private: when ``False`` (the default), rules from the
        ``PRIVATE`` section are ignored.
    """

    def __init__(self, text: str, *, include_private: bool = False) -> None:
        self._rules: dict[str, str] = {}
        section = ICANN_SECTION
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("//"):
                if line == _BEGIN_PRIVATE:
                    section = PRIVATE_SECTION
                elif line in (_BEGIN_ICANN, _END_ICANN, _END_PRIVATE):
                    section = ICANN_SECTION
                continue
            if section == PRIVATE_SECTION and not include_private:
                continue
            rule = _normalize_rule(line)
            if rule is not None:
                self._rules[rule] = section

    def lookup(self, hostname: str) -> PSLMatch:
        """Return the :class:`PSLMatch` for *hostname*."""
        labels = _to_ascii_labels(hostname)
        if labels is None:
            return _NO_MATCH
        rule = self._prevailing_rule(labels)
        if rule is None:
            # Implicit "*" rule of the PSL algorithm: the public suffix is
            # the rightmost label.
            suffix_label_count = 1
            section = None
        else:
            section = self._rules[rule]
            body = rule[1:] if rule.startswith("!") else rule
            suffix_label_count = body.count(".") + 1
            if rule.startswith("!"):
                # Exception rules: drop the leftmost label.
                suffix_label_count -= 1
        public_suffix = ".".join(labels[-suffix_label_count:])
        registrable_domain = None
        if len(labels) > suffix_label_count:
            registrable_domain = ".".join(labels[-(suffix_label_count + 1) :])
        return PSLMatch(public_suffix, registrable_domain, rule, section)

    def public_suffix(self, hostname: str) -> str | None:
        """Return the public suffix of *hostname*, or ``None``."""
        return self.lookup(hostname).public_suffix

    def registrable_domain(self, hostname: str) -> str | None:
        """Return the registrable domain of *hostname*, or ``None``."""
        return self.lookup(hostname).registrable_domain

    def _prevailing_rule(self, labels: list[str]) -> str | None:
        suffixes = [".".join(labels[i:]) for i in range(len(labels))]
        # Exception rules prevail over any other matching rule.
        for suffix in suffixes:
            if "!" + suffix in self._rules:
                return "!" + suffix
        # The matching rule with the most labels prevails; suffixes are
        # generated from longest to shortest.
        for suffix in suffixes:
            if suffix in self._rules:
                return suffix
            _, _, rest = suffix.partition(".")
            if rest and "*." + rest in self._rules:
                return "*." + rest
        return None
