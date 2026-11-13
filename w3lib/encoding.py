"""
Functions for handling encoding of web pages
"""

from __future__ import annotations

import re
import warnings
from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Literal, cast, overload

from frostwork.encoding import (
    autodetect_encoding,
    bom_encoding,
    codec_name,
    declared_encoding,
    decode,
    detect_encoding,
)

if TYPE_CHECKING:
    from collections.abc import Callable

# The value ends at whitespace, ";", "," or the end of the header. Comma is
# not parameter syntax; stopping the value at "," approximates Fetch's
# "extract a MIME type" for comma-joined duplicate headers, keeping the first
# charset rather than the last valid MIME type's.
_HEADER_ENCODING_RE = re.compile(
    r"(?:^|;)[ \t]*charset="
    r'(?:"([\w-]+)"|([\w-]+))'
    r"(?![^\s;,])",
    re.IGNORECASE,
)
# https://mimesniff.spec.whatwg.org/commit-snapshots/39aa53511b13953d84fef8d4131d6f61d0ccbde6/#parse-a-mime-type
# Parameters are ";"-separated name=value pairs whose value is either a token
# or a quoted-string, and a quoted-string is opaque
# (https://fetch.spec.whatwg.org/commit-snapshots/586cd2a44c2a865b37c166dc0740f3fb8bb220d6/#collect-an-http-quoted-string),
# so it has to be consumed as a whole: a "charset=" written inside one belongs
# to that value and is not a parameter of its own.
_HEADER_PARAMETER_RE = re.compile(
    r"(?:^|;)[ \t]*(?P<name>[^\s;=]+)="
    r'(?:"(?P<quoted>[^"\\]*(?:\\.[^"\\]*)*)"(?![^\s;,])'
    r"|(?P<token>[^;,\s]*))"
)
_ENCODING_LABEL_RE = re.compile(r"[\w-]+")
_WHITESPACE = b" \t\n\r\f"
_TAG_NAME_END = _WHITESPACE + b"/>"
_RAW_TEXT_TAGS = frozenset({"script", "style", "title", "textarea"})
_HEAD_TAGS = frozenset(
    {
        "base",
        "basefont",
        "bgsound",
        "head",
        "html",
        "link",
        "meta",
        "noscript",
        "template",
    }
)

EncodingSource = Literal[
    "bom",
    "http-charset",
    "meta",
    "xml",
    "declaration",
    "fallback",
    "probe-callback",
    "default",
]
EncodingStatus = Literal["adopted", "ignored"]


@dataclass(frozen=True, slots=True)
class EncodingCandidate:
    """One encoding candidate in an :class:`EncodingDecisionReport`.

    *start* and *end* are byte offsets into the original body, including any
    BOM. They are ``None`` for candidates that do not come from a byte range,
    such as an HTTP header or a fallback guess.
    """

    source: EncodingSource
    encoding: str | None
    status: EncodingStatus
    reason: str
    label: str | None = None
    start: int | None = None
    end: int | None = None
    bom_length: int | None = None
    valid: bool = True
    details_available: bool = True
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class EncodingDecisionReport:
    """Why :func:`html_to_unicode` decoded a body with a given encoding."""

    encoding: str
    adopted: EncodingCandidate
    bom: EncodingCandidate
    http_charset: EncodingCandidate
    declarations: tuple[EncodingCandidate, ...]
    fallback: tuple[EncodingCandidate, ...]
    notes: tuple[str, ...] = ()

    @property
    def candidates(self) -> tuple[EncodingCandidate, ...]:
        """Every evidence item, in report order."""
        return (self.bom, self.http_charset, *self.declarations, *self.fallback)

    @property
    def ignored(self) -> tuple[EncodingCandidate, ...]:
        """Candidates that did not supply the adopted encoding."""
        return tuple(c for c in self.candidates if c.status == "ignored")


@dataclass(frozen=True, slots=True)
class _Attribute:
    name: str
    value: str
    quoted: bool


@dataclass(frozen=True, slots=True)
class _ParsedTag:
    name: str
    attributes: tuple[_Attribute, ...]
    end: int
    closed: bool
    end_tag: bool


@dataclass(frozen=True, slots=True)
class _Declaration:
    source: Literal["meta", "xml"]
    encoding: str | None
    label: str | None
    start: int
    end: int
    valid: bool
    reason: str
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class _ReportChoice:
    encoding: str
    report: EncodingDecisionReport
    decode_label: str
    bom_length: int
    legacy_decode: bool


def _parse_attributes(
    data: bytes, position: int, limit: int
) -> tuple[tuple[_Attribute, ...], int]:
    attributes: list[_Attribute] = []
    while position < limit:
        while position < limit and data[position] in _WHITESPACE:
            position += 1
        if position >= limit:
            break
        if data[position] == 0x3E:
            return tuple(attributes), position + 1
        if data[position] == 0x2F:
            position += 1
            continue

        name_start = position
        while (
            position < limit
            and data[position] not in _TAG_NAME_END
            and data[position] != 0x3D
        ):
            position += 1
        if position == name_start:
            position += 1
            continue
        name = data[name_start:position].lower().decode("ascii", "ignore")

        value = ""
        quoted = False
        after_name = position
        while after_name < limit and data[after_name] in _WHITESPACE:
            after_name += 1
        if after_name < limit and data[after_name] == 0x3D:
            position = after_name + 1
            while position < limit and data[position] in _WHITESPACE:
                position += 1
            if position < limit and data[position] in (0x22, 0x27):
                quoted = True
                quote = data[position]
                position += 1
                value_start = position
                while position < limit and data[position] != quote:
                    position += 1
                value = data[value_start:position].decode("ascii", "ignore")
                if position < limit:
                    position += 1
            else:
                value_start = position
                while (
                    position < limit
                    and data[position] not in _WHITESPACE
                    and data[position] != 0x3E
                ):
                    position += 1
                value = data[value_start:position].decode("ascii", "ignore")
        attributes.append(_Attribute(name, value, quoted))
    return tuple(attributes), position


def _parse_tag(data: bytes, start: int) -> _ParsedTag | None:
    position = start + 1
    end_tag = False
    if position < len(data) and data[position] == 0x2F:
        end_tag = True
        position += 1
    name_start = position
    while position < len(data) and data[position] not in _TAG_NAME_END:
        position += 1
    if position == name_start:
        return None
    name = data[name_start:position].lower().decode("ascii", "ignore")
    attributes, end = _parse_attributes(data, position, len(data))
    closed = end > start and data[end - 1] == 0x3E
    return _ParsedTag(name, attributes, end, closed, end_tag)


def _comment_end(data: bytes, start: int) -> tuple[int, bool]:
    position = start + 4
    if data.startswith(b">", position):
        return position + 1, True
    if data.startswith(b"->", position):
        return position + 2, True
    normal = data.find(b"-->", position)
    bang = data.find(b"--!>", position)
    if normal < 0 and bang < 0:
        return len(data), False
    if normal < 0:
        return bang + 4, True
    if bang < 0:
        return normal + 3, True
    if normal < bang:
        return normal + 3, True
    return bang + 4, True


def _first_attribute(
    attributes: tuple[_Attribute, ...], name: str
) -> _Attribute | None:
    return next((attribute for attribute in attributes if attribute.name == name), None)


def _resolve_label(label: str) -> str | None:
    label = label.strip()
    if _ENCODING_LABEL_RE.fullmatch(label) is None:
        return None
    return resolve_encoding(label)


def _meta_content_charset_label(content: str) -> str | None:
    lowered = content.lower()
    position = lowered.find("charset")
    while position >= 0:
        after = position + len("charset")
        if after < len(content) and content[after] not in " \t\n\r\f=":
            position = lowered.find("charset", position + 1)
            continue
        while after < len(content) and content[after] in " \t\n\r\f":
            after += 1
        if after >= len(content) or content[after] != "=":
            position = lowered.find("charset", position + 1)
            continue
        after += 1
        while after < len(content) and content[after] in " \t\n\r\f":
            after += 1
        if after < len(content) and content[after] == '"':
            end = content.find('"', after + 1)
            return content[after + 1 : len(content) if end < 0 else end]
        end = after
        while end < len(content) and content[end] not in " \t\n\r\f;":
            end += 1
        return content[after:end]
    return None


def _meta_encoding(
    attributes: tuple[_Attribute, ...],
) -> tuple[str | None, str | None, str]:
    charset = _first_attribute(attributes, "charset")
    if charset is not None:
        label = charset.value.strip()
        if label:
            encoding = _resolve_label(label)
            if encoding is None:
                return None, label, f"charset label {label!r} is not a web encoding"
            return encoding, label, "charset attribute"

    http_equiv = _first_attribute(attributes, "http-equiv")
    content = _first_attribute(attributes, "content")
    if (
        http_equiv is None
        or http_equiv.value.strip().lower() != "content-type"
        or content is None
    ):
        return None, None, "no charset attribute or Content-Type pragma"

    label = _meta_content_charset_label(content.value)
    if label is None:
        return None, None, "the Content-Type pragma declares no usable charset"
    encoding = _resolve_label(label)
    if encoding is None:
        return None, label, f"charset label {label!r} is not a web encoding"
    return encoding, label, "http-equiv Content-Type pragma"


def _meta_declaration(data: bytes, start: int, tag: _ParsedTag) -> _Declaration | None:
    encoding, label, reason = _meta_encoding(tag.attributes)
    if encoding is None and label is None and reason.startswith("no charset"):
        return None
    return _Declaration(
        "meta",
        encoding,
        label,
        start,
        tag.end,
        encoding is not None,
        reason if encoding is not None else f"ignored: {reason}",
        not tag.closed,
    )


def _xml_declaration(data: bytes) -> _Declaration | None:
    if not data.startswith(b"<?xml"):
        return None
    after_name = 5
    if after_name < len(data) and data[after_name] not in _WHITESPACE + b"?>":
        return None
    close = data.find(b"?>", after_name)
    limit = len(data) if close < 0 else close
    attributes, _ = _parse_attributes(data, after_name, limit)
    encoding_attribute = _first_attribute(attributes, "encoding")
    end = len(data) if close < 0 else close + 2
    if (
        encoding_attribute is None
        or not encoding_attribute.quoted
        or not encoding_attribute.value
    ):
        return _Declaration(
            "xml",
            None,
            None if encoding_attribute is None else encoding_attribute.value,
            0,
            end,
            False,
            "ignored: XML declaration has no quoted encoding attribute",
            close < 0,
        )
    label = encoding_attribute.value.strip()
    encoding = _resolve_label(label)
    if encoding is None:
        return _Declaration(
            "xml",
            None,
            label,
            0,
            end,
            False,
            f"ignored: encoding label {label!r} is not a web encoding",
            close < 0,
        )
    return _Declaration(
        "xml",
        encoding,
        label,
        0,
        end,
        True,
        "XML declaration",
        close < 0,
    )


def _record_pseudo_declarations(
    declarations: list[_Declaration],
    data: bytes,
    start: int,
    end: int,
    reason: str,
) -> None:
    meta_pattern = re.compile(rb"<\s*meta(?=[\s/>])", re.IGNORECASE)
    for match in meta_pattern.finditer(data, start, end):
        name_end = match.start() + 1
        while name_end < end and data[name_end] in _WHITESPACE:
            name_end += 1
        attributes, tag_end = _parse_attributes(data, name_end + 4, end)
        encoding, label, detail = _meta_encoding(attributes)
        declarations.append(
            _Declaration(
                "meta",
                encoding,
                label,
                match.start(),
                tag_end,
                False,
                f"ignored: meta-like text {reason} ({detail})",
            )
        )

    xml_pattern = re.compile(rb"<\?xml(?=[\s?>])", re.IGNORECASE)
    for match in xml_pattern.finditer(data, start, end):
        close = data.find(b"?>", match.start() + 5, end)
        declarations.append(
            _Declaration(
                "xml",
                None,
                None,
                match.start(),
                end if close < 0 else close + 2,
                False,
                f"ignored: XML-like text {reason}",
            )
        )


def _raw_text_end(data: bytes, content_start: int, tag: str) -> int:
    pattern = re.compile(rb"</" + tag.encode() + rb"(?=[\s/>])", re.IGNORECASE)
    match = pattern.search(data, content_start)
    if match is None:
        return len(data)
    end_tag = _parse_tag(data, match.start())
    return len(data) if end_tag is None else end_tag.end


def _scan_declarations(data: bytes) -> tuple[_Declaration, ...]:
    declarations: list[_Declaration] = []
    position = 0
    body_started = False
    while position < len(data):
        if body_started and position > 1023:
            reason = "after the 1024-byte window that starts with body content"
            _record_pseudo_declarations(declarations, data, position, len(data), reason)
            break

        start = data.find(b"<", position)
        if start < 0:
            break
        if body_started and start > 1023:
            reason = "after the 1024-byte window that starts with body content"
            _record_pseudo_declarations(declarations, data, start, len(data), reason)
            break
        position = start

        if position == 0 and data.startswith(b"<?xml", position):
            declaration = _xml_declaration(data)
            if declaration is not None:
                declarations.append(declaration)
                position = max(declaration.end, position + 1)
                continue

        if data.startswith(b"<!--", position):
            end, closed = _comment_end(data, position)
            reason = (
                "inside an HTML comment"
                if closed
                else "inside an unterminated HTML comment"
            )
            _record_pseudo_declarations(declarations, data, position + 4, end, reason)
            position = end
            continue

        if data.startswith(b"<!", position) or data.startswith(b"<?", position):
            close = data.find(b">", position + 2)
            end = len(data) if close < 0 else close + 1
            reason = "inside a markup declaration or processing instruction"
            _record_pseudo_declarations(declarations, data, position + 2, end, reason)
            if data.startswith(b"<?xml", position):
                declarations.append(
                    _Declaration(
                        "xml",
                        None,
                        None,
                        position,
                        end,
                        False,
                        "ignored: XML declaration is only honored at byte 0",
                    )
                )
            position = end
            continue

        if position + 1 < len(data) and data[position + 1] in _WHITESPACE:
            name_start = position + 1
            while name_start < len(data) and data[name_start] in _WHITESPACE:
                name_start += 1
            if data[name_start : name_start + 4].lower() == b"meta" and (
                name_start + 4 == len(data)
                or data[name_start + 4] in _TAG_NAME_END
            ):
                attributes, end = _parse_attributes(
                    data, name_start + 4, len(data)
                )
                encoding, label, _ = _meta_encoding(attributes)
                declarations.append(
                    _Declaration(
                        "meta",
                        encoding,
                        label,
                        position,
                        end,
                        False,
                        "ignored: whitespace between '<' and the meta tag name",
                    )
                )
                position = max(end, position + 1)
                continue

        tag = _parse_tag(data, position)
        if tag is None:
            position += 1
            continue

        if tag.end_tag:
            if tag.name == "head":
                body_started = True
            position = max(tag.end, position + 1)
            continue

        if tag.name == "meta":
            declaration = _meta_declaration(data, position, tag)
            if declaration is not None:
                declarations.append(declaration)
        elif tag.name in _RAW_TEXT_TAGS:
            end = _raw_text_end(data, tag.end, tag.name)
            reason = f"inside <{tag.name}> raw text"
            _record_pseudo_declarations(declarations, data, tag.end, end, reason)
            position = end
            continue

        if tag.name not in _HEAD_TAGS and tag.name not in _RAW_TEXT_TAGS:
            body_started = True
        position = max(tag.end, position + 1)

    return tuple(declarations)


def _quoted_aware_charset(content_type: str) -> str | None:
    for match in _HEADER_PARAMETER_RE.finditer(content_type):
        if match.group("name").lower() != "charset":
            continue
        label = match.group("quoted")
        if label is None:
            label = match.group("token")
        if _ENCODING_LABEL_RE.fullmatch(label):
            return resolve_encoding(label)
    return None


def http_content_type_encoding(content_type: str | None) -> str | None:
    """Extract the encoding in the content-type header

    >>> import w3lib.encoding
    >>> w3lib.encoding.http_content_type_encoding("Content-Type: text/html; charset=ISO-8859-4")
    'iso8859-4'

    """

    if content_type:
        match = _HEADER_ENCODING_RE.search(content_type)
        if match:
            # A match inside a quoted-string must be preceded by that string's
            # opening quote, so if no '"' precedes it the fast answer is
            # correct; only otherwise walk the parameters.
            if content_type.find('"', 0, match.start()) < 0:
                return resolve_encoding(match.group(1) or match.group(2))
            return _quoted_aware_charset(content_type)

    return None


def html_body_declared_encoding(html_body_str: str | bytes) -> str | None:
    '''Return the encoding specified in meta tags in the html body,
    or ``None`` if no suitable encoding was found

    >>> import w3lib.encoding
    >>> w3lib.encoding.html_body_declared_encoding(
    ... """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
    ...      "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
    ... <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
    ... <head>
    ...     <title>Some title</title>
    ...     <meta http-equiv="content-type" content="text/html;charset=utf-8" />
    ... </head>
    ... <body>
    ... ...
    ... </body>
    ... </html>""")
    'utf-8'
    >>>

    '''

    if isinstance(html_body_str, str):
        html_body_str = html_body_str.encode("utf-8", "replace")
    name = declared_encoding(html_body_str)
    return None if name is None else codec_name(name)


_DEPRECATED_ENCODING_TRANSLATION = {
    "ascii": "cp1252",
    "big5": "big5hkscs",
    "euc_kr": "cp949",
    "gb2312": "gb18030",
    "gb_2312_80": "gb18030",
    "gbk": "gb18030",
    "iso8859_11": "cp874",
    "iso8859_9": "cp1254",
    "latin_1": "cp1252",
    "macintosh": "mac_roman",
    "shift_jis": "cp932",
    "tis_620": "cp874",
    "win_1251": "cp1251",
    "windows_31j": "cp932",
    "win_31j": "cp932",
    "windows_874": "cp874",
    "win_874": "cp874",
    "x_sjis": "cp932",
    "zh_cn": "gb18030",
}


def __getattr__(name: str) -> Any:
    if name == "DEFAULT_ENCODING_TRANSLATION":
        warnings.warn(
            "w3lib.encoding.DEFAULT_ENCODING_TRANSLATION is deprecated.",
            DeprecationWarning,
            stacklevel=2,
        )
        return _DEPRECATED_ENCODING_TRANSLATION
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


@lru_cache(maxsize=256)
def resolve_encoding(encoding_alias: str) -> str | None:
    """Return the Python codec name of the encoding of the `Encoding
    Standard`_ that `encoding_alias` maps to, or ``None`` if there is none,
    e.g. for ``utf-32``.

    .. _Encoding Standard: https://encoding.spec.whatwg.org/

    >>> import w3lib.encoding
    >>> w3lib.encoding.resolve_encoding('latin1')
    'cp1252'
    >>> w3lib.encoding.resolve_encoding('gb_2312-80')
    'gbk'
    >>> w3lib.encoding.resolve_encoding('base64')
    >>>

    """
    return codec_name(encoding_alias)


def read_bom(data: bytes) -> tuple[None, None] | tuple[str, bytes]:
    r"""Read the byte order mark in the text, if present, and
    return the encoding represented by the BOM and the BOM.

    If no BOM can be detected, ``(None, None)`` is returned.

    As in browsers, a UTF-32LE BOM reads as a UTF-16LE one, and a UTF-16 body
    that starts with an XML declaration and no BOM gives an empty BOM.

    >>> import w3lib.encoding
    >>> w3lib.encoding.read_bom(b'\xfe\xff\x6c\x34')
    ('utf-16-be', b'\xfe\xff')
    >>> w3lib.encoding.read_bom(b'\xff\xfe\x34\x6c')
    ('utf-16-le', b'\xff\xfe')
    >>> w3lib.encoding.read_bom(b'\x01\x02\x03\x04')
    (None, None)
    >>>

    """
    bom = bom_encoding(data)
    if bom is None:
        return None, None
    name, length = bom
    return cast("str", codec_name(name)), data[:length]


def to_unicode(data_str: bytes, encoding: str) -> str:
    r"""Convert a str object to unicode using the encoding given

    If *encoding* names an encoding of the `Encoding Standard`_, *data_str* is
    decoded the way browsers decode it, e.g. ``utf-16`` is UTF-16LE.

    Characters that cannot be converted will be converted to ``\ufffd`` (the
    unicode replacement character).

    .. _Encoding Standard: https://encoding.spec.whatwg.org/
    """
    try:
        return decode(data_str, encoding)
    except LookupError:
        return data_str.decode(encoding, "replace")


def _http_charset_label(content_type_header: str | None) -> str | None:
    if not content_type_header:
        return None
    match = _HEADER_ENCODING_RE.search(content_type_header)
    if match is None:
        return None
    if content_type_header.find('"', 0, match.start()) < 0:
        return match.group(1) or match.group(2)
    for parameter in _HEADER_PARAMETER_RE.finditer(content_type_header):
        if parameter.group("name").lower() != "charset":
            continue
        label = parameter.group("quoted")
        if label is None:
            label = parameter.group("token")
        if (
            _ENCODING_LABEL_RE.fullmatch(label)
            and resolve_encoding(label) is not None
        ):
            return label
    return None


def _http_candidate(
    content_type_header: str | None,
    encoding: str | None,
    chosen_source: EncodingSource,
    bom_present: bool,
) -> EncodingCandidate:
    label = _http_charset_label(content_type_header)
    if not content_type_header:
        return EncodingCandidate(
            "http-charset",
            None,
            "ignored",
            "ignored: no Content-Type header",
            valid=False,
        )
    if encoding is None:
        detail = "no usable charset parameter"
        if label is not None:
            detail = f"charset label {label!r} is not a web encoding"
        return EncodingCandidate(
            "http-charset",
            None,
            "ignored",
            f"ignored: {detail}",
            label=label,
            valid=False,
        )
    if chosen_source == "http-charset":
        return EncodingCandidate(
            "http-charset",
            encoding,
            "adopted",
            "adopted: charset parameter of the Content-Type header",
            label=label,
        )
    reason = (
        "ignored: a BOM takes precedence over the HTTP charset"
        if bom_present
        else "ignored: a higher-priority source supplied the encoding"
    )
    return EncodingCandidate(
        "http-charset", encoding, "ignored", reason, label=label
    )


def _declaration_candidates(
    declarations: tuple[_Declaration, ...],
    encoding: str,
    chosen_source: EncodingSource,
) -> tuple[EncodingCandidate, ...]:
    adopted_index: int | None = None
    if chosen_source == "declaration":
        adopted_index = next(
            (
                index
                for index, declaration in enumerate(declarations)
                if declaration.valid and declaration.encoding == encoding
            ),
            None,
        )

    candidates: list[EncodingCandidate] = []
    if chosen_source == "declaration" and adopted_index is None:
        candidates.append(
            EncodingCandidate(
                "declaration",
                encoding,
                "adopted",
                "adopted from the meta/XML prescan, but its exact byte range "
                "could not be recovered from the available scanner details",
                details_available=False,
            )
        )

    for index, declaration in enumerate(declarations):
        if index == adopted_index:
            status: EncodingStatus = "adopted"
            reason = f"adopted: {declaration.reason}"
            if declaration.truncated:
                reason += "; declaration truncated by the end of the input"
        elif not declaration.valid:
            status = "ignored"
            reason = declaration.reason
        elif chosen_source == "bom":
            status = "ignored"
            reason = "ignored: a BOM takes precedence"
        elif chosen_source == "http-charset":
            status = "ignored"
            reason = "ignored: the HTTP charset takes precedence"
        elif chosen_source == "declaration":
            status = "ignored"
            reason = (
                "ignored: a later declaration supplied the encoding"
                if adopted_index is not None and index < adopted_index
                else "ignored: an earlier declaration supplied the encoding"
            )
        else:
            status = "ignored"
            reason = "ignored: the prescan did not select this declaration"
        candidates.append(
            EncodingCandidate(
                declaration.source,
                declaration.encoding,
                status,
                reason,
                label=declaration.label,
                start=declaration.start,
                end=declaration.end,
                valid=declaration.valid,
                truncated=declaration.truncated,
            )
        )
    return tuple(candidates)


def _fallback_candidates(
    encoding: str,
    chosen_source: EncodingSource,
    bom_present: bool,
    http_present: bool,
    declaration_present: bool,
) -> tuple[EncodingCandidate, ...]:
    if chosen_source == "fallback":
        return (
            EncodingCandidate(
                "fallback",
                encoding,
                "adopted",
                "adopted: UTF-8 validity or byte-based autodetection chose this "
                "encoding; the underlying detector exposes no candidate ranking "
                "or confidence",
                details_available=False,
            ),
        )
    if chosen_source == "probe-callback":
        return (
            EncodingCandidate(
                "probe-callback",
                encoding,
                "adopted",
                "adopted: returned by the caller-provided probe callback",
            ),
        )
    if chosen_source == "default":
        return (
            EncodingCandidate(
                "default",
                encoding,
                "adopted",
                "adopted: caller-provided or built-in default encoding",
            ),
        )

    if bom_present:
        reason = "not consulted: a BOM took precedence"
    elif http_present:
        reason = "not consulted: the HTTP charset took precedence"
    elif declaration_present:
        reason = "not consulted: a declaration took precedence"
    else:
        reason = "not consulted: a higher-priority source supplied the encoding"
    return (
        EncodingCandidate(
            "fallback",
            None,
            "ignored",
            reason,
            valid=False,
            details_available=False,
        ),
    )


def _report_choice(
    content_type_header: str | None,
    html_body_str: bytes,
    default_encoding: str | None,
    auto_detect_fun: Callable[[bytes], str | None] | None,
    *,
    url: str | None,
) -> _ReportChoice:
    bom = bom_encoding(html_body_str)
    http_encoding = http_content_type_encoding(content_type_header)
    declarations = _scan_declarations(html_body_str)
    if bom is None and (auto_detect_fun is not None or default_encoding is not None):
        warnings.warn(
            "The default_encoding and auto_detect_fun parameters of "
            "w3lib.encoding.html_to_unicode() are deprecated.",
            DeprecationWarning,
            stacklevel=3,
        )

    encoding: str
    decode_label: str
    chosen_source: EncodingSource
    bom_length = 0
    legacy_decode = False

    if bom is not None:
        name, bom_length = bom
        encoding = cast("str", codec_name(name))
        decode_label = name
        chosen_source = "bom"
    elif http_encoding is not None:
        encoding = http_encoding
        decode_label = http_encoding
        chosen_source = "http-charset"
        legacy_decode = auto_detect_fun is not None or default_encoding is not None
    else:
        declared = declared_encoding(html_body_str)
        declared_codec = None if declared is None else codec_name(declared)
        if declared_codec is not None:
            encoding = declared_codec
            decode_label = cast("str", declared)
            chosen_source = "declaration"
            legacy_decode = auto_detect_fun is not None or default_encoding is not None
        elif auto_detect_fun is not None or default_encoding is not None:
            legacy_decode = True
            detected = (
                None if auto_detect_fun is None else auto_detect_fun(html_body_str)
            )
            if detected is not None:
                encoding = detected
                decode_label = detected
                chosen_source = "probe-callback"
            else:
                encoding = default_encoding or "utf8"
                decode_label = encoding
                chosen_source = "default"
        else:
            detected = autodetect_encoding(html_body_str, url=url)
            encoding = cast("str", codec_name(detected))
            decode_label = detected
            chosen_source = "fallback"

    bom_candidate = (
        EncodingCandidate(
            "bom",
            encoding,
            "adopted",
            (
                "adopted: BOM-less UTF-16 XML prefix"
                if bom_length == 0
                else "adopted: byte order mark"
            ),
            start=0,
            end=bom_length,
            bom_length=bom_length,
        )
        if bom is not None
        else EncodingCandidate(
            "bom",
            None,
            "ignored",
            "ignored: no recognized BOM",
            valid=False,
        )
    )
    http_candidate = _http_candidate(
        content_type_header, http_encoding, chosen_source, bom is not None
    )
    declaration_candidates = _declaration_candidates(
        declarations, encoding, chosen_source
    )
    fallback_candidates = _fallback_candidates(
        encoding,
        chosen_source,
        bom is not None,
        http_encoding is not None,
        any(declaration.valid for declaration in declarations),
    )
    adopted = next(
        candidate
        for candidate in (
            bom_candidate,
            http_candidate,
            *declaration_candidates,
            *fallback_candidates,
        )
        if candidate.status == "adopted"
    )
    report = EncodingDecisionReport(
        encoding=encoding,
        adopted=adopted,
        bom=bom_candidate,
        http_charset=http_candidate,
        declarations=declaration_candidates,
        fallback=fallback_candidates,
        notes=(
            "Offsets are byte offsets into the supplied body, including any BOM.",
            "Autodetection exposes only its result; no per-candidate confidence "
            "or ranking is available to this report.",
        ),
    )
    return _ReportChoice(
        encoding=encoding,
        report=report,
        decode_label=decode_label,
        bom_length=bom_length,
        legacy_decode=legacy_decode,
    )


def html_encoding_report(
    content_type_header: str | None,
    html_body_str: bytes,
    *,
    url: str | None = None,
) -> EncodingDecisionReport:
    """Return the decision report for the encoding :func:`html_to_unicode`
    would use, without decoding the body.
    """
    return _report_choice(
        content_type_header, html_body_str, None, None, url=url
    ).report


@overload
def html_encoding(
    content_type_header: str | None,
    html_body_str: bytes,
    *,
    url: str | None = None,
    report: Literal[False] = False,
) -> str:
    ...


@overload
def html_encoding(
    content_type_header: str | None,
    html_body_str: bytes,
    *,
    url: str | None = None,
    report: Literal[True],
) -> tuple[str, EncodingDecisionReport]:
    ...


def html_encoding(
    content_type_header: str | None,
    html_body_str: bytes,
    *,
    url: str | None = None,
    report: bool = False,
) -> str | tuple[str, EncodingDecisionReport]:
    """Return the encoding :func:`html_to_unicode` would decode
    *html_body_str* with, given the same *url*, without decoding it.

    .. versionadded:: 2.6.0
       The *url* parameter.

    If *report* is true, return ``(encoding, report)`` instead, where *report*
    describes every candidate and why it was adopted or ignored.

    >>> import w3lib.encoding
    >>> w3lib.encoding.html_encoding(None, b'<meta charset="latin1">')
    'cp1252'
    """
    if report:
        choice = _report_choice(content_type_header, html_body_str, None, None, url=url)
        return choice.encoding, choice.report
    enc = http_content_type_encoding(content_type_header)
    return cast("str", codec_name(detect_encoding(html_body_str, enc, url=url)))


@overload
def html_to_unicode(
    content_type_header: str | None,
    html_body_str: bytes,
    default_encoding: str | None = None,
    auto_detect_fun: Callable[[bytes], str | None] | None = None,
    *,
    url: str | None = None,
    report: Literal[False] = False,
) -> tuple[str, str]:
    ...


@overload
def html_to_unicode(
    content_type_header: str | None,
    html_body_str: bytes,
    default_encoding: str | None = None,
    auto_detect_fun: Callable[[bytes], str | None] | None = None,
    *,
    url: str | None = None,
    report: Literal[True],
) -> tuple[str, str, EncodingDecisionReport]:
    ...


def html_to_unicode(
    content_type_header: str | None,
    html_body_str: bytes,
    default_encoding: str | None = None,
    auto_detect_fun: Callable[[bytes], str | None] | None = None,
    *,
    url: str | None = None,
    report: bool = False,
) -> tuple[str, str] | tuple[str, str, EncodingDecisionReport]:
    r'''Convert raw html bytes to unicode

    .. versionadded:: 2.6.0
       The *url* parameter.

    This finds the encoding of the html body the way a web browser does,
    trying in order:

    * BOM (byte-order mark)
    * http content type header
    * meta or xml tag declarations
    * UTF-8, if the body is valid UTF-8
    * the encoding guessed from the bytes of the body and the top-level domain
      of *url*, the URL of the body, as Firefox does

    If a BOM is found, it will be stripped.

    If `content_type_header` is not present, ``None`` can be passed signifying
    that the header was not present.

    This method will not fail, if characters cannot be converted to unicode,
    ``\ufffd`` (the unicode replacement character) will be inserted instead.

    Returns a tuple of ``(<encoding used>, <unicode_string>)``. If *report* is
    true, a third item is added: the :class:`EncodingDecisionReport` that
    records the BOM, HTTP charset, decoded declarations and fallback probe.

    Examples:

    >>> import w3lib.encoding
    >>> w3lib.encoding.html_to_unicode(None,
    ... b"""<!DOCTYPE html>
    ... <head>
    ... <meta charset="UTF-8" />
    ... <meta name="viewport" content="width=device-width" />
    ... <title>Creative Commons France</title>
    ... <link rel='canonical' href='http://creativecommons.fr/' />
    ... <body>
    ... <p>Creative Commons est une organisation \xc3\xa0 but non lucratif
    ... qui a pour dessein de faciliter la diffusion et le partage des oeuvres
    ... tout en accompagnant les nouvelles pratiques de cr\xc3\xa9ation \xc3\xa0 l\xe2\x80\x99\xc3\xa8re numerique.</p>
    ... </body>
    ... </html>""")
    ('utf-8', '<!DOCTYPE html>\n<head>\n<meta charset="UTF-8" />\n<meta name="viewport" content="width=device-width" />\n<title>Creative Commons France</title>\n<link rel=\'canonical\' href=\'http://creativecommons.fr/\' />\n<body>\n<p>Creative Commons est une organisation \xe0 but non lucratif\nqui a pour dessein de faciliter la diffusion et le partage des oeuvres\ntout en accompagnant les nouvelles pratiques de cr\xe9ation \xe0 l\u2019\xe8re numerique.</p>\n</body>\n</html>')
    >>>

    '''
    if report:
        choice = _report_choice(
            content_type_header,
            html_body_str,
            default_encoding,
            auto_detect_fun,
            url=url,
        )
        body_to_decode = html_body_str[choice.bom_length :]
        text = (
            to_unicode(body_to_decode, choice.encoding)
            if choice.legacy_decode
            else decode(body_to_decode, choice.decode_label)
        )
        return choice.encoding, text, choice.report

    bom = bom_encoding(html_body_str)
    if bom is not None:
        name, length = bom
        return cast("str", codec_name(name)), decode(html_body_str[length:], name)
    enc = http_content_type_encoding(content_type_header)
    if auto_detect_fun is None and default_encoding is None:
        name = detect_encoding(html_body_str, enc, url=url)
        return cast("str", codec_name(name)), decode(html_body_str, name)
    warnings.warn(
        "The default_encoding and auto_detect_fun parameters of "
        "w3lib.encoding.html_to_unicode() are deprecated.",
        DeprecationWarning,
        stacklevel=2,
    )
    if enc is None:
        enc = html_body_declared_encoding(html_body_str)
    if enc is None and auto_detect_fun is not None:
        enc = auto_detect_fun(html_body_str)
    if enc is None:
        enc = default_encoding or "utf8"
    return enc, to_unicode(html_body_str, enc)
