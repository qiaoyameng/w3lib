from __future__ import annotations

import codecs
import enum
import re
import unicodedata
from base64 import b64encode
from collections.abc import Mapping, MutableMapping, Sequence
from io import BytesIO
from typing import Any, NamedTuple, TypeAlias, overload

from w3lib._util import to_unicode


# RFC 9110 token character (tchar).
_TOKEN_RE = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")

# RFC 5987 attr-char (percent-encoded octets are handled separately).
_ATTR_CHARS = frozenset("!$&+-.^_`|~")
_HEX_DIGITS = frozenset("0123456789ABCDEFabcdef")
# RFC 5987 value chars allowed outside percent-encoding: attr-chars plus
# ASCII letters and digits.
_ATTR_ALLOWED = _ATTR_CHARS | frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

# Used when a filename is missing or reduced to nothing by sanitization.
DEFAULT_FILENAME = "download"


def _is_bare_value(value: str) -> bool:
    """Whether *value* is an acceptable unquoted parameter value.

    RFC 9110 tokens are ASCII, but real servers routinely send unquoted
    non-ASCII names; those are accepted. Spaces, separators, quotes and
    control characters still require quoting.
    """
    if not value:
        return False
    return all(
        char not in '\t\n\r "(),/;<=>?@[\\]{}'
        and unicodedata.category(char) != "Cc"
        for char in value
    )

HeadersDictInput: TypeAlias = Mapping[bytes, Any | Sequence[bytes]]
HeadersDictOutput: TypeAlias = MutableMapping[bytes, list[bytes]]


@overload
def headers_raw_to_dict(headers_raw: bytes) -> HeadersDictOutput: ...


@overload
def headers_raw_to_dict(headers_raw: None) -> None: ...


def headers_raw_to_dict(headers_raw: bytes | None) -> HeadersDictOutput | None:
    r"""
    Convert raw headers (single multi-line bytestring)
    to a dictionary.

    For example:

    >>> import w3lib.http
    >>> w3lib.http.headers_raw_to_dict(b"Content-type: text/html\n\rAccept: gzip\n\n")   # doctest: +SKIP
    {'Content-type': ['text/html'], 'Accept': ['gzip']}

    Incorrect input:

    >>> w3lib.http.headers_raw_to_dict(b"Content-typt gzip\n\n")
    {}
    >>>

    Argument is ``None`` (return ``None``):

    >>> w3lib.http.headers_raw_to_dict(None)
    >>>

    """

    if headers_raw is None:
        return None

    if not headers_raw:
        return {}

    result_dict: HeadersDictOutput = {}

    for header in BytesIO(headers_raw):
        key, sep, value = header.partition(b":")
        if not sep:
            continue

        key, value = key.strip(), value.strip()

        if key in result_dict:
            result_dict[key].append(value)
        else:
            result_dict[key] = [value]

    return result_dict


@overload
def headers_dict_to_raw(headers_dict: HeadersDictInput) -> bytes: ...


@overload
def headers_dict_to_raw(headers_dict: None) -> None: ...


def headers_dict_to_raw(headers_dict: HeadersDictInput | None) -> bytes | None:
    r"""
    Returns a raw HTTP headers representation of headers

    For example:

    >>> import w3lib.http
    >>> w3lib.http.headers_dict_to_raw({b'Content-type': b'text/html', b'Accept': b'gzip'}) # doctest: +SKIP
    'Content-type: text/html\\r\\nAccept: gzip'
    >>>

    Note that keys and values must be bytes.

    Argument is ``None`` (returns ``None``):

    >>> w3lib.http.headers_dict_to_raw(None)
    >>>

    """

    if headers_dict is None:
        return None

    if not headers_dict:
        return b""

    parts = bytearray()

    for key, value in headers_dict.items():
        if isinstance(value, bytes):
            if parts:
                parts.extend(b"\r\n")
            parts.extend(key + b": " + value)

        elif isinstance(value, (list, tuple)):
            for v in value:
                if parts:
                    parts.extend(b"\r\n")
                parts.extend(key + b": " + v)

    return bytes(parts)


def basic_auth_header(
    username: str | bytes, password: str | bytes, encoding: str = "ISO-8859-1"
) -> bytes:
    """
    Return an `Authorization` header field value for `HTTP Basic Access Authentication (RFC 2617)`_

    >>> import w3lib.http
    >>> w3lib.http.basic_auth_header('someuser', 'somepass')
    b'Basic c29tZXVzZXI6c29tZXBhc3M='

    .. _HTTP Basic Access Authentication (RFC 2617): http://www.ietf.org/rfc/rfc2617.txt

    """

    auth = f"{to_unicode(username)}:{to_unicode(password)}"
    # RFC 2617 doesn't define encoding, but ISO-8859-1 seems to be the
    # most widely used encoding here. See also:
    # http://greenbytes.de/tech/webdav/draft-ietf-httpauth-basicauth-enc-latest.html
    return b"Basic " + b64encode(auth.encode(encoding=encoding))


class FilenameSource(enum.Enum):
    """Where a content disposition filename was taken from."""

    #: The ``filename*`` parameter (RFC 5987 / RFC 8187 extended form).
    EXTENDED = "extended"
    #: The plain ``filename`` parameter.
    BASIC = "basic"
    #: No usable filename was provided.
    NONE = "none"


class ContentDispositionIssue(enum.Enum):
    """Reason codes explaining why parsing or filename selection fell back.

    Every time a header piece cannot be honored, an entry carrying one of
    these codes is reported instead of silently guessed.
    """

    #: The disposition type is not a valid token.
    INVALID_DISPOSITION = "invalid-disposition"
    #: A parameter name is not a valid token.
    INVALID_PARAMETER_NAME = "invalid-parameter-name"
    #: A bare parameter value is not a valid token.
    INVALID_PARAMETER_VALUE = "invalid-parameter-value"
    #: A quoted parameter value is malformed (unterminated, bad escape, or
    #: stray text after the closing quote).
    INVALID_QUOTED_VALUE = "invalid-quoted-value"
    #: An extended parameter (``name*``) is malformed (missing charset or
    #: language separator, illegal character, or a quoted value).
    EXTENDED_SYNTAX = "extended-syntax"
    #: An extended parameter contains a ``%`` not followed by two hex digits.
    MALFORMED_PERCENT = "malformed-percent"
    #: An extended parameter names a charset that is not registered.
    UNKNOWN_CHARSET = "unknown-charset"
    #: The decoded bytes are not valid in the declared charset, or contain a
    #: raw control character.
    DECODE_ERROR = "decode-error"
    #: The same parameter name appears more than once; the first value wins.
    DUPLICATE_PARAMETER = "duplicate-parameter"
    #: ``filename*`` is absent or unusable, so ``filename`` was used.
    FILENAME_BASIC_FALLBACK = "filename-basic-fallback"
    #: Neither ``filename*`` nor ``filename`` gave a usable filename.
    NO_FILENAME = "no-filename"
    #: The chosen filename is empty, or became empty when made safe (only
    #: directory separators or control characters).
    EMPTY_FILENAME = "empty-filename"


class ContentDispositionIssueInfo(NamedTuple):
    """A single fallback reported while parsing a Content-Disposition value."""

    #: What went wrong.
    code: ContentDispositionIssue
    #: Human-readable detail, naming the offending parameter or charset.
    detail: str
    #: Parameter the issue concerns, if any.
    parameter: str | None = None


class ExtendedParameter(NamedTuple):
    """An extended parameter parsed from an ``name*=`` value (RFC 8187)."""

    #: Declared charset, taken verbatim from the parameter (e.g. ``"UTF-8"``).
    charset: str
    #: Declared language tag (possibly empty).
    language: str
    #: Decoded value.
    value: str


class ParsedContentDisposition(NamedTuple):
    """Result of :func:`parse_content_disposition`."""

    #: Disposition type, lowercased (e.g. ``"attachment"``), or ``None``.
    disposition: str | None
    #: Plain parameters, mapping lowercased names to their decoded values.
    parameters: dict[str, str]
    #: Extended (``name*``) parameters, keyed by the name without the ``*``.
    extended_parameters: dict[str, ExtendedParameter]
    #: Filename as declared by the sender, before local sanitization, or
    #: ``None``. This is never guessed or synthesized.
    filename: str | None
    #: Whether :attr:`filename` came from ``filename*``, ``filename``, or no
    #: parameter.
    filename_source: FilenameSource
    #: A filesystem-safe version of :attr:`filename` (path components and
    #: control characters removed; an empty result becomes
    #: :data:`DEFAULT_FILENAME`), or ``None`` when there is no filename.
    safe_filename: str | None
    #: Deterministic list of every fallback applied during parsing.
    issues: list[ContentDispositionIssueInfo]


def _split_on_semicolons(value: str) -> list[str]:
    """Split *value* on semicolons, ignoring those inside quoted strings.

    Backslashes inside a quoted string escape the following character, so an
    escaped quote does not terminate the string.
    """
    parts: list[str] = []
    start = 0
    in_quotes = False
    escaped = False
    for index, char in enumerate(value):
        if in_quotes:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_quotes = False
        elif char == '"':
            in_quotes = True
        elif char == ";":
            parts.append(value[start:index])
            start = index + 1
    parts.append(value[start:])
    return parts


def _parse_quoted_string(text: str) -> tuple[str | None, str]:
    """Parse a quoted-string at the start of *text*.

    Return ``(value, remainder)``. *value* is ``None`` when *text* is not a
    well-formed quoted string (RFC 9110).
    """
    chars = []
    index = 1
    length = len(text)
    while index < length:
        char = text[index]
        if char == '"':
            return "".join(chars), text[index + 1 :]
        if char == "\\":
            index += 1
            if index >= length:
                return None, ""
            char = text[index]
        chars.append(char)
        index += 1
    return None, ""


def _decode_extended_value(
    text: str,
) -> tuple[ExtendedParameter | None, ContentDispositionIssue | None, str]:
    """Parse an RFC 8187 extended-value into an :class:`ExtendedParameter`.

    Return the parameter, or ``(None, issue_code, detail)`` on failure.
    """
    first = text.find("'")
    if first < 0:
        return (
            None,
            ContentDispositionIssue.EXTENDED_SYNTAX,
            "missing charset separator",
        )
    second = text.find("'", first + 1)
    if second < 0:
        return (
            None,
            ContentDispositionIssue.EXTENDED_SYNTAX,
            "missing language separator",
        )

    charset = text[:first]
    language = text[first + 1 : second]
    data = text[second + 1 :]

    if not charset or not _TOKEN_RE.fullmatch(charset):
        return None, ContentDispositionIssue.EXTENDED_SYNTAX, "invalid charset"
    if language and not _TOKEN_RE.fullmatch(language):
        return None, ContentDispositionIssue.EXTENDED_SYNTAX, "invalid language"

    raw = bytearray()
    index = 0
    while index < len(data):
        char = data[index]
        if char == "%":
            hex_pair = data[index + 1 : index + 3]
            if len(hex_pair) != 2 or any(c not in _HEX_DIGITS for c in hex_pair):
                return (
                    None,
                    ContentDispositionIssue.MALFORMED_PERCENT,
                    f"bad escape at position {index}",
                )
            raw.append(int(hex_pair, 16))
            index += 3
        elif char in _ATTR_ALLOWED:
            raw.append(ord(char))
            index += 1
        else:
            return (
                None,
                ContentDispositionIssue.EXTENDED_SYNTAX,
                f"illegal character {char!r}",
            )

    try:
        codecs.lookup(charset)
    except LookupError:
        return (
            None,
            ContentDispositionIssue.UNKNOWN_CHARSET,
            f"unknown charset {charset!r}",
        )

    try:
        decoded = bytes(raw).decode(charset)
    except UnicodeDecodeError as error:
        return (
            None,
            ContentDispositionIssue.DECODE_ERROR,
            f"cannot decode as {charset!r}: {error}",
        )
    if any(unicodedata.category(char) == "Cc" for char in decoded):
        return (
            None,
            ContentDispositionIssue.DECODE_ERROR,
            f"control character while decoding as {charset!r}",
        )
    return ExtendedParameter(charset, language, decoded), None, ""


def safe_filename(filename: str) -> str:
    """Return a filesystem-safe version of *filename*.

    Directory traversal is neutralized by keeping only the part after the
    last ``/`` or ``\\``, and Unicode control characters are removed. The
    result is stripped of surrounding spaces and tabs; if nothing is left,
    :data:`DEFAULT_FILENAME` is returned. No file is created.

    >>> safe_filename('report.pdf')
    'report.pdf'
    >>> safe_filename('../../etc/passwd')
    'passwd'
    >>> safe_filename('C:\\\\Windows\\\\win.ini')
    'win.ini'
    >>> safe_filename('  ')
    'download'
    """
    return _sanitize_filename(filename) or DEFAULT_FILENAME


def _sanitize_filename(filename: str) -> str:
    cleaned = "".join(
        char
        for char in filename
        if unicodedata.category(char) != "Cc"
    )
    # Take the part after the last path separator, so traversal sequences
    # and drive/UNC prefixes cannot target other directories.
    base = cleaned.replace("\\", "/").rsplit("/", 1)[-1]
    return base.strip(" \t")


def parse_content_disposition(
    value: str | bytes,
) -> ParsedContentDisposition:
    """Structurally parse a ``Content-Disposition`` header value.

    The disposition type, plain parameters (RFC 9110) and extended
    parameters (``name*``, RFC 8187) are returned separately. A usable
    filename is selected with ``filename*`` taking precedence over
    ``filename``; both the original name and a filesystem-safe version are
    returned. Nothing is guessed: every recovery is recorded in
    :attr:`ParsedContentDisposition.issues`.

    Byte input is decoded as ISO-8859-1, the header transport encoding;
    extended parameters carry their own charset and are decoded separately.

    >>> result = parse_content_disposition(
    ...     b"attachment; filename=fallback.txt; "
    ...     b"filename*=UTF-8''%E4%B8%AD%E6%96%87.txt"
    ... )
    >>> result.disposition
    'attachment'
    >>> result.filename
    '中文.txt'
    >>> result.filename_source
    <FilenameSource.EXTENDED: 'extended'>
    >>> result.safe_filename
    '中文.txt'
    >>> result.extended_parameters['filename'].charset
    'UTF-8'
    """
    if isinstance(value, bytes):
        text = value.decode("iso-8859-1")
    elif isinstance(value, str):
        text = value
    else:
        raise TypeError(
            f"value must be str or bytes, got {type(value).__name__}"
        )

    issues: list[ContentDispositionIssueInfo] = []
    parameters: dict[str, str] = {}
    extended_parameters: dict[str, ExtendedParameter] = {}
    extended_filename_failed = False

    parts = _split_on_semicolons(text)

    disposition: str | None = None
    first = parts[0].strip()
    if first:
        if _TOKEN_RE.fullmatch(first):
            disposition = first.lower()
        else:
            issues.append(
                ContentDispositionIssueInfo(
                    ContentDispositionIssue.INVALID_DISPOSITION,
                    f"invalid disposition type {first!r}",
                )
            )

    for part in parts[1:]:
        piece = part.strip(" \t")
        if not piece:
            continue
        name, equals, raw_value = piece.partition("=")
        if not equals or not name or not _TOKEN_RE.fullmatch(name):
            issues.append(
                ContentDispositionIssueInfo(
                    ContentDispositionIssue.INVALID_PARAMETER_NAME,
                    f"invalid parameter {piece!r}",
                )
            )
            continue

        name = name.lower()
        if name.endswith("*"):
            base_name = name[:-1]
            if not base_name:
                issues.append(
                    ContentDispositionIssueInfo(
                        ContentDispositionIssue.EXTENDED_SYNTAX,
                        "empty extended parameter name",
                        name,
                    )
                )
                continue
            if raw_value.startswith('"'):
                issues.append(
                    ContentDispositionIssueInfo(
                        ContentDispositionIssue.EXTENDED_SYNTAX,
                        "extended value must not be quoted",
                        name,
                    )
                )
                continue
            extended, issue_code, detail = _decode_extended_value(raw_value)
            if extended is None:
                assert issue_code is not None
                issues.append(
                    ContentDispositionIssueInfo(issue_code, detail, name)
                )
                if base_name == "filename":
                    extended_filename_failed = True
                continue
            if base_name in extended_parameters:
                issues.append(
                    ContentDispositionIssueInfo(
                        ContentDispositionIssue.DUPLICATE_PARAMETER,
                        f"parameter {name!r} repeated",
                        name,
                    )
                )
                continue
            extended_parameters[base_name] = extended
            continue

        if raw_value.startswith('"'):
            parsed_value, remainder = _parse_quoted_string(raw_value)
            if parsed_value is None or remainder.strip(" \t"):
                issues.append(
                    ContentDispositionIssueInfo(
                        ContentDispositionIssue.INVALID_QUOTED_VALUE,
                        f"malformed quoted value for {name!r}",
                        name,
                    )
                )
                continue
            param_value = parsed_value
        else:
            if not _is_bare_value(raw_value):
                issues.append(
                    ContentDispositionIssueInfo(
                        ContentDispositionIssue.INVALID_PARAMETER_VALUE,
                        f"malformed value for {name!r}",
                        name,
                    )
                )
                continue
            param_value = raw_value

        if name in parameters:
            issues.append(
                ContentDispositionIssueInfo(
                    ContentDispositionIssue.DUPLICATE_PARAMETER,
                    f"parameter {name!r} repeated",
                    name,
                )
            )
            continue
        parameters[name] = param_value

    extended_filename = extended_parameters.get("filename")
    basic_filename = parameters.get("filename")

    if extended_filename is not None:
        filename = extended_filename.value
        filename_source = FilenameSource.EXTENDED
    elif basic_filename is not None:
        filename = basic_filename
        filename_source = FilenameSource.BASIC
        if extended_filename_failed:
            issues.append(
                ContentDispositionIssueInfo(
                    ContentDispositionIssue.FILENAME_BASIC_FALLBACK,
                    "filename* parameter is unusable; using filename",
                    "filename*",
                )
            )
    else:
        filename = None
        filename_source = FilenameSource.NONE
        issues.append(
            ContentDispositionIssueInfo(
                ContentDispositionIssue.NO_FILENAME,
                "no filename or filename* parameter",
                "filename",
            )
        )

    if filename is None:
        safe = None
    else:
        safe = safe_filename(filename)
        if not _sanitize_filename(filename):
            issues.append(
                ContentDispositionIssueInfo(
                    ContentDispositionIssue.EMPTY_FILENAME,
                    "filename is empty or reduced to no safe characters",
                    "filename",
                )
            )

    return ParsedContentDisposition(
        disposition,
        parameters,
        extended_parameters,
        filename,
        filename_source,
        safe,
        issues,
    )


__all__ = [
    "ContentDispositionIssue",
    "ContentDispositionIssueInfo",
    "DEFAULT_FILENAME",
    "ExtendedParameter",
    "FilenameSource",
    "ParsedContentDisposition",
    "basic_auth_header",
    "headers_dict_to_raw",
    "headers_raw_to_dict",
    "parse_content_disposition",
    "safe_filename",
]
