from __future__ import annotations

import codecs
import re
from base64 import b64encode
from collections.abc import Mapping, MutableMapping, Sequence
from dataclasses import dataclass, field
from io import BytesIO
from typing import Any, TypeAlias, overload

from w3lib._util import to_unicode

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


@dataclass(frozen=True)
class ContentDispositionExtParam:
    """A decoded `RFC 8187`_ extended parameter (``name*=charset'lang'value``).

    ``value`` is ``None`` when the parameter could not be decoded (unknown
    charset or malformed value); the reason is then reported in
    :attr:`ContentDisposition.warnings` and ``raw`` keeps the undecoded text.

    .. _RFC 8187: https://www.rfc-editor.org/rfc/rfc8187.html
    """

    value: str | None
    charset: str
    language: str
    raw: str


@dataclass(frozen=True)
class ContentDisposition:
    """Structured result of :func:`parse_content_disposition`.

    - ``disposition``: the disposition type, lowercased (e.g. ``attachment``).
    - ``params``: regular parameters, names lowercased, values unquoted and
      unescaped but otherwise untouched.
    - ``ext_params``: RFC 8187 extended parameters as
      :class:`ContentDispositionExtParam` objects.
    - ``filename``: the filename exactly as sent, chosen from ``filename*``
      when available and decodable, else from ``filename``.
    - ``safe_filename``: ``filename`` sanitized for local saving (no
      directory components, control characters or Windows-hostile
      trailing characters), or ``None`` when nothing usable remains.
    - ``warnings``: every fallback or lossy decision taken while parsing,
      so callers never have to guess why a value looks the way it does.
    """

    disposition: str
    params: dict[str, str] = field(default_factory=dict)
    ext_params: dict[str, ContentDispositionExtParam] = field(default_factory=dict)
    filename: str | None = None
    safe_filename: str | None = None
    warnings: tuple[str, ...] = ()


_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _split_header_parts(value: str) -> list[str]:
    """Split a header value on ``;`` that are not inside a quoted string.

    Only ``\\"`` and ``\\\\`` count as escapes, matching how
    :func:`_unquote` interprets them.
    """
    parts = []
    current: list[str] = []
    in_quote = False
    index = 0
    while index < len(value):
        char = value[index]
        if (
            in_quote
            and char == "\\"
            and index + 1 < len(value)
            and value[index + 1] in ('"', "\\")
        ):
            current.append(char)
            current.append(value[index + 1])
            index += 2
            continue
        if char == '"':
            current.append(char)
            in_quote = not in_quote
        elif char == ";" and not in_quote:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
        index += 1
    parts.append("".join(current))
    return parts


def _unquote(value: str, warnings: list[str]) -> str:
    """Unescape a quoted-string value, recording malformed input.

    Only ``\\"`` and ``\\\\`` are unescaped; other backslashes are kept
    literally, so that Windows paths such as ``C:\\dir\\file`` survive,
    as `RFC 6266`_ appendix D recommends for filenames.

    .. _RFC 6266: https://www.rfc-editor.org/rfc/rfc6266.html
    """
    out: list[str] = []
    index = 1
    closed = False
    while index < len(value):
        char = value[index]
        if (
            char == "\\"
            and index + 1 < len(value)
            and value[index + 1] in ('"', "\\")
        ):
            out.append(value[index + 1])
            index += 2
        elif char == '"':
            closed = True
            index += 1
            break
        else:
            out.append(char)
            index += 1
    if not closed:
        warnings.append("unterminated quoted string; using the rest of the value")
    elif value[index:].strip():
        warnings.append("ignoring data after the closing quote")
    return "".join(out)


def _percent_decode(value: str) -> tuple[bytes, bool]:
    """Decode ``%XX`` sequences, keeping malformed ones literally."""
    out = bytearray()
    malformed = False
    index = 0
    while index < len(value):
        char = value[index]
        if (
            char == "%"
            and index + 2 < len(value)
            and value[index + 1] in _HEX_DIGITS
            and value[index + 2] in _HEX_DIGITS
        ):
            out.append(int(value[index + 1 : index + 3], 16))
            index += 3
        elif char == "%":
            malformed = True
            out.append(ord("%"))
            index += 1
        elif ord(char) < 256:
            out.append(ord(char))
            index += 1
        else:
            malformed = True
            out.append(ord("?"))
            index += 1
    return bytes(out), malformed


def _parse_ext_param(
    name: str, value: str, warnings: list[str]
) -> ContentDispositionExtParam:
    """Parse an RFC 8187 extended parameter value (``charset'lang'value``)."""
    charset, sep, rest = value.partition("'")
    language, sep2, encoded = rest.partition("'")
    if not sep or not sep2:
        warnings.append(
            f"extended parameter {name!r} is not in the charset'language'value "
            "form; parameter ignored"
        )
        return ContentDispositionExtParam(None, "", "", value)
    charset = charset.strip().lower()
    language = language.strip()
    try:
        codecs.lookup(charset)
    except LookupError:
        warnings.append(
            f"unknown charset {charset!r} in extended parameter {name!r}; "
            "parameter ignored"
        )
        return ContentDispositionExtParam(None, charset, language, value)
    raw_bytes, malformed = _percent_decode(encoded)
    if malformed:
        warnings.append(
            f"malformed percent-encoding in extended parameter {name!r}; "
            "invalid sequences kept literally"
        )
    try:
        decoded = raw_bytes.decode(charset)
    except UnicodeDecodeError:
        decoded = raw_bytes.decode(charset, "replace")
        warnings.append(
            f"bytes in extended parameter {name!r} are not valid {charset}; "
            "undecodable bytes replaced"
        )
    return ContentDispositionExtParam(decoded, charset, language, value)


def _sanitize_filename(filename: str) -> tuple[str | None, list[str]]:
    """Reduce *filename* to something safe to save under, without inventing
    a name of our own."""
    warnings = []
    # Take the last path component, on both Unix and Windows separators.
    basename = re.split(r"[/\\]", filename)[-1]
    if basename != filename:
        warnings.append("directory components removed from the filename")
    # Drop C0 control characters and DEL.
    cleaned = "".join(char for char in basename if char >= " " and char != "\x7f")
    if cleaned != basename:
        warnings.append("control characters removed from the filename")
    # Trailing dots and spaces are not usable on Windows.
    stripped = cleaned.rstrip(" .")
    if stripped != cleaned:
        warnings.append("trailing dots and spaces removed from the filename")
    if not stripped:
        warnings.append("no usable filename remains after sanitization")
        return None, warnings
    return stripped, warnings


def parse_content_disposition(header: str | bytes | None) -> ContentDisposition | None:
    r"""
    Parse a ``Content-Disposition`` header value into a
    :class:`ContentDisposition`.

    >>> import w3lib.http
    >>> result = w3lib.http.parse_content_disposition(
    ...     "attachment; filename*=utf-8''%E6%8A%A5%E8%A1%A8.csv"
    ... )
    >>> result.disposition
    'attachment'
    >>> result.filename
    '\u62a5\u8868.csv'
    >>> result.safe_filename
    '\u62a5\u8868.csv'

    Deterministic policies for ambiguous input (each one also adds an entry
    to ``warnings``):

    - A repeated parameter keeps its first occurrence.
    - A malformed ``%`` sequence in an extended parameter is kept literally.
    - An extended parameter with an unknown charset or a malformed
      ``charset'language'value`` shape is ignored, and filename selection
      falls back to the plain ``filename`` parameter.
    - When both ``filename`` and a decodable ``filename*`` are present,
      ``filename*`` wins, as `RFC 6266`_ recommends.

    ``filename`` is the name as sent; ``safe_filename`` is a sanitized
    variant with directory components, control characters and trailing
    dots or spaces removed. Neither is ever invented: when nothing usable
    remains, they are ``None``.

    Argument is ``None`` (returns ``None``):

    >>> w3lib.http.parse_content_disposition(None)
    >>>

    .. _RFC 6266: https://www.rfc-editor.org/rfc/rfc6266.html
    """
    if header is None:
        return None
    # HTTP field values are bytes on the wire; ISO-8859-1 maps them 1:1.
    value = to_unicode(header, encoding="iso-8859-1")
    warnings: list[str] = []

    parts = _split_header_parts(value)
    disposition = parts[0].strip().lower()

    params: dict[str, str] = {}
    ext_params: dict[str, ContentDispositionExtParam] = {}
    for part in parts[1:]:
        name, sep, param_value = part.partition("=")
        name = name.strip().lower()
        if not name:
            if part.strip():
                warnings.append(f"ignoring parameter without a name: {part.strip()!r}")
            continue
        if not sep:
            warnings.append(f"parameter {name!r} has no value; ignored")
            continue
        param_value = param_value.strip()
        if name.endswith("*"):
            base_name = name[:-1]
            if param_value.startswith('"'):
                warnings.append(
                    f"extended parameter {base_name!r} must not be quoted; "
                    "quotes removed"
                )
                param_value = _unquote(param_value, warnings)
            if base_name in ext_params:
                warnings.append(
                    f"duplicate extended parameter {base_name!r}; "
                    "keeping the first occurrence"
                )
                continue
            ext_params[base_name] = _parse_ext_param(base_name, param_value, warnings)
            continue
        if param_value.startswith('"'):
            param_value = _unquote(param_value, warnings)
        if name in params:
            warnings.append(
                f"duplicate parameter {name!r}; keeping the first occurrence"
            )
            continue
        params[name] = param_value

    filename: str | None = None
    ext_filename = ext_params.get("filename")
    if ext_filename is not None and ext_filename.value is not None:
        filename = ext_filename.value
    elif "filename" in params:
        if ext_filename is not None:
            warnings.append(
                "extended parameter 'filename' is unusable; "
                "falling back to the plain 'filename' parameter"
            )
        filename = params["filename"]

    safe_filename: str | None = None
    if filename is not None:
        safe_filename, sanitize_warnings = _sanitize_filename(filename)
        warnings.extend(sanitize_warnings)

    return ContentDisposition(
        disposition=disposition,
        params=params,
        ext_params=ext_params,
        filename=filename,
        safe_filename=safe_filename,
        warnings=tuple(warnings),
    )
