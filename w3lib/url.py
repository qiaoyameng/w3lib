"""
This module contains general purpose URL functions not found in the standard
library.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import os
import posixpath
import re
from ipaddress import IPv6Address, ip_address
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple, cast, overload
from urllib.parse import ParseResult, urljoin
from urllib.request import pathname2url

from ._url import (
    _PATH_SAFE_CHARS,
    _SAFE_CHARS,
    _SCHEME_RE,
    _SPECIAL_SCHEMES,
    # reexports
    RFC3986_GEN_DELIMS as RFC3986_GEN_DELIMS,
    RFC3986_RESERVED as RFC3986_RESERVED,
    RFC3986_SUB_DELIMS as RFC3986_SUB_DELIMS,
    RFC3986_UNRESERVED as RFC3986_UNRESERVED,
    RFC3986_USERINFO_SAFE_CHARS as RFC3986_USERINFO_SAFE_CHARS,
    _idna_bytes,
    _parse_qs,
    _parse_qsl,
    _quote,
    _quote_into,
    _split_params,
    _strip,
    _unquote,
    _url2pathname,
    _urlencode,
    _urlparse,
    _urlsplit,
    _urlunparse,
    _urlunsplit,
)
from ._util import to_unicode

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from typing import BinaryIO

    from ._types import AnyUnicodeError


# error handling function for bytes-to-Unicode decoding errors with URLs
def _quote_byte(error: UnicodeError) -> tuple[str, int]:
    error = cast("AnyUnicodeError", error)
    text = error.object[error.start : error.end]
    if isinstance(text, str):  # pragma: no cover
        text = text.encode()
    return (to_unicode(_quote(text)), error.end)


codecs.register_error("percentencode", _quote_byte)

# Characters that are safe in all of:
#
# -   RFC 2396 + RFC 2732, as interpreted by Java 8’s java.net.URI class
# -   RFC 3986
# -   The URL living standard
#
# % is currently excluded from these lists of characters, due to limitations
# of the current safe_url_string implementation, but it should also be escaped
# as %25 when it is not already being used as part of an escape character.
_USERINFO_SAFEST_CHARS = RFC3986_USERINFO_SAFE_CHARS.translate(None, delete=b":;=")
_PATH_SAFEST_CHARS = _SAFE_CHARS.translate(None, delete=b"#[]|")
_QUERY_SAFEST_CHARS = _PATH_SAFEST_CHARS
_SPECIAL_QUERY_SAFEST_CHARS = _PATH_SAFEST_CHARS.translate(None, delete=b"'")
_FRAGMENT_SAFEST_CHARS = _PATH_SAFEST_CHARS


def _safe_url_split(
    url: str | bytes,
    encoding: str = "utf8",
    path_encoding: str = "utf8",
    quote_path: bool = True,
) -> tuple[str, str, str, str, str]:
    # urlsplit() chokes on bytes input with non-ASCII chars,
    # so let's decode (to Unicode) using page encoding:
    #   - it is assumed that a raw bytes input comes from a document
    #     encoded with the supplied encoding (or UTF8 by default)
    #   - if the supplied (or default) encoding chokes,
    #     percent-encode offending bytes
    parts = _urlsplit(
        _strip(to_unicode(url, encoding=encoding, errors="percentencode"))
    )
    tmp_buf = bytearray()  # utf-8 bytes

    if parts.username is not None:
        _quote_into(
            _unquote(parts.username),
            tmp_buf,
            _USERINFO_SAFEST_CHARS,
        )

        if parts.password is not None:
            tmp_buf.append(58)  # ord(":")
            _quote_into(
                _unquote(parts.password),
                tmp_buf,
                _USERINFO_SAFEST_CHARS,
            )

        tmp_buf.append(64)  # ord("@")

    if parts.hostname is not None:
        if ":" in parts.hostname:
            # IPv6 address: urlsplit() strips the brackets from the hostname,
            # but they are required in the netloc when rebuilding the URL.
            tmp_buf.append(91)  # ord("[")
            tmp_buf += parts.hostname.encode("ascii")
            tmp_buf.append(93)  # ord("]")
        else:
            try:
                tmp_buf += _idna_bytes(parts.hostname)
            except UnicodeError:
                # IDNA encoding can fail for too long labels (>63 characters) or
                # missing labels (e.g. http://.example.com).
                tmp_buf += parts.hostname.encode()

    if parts.port is not None:
        tmp_buf.append(58)  # ord(":")
        tmp_buf += str(parts.port).encode("ascii")

    netloc = tmp_buf.decode()
    tmp_buf.clear()

    if quote_path:
        _quote_into(parts.path.encode(path_encoding), tmp_buf, _PATH_SAFEST_CHARS)
        path = tmp_buf.decode()
        tmp_buf.clear()
    else:
        path = parts.path

    _quote_into(
        parts.query.encode(encoding),
        tmp_buf,
        _SPECIAL_QUERY_SAFEST_CHARS
        if parts.scheme in _SPECIAL_SCHEMES
        else _QUERY_SAFEST_CHARS,
    )
    query = tmp_buf.decode()
    tmp_buf.clear()

    if parts.fragment:
        _quote_into(parts.fragment.encode(encoding), tmp_buf, _FRAGMENT_SAFEST_CHARS)
        fragment = tmp_buf.decode()
        tmp_buf.clear()
    else:
        fragment = parts.fragment

    # The path of a special URL is never empty, e.g. “https://example.com”
    # serializes as “https://example.com/”.
    if not path and parts.scheme in _SPECIAL_SCHEMES:
        path = "/"

    return (
        parts.scheme,
        netloc,
        path,
        query,
        fragment,
    )


def safe_url_string(
    url: str | bytes,
    encoding: str = "utf8",
    path_encoding: str = "utf8",
    quote_path: bool = True,
) -> str:
    """Return a URL equivalent to *url* that a wide range of web browsers and
    web servers consider valid.

    *url* is parsed according to the rules of the `URL living standard`_,
    and during serialization additional characters are percent-encoded to make
    the URL valid by additional URL standards.

    .. _URL living standard: https://url.spec.whatwg.org/

    The returned URL should be valid by *all* of the following URL standards
    known to be enforced by modern-day web browsers and web servers:

    -   `URL living standard`_

    -   `RFC 3986`_

    -   `RFC 2396`_ and `RFC 2732`_, as interpreted by `Java 8’s java.net.URI
        class`_.

    .. _Java 8’s java.net.URI class: https://docs.oracle.com/javase/8/docs/api/java/net/URI.html
    .. _RFC 2396: https://www.ietf.org/rfc/rfc2396.txt
    .. _RFC 2732: https://www.ietf.org/rfc/rfc2732.txt
    .. _RFC 3986: https://www.ietf.org/rfc/rfc3986.txt

    If a bytes URL is given, it is first converted to `str` using the given
    encoding (which defaults to 'utf-8'). If quote_path is True (default),
    path_encoding ('utf-8' by default) is used to encode URL path component
    which is then quoted. Otherwise, if quote_path is False, path component
    is not encoded or quoted. Given encoding is used for query string
    or form data.

    When passing an encoding, you should use the encoding of the
    original page (the page from which the URL was extracted from).

    Calling this function on an already "safe" URL will return the URL
    unmodified.
    """
    return _urlunsplit(*_safe_url_split(url, encoding, path_encoding, quote_path))


_parent_dirs = re.compile(r"/?(\.\./)+")

# Percent-encoded forms of the single-dot and double-dot path segments of the
# URL living standard, which clients resolve like "." and "..".
_encoded_dot_segments = {
    "%2e": ".",
    ".%2e": "..",
    "%2e.": "..",
    "%2e%2e": "..",
}


def safe_download_url(
    url: str | bytes, encoding: str = "utf8", path_encoding: str = "utf8"
) -> str:
    """Make a url for download. This will call safe_url_string
    and then strip the fragment, if one exists. The path will
    be normalised.

    If the path is outside the document root, it will be changed
    to be within the document root.
    """
    safe_url = safe_url_string(url, encoding, path_encoding)
    scheme, netloc, path, query, _ = _urlsplit(safe_url)
    if path:
        if "%" in path:
            path = "/".join(
                _encoded_dot_segments.get(segment.lower(), segment)
                for segment in path.split("/")
            )
        normalized_path = _parent_dirs.sub("", posixpath.normpath(path))
        if path.endswith("/") and not normalized_path.endswith("/"):
            normalized_path = f"{normalized_path}/"
        path = normalized_path
    return _urlunsplit(scheme, netloc, path, query, "")


def is_url(text: str) -> bool:
    return text.partition("://")[0] in {"file", "http", "https"}


@overload
def url_query_parameter(
    url: str | bytes,
    parameter: str,
    default: None = None,
    keep_blank_values: bool | int = 0,
    *,
    separator: str = "&",
) -> str | None: ...


@overload
def url_query_parameter(
    url: str | bytes,
    parameter: str,
    default: str,
    keep_blank_values: bool | int = 0,
    *,
    separator: str = "&",
) -> str: ...


def url_query_parameter(
    url: str | bytes,
    parameter: str,
    default: str | None = None,
    keep_blank_values: bool | int = 0,
    *,
    separator: str = "&",
) -> str | None:
    """Return the value of a url parameter, given the url and parameter name

    If url contains multiple parameters, the first leftmost one is returned.

    General case:

    >>> import w3lib.url
    >>> w3lib.url.url_query_parameter("product.html?id=200&foo=bar", "id")
    '200'
    >>>

    Return a default value if the parameter is not found:

    >>> w3lib.url.url_query_parameter("product.html?id=200&foo=bar", "notthere", "mydefault")
    'mydefault'
    >>>

    Returns None if `keep_blank_values` not set or 0 (default):

    >>> w3lib.url.url_query_parameter("product.html?id=", "id")
    >>>

    Returns an empty string if `keep_blank_values` set to 1:

    >>> w3lib.url.url_query_parameter("product.html?id=", "id", keep_blank_values=1)
    ''
    >>>

    """

    queryparams = _parse_qs(
        _urlsplit(to_unicode(url)).query,
        keep_blank_values=bool(keep_blank_values),
        separator=separator.encode(),
    )
    parameter_bytes = parameter.encode()
    if parameter_bytes in queryparams:
        return queryparams[parameter_bytes][0].decode(errors="replace")
    return default


def url_query_cleaner(
    url: str | bytes,
    parameterlist: str | Sequence[str] = (),
    sep: str = "&",
    kvsep: str = "=",
    remove: bool = False,
    unique: bool = True,
    keep_fragments: bool = False,
) -> str:
    """Clean URL arguments leaving only those passed in the parameterlist keeping order

    >>> import w3lib.url
    >>> w3lib.url.url_query_cleaner("product.html?id=200&foo=bar&name=wired", ('id',))
    'product.html?id=200'
    >>> w3lib.url.url_query_cleaner("product.html?id=200&foo=bar&name=wired", ['id', 'name'])
    'product.html?id=200&name=wired'
    >>>

    If `unique` is ``False``, do not remove duplicated keys

    >>> w3lib.url.url_query_cleaner("product.html?d=1&e=b&d=2&d=3&other=other", ['d'], unique=False)
    'product.html?d=1&d=2&d=3'
    >>>

    If `remove` is ``True``, leave only those **not in parameterlist**.

    >>> w3lib.url.url_query_cleaner("product.html?id=200&foo=bar&name=wired", ['id'], remove=True)
    'product.html?foo=bar&name=wired'
    >>> w3lib.url.url_query_cleaner("product.html?id=2&foo=bar&name=wired", ['id', 'foo'], remove=True)
    'product.html?name=wired'
    >>>

    By default, URL fragments are removed. If you need to preserve fragments,
    pass the ``keep_fragments`` argument as ``True``.

    >>> w3lib.url.url_query_cleaner('http://domain.tld/?bla=123#123123', ['bla'], remove=True, keep_fragments=True)
    'http://domain.tld/#123123'

    """

    if parameterlist and isinstance(parameterlist, (str, bytes)):
        parameterlist = (parameterlist,)

    if isinstance(url, bytes):
        url = url.decode()

    url, _, fragment = url.partition("#")
    base, _, query = url.partition("?")

    if not query or (not parameterlist and not remove):
        return base if not (keep_fragments and fragment) else f"{base}#{fragment}"

    param_lookup = frozenset(parameterlist)

    seen: set[str] | None = set() if unique else None
    result: list[str] = []

    for ksv in query.split(sep):
        if not ksv:
            continue

        k, _, _ = ksv.partition(kvsep)

        if seen is not None:
            if k in seen:
                continue
            seen.add(k)

        if remove:
            if k in param_lookup:
                continue
        elif k not in param_lookup:
            continue

        result.append(ksv)
    del param_lookup, seen

    url = base if not result else f"{base}?{sep.join(result)}"
    del result

    if keep_fragments and fragment:
        url = f"{url}#{fragment}"

    return url


def _add_or_replace_parameters(
    url: str, params: dict[bytes, bytes], *, separator: str = "&"
) -> str:
    parsed = _urlsplit(url)

    current_args = _parse_qsl(
        parsed.query, keep_blank_values=True, separator=separator.encode()
    )

    new_args: list[tuple[bytes, bytes]] = []
    seen_params: set[bytes] = set()

    for name, value in current_args:
        if name in seen_params:
            continue
        replacement = params.get(name)
        if replacement is None:
            new_args.append((name, value))
        else:
            new_args.append((name, replacement))
            seen_params.add(name)

    for name, value in params.items():
        if name not in seen_params:
            new_args.append((name, value))
    del seen_params, current_args

    return _urlunsplit(
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        _urlencode(new_args, separator.encode()).decode(),
        parsed.fragment,
    )


def add_or_replace_parameter(
    url: str, name: str, new_value: str, *, separator: str = "&"
) -> str:
    """Add or remove a parameter to a given url

    >>> import w3lib.url
    >>> w3lib.url.add_or_replace_parameter('http://www.example.com/index.php', 'arg', 'v')
    'http://www.example.com/index.php?arg=v'
    >>> w3lib.url.add_or_replace_parameter('http://www.example.com/index.php?arg1=v1&arg2=v2&arg3=v3', 'arg4', 'v4')
    'http://www.example.com/index.php?arg1=v1&arg2=v2&arg3=v3&arg4=v4'
    >>> w3lib.url.add_or_replace_parameter('http://www.example.com/index.php?arg1=v1&arg2=v2&arg3=v3', 'arg3', 'v3new')
    'http://www.example.com/index.php?arg1=v1&arg2=v2&arg3=v3new'
    >>> w3lib.url.add_or_replace_parameter('http://www.example.com/index.php?arg1=v1;arg2=v2', 'arg3', 'v3', separator=';')
    'http://www.example.com/index.php?arg1=v1;arg2=v2;arg3=v3'
    >>>

    ``separator`` is used both to split the existing query and to join the
    resulting one.

    """
    return _add_or_replace_parameters(
        url, {name.encode(): new_value.encode()}, separator=separator
    )


def add_or_replace_parameters(
    url: str, new_parameters: dict[str, str], *, separator: str = "&"
) -> str:
    """Add or remove a parameters to a given url

    >>> import w3lib.url
    >>> w3lib.url.add_or_replace_parameters('http://www.example.com/index.php', {'arg': 'v'})
    'http://www.example.com/index.php?arg=v'
    >>> args = {'arg4': 'v4', 'arg3': 'v3new'}
    >>> w3lib.url.add_or_replace_parameters('http://www.example.com/index.php?arg1=v1&arg2=v2&arg3=v3', args)
    'http://www.example.com/index.php?arg1=v1&arg2=v2&arg3=v3new&arg4=v4'
    >>>

    """
    return _add_or_replace_parameters(
        url,
        {k.encode(): v.encode() for k, v in new_parameters.items()},
        separator=separator,
    )


def path_to_file_uri(path: str | os.PathLike[str]) -> str:
    """Convert local filesystem path to legal File URIs as described in:
    http://en.wikipedia.org/wiki/File_URI_scheme
    """
    absolute_path = Path(path).absolute()
    if os.name == "nt" and absolute_path.drive.startswith("\\\\"):
        return absolute_path.as_uri()
    return f"file:///{pathname2url(str(absolute_path)).lstrip('/')}"


def file_uri_to_path(uri: str) -> str:
    """Convert File URI to local filesystem path according to:
    http://en.wikipedia.org/wiki/File_URI_scheme
    """
    parsed = _urlparse(uri)
    path = parsed.path
    if os.name == "nt" and parsed.netloc and parsed.netloc.lower() != "localhost":
        path = f"//{parsed.netloc}{path}"
    return _url2pathname(path)


def any_to_uri(uri_or_path: str) -> str:
    """If given a path name, return its File URI, otherwise return it
    unmodified
    """
    if os.path.splitdrive(uri_or_path)[0]:
        return path_to_file_uri(uri_or_path)
    return uri_or_path if _urlparse(uri_or_path)[0] else path_to_file_uri(uri_or_path)


def add_http_if_no_scheme(url: str) -> str:
    """Add ``http`` as the default scheme if it is missing from *url*."""
    if not re.match(r"^\w+://", url, flags=re.IGNORECASE):
        scheme = "http:" if _urlparse(url).netloc else "http://"
        url = scheme + url
    return url


# ASCII characters.
_char = set(map(chr, range(127)))

# RFC 2045 token.
_token = r"[{}]+".format(
    re.escape(
        "".join(
            _char
            -
            # Control characters.
            set(map(chr, range(32)))
            -
            # tspecials and space.
            set('()<>@,;:\\"/[]?= ')
        )
    )
)

# RFC 822 quoted-string, without surrounding quotation marks.
_quoted_string = r"(?:[{}]|(?:\\[{}]))*".format(
    re.escape("".join(_char - {'"', "\\", "\r"})), re.escape("".join(_char))
)

# Encode the regular expression strings to make them into bytes, as Python 3
# bytes have no format() method, but bytes must be passed to re.compile() in
# order to make a pattern object that can be used to match on bytes.

# RFC 2397 mediatype.
_mediatype_pattern = re.compile(rf"{_token}/{_token}".encode())
_mediatype_parameter_pattern = re.compile(
    rf';({_token})=(?:({_token})|"({_quoted_string})")'.encode()
)
del _char, _token, _quoted_string


class ParseDataURIResult(NamedTuple):
    """Named tuple returned by :func:`parse_data_uri`."""

    #: MIME type type and subtype, separated by / (e.g. ``"text/plain"``).
    media_type: str
    #: MIME type parameters (e.g. ``{"charset": "US-ASCII"}``).
    media_type_parameters: dict[str, str]
    #: Data, decoded if it was encoded in base64 format.
    data: bytes


def parse_data_uri(uri: str | bytes) -> ParseDataURIResult:
    """Parse a data: URI into :class:`ParseDataURIResult`."""
    if not isinstance(uri, bytes):
        uri = safe_url_string(uri).encode("ascii")

    scheme, _, uri = uri.partition(b":")
    if not scheme or not uri:
        raise ValueError("invalid URI")
    if scheme.lower() != b"data":
        raise ValueError("not a data URI")

    # RFC 3986 section 2.1 allows percent encoding to escape characters that
    # would be interpreted as delimiters, implying that actual delimiters
    # should not be percent-encoded.
    # Decoding before parsing will allow malformed URIs with percent-encoded
    # delimiters, but it makes parsing easier and should not affect
    # well-formed URIs, as the delimiters used in this URI scheme are not
    # allowed, percent-encoded or not, in tokens.
    uri = _unquote(uri)

    media_type = "text/plain"
    media_type_params = {}

    m = _mediatype_pattern.match(uri)
    if m:
        media_type = m.group().decode()
        uri = uri[m.end() :]
    else:
        media_type_params["charset"] = "US-ASCII"

    while m := _mediatype_parameter_pattern.match(uri):
        attribute, value, value_quoted = m.groups()
        if value_quoted is not None:
            value = re.sub(rb"\\(.)", rb"\1", value_quoted)
        media_type_params[attribute.decode()] = value.decode()
        uri = uri[m.end() :]

    is_base64, _, data = uri.partition(b",")
    if is_base64:
        if is_base64 != b";base64":
            raise ValueError("invalid data URI")
        data = base64.b64decode(data)

    return ParseDataURIResult(media_type, media_type_params, data)


class ParseDataURIStreamResult(NamedTuple):
    """Named tuple returned by :func:`parse_data_uri_stream`."""

    #: MIME type type and subtype, separated by / (e.g. ``"text/plain"``).
    media_type: str
    #: MIME type parameters (e.g. ``{"charset": "US-ASCII"}``).
    media_type_parameters: dict[str, str]
    #: Number of decoded data bytes written to the sink.
    bytes_written: int


_HEX_BYTES = b"0123456789abcdefABCDEF"


class _PercentDecoder:
    """Incrementally decode %HH sequences, like :func:`~w3lib._url._unquote`.

    Up to 2 bytes are kept back when a chunk ends in the middle of a
    percent-encoded triplet; they are decoded once the rest of the triplet
    arrives, or passed through verbatim at the end of the input.
    """

    def __init__(self) -> None:
        self._pending = bytearray()

    def feed(self, data: bytes) -> bytes:
        data = bytes(self._pending) + data
        self._pending.clear()
        hold = 0
        if data.endswith(b"%"):
            hold = 1
        elif len(data) >= 2 and data[-2] == 0x25 and data[-1] in _HEX_BYTES:
            hold = 2
        if hold:
            self._pending += data[-hold:]
            data = data[:-hold]
        return _unquote(data)

    def finalize(self) -> bytes:
        output = bytes(self._pending)
        self._pending.clear()
        return output


_B64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_B64_DISCARD = bytes(
    byte for byte in range(256) if byte not in _B64_ALPHABET and byte != 0x3D
)


class _Base64Decoder:
    """Incrementally decode base64 data with strict padding rules.

    Characters outside the base64 alphabet are discarded, like
    :func:`base64.b64decode` does by default, but padding is handled
    strictly: padding is only allowed to complete the final 4-character
    quantum, and any data after it, as well as a truncated final quantum,
    raises :exc:`binascii.Error`.
    """

    def __init__(self) -> None:
        self._quantum = bytearray()
        self._done = False

    def feed(self, data: bytes) -> bytes:
        cleaned = data.translate(None, _B64_DISCARD)
        if self._done:
            if cleaned:
                raise binascii.Error("Excess data after padding")
            return b""
        if not cleaned:
            return b""
        buf = bytes(self._quantum) + cleaned
        self._quantum.clear()
        padding_at = buf.find(b"=")
        if padding_at < 0:
            end = len(buf) // 4 * 4
            self._quantum += buf[end:]
            return binascii.a2b_base64(buf[:end]) if end else b""
        size = padding_at % 4
        if size < 2:
            raise binascii.Error("Leading padding not allowed")
        end = padding_at - size
        output = binascii.a2b_base64(buf[:end]) if end else b""
        tail = buf[end:]
        if len(tail) < 4:
            # Incomplete padded quantum, wait for more input.
            self._quantum += tail
            return output
        quantum = tail[:4]
        if quantum[size:] != b"=" * (4 - size):
            raise binascii.Error("Discontinuous padding not allowed")
        self._done = True
        if len(tail) > 4:
            raise binascii.Error("Excess data after padding")
        return output + binascii.a2b_base64(quantum)

    def finalize(self) -> bytes:
        quantum = bytes(self._quantum)
        self._quantum.clear()
        if self._done or not quantum:
            return b""
        if len(quantum) == 1:
            raise binascii.Error(
                "Invalid base64-encoded string: number of data characters (1) "
                "cannot be 1 more than a multiple of 4"
            )
        raise binascii.Error("Incorrect padding")


def _write_all(sink: BinaryIO, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = sink.write(view)
        if written is None:
            # Some file-like objects report nothing; assume all bytes were
            # accepted.
            return
        if written <= 0:
            raise OSError("data sink accepted 0 bytes")
        view = view[written:]


class _DataURIMetadataParser:
    """Find the comma that separates data URI metadata from the data.

    Consumes the percent-decoded bytes that follow the ``data:`` scheme and
    reports the first comma found outside of a quoted-string media type
    parameter value, which is where the metadata ends and the data begins.
    """

    def __init__(self) -> None:
        self.buffer = bytearray()
        self._in_quote = False
        self._escaped = False

    def feed(self, data: bytes) -> int:
        """Consume decoded metadata bytes.

        Return the index right after the separating comma if it is found in
        *data* (everything from that index on is data), or -1 otherwise.
        """
        for index, byte in enumerate(data):
            if self._escaped:
                self._escaped = False
            elif self._in_quote:
                if byte == 0x5C:  # "\\"
                    self._escaped = True
                elif byte == 0x22:  # '"'
                    self._in_quote = False
            elif byte == 0x22:  # '"'
                self._in_quote = True
            elif byte == 0x2C:  # ","
                return index + 1
            self.buffer.append(byte)
        return -1


def parse_data_uri_stream(
    chunks: Iterable[str | bytes],
    sink: BinaryIO,
    *,
    max_metadata_size: int = 1024,
    max_data_size: int | None = None,
) -> ParseDataURIStreamResult:
    """Parse a data: URI received in chunks, writing the data into *sink*.

    This is a streaming counterpart of :func:`parse_data_uri` that avoids
    loading the whole URI and its decoded data into memory, which makes it
    suitable for very large data URIs.

    *chunks* is an iterable of URI fragments. ``str`` fragments are encoded
    as UTF-8; unlike :func:`parse_data_uri`, no :func:`safe_url_string`
    normalization is applied, as it cannot be reproduced chunk by chunk, so
    control characters and leading or trailing whitespace are preserved
    instead of being removed. To get the exact same output as
    ``parse_data_uri(uri)`` for arbitrary input, pass
    ``safe_url_string(uri).encode("ascii")`` (in chunks) instead of *uri*
    itself. *sink* is a binary file-like object where the decoded data is
    written through its ``write()`` method.

    The metadata (the URI scheme, media type and media type parameters, i.e.
    everything before the ``,`` that separates them from the data, keeping in
    mind that quoted-string parameter values may contain commas) is first
    read and validated in full, and only then is the data processed chunk by
    chunk, decoding percent-encoded triplets and, if the metadata ends with
    ``;base64``, base64 data. Percent-encoded triplets and base64 quanta
    split across chunk boundaries are handled transparently. Unlike
    :func:`parse_data_uri`, base64 padding is checked strictly: padding in
    the middle of the data or after the final quantum, and truncated final
    quanta, raise :exc:`binascii.Error` (a :exc:`ValueError` subclass).

    *max_metadata_size* is the maximum number of bytes allowed for the scheme
    and the percent-decoded metadata. *max_data_size* is the maximum number
    of decoded data bytes to write into *sink*; ``None`` (default) means no
    limit. Both limits are enforced on the actual (decoded) sizes, and
    exceeding either raises :exc:`ValueError`.

    On success a :class:`ParseDataURIStreamResult` is returned, with the
    media type, its parameters and the number of bytes written into *sink*.

    On failure (invalid or truncated input, exceeded limits, or an exception
    raised by *sink*) an exception is raised and *sink* may already contain
    part of the data; no attempt is made to roll back written bytes.
    """
    iterator = iter(chunks)

    # Read the scheme, which is not percent-decoded.
    scheme = bytearray()
    colon_found = False
    for chunk in iterator:
        chunk = _normalize_data_uri_chunk(chunk)
        colon_at = chunk.find(b":")
        if colon_at >= 0:
            scheme += chunk[:colon_at]
            rest = chunk[colon_at + 1 :]
            colon_found = True
            break
        scheme += chunk
        if len(scheme) > max_metadata_size:
            raise ValueError(
                f"data URI metadata exceeds the maximum of {max_metadata_size} bytes"
            )
    else:
        rest = b""

    if not colon_found or not scheme:
        raise ValueError("invalid URI")
    if scheme.lower() != b"data":
        raise ValueError("not a data URI")

    # Read the metadata, percent-decoding on the fly, up to the separating
    # comma.
    metadata_parser = _DataURIMetadataParser()
    percent_decoder = _PercentDecoder()
    pending_data = b""
    boundary_found = False

    def post_scheme_chunks() -> Iterable[bytes]:
        yield rest
        for chunk in iterator:
            yield _normalize_data_uri_chunk(chunk)

    for chunk in post_scheme_chunks():
        decoded = percent_decoder.feed(chunk)
        data_at = metadata_parser.feed(decoded)
        if len(scheme) + len(metadata_parser.buffer) > max_metadata_size:
            raise ValueError(
                f"data URI metadata exceeds the maximum of {max_metadata_size} bytes"
            )
        if data_at >= 0:
            pending_data = decoded[data_at:]
            boundary_found = True
            break
    if not boundary_found:
        decoded = percent_decoder.finalize()
        data_at = metadata_parser.feed(decoded)
        if len(scheme) + len(metadata_parser.buffer) > max_metadata_size:
            raise ValueError(
                f"data URI metadata exceeds the maximum of {max_metadata_size} bytes"
            )
        if data_at >= 0:
            pending_data = decoded[data_at:]
            boundary_found = True

    if not boundary_found and not metadata_parser.buffer:
        raise ValueError("invalid URI")

    metadata = bytes(metadata_parser.buffer)

    media_type = "text/plain"
    media_type_params: dict[str, str] = {}

    m = _mediatype_pattern.match(metadata)
    if m:
        media_type = m.group().decode()
        metadata = metadata[m.end() :]
    else:
        media_type_params["charset"] = "US-ASCII"

    while m := _mediatype_parameter_pattern.match(metadata):
        attribute, value, value_quoted = m.groups()
        if value_quoted is not None:
            value = re.sub(rb"\\(.)", rb"\1", value_quoted)
        media_type_params[attribute.decode()] = value.decode()
        metadata = metadata[m.end() :]

    if metadata == b";base64":
        is_base64 = True
    elif metadata:
        raise ValueError("invalid data URI")
    else:
        is_base64 = False

    base64_decoder = _Base64Decoder() if is_base64 else None
    bytes_written = 0

    def emit(decoded: bytes) -> None:
        nonlocal bytes_written
        if not decoded:
            return
        if max_data_size is not None and bytes_written + len(decoded) > max_data_size:
            raise ValueError(
                f"data URI data exceeds the maximum of {max_data_size} bytes"
            )
        _write_all(sink, decoded)
        bytes_written += len(decoded)

    def process_decoded(decoded: bytes) -> None:
        if base64_decoder is not None:
            decoded = base64_decoder.feed(decoded)
        emit(decoded)

    process_decoded(pending_data)
    for chunk in iterator:
        process_decoded(percent_decoder.feed(_normalize_data_uri_chunk(chunk)))
    process_decoded(percent_decoder.finalize())
    if base64_decoder is not None:
        emit(base64_decoder.finalize())

    return ParseDataURIStreamResult(media_type, media_type_params, bytes_written)


def _normalize_data_uri_chunk(chunk: str | bytes) -> bytes:
    if isinstance(chunk, str):
        return chunk.encode("utf-8")
    if isinstance(chunk, (bytes, bytearray, memoryview)):
        return bytes(chunk)
    raise TypeError(
        f"data URI chunks must be str or bytes-like, not {type(chunk).__name__}"
    )


__all__ = [
    "add_http_if_no_scheme",
    "add_or_replace_parameter",
    "add_or_replace_parameters",
    "any_to_uri",
    "canonicalize_url",
    "file_uri_to_path",
    "is_url",
    "parse_data_uri",
    "parse_data_uri_stream",
    "path_to_file_uri",
    "safe_download_url",
    "safe_url_string",
    "url_query_cleaner",
    "url_query_parameter",
]


_DOT_SEGMENTS = {
    ".": ".",
    "%2e": ".",
    "..": "..",
    ".%2e": "..",
    "%2e.": "..",
    "%2e%2e": "..",
}


def _remove_dot_segments(path: str) -> str:
    """Resolve dot segments in *path*, which starts with "/" (RFC 3986,
    section 5.2.4), including their percent-encoded spellings."""
    # Every segment follows a "/", so a path without "/." or "/%2" has no dot
    # segment.
    if "/." not in path and "/%2" not in path:
        return path
    segments = path[1:].split("/")
    output: list[str] = []
    for segment in segments[:-1]:
        dots = _DOT_SEGMENTS.get(segment.lower())
        if dots == "..":
            if output:
                output.pop()
        elif dots is None:
            output.append(segment)
    # A trailing dot segment leaves the path ending in "/".
    last = segments[-1]
    dots = _DOT_SEGMENTS.get(last.lower())
    if dots == "..":
        if output:
            output.pop()
        output.append("")
    elif dots == ".":
        output.append("")
    else:
        output.append(last)
    return "/" + "/".join(output)


def _urljoin(base: str, url: str) -> str:
    """Resolve *url* against *base* following the `URL living standard`_.

    .. _URL living standard: https://url.spec.whatwg.org/#concept-basic-url-parser

    If *base* has no scheme, :func:`urllib.parse.urljoin` resolves *url*
    instead. Raises :exc:`ValueError` if *url* cannot be resolved against
    *base*, i.e. if *base* has an opaque path (e.g. ``mailto:a``) and *url* is
    neither absolute nor a fragment.
    """
    base, url = _strip(base), _strip(url)
    base_parts = _urlsplit(base)
    scheme = base_parts.scheme
    if not scheme:
        return urljoin(base, url)
    special = scheme in _SPECIAL_SCHEMES
    if m := _SCHEME_RE.match(url):
        # Only a special scheme matching that of the base keeps the URL
        # relative, e.g. "http:foo".
        if not special or m.group(1).lower() != scheme:
            return url
        url = url[m.end() :]

    url, hash_mark, fragment = url.partition("#")
    path, question_mark, query = url.partition("?")
    base_has_authority = special or base[len(scheme) + 1 : len(scheme) + 3] == "//"
    if (
        not base_has_authority
        and base_parts.path[:1] != "/"
        and (path or question_mark or not hash_mark)
    ):
        raise ValueError(f"Only a fragment can be resolved against {base!r}")

    if not path:
        base = base.partition("#")[0]
        if question_mark:
            base = base.partition("?")[0]
        return f"{base}{question_mark}{query}{hash_mark}{fragment}"

    tail = f"{question_mark}{query}{hash_mark}{fragment}"
    if special:
        path = path.replace("\\", "/")
    if path[:2] == "//":
        # Special schemes other than file ignore any extra slash before the
        # host, e.g. "///example.com" is "//example.com".
        if special and scheme != "file":
            path = f"//{path.lstrip('/')}"
        if (authority_end := path.find("/", 2)) != -1:
            path = path[:authority_end] + _remove_dot_segments(path[authority_end:])
        return f"{scheme}:{path}{tail}"
    if path[0] != "/":
        base_path = base_parts.path
        path = f"{base_path[: base_path.rfind('/') + 1] or '/'}{path}"
    path = _remove_dot_segments(path)
    if base_has_authority:
        return f"{scheme}://{base_parts.netloc}{path}{tail}"
    return f"{scheme}:{path}{tail}"


def canonicalize_url(
    url: str | bytes | ParseResult,
    keep_blank_values: bool = True,
    keep_fragments: bool = False,
    encoding: str | None = None,
    *,
    query_separator: str = "&",
) -> str:
    r"""Canonicalize the given url by applying the following procedures:

    .. versionchanged:: VERSION
        Dot segments (``.`` and ``..``) in the path are now resolved, and
        IPv6 addresses in the host are now normalized.

    - make the URL safe
    - sort query arguments, first by key, then by value
    - normalize all spaces (in query arguments) '+' (plus symbol)
    - normalize percent encodings case (%2f -> %2F)
    - remove query arguments with blank values (unless `keep_blank_values` is True)
    - remove fragments (unless `keep_fragments` is True)
    - resolve dot segments (``.`` and ``..``) in the path
    - normalize IPv6 addresses in the host

    The url passed can be bytes or unicode, while the url returned is
    always a native str (bytes in Python 2, unicode in Python 3).

    >>> import w3lib.url
    >>>
    >>> # sorting query arguments
    >>> w3lib.url.canonicalize_url('http://www.example.com/do?c=3&b=5&b=2&a=50')
    'http://www.example.com/do?a=50&b=2&b=5&c=3'
    >>>
    >>> # UTF-8 conversion + percent-encoding of non-ASCII characters
    >>> w3lib.url.canonicalize_url('http://www.example.com/r\u00e9sum\u00e9')
    'http://www.example.com/r%C3%A9sum%C3%A9'
    >>>
    >>> # a query separator other than the default '&'
    >>> w3lib.url.canonicalize_url('http://www.example.com/do?c=3;a=50', query_separator=';')
    'http://www.example.com/do?a=50;c=3'
    >>>
    >>> # resolving dot segments and normalizing an IPv6 address
    >>> w3lib.url.canonicalize_url('http://[::0:1]/a/../b')
    'http://[::1]/b'
    >>>

    For more examples, see the tests in `tests/test_url.py`.
    """
    # If supplied `encoding` is not compatible with all characters in `url`,
    # fallback to UTF-8 as safety net.
    # UTF-8 can handle all Unicode characters,
    # so we should be covered regarding URL normalization,
    # if not for proper URL expected by remote website.
    if isinstance(url, ParseResult):
        url = _urlunparse(*url)
    try:
        scheme, netloc, path, query, fragment = _safe_url_split(
            url, encoding=encoding or "utf8"
        )
    except UnicodeEncodeError:
        scheme, netloc, path, query, fragment = _safe_url_split(url, encoding="utf8")
    path, params = _split_params(scheme, path)

    # 1. decode query-string as UTF-8 (or keep raw bytes),
    #    sort values,
    #    and percent-encode them back

    # Python's urllib.parse.parse_qsl does not work as wanted
    # for percent-encoded characters that do not match passed encoding,
    # they get lost.
    #
    # e.g., 'q=b%a3' becomes [('q', 'b\ufffd')]
    # (ie. with 'REPLACEMENT CHARACTER' (U+FFFD),
    #      instead of \xa3 that you get with Python2's parse_qsl)
    #
    # what we want here is to keep raw bytes, and percent encode them
    # so as to preserve whatever encoding what originally used.
    #
    # See https://tools.ietf.org/html/rfc3987#section-6.4:
    #
    # For example, it is possible to have a URI reference of
    # "http://www.example.org/r%E9sum%E9.xml#r%C3%A9sum%C3%A9", where the
    # document name is encoded in iso-8859-1 based on server settings, but
    # where the fragment identifier is encoded in UTF-8 according to
    # [XPointer]. The IRI corresponding to the above URI would be (in XML
    # notation)
    # "http://www.example.org/r%E9sum%E9.xml#r&#xE9;sum&#xE9;".
    # Similar considerations apply to query parts.  The functionality of
    # IRIs (namely, to be able to include non-ASCII characters) can only be
    # used if the query part is encoded in UTF-8.
    if query:
        keyvals = _parse_qsl(
            query, keep_blank_values, separator=query_separator.encode()
        )

        if len(keyvals) > 1:
            keyvals.sort()

        query = _urlencode(keyvals, query_separator.encode()).decode()
        del keyvals

    # 2. decode percent-encoded sequences in path as UTF-8 (or keep raw bytes)
    #    and percent-encode path again (this normalizes to upper-case %XX)
    path = _quote(_unquotepath(path), _PATH_SAFE_CHARS).decode() if path else "/"

    # 3. resolve dot segments (RFC 3986, section 5.2.4), but only for a
    #    hierarchical path. A path that does not start with "/" is an opaque
    #    path (URL Standard), whose dot segments browsers leave untouched
    #    (e.g. "mailto:a/../b" stays as is, while "foo:/a/../b" resolves).
    if path.startswith("/"):
        path = _remove_dot_segments(path)

    fragment = "" if not keep_fragments else fragment

    # Apply lowercase to the domain, but not to the userinfo.
    uinf_sep_idx = netloc.rfind("@")
    host = (
        (netloc[uinf_sep_idx + 1 :] if uinf_sep_idx != -1 else netloc)
        .lower()
        .removesuffix(":")
    )
    netloc = (netloc[: uinf_sep_idx + 1] + host) if uinf_sep_idx != -1 else host

    netloc = _normalize_ipv6_host(netloc)

    # every part should be safe already
    return _urlunparse(scheme, netloc, path, params, query, fragment)


def _normalize_ipv6_host(netloc: str) -> str:
    """Normalize an IPv6 address in the host part of *netloc*, if any (RFC 5952)."""
    if "[" not in netloc:
        return netloc
    bracket_start = netloc.index("[")
    bracket_end = netloc.find("]", bracket_start)
    if bracket_end == -1:
        return netloc
    try:
        address = ip_address(netloc[bracket_start + 1 : bracket_end])
    except ValueError:
        return netloc
    if not isinstance(address, IPv6Address):
        return netloc
    return f"{netloc[:bracket_start]}[{address}]{netloc[bracket_end + 1 :]}"


def _unquotepath(path: str) -> bytes:
    if "%" not in path:
        return path.encode()
    # standard lib's unquote() does not work for non-UTF-8
    # percent-escaped characters, they get lost.
    # e.g., '%a3' becomes 'REPLACEMENT CHARACTER' (U+FFFD)
    return _unquote(
        path.replace("%25", "%2525")
        .replace("%2f", "%252F")
        .replace("%2F", "%252F")
        .replace("%3b", "%253B")
        .replace("%3B", "%253B")
        .replace("%3f", "%253F")
        .replace("%3F", "%253F")
    )


def parse_url(
    url: str | bytes | ParseResult, encoding: str | None = None
) -> ParseResult:
    """Return urlparsed url from the given argument (which could be an already
    parsed url)
    """
    if isinstance(url, ParseResult):
        return url
    return _urlparse(to_unicode(url, encoding))


def parse_qsl_to_bytes(
    qs: str, keep_blank_values: bool = False, *, separator: str = "&"
) -> list[tuple[bytes, bytes]]:
    """Parse a query given as a string argument.

    Data are returned as a list of name, value pairs as bytes.

    Arguments:

    qs: percent-encoded query string to be parsed

    keep_blank_values: flag indicating whether blank values in
        percent-encoded queries should be treated as blank strings.  A
        true value indicates that blanks should be retained as blank
        strings.  The default false value indicates that blank values
        are to be ignored and treated as if they were  not included.

    separator: string used to separate query parameters, e.g. ``";"`` for
        queries that use the legacy semicolon separator.

    """
    return _parse_qsl(qs, keep_blank_values, separator=separator.encode())
