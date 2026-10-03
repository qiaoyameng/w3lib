"""
Parsing of the HTML ``srcset`` attribute.
"""

from __future__ import annotations

import re
from typing import NamedTuple

from w3lib.html import HTML5_WHITESPACE
from w3lib.url import _urljoin

__all__ = ["ImageCandidate", "parse_srcset"]

# A "w" or "h" descriptor: a valid non-negative integer and the letter.
_INTEGER_DESCRIPTOR_RE = re.compile(r"([0-9]+)([wh])")
# An "x" descriptor: a valid floating-point number and the letter.
_FLOAT_DESCRIPTOR_RE = re.compile(
    r"(-?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)x"
)

_WS_OR_COMMA = HTML5_WHITESPACE + ","

# Descriptor tokenizer states.
_IN_DESCRIPTOR, _IN_PARENS, _AFTER_DESCRIPTOR = range(3)


class ImageCandidate(NamedTuple):
    """Named tuple of one image candidate of a ``srcset`` attribute value,
    as returned by :func:`parse_srcset`."""

    #: The candidate URL, resolved against *base_url* if one was passed to
    #: :func:`parse_srcset`, and equal to :attr:`raw_url` otherwise.
    url: str
    #: The candidate URL as it appeared in the ``srcset`` value.
    raw_url: str
    #: The width of the ``w`` descriptor, or ``None`` if there was none.
    width: int | None
    #: The pixel density of the ``x`` descriptor, or ``None`` if there was
    #: none.
    density: float | None
    #: Offset of the first character of the candidate in the ``srcset``
    #: value.
    start: int
    #: Offset just past the last character of the candidate in the ``srcset``
    #: value.
    end: int


def parse_srcset(srcset: str, base_url: str | None = None) -> list[ImageCandidate]:
    """Parse the value of an HTML ``srcset`` attribute into a list of
    :class:`ImageCandidate`.

    The tokenization rules of the `HTML standard`_ are followed, so commas
    inside a URL, e.g. in a data: URL, do not split candidates, and neither
    do commas inside parentheses in descriptors.

    .. _HTML standard: https://html.spec.whatwg.org/multipage/images.html#parse-a-srcset-attribute

    A candidate carries at most one of a width descriptor (``w``) and a
    pixel density descriptor (``x``). Candidates with a negative value, a
    zero width, a repeated descriptor, both a width and a pixel density, or
    an unknown descriptor are discarded, but do not affect the candidates
    that follow them. No selection between the returned candidates is
    performed.

    If *base_url* is given, the URL of each candidate is resolved against
    it, and :attr:`ImageCandidate.raw_url` keeps the URL as it appeared in
    *srcset*. Otherwise both attributes hold the URL as it appeared in
    *srcset*.

    >>> parse_srcset("small.jpg 480w, large.jpg 2x")
    [ImageCandidate(url='small.jpg', raw_url='small.jpg', width=480, density=None, start=0, end=14), ImageCandidate(url='large.jpg', raw_url='large.jpg', width=None, density=2.0, start=16, end=28)]
    >>> parse_srcset("a.jpg 1x, b.jpg 2x", base_url="https://example.com/dir/")
    [ImageCandidate(url='https://example.com/dir/a.jpg', raw_url='a.jpg', width=None, density=1.0, start=0, end=8), ImageCandidate(url='https://example.com/dir/b.jpg', raw_url='b.jpg', width=None, density=2.0, start=10, end=18)]
    """
    candidates: list[ImageCandidate] = []
    position = 0
    length = len(srcset)
    while True:
        # Splitting loop: candidates are separated by runs of whitespace and
        # commas.
        while position < length and srcset[position] in _WS_OR_COMMA:
            position += 1
        if position >= length:
            return candidates
        start = position
        # The URL runs to the next whitespace character, so commas in it,
        # e.g. in data: URLs, do not split the candidate.
        while position < length and srcset[position] not in HTML5_WHITESPACE:
            position += 1
        url = srcset[start:position]
        if url.endswith(","):
            # Trailing commas belong to the separator, not to the URL.
            url = url.rstrip(",")
            if not url:
                return candidates
        end = start + len(url)
        descriptors: list[str] = []
        # Descriptor tokenizer: whitespace-separated tokens after the URL,
        # up to the comma that ends the candidate. Parentheses are matched,
        # so that a comma in an unknown descriptor does not end the
        # candidate either.
        while position < length and srcset[position] in HTML5_WHITESPACE:
            position += 1
        current: list[str] = []
        state = _IN_DESCRIPTOR
        while True:
            char = srcset[position] if position < length else ""
            if state == _IN_DESCRIPTOR:
                if not char:
                    if current:
                        descriptors.append("".join(current))
                        end = position
                    break
                if char in HTML5_WHITESPACE:
                    if current:
                        descriptors.append("".join(current))
                        current = []
                        end = position
                    state = _AFTER_DESCRIPTOR
                elif char == ",":
                    if current:
                        descriptors.append("".join(current))
                        end = position
                    position += 1
                    break
                elif char == "(":
                    current.append(char)
                    state = _IN_PARENS
                else:
                    current.append(char)
            elif state == _IN_PARENS:
                if not char:
                    descriptors.append("".join(current))
                    end = position
                    break
                if char == ")":
                    current.append(char)
                    state = _IN_DESCRIPTOR
                else:
                    current.append(char)
            else:  # _AFTER_DESCRIPTOR
                if not char:
                    break
                if char not in HTML5_WHITESPACE:
                    # Re-read the character as the start of a descriptor.
                    state = _IN_DESCRIPTOR
                    position -= 1
            position += 1
        # Descriptor parser: a candidate keeps at most one of a width
        # ("w") and a pixel density ("x"), and a future-compatible height
        # ("h") only alongside a width. Anything else, a negative value, a
        # zero width or height, or a repeated descriptor invalidates the
        # candidate, but not the candidates that follow it.
        width: int | None = None
        density: float | None = None
        future_compat_h: int | None = None
        error = False
        for descriptor in descriptors:
            if match := _INTEGER_DESCRIPTOR_RE.fullmatch(descriptor):
                try:
                    value = int(match.group(1))
                except ValueError:
                    # More digits than int() accepts.
                    error = True
                    continue
                if match.group(2) == "w":
                    if width is not None or density is not None or value == 0:
                        error = True
                    width = value
                else:
                    if (
                        future_compat_h is not None
                        or density is not None
                        or value == 0
                    ):
                        error = True
                    future_compat_h = value
            elif match := _FLOAT_DESCRIPTOR_RE.fullmatch(descriptor):
                if density is not None or width is not None:
                    error = True
                density = float(match.group(1))
                if density < 0:
                    error = True
            else:
                error = True
        if future_compat_h is not None and width is None:
            error = True
        if error:
            continue
        raw_url = url
        if base_url is not None:
            try:
                url = _urljoin(base_url, raw_url)
            except ValueError:
                # The base URL has an opaque path; keep the raw URL.
                url = raw_url
        candidates.append(ImageCandidate(url, raw_url, width, density, start, end))
