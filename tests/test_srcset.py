from hypothesis import given, strategies as st

from w3lib.srcset import ImageCandidate, parse_srcset


class TestParseSrcset:
    def test_empty(self):
        assert parse_srcset("") == []
        assert parse_srcset("  , ,\n\t") == []

    def test_width_descriptor(self):
        (candidate,) = parse_srcset("a.jpg 480w")
        assert candidate.url == "a.jpg"
        assert candidate.raw_url == "a.jpg"
        assert candidate.width == 480
        assert candidate.density is None

    def test_density_descriptor(self):
        (candidate,) = parse_srcset("a.jpg 1.5x")
        assert candidate.width is None
        assert candidate.density == 1.5

    def test_no_descriptors(self):
        (candidate,) = parse_srcset("a.jpg")
        assert candidate.width is None
        assert candidate.density is None

    def test_multiple_candidates(self):
        candidates = parse_srcset("small.jpg 480w, medium.jpg 768w, large.jpg 2x")
        assert [(c.url, c.width, c.density) for c in candidates] == [
            ("small.jpg", 480, None),
            ("medium.jpg", 768, None),
            ("large.jpg", None, 2.0),
        ]

    def test_data_url_with_commas(self):
        # Commas in a URL, e.g. in a data: URL, do not split candidates.
        srcset = "data:image/gif;base64,R0lGODlhAQABAAAAACw= 1x, data:,foo 2x"
        first, second = parse_srcset(srcset)
        assert first.url == "data:image/gif;base64,R0lGODlhAQABAAAAACw="
        assert first.density == 1.0
        assert srcset[first.start : first.end] == (
            "data:image/gif;base64,R0lGODlhAQABAAAAACw= 1x"
        )
        assert second.url == "data:,foo"
        assert second.density == 2.0

    def test_data_url_trailing_comma(self):
        # Trailing commas belong to the separator, not to the URL.
        (candidate,) = parse_srcset("data:,foo,")
        assert candidate.url == "data:,foo"
        assert candidate.width is None
        assert candidate.density is None

    def test_comma_in_url_without_whitespace(self):
        # A comma only ends a candidate after the URL token, i.e. after
        # whitespace; within the URL token it is part of the URL.
        (candidate,) = parse_srcset("a.jpg,b.jpg 2x")
        assert candidate.url == "a.jpg,b.jpg"
        assert candidate.density == 2.0

    def test_empty_descriptors(self):
        # A trailing comma, repeated commas and a comma right after the URL
        # all leave a candidate without descriptors.
        candidates = parse_srcset("a.jpg 1x,, b.jpg 2x,")
        assert [(c.url, c.density) for c in candidates] == [
            ("a.jpg", 1.0),
            ("b.jpg", 2.0),
        ]
        candidates = parse_srcset("a.jpg , b.jpg 2x")
        assert [(c.url, c.width, c.density) for c in candidates] == [
            ("a.jpg", None, None),
            ("b.jpg", None, 2.0),
        ]
        candidates = parse_srcset("a.jpg 1x , b.jpg 2x")
        assert [(c.url, c.density) for c in candidates] == [
            ("a.jpg", 1.0),
            ("b.jpg", 2.0),
        ]

    def test_whitespace(self):
        # Any run of HTML whitespace separates URLs, descriptors and
        # candidates.
        candidates = parse_srcset("a.jpg\t\t1x,\n\fb.jpg\r  2x")
        assert [(c.url, c.density) for c in candidates] == [
            ("a.jpg", 1.0),
            ("b.jpg", 2.0),
        ]

    def test_positions(self):
        srcset = "  a.jpg 480w,\tb.jpg 2x  "
        first, second = parse_srcset(srcset)
        assert (first.start, first.end) == (2, 12)
        assert srcset[first.start : first.end] == "a.jpg 480w"
        assert (second.start, second.end) == (14, 22)
        assert srcset[second.start : second.end] == "b.jpg 2x"

    def test_bad_candidate_does_not_swallow_good_ones(self):
        (candidate,) = parse_srcset("bad.jpg 1z, good.jpg 2x")
        assert candidate.url == "good.jpg"
        assert candidate.density == 2.0
        (candidate,) = parse_srcset("bad1.jpg 1q, bad2.jpg 0w, good.jpg 3x")
        assert candidate.url == "good.jpg"
        assert candidate.density == 3.0

    def test_negative_descriptors_rejected(self):
        assert parse_srcset("a.jpg -1w") == []
        assert parse_srcset("a.jpg -1.5x") == []
        assert parse_srcset("a.jpg -1x") == []

    def test_zero_descriptors(self):
        # A zero width is invalid, a zero pixel density is not.
        assert parse_srcset("a.jpg 0w") == []
        (candidate,) = parse_srcset("a.jpg 0x")
        assert candidate.density == 0.0

    def test_duplicate_descriptors_rejected(self):
        assert parse_srcset("a.jpg 1x 2x") == []
        assert parse_srcset("a.jpg 100w 200w") == []
        assert parse_srcset("a.jpg 100w 50h 60h") == []

    def test_mutually_exclusive_descriptors_rejected(self):
        assert parse_srcset("a.jpg 100w 1x") == []
        assert parse_srcset("a.jpg 1x 100w") == []
        assert parse_srcset("a.jpg 1x 50h") == []

    def test_height_descriptor(self):
        # An "h" descriptor is only valid alongside a "w" descriptor, and is
        # parsed for future compatibility.
        (candidate,) = parse_srcset("a.jpg 100w 50h")
        assert candidate.width == 100
        assert candidate.density is None
        assert parse_srcset("a.jpg 50h") == []
        assert parse_srcset("a.jpg 100w 0h") == []

    def test_invalid_descriptors(self):
        assert parse_srcset("a.jpg 1X") == []  # descriptors are lowercase
        assert parse_srcset("a.jpg 100") == []
        assert parse_srcset("a.jpg 1.5w") == []
        assert parse_srcset("a.jpg x") == []
        assert parse_srcset("a.jpg +1x") == []
        assert parse_srcset("a.jpg 1.x") == []

    def test_valid_number_syntaxes(self):
        (candidate,) = parse_srcset("a.jpg .5x")
        assert candidate.density == 0.5
        (candidate,) = parse_srcset("a.jpg 1e2x")
        assert candidate.density == 100.0
        (candidate,) = parse_srcset("a.jpg 007w")
        assert candidate.width == 7

    def test_parentheses(self):
        # Parentheses in descriptors are matched, so a comma in an unknown
        # descriptor does not end the candidate; the unknown descriptor
        # invalidates only its own candidate.
        (candidate,) = parse_srcset("a.jpg (unknown, 1.5) 1x, b.jpg 2x")
        assert candidate.url == "b.jpg"
        assert candidate.density == 2.0

    def test_unclosed_parentheses(self):
        # An unclosed parenthesis swallows the rest of the value into the
        # descriptor, as in the HTML standard.
        assert parse_srcset("a.jpg (unclosed, b.jpg 2x") == []

    def test_descriptor_without_whitespace_after_comma(self):
        # Without whitespace after the comma of the URL token, what follows
        # is tokenized as descriptors of the same candidate.
        assert parse_srcset("a.jpg, b.jpg") == []

    def test_base_url(self):
        candidates = parse_srcset(
            "a.jpg 1x, /b.jpg 2x, https://cdn.example.com/c.jpg 3x",
            base_url="https://example.com/dir/page.html",
        )
        assert [c.url for c in candidates] == [
            "https://example.com/dir/a.jpg",
            "https://example.com/b.jpg",
            "https://cdn.example.com/c.jpg",
        ]
        assert [c.raw_url for c in candidates] == [
            "a.jpg",
            "/b.jpg",
            "https://cdn.example.com/c.jpg",
        ]

    def test_base_url_data_url(self):
        (candidate,) = parse_srcset(
            "data:,foo 1x", base_url="https://example.com/"
        )
        assert candidate.url == "data:,foo"
        assert candidate.raw_url == "data:,foo"

    def test_base_url_opaque_path(self):
        # A base URL with an opaque path cannot resolve a relative URL; the
        # raw URL is kept.
        (candidate,) = parse_srcset("a.jpg 1x", base_url="mailto:a@example.com")
        assert candidate.url == "a.jpg"
        assert candidate.raw_url == "a.jpg"

    def test_returned_type(self):
        (candidate,) = parse_srcset("a.jpg 1x")
        assert isinstance(candidate, ImageCandidate)
        assert candidate == ("a.jpg", "a.jpg", None, 1.0, 0, 8)

    @given(st.text())
    def test_fuzz(self, srcset):
        for candidate in parse_srcset(srcset):
            assert 0 <= candidate.start <= candidate.end <= len(srcset)

    @given(st.text(), st.text())
    def test_fuzz_base_url(self, srcset, base_url):
        for candidate in parse_srcset(srcset, base_url=base_url):
            assert 0 <= candidate.start <= candidate.end <= len(srcset)
