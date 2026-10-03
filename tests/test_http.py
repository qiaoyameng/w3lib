from collections import OrderedDict

from w3lib.http import (
    HeadersDictInput,
    basic_auth_header,
    headers_dict_to_raw,
    headers_raw_to_dict,
    parse_content_disposition,
)


class TestHttp:
    def test_basic_auth_header(self):
        assert (
            basic_auth_header("someuser", "somepass")
            == b"Basic c29tZXVzZXI6c29tZXBhc3M="
        )
        # Check url unsafe encoded header
        assert (
            basic_auth_header("someuser", "@<yu9>&o?Q")
            == b"Basic c29tZXVzZXI6QDx5dTk+Jm8/UQ=="
        )

    def test_basic_auth_header_encoding(self):
        assert (
            basic_auth_header("somæusèr", "sømepäss", encoding="utf8")
            == b"Basic c29tw6Z1c8Oocjpzw7htZXDDpHNz"
        )
        # default encoding (ISO-8859-1)
        assert (
            basic_auth_header("somæusèr", "sømepäss")
            == b"Basic c29t5nVz6HI6c/htZXDkc3M="
        )

    def test_headers_raw_dict_none(self):
        assert headers_raw_to_dict(None) is None
        assert headers_dict_to_raw(None) is None

    def test_headers_raw_dict_empty(self):
        assert headers_raw_to_dict(b"") == {}
        assert headers_dict_to_raw({}) == b""

    def test_headers_raw_to_dict(self):
        raw = b"Content-type: text/html\n\rAccept: gzip\n\r\
                Cache-Control: no-cache\n\rCache-Control: no-store\n\n"
        dct = {
            b"Content-type": [b"text/html"],
            b"Accept": [b"gzip"],
            b"Cache-Control": [b"no-cache", b"no-store"],
        }
        assert headers_raw_to_dict(raw) == dct

    def test_headers_dict_to_raw(self):
        dct = OrderedDict([(b"Content-type", b"text/html"), (b"Accept", b"gzip")])
        assert headers_dict_to_raw(dct) == b"Content-type: text/html\r\nAccept: gzip"

    def test_headers_dict_to_raw_listtuple(self):
        dct: HeadersDictInput = OrderedDict(
            [(b"Content-type", [b"text/html"]), (b"Accept", [b"gzip"])]
        )
        assert headers_dict_to_raw(dct) == b"Content-type: text/html\r\nAccept: gzip"

        dct = OrderedDict([(b"Content-type", (b"text/html",)), (b"Accept", (b"gzip",))])
        assert headers_dict_to_raw(dct) == b"Content-type: text/html\r\nAccept: gzip"

        dct = OrderedDict([(b"Cookie", (b"val001", b"val002")), (b"Accept", b"gzip")])
        assert (
            headers_dict_to_raw(dct)
            == b"Cookie: val001\r\nCookie: val002\r\nAccept: gzip"
        )

        dct = OrderedDict([(b"Cookie", [b"val001", b"val002"]), (b"Accept", b"gzip")])
        assert (
            headers_dict_to_raw(dct)
            == b"Cookie: val001\r\nCookie: val002\r\nAccept: gzip"
        )

    def test_headers_dict_to_raw_wrong_values(self):
        dct: HeadersDictInput = OrderedDict(
            [
                (b"Content-type", 0),
            ]
        )
        assert headers_dict_to_raw(dct) == b""

        dct = OrderedDict([(b"Content-type", 1), (b"Accept", [b"gzip"])])
        assert headers_dict_to_raw(dct) == b"Accept: gzip"


class TestParseContentDisposition:
    def test_none(self):
        assert parse_content_disposition(None) is None

    def test_empty(self):
        result = parse_content_disposition("")
        assert result is not None
        assert result.disposition == ""
        assert result.params == {}
        assert result.filename is None
        assert result.safe_filename is None

    def test_simple(self):
        result = parse_content_disposition('Attachment; filename="report.csv"')
        assert result is not None
        assert result.disposition == "attachment"
        assert result.params == {"filename": "report.csv"}
        assert result.filename == "report.csv"
        assert result.safe_filename == "report.csv"
        assert result.warnings == ()

    def test_bytes_header(self):
        result = parse_content_disposition(b'attachment; filename="report.csv"')
        assert result is not None
        assert result.filename == "report.csv"

    def test_semicolon_and_escape_in_quotes(self):
        result = parse_content_disposition(
            r'attachment; filename="a;b \"c\".txt"; x=1'
        )
        assert result is not None
        assert result.filename == 'a;b "c".txt'
        assert result.params == {"filename": 'a;b "c".txt', "x": "1"}

    def test_unterminated_quote(self):
        result = parse_content_disposition('attachment; filename="abc.txt')
        assert result is not None
        assert result.filename == "abc.txt"
        assert any("unterminated" in w for w in result.warnings)

    def test_ext_param_utf8(self):
        result = parse_content_disposition(
            "attachment; filename*=utf-8''%E6%8A%A5%E8%A1%A8.csv"
        )
        assert result is not None
        assert result.filename == "报表.csv"
        assert result.safe_filename == "报表.csv"
        ext = result.ext_params["filename"]
        assert ext.charset == "utf-8"
        assert ext.language == ""
        assert ext.value == "报表.csv"

    def test_ext_param_language_and_charset_case(self):
        result = parse_content_disposition(
            "attachment; filename*=UTF-8'zh-CN'%E6%8A%A5%E8%A1%A8.csv"
        )
        assert result is not None
        ext = result.ext_params["filename"]
        assert ext.language == "zh-CN"
        assert ext.value == "报表.csv"

    def test_same_chinese_name_multiple_encodings(self):
        name = "中文.txt"
        for encoding in ("utf-8", "gbk", "big5"):
            encoded = "".join(f"%{b:02X}" for b in name.encode(encoding))
            result = parse_content_disposition(
                f"attachment; filename*={encoding}''{encoded}"
            )
            assert result is not None
            assert result.filename == name, encoding
            assert result.safe_filename == name, encoding
            assert result.warnings == (), encoding

    def test_filename_star_wins_over_filename(self):
        result = parse_content_disposition(
            "attachment; filename=plain.txt; "
            "filename*=utf-8''%E6%8A%A5%E8%A1%A8.csv"
        )
        assert result is not None
        assert result.filename == "报表.csv"
        # The losing parameter keeps its value, untouched.
        assert result.params["filename"] == "plain.txt"

    def test_unknown_charset_falls_back_to_filename(self):
        result = parse_content_disposition(
            "attachment; filename*=x-unknown''%41.txt; filename=plain.txt"
        )
        assert result is not None
        assert result.filename == "plain.txt"
        assert result.ext_params["filename"].value is None
        assert result.ext_params["filename"].raw == "x-unknown''%41.txt"
        assert any("unknown charset" in w for w in result.warnings)
        assert any("falling back" in w for w in result.warnings)

    def test_malformed_ext_param_shape(self):
        result = parse_content_disposition(
            "attachment; filename*=no-separators; filename=plain.txt"
        )
        assert result is not None
        assert result.filename == "plain.txt"
        assert result.ext_params["filename"].value is None
        assert any("charset'language'value" in w for w in result.warnings)

    def test_malformed_percent_kept_literally(self):
        result = parse_content_disposition(
            "attachment; filename*=utf-8''a%ZZb%2.txt"
        )
        assert result is not None
        assert result.filename == "a%ZZb%2.txt"
        assert any("malformed percent-encoding" in w for w in result.warnings)

    def test_invalid_bytes_for_charset_replaced(self):
        result = parse_content_disposition(
            "attachment; filename*=utf-8''%FF.txt"
        )
        assert result is not None
        assert result.filename == "�.txt"
        assert any("not valid utf-8" in w for w in result.warnings)

    def test_duplicate_params_keep_first(self):
        result = parse_content_disposition(
            "attachment; filename=one.txt; filename=two.txt; "
            "filename*=utf-8''a.txt; filename*=utf-8''b.txt"
        )
        assert result is not None
        assert result.params["filename"] == "one.txt"
        assert result.ext_params["filename"].value == "a.txt"
        assert sum("duplicate" in w for w in result.warnings) == 2

    def test_parameter_without_value(self):
        result = parse_content_disposition("attachment; filename=a.txt; loose")
        assert result is not None
        assert "loose" not in result.params
        assert any("no value" in w for w in result.warnings)

    def test_other_params_not_rewritten(self):
        result = parse_content_disposition(
            "attachment; filename*=utf-8''%E6%8A%A5%E8%A1%A8.csv; "
            'name="field;name"; size=10; creation-date="Wed, 01 Jan 2020"'
        )
        assert result is not None
        assert result.params == {
            "name": "field;name",
            "size": "10",
            "creation-date": "Wed, 01 Jan 2020",
        }
        assert list(result.ext_params) == ["filename"]

    def test_path_traversal_unix(self):
        result = parse_content_disposition(
            "attachment; filename=../../etc/passwd"
        )
        assert result is not None
        assert result.filename == "../../etc/passwd"
        assert result.safe_filename == "passwd"
        assert any("directory components" in w for w in result.warnings)

    def test_path_traversal_windows(self):
        result = parse_content_disposition(
            r'attachment; filename="C:\Windows\system32\evil.dll"'
        )
        assert result is not None
        assert result.filename == r"C:\Windows\system32\evil.dll"
        assert result.safe_filename == "evil.dll"

    def test_control_characters_removed(self):
        result = parse_content_disposition(
            'attachment; filename="a\tb\x00c.txt"'
        )
        assert result is not None
        assert result.filename == "a\tb\x00c.txt"
        assert result.safe_filename == "abc.txt"
        assert any("control characters" in w for w in result.warnings)

    def test_trailing_dots_and_spaces_removed(self):
        result = parse_content_disposition('attachment; filename="name.txt. "')
        assert result is not None
        assert result.filename == "name.txt. "
        assert result.safe_filename == "name.txt"

    def test_no_usable_filename(self):
        for header in (
            'attachment; filename=""',
            'attachment; filename="../.."',
            'attachment; filename="   "',
            "attachment; filename*=utf-8''",
        ):
            result = parse_content_disposition(header)
            assert result is not None
            assert result.safe_filename is None, header
            assert any("no usable filename" in w for w in result.warnings)

    def test_no_filename_at_all(self):
        result = parse_content_disposition("inline")
        assert result is not None
        assert result.disposition == "inline"
        assert result.filename is None
        assert result.safe_filename is None
        assert result.warnings == ()
