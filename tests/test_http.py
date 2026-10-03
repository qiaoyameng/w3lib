from collections import OrderedDict

from w3lib.http import (
    ContentDispositionIssue,
    ExtendedParameter,
    FilenameSource,
    HeadersDictInput,
    basic_auth_header,
    headers_dict_to_raw,
    headers_raw_to_dict,
    parse_content_disposition,
    safe_filename,
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


class TestContentDisposition:
    def test_simple_attachment(self):
        result = parse_content_disposition("attachment")
        assert result.disposition == "attachment"
        assert result.parameters == {}
        assert result.extended_parameters == {}
        assert result.filename is None
        assert result.filename_source is FilenameSource.NONE
        assert result.safe_filename is None
        assert [i.code for i in result.issues] == [ContentDispositionIssue.NO_FILENAME]

    def test_disposition_case_insensitive(self):
        result = parse_content_disposition("AttachMENT")
        assert result.disposition == "attachment"

    def test_inline_disposition(self):
        result = parse_content_disposition("inline; filename=photo.png")
        assert result.disposition == "inline"
        assert result.filename == "photo.png"
        assert result.safe_filename == "photo.png"
        assert result.filename_source is FilenameSource.BASIC

    def test_invalid_disposition(self):
        result = parse_content_disposition('"attachment"; filename=a.txt')
        assert result.disposition is None
        assert result.filename == "a.txt"
        assert (
            result.issues[0].code
            is ContentDispositionIssue.INVALID_DISPOSITION
        )

    def test_basic_filename(self):
        result = parse_content_disposition('attachment; filename="report.pdf"')
        assert result.parameters == {"filename": "report.pdf"}
        assert result.filename == "report.pdf"
        assert result.filename_source is FilenameSource.BASIC
        assert result.issues == []

    def test_bare_token_filename(self):
        result = parse_content_disposition("attachment; filename=report.pdf")
        assert result.filename == "report.pdf"
        assert result.issues == []

    def test_quoted_semicolon_inside_value(self):
        result = parse_content_disposition(
            'attachment; filename="final; report.pdf"; size=42'
        )
        assert result.parameters["filename"] == "final; report.pdf"
        assert result.parameters["size"] == "42"
        assert result.filename == "final; report.pdf"
        assert result.issues == []

    def test_escaped_quote_and_backslash(self):
        result = parse_content_disposition(
            'attachment; filename="a\\"b\\\\c.pdf"'
        )
        assert result.filename == 'a"b\\c.pdf'
        assert result.issues == []

    def test_unterminated_quoted_value_rejected(self):
        result = parse_content_disposition('attachment; filename="broken')
        assert "filename" not in result.parameters
        assert result.filename is None
        assert (
            ContentDispositionIssue.INVALID_QUOTED_VALUE
            in [i.code for i in result.issues]
        )

    def test_trailing_text_after_quote_rejected(self):
        result = parse_content_disposition('attachment; filename="a.pdf"junk')
        assert "filename" not in result.parameters
        assert (
            ContentDispositionIssue.INVALID_QUOTED_VALUE
            in [i.code for i in result.issues]
        )

    def test_invalid_parameter_name(self):
        result = parse_content_disposition("attachment; bad name=x")
        assert (
            ContentDispositionIssue.INVALID_PARAMETER_NAME
            in [i.code for i in result.issues]
        )

    def test_invalid_bare_value(self):
        result = parse_content_disposition("attachment; filename=has space")
        assert "filename" not in result.parameters
        assert (
            ContentDispositionIssue.INVALID_PARAMETER_VALUE
            in [i.code for i in result.issues]
        )

    def test_chinese_filename_utf8_extended(self):
        result = parse_content_disposition(
            b"attachment; filename*=UTF-8''%E4%B8%AD%E6%96%87.txt"
        )
        ext = result.extended_parameters["filename"]
        assert ext == ExtendedParameter("UTF-8", "", "中文.txt")
        assert result.filename == "中文.txt"
        assert result.safe_filename == "中文.txt"
        assert result.filename_source is FilenameSource.EXTENDED
        assert result.issues == []

    def test_chinese_filename_gbk_extended(self):
        result = parse_content_disposition(
            b"attachment; filename*=gbk''%D6%D0%CE%C4.txt"
        )
        ext = result.extended_parameters["filename"]
        assert ext.charset == "gbk"
        assert ext.language == ""
        assert ext.value == "中文.txt"
        assert result.filename == "中文.txt"
        assert result.issues == []

    def test_chinese_filename_language_segment(self):
        result = parse_content_disposition(
            b"attachment; filename*=utf-8'zh-CN'%E4%B8%AD%E6%96%87.txt"
        )
        assert result.extended_parameters["filename"].language == "zh-CN"
        assert result.filename == "中文.txt"
        assert result.issues == []

    def test_chinese_raw_bytes_basic_fallback_is_latin1(self):
        # Raw non-ASCII bytes in a plain filename are ISO-8859-1 header text;
        # the charset is not guessed from the byte pattern.
        result = parse_content_disposition(
            b'attachment; filename="\xe4\xb8\xad.txt"'
        )
        assert result.filename == "\xe4\xb8\xad.txt"
        assert result.filename_source is FilenameSource.BASIC
        assert result.issues == []

    def test_extended_takes_priority_over_basic(self):
        result = parse_content_disposition(
            b"attachment; filename=fallback.txt; "
            b"filename*=UTF-8''%E4%B8%AD%E6%96%87.txt"
        )
        assert result.filename == "中文.txt"
        assert result.safe_filename == "中文.txt"
        assert result.filename_source is FilenameSource.EXTENDED
        # Both parameters are preserved, distinct names are not duplicates.
        assert result.parameters["filename"] == "fallback.txt"
        assert result.extended_parameters["filename"].value == "中文.txt"
        assert result.issues == []

    def test_basic_used_when_extended_missing(self):
        result = parse_content_disposition("attachment; filename=only.txt")
        assert result.filename == "only.txt"
        assert result.filename_source is FilenameSource.BASIC
        assert result.issues == []

    def test_basic_used_when_extended_unknown_charset(self):
        result = parse_content_disposition(
            "attachment; filename*=bogus''%E4%B8%AD.txt; filename=ok.txt"
        )
        assert "filename" not in result.extended_parameters
        assert result.filename == "ok.txt"
        assert result.filename_source is FilenameSource.BASIC
        codes = [i.code for i in result.issues]
        assert ContentDispositionIssue.UNKNOWN_CHARSET in codes
        assert ContentDispositionIssue.FILENAME_BASIC_FALLBACK in codes

    def test_malformed_percent_encoding(self):
        result = parse_content_disposition(
            "attachment; filename*=UTF-8''%E4%B8%ZZ.txt"
        )
        assert "filename" not in result.extended_parameters
        assert result.filename is None
        assert (
            ContentDispositionIssue.MALFORMED_PERCENT
            in [i.code for i in result.issues]
        )

    def test_trailing_percent_is_malformed(self):
        result = parse_content_disposition("attachment; filename*=UTF-8''abc%")
        assert (
            ContentDispositionIssue.MALFORMED_PERCENT
            in [i.code for i in result.issues]
        )

    def test_decode_error_uses_basic_fallback(self):
        result = parse_content_disposition(
            "attachment; filename*=UTF-8''%FF%FE.txt; filename=ok.txt"
        )
        assert result.filename == "ok.txt"
        codes = [i.code for i in result.issues]
        assert ContentDispositionIssue.DECODE_ERROR in codes
        assert ContentDispositionIssue.FILENAME_BASIC_FALLBACK in codes

    def test_extended_syntax_missing_separators(self):
        for bad_value in ("UTF-8data", "UTF-8'data"):
            result = parse_content_disposition(
                f"attachment; filename*={bad_value}"
            )
            assert (
                ContentDispositionIssue.EXTENDED_SYNTAX
                in [i.code for i in result.issues]
            )

    def test_extended_quoted_value_rejected(self):
        result = parse_content_disposition(
            "attachment; filename*=\"UTF-8''%E4%B8%AD.txt\""
        )
        assert (
            ContentDispositionIssue.EXTENDED_SYNTAX
            in [i.code for i in result.issues]
        )

    def test_duplicate_basic_parameter_first_wins(self):
        result = parse_content_disposition(
            "attachment; filename=a.txt; filename=b.txt"
        )
        assert result.filename == "a.txt"
        duplicate = [
            i for i in result.issues
            if i.code is ContentDispositionIssue.DUPLICATE_PARAMETER
        ]
        assert len(duplicate) == 1
        assert duplicate[0].parameter == "filename"

    def test_duplicate_extended_parameter_first_wins(self):
        result = parse_content_disposition(
            "attachment; filename*=UTF-8''a.txt; filename*=UTF-8''b.txt"
        )
        assert result.filename == "a.txt"
        assert (
            ContentDispositionIssue.DUPLICATE_PARAMETER
            in [i.code for i in result.issues]
        )

    def test_empty_quoted_filename(self):
        result = parse_content_disposition('attachment; filename=""')
        assert result.filename == ""
        assert result.safe_filename == "download"
        assert (
            ContentDispositionIssue.EMPTY_FILENAME
            in [i.code for i in result.issues]
        )

    def test_no_filename_parameter(self):
        result = parse_content_disposition(
            "attachment; creation-date=\"Wed, 12 Feb 1997 16:29:51 -0500\""
        )
        assert result.filename is None
        assert result.safe_filename is None
        assert (
            ContentDispositionIssue.NO_FILENAME
            in [i.code for i in result.issues]
        )

    def test_path_traversal_posix(self):
        result = parse_content_disposition(
            'attachment; filename="../../etc/passwd"'
        )
        assert result.filename == "../../etc/passwd"
        assert result.safe_filename == "passwd"

    def test_path_traversal_windows(self):
        result = parse_content_disposition(
            'attachment; filename="C:\\\\Windows\\\\win.ini"'
        )
        assert result.filename == "C:\\Windows\\win.ini"
        assert result.safe_filename == "win.ini"

    def test_unc_and_root_paths(self):
        assert safe_filename("\\\\server\\share\\f.txt") == "f.txt"
        assert safe_filename("/etc/passwd") == "passwd"

    def test_only_separators_uses_default(self):
        result = parse_content_disposition('attachment; filename="../../"')
        assert result.filename == "../../"
        assert result.safe_filename == "download"
        assert (
            ContentDispositionIssue.EMPTY_FILENAME
            in [i.code for i in result.issues]
        )

    def test_control_characters_removed(self):
        result = parse_content_disposition('attachment; filename="a\x00b.txt"')
        assert result.filename == "a\x00b.txt"
        assert result.safe_filename == "ab.txt"

    def test_control_only_filename_uses_default(self):
        result = parse_content_disposition('attachment; filename="\x00\x01"')
        assert result.safe_filename == "download"
        assert (
            ContentDispositionIssue.EMPTY_FILENAME
            in [i.code for i in result.issues]
        )

    def test_safe_filename_trims_surrounding_whitespace(self):
        assert safe_filename("  report.pdf  ") == "report.pdf"
        assert safe_filename("  ") == "download"

    def test_other_parameters_not_altered(self):
        header = (
            'attachment; filename="../../evil.txt"; size="42"; '
            "creation-date=\"Wed, 12 Feb 1997 16:29:51 -0500\"; "
            "readdate=\"Wed, 12 Feb 1997 16:29:51 -0500\"; "
            'name*0="start"'
        )
        result = parse_content_disposition(header)
        assert result.parameters["size"] == "42"
        assert result.parameters["creation-date"] == (
            "Wed, 12 Feb 1997 16:29:51 -0500"
        )
        assert result.parameters["readdate"] == (
            "Wed, 12 Feb 1997 16:29:51 -0500"
        )
        assert result.parameters["name*0"] == "start"
        assert result.filename == "../../evil.txt"
        assert result.safe_filename == "evil.txt"

    def test_other_extended_parameters_parsed(self):
        result = parse_content_disposition(
            b"attachment; title*=utf-8'en'%E4%B8%AD%E6%96%87; filename=x"
        )
        assert result.extended_parameters["title"] == ExtendedParameter(
            "utf-8", "en", "中文"
        )
        assert result.filename == "x"

    def test_bytes_input_decoded_as_latin1(self):
        result = parse_content_disposition(b"attachment; filename=caf\xe9.txt")
        assert result.filename == "caf\xe9.txt"

    def test_non_string_input_raises(self):
        import pytest

        with pytest.raises(TypeError):
            parse_content_disposition(123)  # type: ignore[arg-type]
